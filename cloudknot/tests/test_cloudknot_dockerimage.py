from __future__ import absolute_import, division, print_function

import cloudknot as ck
import configparser
import docker
import filecmp
import os
import os.path as op
import pytest
import six
import tempfile
import tenacity
import uuid

UNIT_TEST_PREFIX = 'cloudknot-unit-test'
data_path = op.join(ck.__path__[0], 'data')


def get_testing_name():
    u = str(uuid.uuid4()).replace('-', '')[:8]
    name = UNIT_TEST_PREFIX + '-' + u
    return name


@pytest.fixture(scope='module')
def bucket_cleanup():
    ck.set_s3_bucket('cloudknot-travis-build-45814031-351c-'
                     '4b27-9a40-672c971f7e83')
    yield None
    bucket = ck.get_s3_bucket()
    bucket_policy = ck.aws.base_classes.get_s3_policy_name(bucket)

    s3 = ck.aws.clients['s3']
    s3.delete_bucket(Bucket=bucket)

    iam = ck.aws.clients['iam']
    response = iam.list_policies(
        Scope='Local',
        PathPrefix='/cloudknot/'
    )

    policy_dict = [p for p in response.get('Policies')
                   if p['PolicyName'] == bucket_policy][0]

    arn = policy_dict['Arn']

    response = iam.list_policy_versions(
        PolicyArn=arn
    )

    # Get non-default versions
    versions = [v for v in response.get('Versions')
                if not v['IsDefaultVersion']]

    # Get the oldest version and delete it
    for v in versions:
        iam.delete_policy_version(
            PolicyArn=arn,
            VersionId=v['VersionId']
        )

    response = iam.list_entities_for_policy(
        PolicyArn=arn,
        EntityFilter='Role'
    )

    roles = response.get('PolicyRoles')
    for role in roles:
        iam.detach_role_policy(
            RoleName=role['RoleName'],
            PolicyArn=arn
        )

    iam.delete_policy(PolicyArn=arn)


@pytest.fixture(scope='module')
def cleanup(bucket_cleanup):
    """Use this fixture to delete all unit testing resources
    regardless of of the failure or success of the test"""
    yield None
    iam = ck.aws.clients['iam']
    ec2 = ck.aws.clients['ec2']
    batch = ck.aws.clients['batch']
    ecs = ck.aws.clients['ecs']
    config_file = ck.config.get_config_file()
    section_suffix = ck.get_profile() + ' ' + ck.get_region()
    jq_section_name = 'job-queues ' + section_suffix
    ce_section_name = 'compute-environments ' + section_suffix
    jd_section_name = 'job-definitions ' + section_suffix
    roles_section_name = 'roles ' + ck.get_profile() + ' global'
    vpc_section_name = 'vpc ' + section_suffix
    sg_section_name = 'security-groups ' + section_suffix

    retry = tenacity.Retrying(
        wait=tenacity.wait_exponential(max=16),
        stop=tenacity.stop_after_delay(120),
        retry=tenacity.retry_if_exception_type(
            batch.exceptions.ClientException
        )
    )

    # Clean up job queues from AWS
    # ----------------------------
    # Find all unit testing job queues
    response = batch.describe_job_queues()

    job_queues = [
        {
            'name': d['jobQueueName'],
            'arn': d['jobQueueArn'],
            'state': d['state'],
            'status': d['status']
        } for d in response.get('jobQueues')
    ]

    while response.get('nextToken'):
        response = batch.describe_job_queues(
            nextToken=response.get('nextToken')
        )

        job_queues = job_queues + [
            {
                'name': d['jobQueueName'],
                'arn': d['jobQueueArn'],
                'state': d['state'],
                'status': d['status']
            } for d in response.get('jobQueues')
        ]

    unit_test_JQs = list(filter(
        lambda d: UNIT_TEST_PREFIX in d['name'], job_queues
    ))

    enabled = list(filter(
        lambda d: d['state'] == 'ENABLED', unit_test_JQs
    ))

    for jq in enabled:
        ck.aws.wait_for_job_queue(name=jq['name'], max_wait_time=180)
        retry.call(batch.update_job_queue,
                   jobQueue=jq['arn'], state='DISABLED')

    config = configparser.ConfigParser()
    with ck.config.rlock:
        config.read(config_file)

    requires_deletion = list(filter(
        lambda d: d['status'] not in ['DELETED', 'DELETING'],
        unit_test_JQs
    ))

    for jq in requires_deletion:
        ck.aws.wait_for_job_queue(name=jq['name'], max_wait_time=180)

        # Finally, delete the job queue
        retry.call(batch.delete_job_queue, jobQueue=jq['arn'])

        # Clean up config file
        try:
            config.remove_option(jq_section_name, jq['name'])
        except configparser.NoSectionError:
            pass

    with open(config_file, 'w') as f:
        config.write(f)

    # Clean up compute environments from AWS
    # --------------------------------------
    # Find all unit testing compute environments
    response = batch.describe_compute_environments()

    comp_envs = [
        {
            'name': d['computeEnvironmentName'],
            'arn': d['computeEnvironmentArn'],
            'state': d['state'],
            'status': d['status']
        } for d in response.get('computeEnvironments')
    ]

    while response.get('nextToken'):
        response = batch.describe_compute_environments(
            nextToken=response.get('nextToken')
        )

        comp_envs = comp_envs + [
            {
                'name': d['computeEnvironmentName'],
                'arn': d['computeEnvironmentArn'],
                'state': d['state'],
                'status': d['status']
            } for d in response.get('computeEnvironments')
        ]

    unit_test_CEs = list(filter(
        lambda d: UNIT_TEST_PREFIX in d['name'], comp_envs
    ))

    enabled = list(filter(
        lambda d: d['state'] == 'ENABLED', unit_test_CEs
    ))

    for ce in enabled:
        ck.aws.wait_for_compute_environment(
            arn=ce['arn'], name=ce['name'], log=False
        )

        # Set the compute environment state to 'DISABLED'
        retry.call(batch.update_compute_environment,
                   computeEnvironment=ce['arn'],
                   state='DISABLED')

    config = configparser.ConfigParser()
    with ck.config.rlock:
        config.read(config_file)

    for ce in unit_test_CEs:
        # Then disassociate from any job queues
        response = batch.describe_job_queues()
        associated_queues = list(filter(
            lambda q: ce['arn'] in [
                c['computeEnvironment'] for c
                in q['computeEnvironmentOrder']
            ],
            response.get('jobQueues')
        ))

        for queue in associated_queues:
            arn = queue['jobQueueArn']
            name = queue['jobQueueName']

            # Disable submissions to the queue
            if queue['state'] == 'ENABLED':
                ck.aws.wait_for_job_queue(
                    name=name, log=True, max_wait_time=180
                )
                retry.call(batch.update_job_queue,
                           jobQueue=arn, state='DISABLED')

            # Delete the job queue
            if queue['status'] not in ['DELETED', 'DELETING']:
                ck.aws.wait_for_job_queue(
                    name=name, log=True, max_wait_time=180
                )
                retry.call(batch.delete_job_queue, jobQueue=arn)

            # Clean up config file
            try:
                config.remove_option(jq_section_name, name)
            except configparser.NoSectionError:
                pass

    requires_deletion = list(filter(
        lambda d: d['status'] not in ['DELETED', 'DELETING'],
        unit_test_CEs
    ))

    for ce in requires_deletion:
        # Now get the associated ECS cluster
        response = batch.describe_compute_environments(
            computeEnvironments=[ce['arn']]
        )
        cluster_arn = response.get('computeEnvironments')[0]['ecsClusterArn']

        # Get container instances
        response = ecs.list_container_instances(
            cluster=cluster_arn,
        )
        instances = response.get('containerInstanceArns')

        for i in instances:
            ecs.deregister_container_instance(
                cluster=cluster_arn,
                containerInstance=i,
                force=True
            )

        retry_if_exception = tenacity.Retrying(
            wait=tenacity.wait_exponential(max=16),
            stop=tenacity.stop_after_delay(120),
            retry=tenacity.retry_if_exception_type()
        )
        retry_if_exception.call(
            ecs.delete_cluster,
            cluster=cluster_arn
        )

        ck.aws.wait_for_compute_environment(
            arn=ce['arn'], name=ce['name'], log=False
        )

        retry.call(
            batch.delete_compute_environment,
            computeEnvironment=ce['arn']
        )

        # Clean up config file
        try:
            config.remove_option(ce_section_name, ce['name'])
        except configparser.NoSectionError:
            pass

    with open(config_file, 'w') as f:
        config.write(f)

    # Clean up job definitions from AWS
    # ---------------------------------
    # Find all unit testing job definitions
    response = batch.describe_job_definitions(status='ACTIVE')

    jds = [{'name': d['jobDefinitionName'], 'arn': d['jobDefinitionArn']}
           for d in response.get('jobDefinitions')]

    unit_test_jds = list(filter(
        lambda d: UNIT_TEST_PREFIX in d['name'],
        jds
    ))

    while response.get('nextToken'):
        response = batch.describe_job_definitions(
            status='ACTIVE',
            nextToken=response.get('nextToken')
        )

        jds = [{'name': d['jobDefinitionName'],
                'arn': d['jobDefinitionArn']}
               for d in response.get('jobDefinitions')]

        unit_test_jds = unit_test_jds + list(filter(
            lambda d: UNIT_TEST_PREFIX in d['name'],
            jds
        ))

    config = configparser.ConfigParser()
    with ck.config.rlock:
        config.read(config_file)

        for jd in unit_test_jds:
            # Deregister the job definition
            retry.call(batch.deregister_job_definition,
                       jobDefinition=jd['arn'])

            # Clean up config file
            try:
                config.remove_option(jd_section_name, jd['name'])
            except configparser.NoSectionError:
                pass

        with open(config_file, 'w') as f:
            config.write(f)

    # Clean up security_groups from AWS
    # ---------------------------------
    # Find all unit test security groups
    ec2_retry = tenacity.Retrying(
        wait=tenacity.wait_exponential(max=16),
        stop=tenacity.stop_after_delay(60),
        retry=tenacity.retry_if_exception_type(
            ec2.exceptions.ClientError
        )
    )

    response = ec2.describe_security_groups()
    sgs = [
        {'name': d['GroupName'], 'id': d['GroupId']}
        for d in response.get('SecurityGroups')
    ]
    unit_test_sgs = filter(
        lambda d: UNIT_TEST_PREFIX in d['name'],
        sgs
    )

    config = configparser.ConfigParser()
    with ck.config.rlock:
        config.read(config_file)

        for sg in unit_test_sgs:
            # Delete role
            ec2_retry.call(ec2.delete_security_group, GroupId=sg['id'])

            # Clean up config file
            try:
                config.remove_option(sg_section_name, sg['id'])
            except configparser.NoSectionError:
                pass

        with open(config_file, 'w') as f:
            config.write(f)

    # Clean up VPCs from AWS
    # ----------------------
    config = configparser.ConfigParser()
    with ck.config.rlock:
        config.read(config_file)

        # Find all VPCs with a Name tag key
        response = ec2.describe_vpcs(
            Filters=[{
                'Name': 'tag-key',
                'Values': ['Name']
            }]
        )

        for vpc in response.get('Vpcs'):
            # Test if the unit-test prefix is in the name
            if UNIT_TEST_PREFIX in [
                d for d in vpc['Tags'] if d['Key'] == 'Name'
            ][0]['Value']:
                # Retrieve and delete subnets
                response = ec2.describe_subnets(
                    Filters=[
                        {
                            'Name': 'vpc-id',
                            'Values': [vpc['VpcId']]
                        }
                    ]
                )

                subnets = [d['SubnetId'] for d in response.get('Subnets')]

                for subnet_id in subnets:
                    ec2_retry.call(ec2.delete_subnet, SubnetId=subnet_id)

                response = ec2.describe_network_acls(Filters=[
                    {'Name': 'vpc-id', 'Values': [vpc['VpcId']]},
                    {'Name': 'default', 'Values': ['false']}
                ])

                network_acl_ids = [n['NetworkAclId']
                                   for n in response.get('NetworkAcls')]

                # Delete the network ACL
                for net_id in network_acl_ids:
                    ec2_retry.call(ec2.delete_network_acl, NetworkAclId=net_id)

                response = ec2.describe_route_tables(Filters=[
                    {'Name': 'vpc-id', 'Values': [vpc['VpcId']]},
                    {'Name': 'association.main', 'Values': ['false']}
                ])

                route_table_ids = [rt['RouteTableId']
                                   for rt in response.get('RouteTables')]

                # Delete the route table
                for rt_id in route_table_ids:
                    ec2_retry.call(ec2.delete_route_table, RouteTableId=rt_id)

                # Detach and delete the internet gateway
                response = ec2.describe_internet_gateways(Filters=[{
                    'Name': 'attachment.vpc-id',
                    'Values': [vpc['VpcId']]
                }])

                gateway_ids = [g['InternetGatewayId']
                               for g in response.get('InternetGateways')]

                for gid in gateway_ids:
                    ec2_retry.call(ec2.detach_internet_gateway,
                                   InternetGatewayId=gid,
                                   VpcId=vpc['VpcId'])
                    ec2_retry.call(ec2.delete_internet_gateway,
                                   InternetGatewayId=gid)

                # delete the VPC
                ec2_retry.call(ec2.delete_vpc, VpcId=vpc['VpcId'])

                # Clean up config file
                try:
                    config.remove_option(vpc_section_name, vpc['VpcId'])
                except configparser.NoSectionError:
                    pass

        with open(config_file, 'w') as f:
            config.write(f)

    # Clean up roles from AWS
    # -----------------------
    # Find all unit test roles
    response = iam.list_roles()
    role_names = [d['RoleName'] for d in response.get('Roles')]
    unit_test_roles = filter(
        lambda n: UNIT_TEST_PREFIX in n,
        role_names
    )

    for role_name in unit_test_roles:
        # Remove instance profiles
        response = iam.list_instance_profiles_for_role(RoleName=role_name)
        for ip in response.get('InstanceProfiles'):
            iam.remove_role_from_instance_profile(
                InstanceProfileName=ip['InstanceProfileName'],
                RoleName=role_name
            )
            iam.delete_instance_profile(
                InstanceProfileName=ip['InstanceProfileName']
            )

        # Detach policies from role
        response = iam.list_attached_role_policies(RoleName=role_name)
        for policy in response.get('AttachedPolicies'):
            iam.detach_role_policy(
                RoleName=role_name,
                PolicyArn=policy['PolicyArn']
            )

        # Delete role
        iam.delete_role(RoleName=role_name)

    # Clean up config file
    config = configparser.ConfigParser()
    with ck.config.rlock:
        config.read(config_file)
        for role_name in config.options(roles_section_name):
            if UNIT_TEST_PREFIX in role_name:
                config.remove_option(roles_section_name, role_name)
        with open(config_file, 'w') as f:
            config.write(f)


@pytest.fixture(scope='module')
def cleanup_repos(bucket_cleanup):
    yield None
    ecr = ck.aws.clients['ecr']
    config_file = ck.config.get_config_file()
    section_suffix = ck.get_profile() + ' ' + ck.get_region()
    repos_section_name = 'docker-repos ' + section_suffix

    # Clean up repos from AWS
    # -----------------------
    # Get all repos with unit test prefix in the name
    response = ecr.describe_repositories()
    repos = [r for r in response.get('repositories')
             if ('unit_testing_func' in r['repositoryName']
                 or 'test_func_input' in r['repositoryName']
                 or 'simple_unit_testing_func' in r['repositoryName']
                 or UNIT_TEST_PREFIX in r['repositoryName'])]

    # Delete the AWS ECR repo
    for r in repos:
        ecr.delete_repository(
            registryId=r['registryId'],
            repositoryName=r['repositoryName'],
            force=True
        )

    # Clean up repos from config file
    config = configparser.ConfigParser()
    with ck.config.rlock:
        config.read(config_file)
        for repo_name in config.options(repos_section_name):
            if UNIT_TEST_PREFIX in repo_name:
                config.remove_option(repos_section_name, repo_name)
        with open(config_file, 'w') as f:
            config.write(f)


def test_Pars(bucket_cleanup):
    config_file = ck.config.get_config_file()
    p = None

    try:
        name = get_testing_name()
        p = ck.Pars(name=name)

        # Re-instantiate the PARS so that it retrieves from config
        # with resources that already exist
        p = ck.Pars(name=name)

        pre = name + '-cloudknot-'
        assert p.batch_service_role.name == pre + 'batch-service-role'
        assert p.ecs_instance_role.name == pre + 'ecs-instance-role'
        assert p.spot_fleet_role.name == pre + 'spot-fleet-role'
        assert p.vpc.name == pre + 'vpc'
        assert p.security_group.name == pre + 'security-group'

        # Clobber the resources without clobbering the PARS
        # in order to leave the config file untouched
        p.batch_service_role.clobber()
        p.ecs_instance_role.clobber()
        p.ecs_task_role.clobber()
        p.spot_fleet_role.clobber()
        p.security_group.clobber()
        p.vpc.clobber()

        # Now re-instantiate so that the PARS loads from the config file
        # with resources that don't exist anymore
        # First, with specifying other resource names, to throw error
        with pytest.raises(ValueError):
            ck.Pars(name=name, spot_fleet_role_name=get_testing_name())

        # And for real this time
        p = ck.Pars(name=name)

        # Now remove the section from config file
        config = configparser.ConfigParser()
        with ck.config.rlock:
            config.read(config_file)
            config.remove_section('pars ' + name)
            with open(config_file, 'w') as f:
                config.write(f)

        # And re-instantiate by supplying resource names
        p = ck.Pars(
            name=name,
            batch_service_role_name=p.batch_service_role.name,
            ecs_instance_role_name=p.ecs_instance_role.name,
            spot_fleet_role_name=p.spot_fleet_role.name,
            vpc_id=p.vpc.vpc_id,
            security_group_id=p.security_group.security_group_id,
            use_default_vpc=False
        )

        assert p.batch_service_role.name == pre + 'batch-service-role'
        assert p.ecs_instance_role.name == pre + 'ecs-instance-role'
        assert p.spot_fleet_role.name == pre + 'spot-fleet-role'
        assert p.vpc.name == pre + 'vpc'
        assert p.security_group.name == pre + 'security-group'

        # Do that last part over again but specify VPC and security group
        # names instead of IDs
        # Remove the section from config file
        config = configparser.ConfigParser()
        with ck.config.rlock:
            config.read(config_file)
            config.remove_section('pars ' + name)
            with open(config_file, 'w') as f:
                config.write(f)

        # And re-instantiate by supplying resource names
        p = ck.Pars(
            name=name,
            batch_service_role_name=p.batch_service_role.name,
            ecs_instance_role_name=p.ecs_instance_role.name,
            spot_fleet_role_name=p.spot_fleet_role.name,
            vpc_name=p.vpc.name,
            security_group_name=p.security_group.name,
            use_default_vpc=False
        )

        assert p.batch_service_role.name == pre + 'batch-service-role'
        assert p.ecs_instance_role.name == pre + 'ecs-instance-role'
        assert p.spot_fleet_role.name == pre + 'spot-fleet-role'
        assert p.vpc.name == pre + 'vpc'
        assert p.security_group.name == pre + 'security-group'

        # Test setting new batch service role
        # -----------------------------------
        with pytest.raises(ValueError):
            p.batch_service_role = 42

        role = ck.aws.IamRole(
            name=get_testing_name(),
            service='batch',
            policies=('AWSBatchServiceRole',)
        )
        p.batch_service_role = role

        # Assert batch service role attribute is the same
        assert p.batch_service_role == role

        # Assert config file changed
        config = configparser.ConfigParser()
        with ck.config.rlock:
            config.read(config_file)

        assert config.get(p.pars_name, 'batch-service-role') == role.name

        # Test setting new ecs instance role
        # ----------------------------------
        with pytest.raises(ValueError):
            p.ecs_instance_role = 42

        role = ck.aws.IamRole(
            name=get_testing_name(),
            service='ec2',
            policies=('AmazonEC2ContainerServiceforEC2Role',),
            add_instance_profile=True
        )
        p.ecs_instance_role = role

        # Assert ecs instance role attribute is the same
        assert p.ecs_instance_role == role

        # Assert config file changed
        config = configparser.ConfigParser()
        with ck.config.rlock:
            config.read(config_file)

        assert config.get(p.pars_name, 'ecs-instance-role') == role.name

        # Test setting new spot fleet role
        # --------------------------------
        with pytest.raises(ValueError):
            p.spot_fleet_role = 42

        role = ck.aws.IamRole(
            name=get_testing_name(),
            service='spotfleet',
            policies=('AmazonEC2SpotFleetRole',)
        )
        p.spot_fleet_role = role

        # Assert spot fleet role attribute is the same
        assert p.spot_fleet_role == role

        # Assert config file changed
        config = configparser.ConfigParser()
        with ck.config.rlock:
            config.read(config_file)

        assert config.get(p.pars_name, 'spot-fleet-role') == role.name

        # Test setting new security group
        # --------------------------------
        with pytest.raises(ValueError):
            p.security_group = 42

        sg = ck.aws.SecurityGroup(name=get_testing_name(), vpc=p.vpc)
        p.security_group = sg

        # Assert spot fleet role attribute is the same
        assert p.security_group == sg

        # Assert config file changed
        config = configparser.ConfigParser()
        with ck.config.rlock:
            config.read(config_file)

        assert (config.get(p.pars_name, 'security-group') ==
                sg.security_group_id)

        # Test setting new VPC
        # --------------------------------
        with pytest.raises(ValueError):
            p.vpc = 42

        vpc = ck.aws.Vpc(name=get_testing_name())
        p.vpc = vpc

        # Assert spot fleet role attribute is the same
        assert p.vpc == vpc

        # Assert config file changed
        config = configparser.ConfigParser()
        with ck.config.rlock:
            config.read(config_file)

        assert config.get(p.pars_name, 'vpc') == vpc.vpc_id

        p.clobber()

        config = configparser.ConfigParser()
        with ck.config.rlock:
            config.read(config_file)

        assert 'pars ' + name not in config.sections()

        # Test Exceptions on invalid input
        # --------------------------------
        # Assert ValueError on invalid name
        with pytest.raises(ValueError):
            ck.Pars(name=42)

        # Assert ValueError on invalid vpc_name
        with pytest.raises(ValueError):
            ck.Pars(name=get_testing_name(), vpc_name=42)

        # Assert ValueError on invalid vpc_id
        with pytest.raises(ValueError):
            ck.Pars(name=get_testing_name(), vpc_id=42)

        # Assert ValueError on invalid security_group_name
        with pytest.raises(ValueError):
            ck.Pars(name=get_testing_name(), security_group_name=42)

        # Assert ValueError on invalid security_group_id
        with pytest.raises(ValueError):
            ck.Pars(name=get_testing_name(), security_group_id=42)

        # Assert ValueError on invalid batch_service_role_name
        with pytest.raises(ValueError):
            ck.Pars(name=get_testing_name(), batch_service_role_name=42)

        # Assert ValueError on invalid ecs_instance_role_name
        with pytest.raises(ValueError):
            ck.Pars(name=get_testing_name(), ecs_instance_role_name=42)

        # Assert ValueError on invalid spot_fleet_role_name
        with pytest.raises(ValueError):
            ck.Pars(name=get_testing_name(), spot_fleet_role_name=42)
    except Exception as e:
        if p:
            p.clobber()

        raise e


def simple_unit_testing_func(name=None):
    """Simple test function with no imports for a small docker image"""
    return 'Hello world!'


def unit_testing_func(name=None, no_capitalize=False):
    """Test function for unit testing of cloudknot.DockerImage

    Import statements of various formats are deliberately scattered
    throughout the function to test the pipreqs components of
    clouknot.DockerImage
    """
    import sys  # noqa: F401
    import boto3.ec2  # noqa: F401
    import AFQ  # noqa: F401
    if name:
        from docker import api  # noqa: F401
        from os.path import join  # noqa: F401

        if not no_capitalize:
            import pytest as pt  # noqa: F401
            import h5py.utils as h5utils  # noqa: F401

            name = name.title()

        return 'Hello {0}!'.format(name)

    from six import binary_type as bt  # noqa: F401
    from dask.base import curry as dbc  # noqa: F401

    return 'Hello world!'


def test_DockerImage(cleanup_repos):
    config = configparser.ConfigParser()
    config_file = ck.config.get_config_file()
    ecr = ck.aws.clients['ecr']

    try:
        correct_pip_imports = set([
            'boto3', 'six', 'dask', 'docker',
            'pytest', 'h5py', 'cloudpickle'
        ])

        # First, test a DockerImage instance with `func` input
        # ----------------------------------------------------
        di = ck.DockerImage(func=unit_testing_func)

        assert di.name == unit_testing_func.__name__
        import_names = set([d['name'] for d in di.pip_imports])
        assert import_names == correct_pip_imports
        assert di.missing_imports == ['AFQ']
        assert di.username == 'cloudknot-user'
        assert di.func == unit_testing_func

        py_dir = 'py3' if six.PY3 else 'py2'

        # Compare the created files with the reference files
        correct_dir = op.join(
            data_path, 'docker_reqs_ref_data', py_dir, 'ref1'
        )
        correct_req_path = op.join(correct_dir, 'requirements.txt')
        correct_dockerfile = op.join(correct_dir, 'Dockerfile')

        correct_script_path = op.join(correct_dir, 'unit_testing_func.py')

        with open(correct_req_path) as f:
            correct_reqs = set([s.split('=')[0] for s in f.readlines()])

        with open(di.req_path) as f:
            created_reqs = set([s.split('=')[0] for s in f.readlines()])

        assert created_reqs == correct_reqs
        assert filecmp.cmp(di.docker_path, correct_dockerfile, shallow=False)
        assert filecmp.cmp(di.script_path, correct_script_path, shallow=False)

        # Confirm that the docker image is in the config file
        config = configparser.ConfigParser()
        with ck.config.rlock:
            config.read(config_file)

        assert 'docker-image ' + di.name in config.sections()

        # Next, retrieve another instance with the same name, confirm that it
        # retrieves the same info from the config file
        di2 = ck.DockerImage(name=di.name)
        assert di2.build_path == di.build_path
        assert di2.docker_path == di.docker_path
        assert di2.images == di.images
        assert di2.missing_imports == di.missing_imports
        assert di2.name == di.name
        assert di2.pip_imports == di.pip_imports
        assert di2.repo_uri == di.repo_uri
        assert di2.req_path == di.req_path
        assert di2.script_path == di.script_path
        assert di2.username == di.username

        # Clobber and confirm that it deleted all the created files and dirs
        di2.clobber()
        assert not op.isfile(di.req_path)
        assert not op.isfile(di.docker_path)
        assert not op.isfile(di.script_path)
        assert not op.isdir(di.build_path)

        # Assert that it was removed from the config file
        # If we just re-read the config file, config will keep the union
        # of the in memory values and the file values, updating the
        # intersection of the two with the file values. So we must clear
        # config and then re-read the file
        config = configparser.ConfigParser()
        with ck.config.rlock:
            config.read(config_file)

        assert 'docker-image ' + di.name not in config.sections()

        # Second, test a DockerImage with a func and a dir_name
        # -----------------------------------------------------
        dir_name = tempfile.mkdtemp(dir=os.getcwd())
        di = ck.DockerImage(
            func=unit_testing_func,
            dir_name=dir_name
        )

        assert di.name == unit_testing_func.__name__
        import_names = set([d['name'] for d in di.pip_imports])
        assert import_names == correct_pip_imports
        assert di.missing_imports == ['AFQ']
        assert di.username == 'cloudknot-user'
        assert di.func == unit_testing_func

        with open(di.req_path) as f:
            created_reqs = set([s.split('=')[0] for s in f.readlines()])

        assert created_reqs == correct_reqs
        assert filecmp.cmp(di.docker_path, correct_dockerfile, shallow=False)
        assert filecmp.cmp(di.script_path, correct_script_path, shallow=False)

        # Confirm that the docker image is in the config file
        config = configparser.ConfigParser()
        with ck.config.rlock:
            config.read(config_file)

        assert 'docker-image ' + di.name in config.sections()

        # Clobber and confirm that it deleted all the created files and dirs
        di.clobber()
        assert not op.isfile(di.req_path)
        assert not op.isfile(di.docker_path)
        assert not op.isfile(di.script_path)
        assert not op.isdir(di.build_path)

        # Assert that it was removed from the config file
        # If we just re-read the config file, config will keep the union
        # of the in memory values and the file values, updating the
        # intersection of the two with the file values. So we must clear
        # config and then re-read the file
        config = configparser.ConfigParser()
        with ck.config.rlock:
            config.read(config_file)

        assert 'docker-image ' + di.name not in config.sections()

        # Third, test a DockerImage with script_path and dir_name input
        # -------------------------------------------------------------
        correct_dir = op.join(
            data_path, 'docker_reqs_ref_data', py_dir, 'ref2'
        )
        script_path = op.join(correct_dir, 'test_func_input.py')

        # Put the results in a temp dir with a pre-existing file
        dir_name = tempfile.mkdtemp(dir=os.getcwd())
        _, tmp_file_name = tempfile.mkstemp(dir=dir_name)

        di = ck.DockerImage(
            script_path=script_path,
            dir_name=dir_name,
            username='unit-test-username'
        )

        assert di.name == op.basename(script_path)
        import_names = set([d['name'] for d in di.pip_imports])
        assert import_names == correct_pip_imports
        assert di.missing_imports == []
        assert di.username == 'unit-test-username'
        assert di.func is None
        assert di.build_path == dir_name
        assert di.script_path == script_path

        # Compare the created files with the reference files
        correct_dir = op.join(
            data_path, 'docker_reqs_ref_data', py_dir, 'ref2'
        )
        correct_req_path = op.join(correct_dir, 'requirements.txt')
        correct_dockerfile = op.join(correct_dir, 'Dockerfile')

        with open(correct_req_path) as f:
            correct_reqs = set([s.split('=')[0] for s in f.readlines()])

        with open(di.req_path) as f:
            created_reqs = set([s.split('=')[0] for s in f.readlines()])

        assert created_reqs == correct_reqs
        assert filecmp.cmp(di.docker_path, correct_dockerfile, shallow=False)

        # Confirm that the docker image is in the config file
        config = configparser.ConfigParser()
        with ck.config.rlock:
            config.read(config_file)

        assert 'docker-image ' + di.name in config.sections()

        # Clobber and confirm that it deleted all the created files
        di.clobber()
        assert not op.isfile(di.req_path)
        assert not op.isfile(di.docker_path)

        # But since we had a pre-existing file in the build_path, it should not
        # have deleted the build_path or the input python script
        assert op.isfile(di.script_path)
        assert op.isfile(tmp_file_name)
        assert op.isdir(di.build_path)

        # Now delete them to clean up after ourselves
        os.remove(tmp_file_name)
        os.rmdir(di.build_path)

        # Assert that it was removed from the config file
        # If we just re-read the config file, config will keep the union
        # of the in memory values and the file values, updating the
        # intersection of the two with the file values. So we must clear
        # config and then re-read the file
        config = configparser.ConfigParser()
        with ck.config.rlock:
            config.read(config_file)

        assert 'docker-image ' + di.name not in config.sections()

        # Test for exception handling of incorrect input
        # ----------------------------------------------

        # Assert ValueError on no input
        with pytest.raises(ValueError):
            ck.DockerImage()

        # Assert ValueError on name plus other input
        with pytest.raises(ValueError):
            ck.DockerImage(name=get_testing_name(), func=unit_testing_func)

        # Assert ValueError on non-string name input
        with pytest.raises(ValueError):
            ck.DockerImage(name=42)

        # Assert ValueError on non-existent name input
        with pytest.raises(ck.aws.ResourceDoesNotExistException):
            ck.DockerImage(name=get_testing_name())

        # Assert ValueError on redundant input
        with pytest.raises(ValueError):
            ck.DockerImage(
                func=unit_testing_func,
                script_path=correct_script_path,
                dir_name=os.getcwd()
            )

        # Assert ValueError on invalid script path
        with pytest.raises(ValueError):
            ck.DockerImage(script_path=str(uuid.uuid4()), dir_name=os.getcwd())

        # Assert ValueError on invalid dir name
        with pytest.raises(ValueError):
            ck.DockerImage(
                script_path=correct_script_path,
                dir_name=str(uuid.uuid4())
            )

        correct_dir = op.join(
            data_path, 'docker_reqs_ref_data', py_dir, 'ref1'
        )
        # Assert ValueError to prevent overwriting existing script
        with pytest.raises(ValueError):
            ck.DockerImage(func=unit_testing_func, dir_name=correct_dir)

        # Assert ValueError to prevent overwriting existing Dockerfile
        with pytest.raises(ValueError):
            ck.DockerImage(script_path=correct_script_path)

        # Assert ValueError to prevent overwriting existing requirements.txt
        # First, avoid the existing Dockerfile error by renaming the Dockerfile
        old_dockerfile = op.join(op.dirname(correct_script_path), 'Dockerfile')

        new_dockerfile = op.join(
            op.dirname(correct_script_path), 'tmpdockerfile'
        )
        os.rename(old_dockerfile, new_dockerfile)

        # Assert the ValueError
        with pytest.raises(ValueError):
            ck.DockerImage(script_path=correct_script_path)

        # Clean up our mess by renaming to the old Dockerfile
        os.rename(new_dockerfile, old_dockerfile)

        # Finally, test the build and push methods
        # ----------------------------------------

        # Make one last DockerImage instance with the simple_unit_testing_func
        di = ck.DockerImage(func=simple_unit_testing_func)

        # Create a repo to which to push this image
        response = ecr.create_repository(repositoryName=get_testing_name())
        repo_name = response['repository']['repositoryName']
        repo_uri = response['repository']['repositoryUri']

        repo = ck.aws.DockerRepo(name=repo_name)

        # Assert ValueError on push without args
        with pytest.raises(ValueError):
            di.push()

        # Assert ValueError on over-specified input
        with pytest.raises(ValueError):
            di.push(repo="input doesn't matter here", repo_uri=str(repo_uri))

        # Assert ValueError on push before build
        with pytest.raises(ValueError):
            di.push(repo_uri=str(repo_uri))

        # Assert ValueError on incorrect build args
        with pytest.raises(ValueError):
            di.build(tags=[42, -42])

        # Assert ValueError on 'latest' in tags
        with pytest.raises(ValueError):
            di.build(tags=['testing', 'latest'])

        tags = ['testing', ['testing1', 'testing2']]
        image_names = [None, 'testing_image']

        for idx, (tag, n) in enumerate(zip(tags, image_names)):
            di.build(tags=tag, image_name=n)

            n = n if n else 'cloudknot/' + di.name
            if isinstance(tag, six.string_types):
                tag = [tag]

            images = [{'name': n, 'tag': t} for t in tag]
            for im in images:
                assert im in di.images

            if idx % 2:
                di.push(repo_uri=str(repo_uri))
            else:
                di.push(repo=repo)

            assert repo_uri in di.repo_uri

        # Assert ValueError on push with invalid repo
        with pytest.raises(ValueError):
            di.push(repo=42)

        # Assert ValueError on push with invalid repo_uri
        with pytest.raises(ValueError):
            di.push(repo_uri=42)

        di.clobber()

        # Assert error on build after clobber
        with pytest.raises(ck.aws.ResourceClobberedException):
            di.build(tags=['testing'])

        # Assert ValueError on push with invalid repo_uri
        with pytest.raises(ck.aws.ResourceClobberedException):
            di.push(repo=repo)
    except Exception as e:
        # Get all local images with unit test prefix in any of the repo tags
        c = docker.from_env().api
        unit_test_images = [
            im for im in c.images()
            if any(('unit_testing_func' in tag or 'test_func_input' in tag)
                   for tag in im['RepoTags'])
        ]

        # Remove local images
        for im in unit_test_images:
            for tag in im['RepoTags']:
                c.remove_image(tag, force=True)

        # Clean up config file
        config = configparser.ConfigParser()
        with ck.config.rlock:
            config.read(config_file)

            for name in config.sections():
                if name in ['docker-image unit_testing_func',
                            'docker-image test_func_input.py']:
                    config.remove_section(name)

            try:
                section_name = 'docker-repos' + ck.aws.get_region()
                for option in config.options(section_name):
                    if UNIT_TEST_PREFIX in option:
                        config.remove_option(section_name, option)
            except configparser.NoSectionError:
                pass

            with open(config_file, 'w') as f:
                config.write(f)

        raise e


def test_Knot(cleanup_repos):
    config_file = ck.config.get_config_file()
    knot, knot2 = None, None

    try:
        pars = ck.Pars(name=get_testing_name())

        name = get_testing_name()
        knot = ck.Knot(name=name, pars=pars, func=unit_testing_func)

        # Now remove the images and repo-uri from the docker-image
        # Forcing the next call to Knot to rebuild and re-push the image.
        config = configparser.ConfigParser()
        with ck.config.rlock:
            config.read(config_file)
            config.set('docker-image ' + knot.docker_image.name, 'images', '')
            config.set('docker-image ' + knot.docker_image.name,
                       'repo-uri', '')
            with open(config_file, 'w') as f:
                config.write(f)

        # Re-instantiate the knot so that it retrieves from config
        # with AWS resources that already exist
        knot = ck.Knot(name=name)

        # Assert properties are as expected
        assert knot.name == name
        assert knot.knot_name == 'knot ' + name
        assert knot.pars.name == pars.name
        assert knot.docker_image.name == unit_testing_func.__name__
        assert knot.docker_repo.name == 'cloudknot'
        pre = name + '-cloudknot-'
        assert knot.job_definition.name == pre + 'job-definition'
        assert knot.job_queue.name == pre + 'job-queue'
        assert knot.compute_environment.name == pre + 'compute-environment'

        # Now remove the knot section from config file
        config = configparser.ConfigParser()
        with ck.config.rlock:
            config.read(config_file)
            config.remove_section('knot ' + name)
            with open(config_file, 'w') as f:
                config.write(f)

        # And re-instantiate by supplying resource names
        knot2 = ck.Knot(
            name=name,
            pars=knot.pars,
            docker_image=knot.docker_image,
            job_definition_name=knot.job_definition.name,
            compute_environment_name=knot.compute_environment.name,
            job_queue_name=knot.job_queue.name
        )

        # Assert properties are as expected
        assert knot2.name == name
        assert knot2.knot_name == 'knot ' + name
        assert knot2.pars.name == pars.name
        assert knot2.docker_image.name == unit_testing_func.__name__
        assert knot2.docker_repo is None
        assert knot2.job_definition.name == pre + 'job-definition'
        assert knot2.job_queue.name == pre + 'job-queue'
        assert knot2.compute_environment.name == pre + 'compute-environment'

        knot2.clobber(clobber_pars=True, clobber_image=True)
    except Exception as e:
        try:
            if knot2:
                knot2.clobber(clobber_pars=True, clobber_image=True)
            elif knot:
                knot.clobber(clobber_pars=True, clobber_image=True)
        except Exception:
            pass

        raise e

    pars = None
    ce = None
    jd = None
    jq = None
    knot = None

    # The next tests will use the default pars, if it already exists in the
    # config file, we shouldn't delete it when we're done.
    # Otherwise, clobber it
    config = configparser.ConfigParser()
    with ck.config.rlock:
        config.read(config_file)

    clobber_pars = 'pars default' not in config.sections()

    try:
        pars = ck.Pars()

        # Make a job definition for input testing
        jd = ck.aws.JobDefinition(
            name=get_testing_name(),
            job_role=pars.batch_service_role,
            docker_image='ubuntu',
        )

        # Make a compute environment for input testing
        ce = ck.aws.ComputeEnvironment(
            name=get_testing_name(),
            batch_service_role=pars.batch_service_role,
            instance_role=pars.ecs_instance_role, vpc=pars.vpc,
            security_group=pars.security_group,
            spot_fleet_role=pars.spot_fleet_role,
        )

        ck.aws.wait_for_compute_environment(
            arn=ce.arn, name=ce.name
        )

        # Make a job queue for input testing
        jq = ck.aws.JobQueue(
            name=get_testing_name(),
            compute_environments=ce,
            priority=1
        )

        with pytest.raises(ValueError):
            knot = ck.Knot(
                name=get_testing_name(),
                func=unit_testing_func,
                job_definition_name=jd.name,
                job_def_vcpus=42
            )

        with pytest.raises(ValueError):
            knot = ck.Knot(
                name=get_testing_name(),
                func=unit_testing_func,
                compute_environment_name=ce.name,
                desired_vcpus=42
            )

        with pytest.raises(ValueError):
            knot = ck.Knot(
                name=get_testing_name(),
                func=unit_testing_func,
                job_queue_name=jq.name,
                priority=42
            )
    finally:
        try:
            if knot:
                knot.clobber()

            for resource in [jq, ce, jd]:
                if resource:
                    resource.clobber()

            if pars and clobber_pars:
                pars.clobber()
        except Exception:
            pass

    # Test Exceptions on invalid input
    # --------------------------------
    # Assert ValueError on invalid name
    with pytest.raises(ValueError):
        ck.Knot(name=42)

    # Assert ValueError on invalid pars input
    with pytest.raises(ValueError):
        ck.Knot(func=unit_testing_func, pars=42)
