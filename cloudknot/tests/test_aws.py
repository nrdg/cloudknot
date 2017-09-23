"""Test classes, functions, etc. in the aws submodule

This file contains tests for classes, functions, etc. in the aws submodule.
Each of the classes in the AWS submodule represents an AWS resource.
The tests for each resource all follow the same pattern:

* Smoke testing:
  - Use boto3 to create a resource.
  - Use cloudknot to create a resource with same name and different properties.
  - Assert that cloudknot resource instance raises an ResourceExistsException.
  - Use cloudknot to create a resource instance with only the (name, ARN, etc.)
    input of the pre-existing resource (no conflicting parameter info).
  - Confirm that the cloudknot resource instance has the right properties.
  - Confirm that the resource is now in the config file.
  - Create some more resource instances from scratch, perhaps with different
    input values.
  - Use boto3 to confirm their existence and properties.
  - Confirm that they now exist in the config file.
  - Clobber the resources we created.
  - Use boto3 to confirm that they don't exist anymore.
  - Confirm that they were removed from the config file.
* Other tests of improper input
"""
from __future__ import absolute_import, division, print_function

import configparser
import json
import pytest
import uuid

import boto3
import cloudknot as ck

UNIT_TEST_PREFIX = 'cloudknot-unit-test'


def get_unit_test_name():
    return UNIT_TEST_PREFIX + '-' + str(uuid.uuid4())


def get_unit_test_error_assertion_name():
    return UNIT_TEST_PREFIX + '-assert-error-' + str(uuid.uuid4())


def test_wait_for_compute_environment():
    # Create a PARS and ComputeEnvironment to test the function
    pars = None
    ce = None
    try:
        name = get_unit_test_name()
        pars = ck.Pars(name='unit-test')

        ce = ck.aws.ComputeEnvironment(
            name=name, batch_service_role=pars.batch_service_role,
            instance_role=pars.ecs_instance_role, vpc=pars.vpc,
            security_group=pars.security_group,
            spot_fleet_role=pars.spot_fleet_role
        )

        with pytest.raises(SystemExit):
            ck.aws.wait_for_compute_environment(
                arn=ce.arn, name=ce.name,
                log=False, max_wait_time=0
            )
    finally:  # pragma: nocover
        # Cleanup
        if ce:
            ce.clobber()
        # if pars:
        #     pars.clobber()


def test_wait_for_job_queue():
    # Create a PARS and ComputeEnvironment to test the function
    pars = None
    ce = None
    jq = None
    try:
        pars = ck.Pars(name='unit-test')

        ce = ck.aws.ComputeEnvironment(
            name=get_unit_test_name(),
            batch_service_role=pars.batch_service_role,
            instance_role=pars.ecs_instance_role, vpc=pars.vpc,
            security_group=pars.security_group,
            spot_fleet_role=pars.spot_fleet_role
        )

        ck.aws.wait_for_compute_environment(
            arn=ce.arn, name=ce.name, log=False
        )

        jq = ck.aws.JobQueue(
            name=get_unit_test_name(),
            compute_environments=ce
        )

        with pytest.raises(SystemExit):
            ck.aws.wait_for_job_queue(
                name=jq.name,
                log=False, max_wait_time=0
            )
    finally:  # pragma: nocover
        # Cleanup
        if jq:
            jq.clobber()

        if ce:
            ce.clobber()

        # if pars:
        #     pars.clobber()


def test_ObjectWithUsernameAndMemory():
    for mem in [-42, 'not-an-int']:
        with pytest.raises(ValueError):
            ck.aws.base_classes.ObjectWithUsernameAndMemory(
                name=get_unit_test_error_assertion_name(),
                memory=mem
            )


def test_IamRole():
    iam = boto3.client('iam')
    config = configparser.ConfigParser()
    config_file = ck.config.get_config_file()

    try:
        # Use boto3 to create a role
        name = get_unit_test_name()

        service = 'batch.amazonaws.com'
        role_policy = {
            'Version': '2012-10-17',
            'Statement': [
                {
                    'Effect': 'Allow',
                    'Principal': {
                        'Service': service
                    },
                    'Action': 'sts:AssumeRole'
                }
            ]
        }

        policy = {
            'name': 'AWSLambdaRole',
            'arn': 'arn:aws:iam::aws:policy/service-role/AWSLambdaRole'
        }

        response = iam.create_role(
            RoleName=name,
            AssumeRolePolicyDocument=json.dumps(role_policy),
        )
        arn = response.get('Role')['Arn']

        iam.attach_role_policy(
            PolicyArn=policy['arn'],
            RoleName=name
        )

        # Create an IamRole with same name and different properties.
        # Confirm that IamRole raises a ResourceExistsException.
        with pytest.raises(ck.aws.ResourceExistsException) as e:
            ck.aws.IamRole(name=name, service='ec2')

        assert e.value.resource_id == name

        # Then create an IamRole with only that name or ARN to have cloudknot
        # retrieve that role.
        role = ck.aws.IamRole(name=name)

        # Confirm that the instance has the right properties.
        assert role.service == service
        assert role.arn == arn
        assert role.policies == (policy['name'],)

        # Confirm that the role is in the config file
        config.read(config_file)
        assert name in config.options('roles')

        # Clobber the role
        role.clobber()
        # Assert that it was removed from AWS
        with pytest.raises(iam.exceptions.NoSuchEntityException):
            iam.get_role(RoleName=name)

        # Assert that it was removed from the config file
        # If we just re-read the config file, config will keep the union
        # of the in memory values and the file values, updating the
        # intersection of the two with the file values. So we must set
        # config to None and then re-read the file
        config = None
        config = configparser.ConfigParser()
        config.read(config_file)
        assert name not in config.options('roles')

        # Try to retrieve a role that does not exist
        name = get_unit_test_name()
        with pytest.raises(ck.aws.ResourceDoesNotExistException) as e:
            ck.aws.IamRole(name=name)

        assert e.value.resource_id == name

        # Create two roles, one with an instance profile and one without.
        names = [get_unit_test_name() for i in range(2)]
        descriptions = ['Role for unit test of cloudknot.aws.IamRole()', None]
        services = ['ec2', 'ecs-tasks']
        policy_set = ['AmazonS3FullAccess',
                      ['AWSLambdaExecute', 'AmazonS3ReadOnlyAccess']]
        instance_profile_flags = [True, False]

        for (n, d, s, p, i) in zip(
            names, descriptions, services, policy_set, instance_profile_flags
        ):
            role = ck.aws.IamRole(name=n, description=d, service=s,
                                  policies=p, add_instance_profile=i)

            # Use boto3 to confirm their existence and properties
            assert role.name == n
            d = d if d else 'This role was generated by cloudknot'
            assert role.description == d
            assert role.service == s + '.amazonaws.com'
            p = (p,) if isinstance(p, str) else tuple(p)
            assert set(role.policies) == set(p)
            assert role.add_instance_profile == i
            if i:
                assert role.instance_profile_arn
            else:
                assert role.instance_profile_arn is None

            # Confirm that they exist in the config file
            config.read(config_file)
            assert n in config.options('roles')

            # Clobber roles and use boto3 to confirm that they don't exist
            role.clobber()
            with pytest.raises(iam.exceptions.NoSuchEntityException):
                iam.get_role(RoleName=n)

            # Assert that they were removed from the config file
            # If we just re-read the config file, config will keep the union
            # of the in memory values and the file values, updating the
            # intersection of the two with the file values. So we must set
            # config to None and then re-read the file
            config = None
            config = configparser.ConfigParser()
            config.read(config_file)
            assert n not in config.options('roles')

        # Test for correct handling of incorrect input
        with pytest.raises(ValueError) as e:
            ck.aws.IamRole(name='not-important', service='value-error')
        with pytest.raises(ValueError) as e:
            ck.aws.IamRole(name='not-important', service='ec2', policies=455)
        with pytest.raises(ValueError) as e:
            ck.aws.IamRole(name='not-important', service='ec2',
                           policies=[455, 455])
        with pytest.raises(ValueError) as e:
            ck.aws.IamRole(name='not-important', service='ec2',
                           policies='NotAnAWSPolicy')
        with pytest.raises(ValueError) as e:
            ck.aws.IamRole(name='not-important', service='ec2',
                           add_instance_profile=455)

    except Exception as e:  # pragma: nocover
        # Clean up roles from AWS
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
        config.read(config_file)
        for role_name in config.options('roles'):
            if UNIT_TEST_PREFIX in role_name:
                config.remove_option('roles', role_name)
        with open(config_file, 'w') as f:
            config.write(f)

        # Pass the exception through
        raise e


def test_Vpc():
    ec2 = boto3.client('ec2')
    config = configparser.ConfigParser()
    config_file = ck.config.get_config_file()

    try:
        # Use boto3 to create a VPC
        name = get_unit_test_name()
        ipv4_cidr = '10.0.0.0/16'
        instance_tenancy = 'default'

        response = ec2.create_vpc(
            CidrBlock=ipv4_cidr,
            InstanceTenancy=instance_tenancy
        )

        vpc_id = response.get('Vpc')['VpcId']

        # Tag the VPC
        ec2.create_tags(
            Resources=[vpc_id],
            Tags=[
                {
                    'Key': 'Name',
                    'Value': name
                },
                {
                    'Key': 'owner',
                    'Value': 'cloudknot'
                }
            ]
        )

        # Create a VPC with same name but different description.
        # Confirm that SecurityGroup raises a ResourceExistsException.
        with pytest.raises(ck.aws.ResourceExistsException) as e:
            ck.aws.Vpc(
                name=name,
                instance_tenancy='dedicated'
            )

        assert e.value.resource_id == vpc_id

        # Then create a VPC with only that vpc_id to have
        # cloudknot retrieve that security group.
        vpc = ck.aws.Vpc(vpc_id=vpc_id)

        # Confirm that the instance has the right properties.
        assert vpc.pre_existing
        assert vpc.ipv4_cidr == ipv4_cidr
        assert vpc.instance_tenancy == instance_tenancy
        assert vpc.vpc_id == vpc_id
        assert vpc.subnet_ids == []

        # Confirm that the role is in the config file
        config.read(config_file)
        assert vpc_id in config.options('vpc')

        # Clobber the role
        vpc.clobber()

        # Assert that it was removed from AWS
        with pytest.raises(ec2.exceptions.ClientError) as e:
            ec2.describe_vpcs(VpcIds=[vpc_id])

        assert e.value.response.get('Error')['Code'] == 'InvalidVpcID.NotFound'

        # Assert that it was removed from the config file
        # If we just re-read the config file, config will keep the union
        # of the in memory values and the file values, updating the
        # intersection of the two with the file values. So we must set
        # config to None and then re-read the file
        config = None
        config = configparser.ConfigParser()
        config.read(config_file)
        assert vpc_id not in config.options('vpc')

        # Try to retrieve a security group that does not exist
        vpc_id = get_unit_test_name()
        with pytest.raises(ck.aws.ResourceDoesNotExistException) as e:
            ck.aws.Vpc(vpc_id=vpc_id)

        assert e.value.resource_id == vpc_id

        # Create Vpc instances, with different input types
        names = [get_unit_test_name() for i in range(3)]
        ipv4s = ['11.0.0.0/16', '10.1.0.0/16', None]
        instance_tenancies = ['default', 'dedicated', None]

        for (n, ip, it) in zip(names, ipv4s, instance_tenancies):
            vpc = ck.aws.Vpc(name=n, ipv4_cidr=ip, instance_tenancy=it)

            # Use boto3 to confirm their existence and properties
            assert not vpc.pre_existing
            assert vpc.name == n
            ip = ip if ip else '10.0.0.0/16'
            assert vpc.ipv4_cidr == ip
            it = it if it else 'default'
            assert vpc.instance_tenancy == it
            assert vpc.subnet_ids

            # Confirm that they exist in the config file
            config.read(config_file)
            assert vpc.vpc_id in config.options('vpc')

            # Clobber security group
            vpc.clobber()

            # Assert that it was removed from AWS
            with pytest.raises(ec2.exceptions.ClientError) as e:
                ec2.describe_vpcs(VpcIds=[vpc.vpc_id])

            error_code = e.value.response.get('Error')['Code']
            assert error_code == 'InvalidVpcID.NotFound'

            # Assert that they were removed from the config file
            # If we just re-read the config file, config will keep the union
            # of the in memory values and the file values, updating the
            # intersection of the two with the file values. So we must set
            # config to None and then re-read the file
            config = None
            config = configparser.ConfigParser()
            config.read(config_file)
            assert vpc.vpc_id not in config.options('vpc')

        # Create another vpc without a Name tag
        response = ec2.create_vpc(
            CidrBlock=ipv4_cidr,
            InstanceTenancy=instance_tenancy
        )

        # Use cloudknot to retrieve this VPC
        vpc_id = response.get('Vpc')['VpcId']
        vpc = ck.aws.Vpc(vpc_id=vpc_id)

        # And confirm that cloudknot filled in a Name tag
        response = ec2.describe_vpcs(VpcIds=[vpc_id])
        tags = response.get('Vpcs')[0]['Tags']
        name_tag = list(filter(lambda d: d['Key'] == 'Name', tags))[0]
        assert name_tag['Value'] == 'cloudknot-acquired-pre-existing-vpc'

        # Now associate a security group
        sg = ck.aws.SecurityGroup(
            name=get_unit_test_error_assertion_name(),
            vpc=vpc
        )

        # And assert that clobber raises a CannotDeleteResourceException
        with pytest.raises(ck.aws.CannotDeleteResourceException) as e:
            vpc.clobber()

        assert sg.security_group_id in e.value.resource_id

        # Actually clobber stuff.
        sg.clobber()
        vpc.clobber()

        # Test for correct handling of incorrect input
        # Assert ValueError on no input
        with pytest.raises(ValueError):
            ck.aws.Vpc()

        # Assert ValueError on vpc_id and name input
        with pytest.raises(ValueError):
            ck.aws.Vpc(
                vpc_id=get_unit_test_error_assertion_name(),
                name=get_unit_test_error_assertion_name()
            )

        # Assert ValueError on invalid ipv4_cidr
        with pytest.raises(ValueError):
            ck.aws.Vpc(
                name=get_unit_test_error_assertion_name(),
                ipv4_cidr='not-valid'
            )

        # Assert ValueError on invalid instance tenancy
        with pytest.raises(ValueError):
            ck.aws.Vpc(
                name=get_unit_test_error_assertion_name(),
                instance_tenancy='not-valid'
            )

        # Assert ResourceDoesNotExistException on invalid vpc_id
        name = get_unit_test_error_assertion_name()
        with pytest.raises(ck.aws.ResourceDoesNotExistException) as e:
            ck.aws.Vpc(vpc_id=name)

        assert e.value.resource_id == name

    except Exception as e:  # pragma: nocover
        # Clean up VPCs from AWS
        # Find all unit test security groups
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
                    ec2.delete_subnet(SubnetId=subnet_id)

                # delete the VPC
                ec2.delete_vpc(VpcId=vpc['VpcId'])

                # Clean up config file
                config.remove_option('vpc', vpc['VpcId'])

        with open(config_file, 'w') as f:
            config.write(f)

        # Pass the exception through
        raise e


def test_SecurityGroup():
    ec2 = boto3.client('ec2')
    config = configparser.ConfigParser()
    config_file = ck.config.get_config_file()

    try:
        # Use boto3 to create a security group
        name = get_unit_test_name()
        description = 'Security group for cloudknot unit testing'

        # Create a VPC to attach the security group to
        response = ec2.create_vpc(CidrBlock='10.0.0.0/16')
        vpc_id = response.get('Vpc')['VpcId']

        response = ec2.create_security_group(
            GroupName=name,
            Description=description,
            VpcId=vpc_id
        )
        group_id = response.get('GroupId')

        # Tag the VPC and security group for easy cleanup later
        ec2.create_tags(
            Resources=[vpc_id, group_id],
            Tags=[
                {
                    'Key': 'Name',
                    'Value': 'cloudknot-security-group-unit-test'
                },
                {
                    'Key': 'owner',
                    'Value': 'cloudknot'
                }
            ]
        )

        # Create a Vpc instance for the same Vpc that we just created
        vpc = ck.aws.Vpc(vpc_id=vpc_id)

        # Create a SecurityGroup with same name but different description.
        # Confirm that SecurityGroup raises a ResourceExistsException.
        with pytest.raises(ck.aws.ResourceExistsException) as e:
            ck.aws.SecurityGroup(
                name=name,
                vpc=vpc,
                description='conflicting description'
            )

        assert e.value.resource_id == group_id

        # Then create a SecurityGroup with only that group_id to have
        # cloudknot retrieve that security group.
        sg = ck.aws.SecurityGroup(security_group_id=group_id)

        # Confirm that the instance has the right properties.
        assert sg.pre_existing
        assert sg.vpc is None
        assert sg.vpc_id == vpc_id
        assert sg.description == description
        assert sg.security_group_id == group_id

        # Confirm that the role is in the config file
        config.read(config_file)
        assert group_id in config.options('security-groups')

        # Clobber the role
        sg.clobber()

        # Assert that it was removed from AWS
        with pytest.raises(ec2.exceptions.ClientError) as e:
            ec2.describe_security_groups(GroupIds=[group_id])

        assert e.value.response.get('Error')['Code'] == 'InvalidGroup.NotFound'

        # Assert that it was removed from the config file
        # If we just re-read the config file, config will keep the union
        # of the in memory values and the file values, updating the
        # intersection of the two with the file values. So we must set
        # config to None and then re-read the file
        config = None
        config = configparser.ConfigParser()
        config.read(config_file)
        assert group_id not in config.options('security-groups')

        # Try to retrieve a security group that does not exist
        group_id = get_unit_test_name()
        with pytest.raises(ck.aws.ResourceDoesNotExistException) as e:
            ck.aws.SecurityGroup(security_group_id=group_id)

        assert e.value.resource_id == group_id

        # Create SecurityGroup instances, one with description and one without
        names = [get_unit_test_name() for i in range(2)]
        vpcs = [vpc, vpc]
        descriptions = [
            'Security Group for unit testing of cloudknot.aws.SecurityGroup()',
            None
        ]

        for (n, v, d) in zip(names, vpcs, descriptions):
            sg = ck.aws.SecurityGroup(
                name=n, vpc=v, description=d
            )

            # Use boto3 to confirm their existence and properties
            assert sg.name == n
            d = d if d else \
                'This security group was automatically generated by cloudknot.'
            assert sg.description == d
            assert sg.vpc == v
            assert sg.vpc_id == v.vpc_id

            # Confirm that they exist in the config file
            config.read(config_file)
            assert sg.security_group_id in config.options('security-groups')

            # Clobber security group
            sg.clobber()

            # Assert that it was removed from AWS
            with pytest.raises(ec2.exceptions.ClientError) as e:
                ec2.describe_security_groups(GroupIds=[sg.security_group_id])

            error_code = e.value.response.get('Error')['Code']
            assert error_code == 'InvalidGroup.NotFound'

            # Assert that they were removed from the config file
            # If we just re-read the config file, config will keep the union
            # of the in memory values and the file values, updating the
            # intersection of the two with the file values. So we must set
            # config to None and then re-read the file
            config = None
            config = configparser.ConfigParser()
            config.read(config_file)
            assert sg.security_group_id not in config.options(
                'security-groups'
            )

        # Test for correct handling of incorrect input
        # Assert ValueError on no input
        with pytest.raises(ValueError) as e:
            ck.aws.SecurityGroup()

        # Assert ValueError on name and group_id input
        with pytest.raises(ValueError) as e:
            ck.aws.SecurityGroup(
                security_group_id=get_unit_test_error_assertion_name(),
                name=get_unit_test_error_assertion_name()
            )

        # Assert ValueError on invalid vpc input
        with pytest.raises(ValueError) as e:
            ck.aws.SecurityGroup(
                name=get_unit_test_error_assertion_name(),
                vpc=5
            )

        # Finally clean up the VPC that we used for testing
        vpc.clobber()

    except Exception as e:  # pragma: nocover
        # Clean up security_groups and VPCs from AWS
        # Find all unit test security groups
        response = ec2.describe_security_groups()
        sgs = [
            {'name': d['GroupName'], 'id': d['GroupId']}
            for d in response.get('SecurityGroups')
        ]
        unit_test_sgs = filter(
            lambda d: UNIT_TEST_PREFIX in d['name'],
            sgs
        )

        config.read(config_file)

        for sg in unit_test_sgs:
            # Delete role
            ec2.delete_security_group(GroupId=sg['id'])

            # Clean up config file
            config.remove_option('security-groups', sg['id'])

        # Find all VPCs with tag owner = 'cloudknot-security-group-unit-test
        response = ec2.describe_vpcs(
            Filters=[{
                'Name': 'tag:owner',
                'Values': ['cloudknot-security-group-unit-test']
            }]
        )

        for vpc in response.get('Vpcs'):
            ec2.delete_vpc(VpcId=vpc['VpcId'])

            # Clean up config file
            config.remove_option('vpc', vpc['VpcId'])

        with open(config_file, 'w') as f:
            config.write(f)

        # Pass the exception through
        raise e


def test_JobDefinition():
    # Create a unit testing PARS
    pars = ck.Pars(name='unit-test')

    batch = boto3.client('batch')
    config = configparser.ConfigParser()
    config_file = ck.config.get_config_file()

    try:
        # Use boto3 to create a job definition
        name = get_unit_test_name()
        image = 'ubuntu'
        vcpus = 3
        memory = 8000
        command = ['echo', 'hello']
        user = UNIT_TEST_PREFIX + '-user'
        retries = 3

        job_container_properties = {
            'image': image,
            'vcpus': vcpus,
            'memory': memory,
            'command': command,
            'jobRoleArn': pars.batch_service_role.arn,
            'user': user
        }

        response = batch.register_job_definition(
            jobDefinitionName=name,
            type='container',
            containerProperties=job_container_properties,
            retryStrategy={'attempts': retries}
        )

        arn = response['jobDefinitionArn']

        # Create a JobDefinition with same name but different description.
        # Confirm that JobDefinition raises a ResourceExistsException.
        with pytest.raises(ck.aws.ResourceExistsException) as e:
            ck.aws.JobDefinition(
                name=name,
                job_role='throw an error please',
            )

        assert e.value.resource_id == arn

        # Then create a JobDefinition with only that arn to have
        # cloudknot retrieve that job definition.
        jd = ck.aws.JobDefinition(arn=arn)

        # Confirm that the instance has the right properties.
        assert jd.pre_existing
        assert jd.name == name
        assert jd.job_role == pars.batch_service_role.arn
        assert jd.docker_image == image
        assert jd.vcpus == vcpus
        assert jd.memory == memory
        assert jd.username == user
        assert jd.retries == retries
        assert jd.arn == arn

        # Confirm that the role is in the config file
        config.read(config_file)
        assert name in config.options('job-definitions')

        # Clobber the role
        jd.clobber()

        # Assert that it was removed from AWS
        response = batch.describe_job_definitions(jobDefinitions=[arn])
        assert len(response.get('jobDefinitions')) == 1
        assert response.get('jobDefinitions')[0]['status'] == 'INACTIVE'

        # Assert that it was removed from the config file
        # If we just re-read the config file, config will keep the union
        # of the in memory values and the file values, updating the
        # intersection of the two with the file values. So we must set
        # config to None and then re-read the file
        config = None
        config = configparser.ConfigParser()
        config.read(config_file)
        assert name not in config.options('job-definitions')

        # Try to retrieve a job definition that does not exist
        nonexistent_arn = arn.replace(
            UNIT_TEST_PREFIX,
            UNIT_TEST_PREFIX + '-nonexistent'
        )
        with pytest.raises(ck.aws.ResourceDoesNotExistException) as e:
            ck.aws.JobDefinition(arn=nonexistent_arn)

        assert e.value.resource_id == nonexistent_arn

        # Create two job definitions, one with default values for vcpus,
        # memory, and username and one with explicit values

        names = [get_unit_test_name() for i in range(2)]
        job_roles = [pars.batch_service_role for i in range(2)]
        docker_images = ['ubuntu', 'ubuntu']
        vcpus = [5, None]
        memories = [12000, None]
        usernames = ['unit-test-user', None]
        retries = [5, None]

        for (n, jr, di, v, m, u, r) in zip(
                names, job_roles, docker_images, vcpus,
                memories, usernames, retries
        ):
            jd = ck.aws.JobDefinition(
                name=n, job_role=jr, docker_image=di, vcpus=v, memory=m,
                username=u, retries=r
            )

            # Use boto3 to confirm their existence and properties
            assert jd.name == n
            assert not jd.pre_existing
            assert jd.job_role == jr
            assert jd.docker_image == di
            v = v if v else 1
            assert jd.vcpus == v
            r = r if r else 3
            assert jd.retries == r
            m = m if m else 32000
            assert jd.memory == m

            # assert arn

            # Confirm that they exist in the config file
            config.read(config_file)
            assert jd.name in config.options('job-definitions')

            # Clobber the job definition
            jd.clobber()

            # Assert that it was removed from AWS
            response = batch.describe_job_definitions(jobDefinitions=[jd.arn])
            assert len(response.get('jobDefinitions')) == 1
            assert response.get('jobDefinitions')[0]['status'] == 'INACTIVE'

            # Assert that they were removed from the config file
            # If we just re-read the config file, config will keep the union
            # of the in memory values and the file values, updating the
            # intersection of the two with the file values. So we must set
            # config to None and then re-read the file
            config = None
            config = configparser.ConfigParser()
            config.read(config_file)
            assert jd.name not in config.options('job-definitions')

        # Test for correct handling of incorrect input
        with pytest.raises(ValueError) as e:
            ck.aws.JobDefinition()
        with pytest.raises(ValueError) as e:
            ck.aws.JobDefinition(
                arn=get_unit_test_error_assertion_name(),
                name=get_unit_test_error_assertion_name()
            )
        with pytest.raises(ValueError) as e:
            ck.aws.JobDefinition(
                name=get_unit_test_error_assertion_name(),
                job_role=5, docker_image='ubuntu'
            )
        with pytest.raises(ValueError) as e:
            ck.aws.JobDefinition(
                name=get_unit_test_error_assertion_name(),
                job_role=pars.batch_service_role,
                docker_image=5
            )
        with pytest.raises(ValueError) as e:
            ck.aws.JobDefinition(
                name=get_unit_test_error_assertion_name(),
                job_role=pars.batch_service_role,
                docker_image='ubuntu',
                vcpus=-2
            )
        with pytest.raises(ValueError) as e:
            ck.aws.JobDefinition(
                name=get_unit_test_error_assertion_name(),
                job_role=pars.batch_service_role,
                docker_image='ubuntu',
                retries=0
            )
        with pytest.raises(ValueError) as e:
            ck.aws.JobDefinition(
                name=get_unit_test_error_assertion_name(),
                job_role=pars.batch_service_role,
                docker_image='ubuntu',
                retries=100
            )

        # Clean up the PARS
        # pars.clobber()

    except Exception as e:  # pragma: nocover
        # Clean up job definitions from AWS
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

        config.read(config_file)

        for jd in unit_test_jds:
            # Deregister the job definition
            batch.deregister_job_definition(jobDefinition=jd['arn'])

            # Clean up config file
            config.remove_option('job-definitions', jd['name'])

        with open(config_file, 'w') as f:
            config.write(f)

        # Clean up the PARS
        # pars.clobber()

        # Pass the exception through
        raise e


def test_ComputeEnvironment():
    # Create a unit testing PARS
    pars = ck.Pars(name='unit-test')

    batch = boto3.client('batch')
    config = configparser.ConfigParser()
    config_file = ck.config.get_config_file()

    try:
        # Use boto3 to create a compute environment
        name = get_unit_test_name()

        resource_type = 'SPOT'
        min_vcpus = 1
        max_vcpus = 256
        desired_vcpus = 8
        instance_types = ['optimal']
        bid_percentage = 50

        compute_resources = {
            'type': resource_type,
            'minvCpus': min_vcpus,
            'maxvCpus': max_vcpus,
            'desiredvCpus': desired_vcpus,
            'instanceTypes': instance_types,
            'subnets': pars.vpc.subnet_ids,
            'securityGroupIds': [pars.security_group.security_group_id],
            'instanceRole': pars.ecs_instance_role.instance_profile_arn,
            'bidPercentage': bid_percentage,
            'spotIamFleetRole': pars.spot_fleet_role.arn
        }

        response = batch.create_compute_environment(
            computeEnvironmentName=name,
            type='MANAGED',
            state='ENABLED',
            computeResources=compute_resources,
            serviceRole=pars.batch_service_role.arn
        )

        arn = response['computeEnvironmentArn']

        # Create a ComputeEnvironment with same name but different description.
        # Confirm that ComputeEnvironment raises a ResourceExistsException.
        with pytest.raises(ck.aws.ResourceExistsException) as e:
            ck.aws.ComputeEnvironment(
                name=name, batch_service_role=pars.batch_service_role,
                instance_role=pars.ecs_instance_role, vpc=pars.vpc,
                security_group=pars.security_group,
                spot_fleet_role=pars.spot_fleet_role,
                resource_type='EC2'
            )

        assert e.value.resource_id == arn

        # Then create a ComputeEnvironment with only that arn to have
        # cloudknot retrieve that job definition.
        ce = ck.aws.ComputeEnvironment(arn=arn)

        # Confirm that the instance has the right properties.
        assert ce.pre_existing
        assert ce.name == name
        assert ce.batch_service_role is None
        assert ce.batch_service_arn == pars.batch_service_role.arn
        assert ce.instance_role is None
        assert (ce.instance_role_arn ==
                pars.ecs_instance_role.instance_profile_arn)
        assert ce.vpc is None
        assert ce.subnets == pars.vpc.subnet_ids
        assert ce.security_group is None
        assert ce.security_group_ids == [pars.security_group.security_group_id]
        assert ce.spot_fleet_role is None
        assert ce.spot_fleet_role_arn == pars.spot_fleet_role.arn
        assert ce.instance_types == instance_types
        assert ce.resource_type == resource_type
        assert ce.min_vcpus == min_vcpus
        assert ce.max_vcpus == max_vcpus
        assert ce.desired_vcpus == desired_vcpus
        assert ce.image_id is None
        assert ce.ec2_key_pair is None
        assert not ce.tags
        assert ce.bid_percentage == 50
        assert ce.arn == arn

        # Confirm that the role is in the config file
        config.read(config_file)
        assert name in config.options('compute-environments')

        # Before clobbering, associate this compute environment with a
        # job queue in order to test the job queue disassociation statements
        # in ComputeEnvironment().clobber()
        ck.aws.wait_for_compute_environment(
            arn=ce.arn, name=ce.name, log=False
        )
        jq = ck.aws.JobQueue(
            name=get_unit_test_name(),
            compute_environments=ce
        )

        # Clobber the compute environment first, then the job queue
        with pytest.raises(ck.aws.CannotDeleteResourceException) as e:
            ce.clobber()

        assert e.value.resource_id[0]['jobQueueName'] == jq.name

        jq.clobber()
        ce.clobber()

        # Assert that it was removed from AWS
        response = batch.describe_compute_environments(
            computeEnvironments=[arn]
        )
        response_ce = response.get('computeEnvironments')
        assert (not response_ce or response_ce[0]['status'] == 'DELETING')

        # Assert that it was removed from the config file
        # If we just re-read the config file, config will keep the union
        # of the in memory values and the file values, updating the
        # intersection of the two with the file values. So we must set
        # config to None and then re-read the file
        config = None
        config = configparser.ConfigParser()
        config.read(config_file)
        assert name not in config.options('compute-environments')

        # Try to retrieve a job definition that does not exist
        nonexistent_arn = arn.replace(
            UNIT_TEST_PREFIX,
            UNIT_TEST_PREFIX + '-nonexistent'
        )
        with pytest.raises(ck.aws.ResourceDoesNotExistException) as e:
            ck.aws.ComputeEnvironment(arn=nonexistent_arn)

        assert e.value.resource_id == nonexistent_arn

        # Create two compute environments with different parameters

        names = [get_unit_test_name() for i in range(4)]
        batch_service_roles = [pars.batch_service_role] * 4
        instance_roles = [pars.ecs_instance_role] * 4
        vpcs = [pars.vpc] * 4
        security_groups = [pars.security_group] * 4
        spot_fleet_roles = [None] + [pars.spot_fleet_role] * 3
        instance_types = ['optimal'] + [['m4.16xlarge']] * 3
        resource_types = ['EC2', 'SPOT', 'SPOT', 'SPOT']
        min_vcpus = [1, None, None, None]
        max_vcpus = [128, None, None, None]
        desired_vcpus = [4, None, None, None]
        image_ids = ['ami-a4c7edb2'] + [None] * 3
        ec2_key_pairs = [None, None, None, None]
        tags = [{'name': UNIT_TEST_PREFIX + '-instance'}] * 2 + [None] * 2
        bid_percentages = [None, -10, 110, 45]

        for (n, bsr, ir, v, sg, sfr, it, rt, minv, maxv, desv, im_id,
             ec2_key, t, bp) in zip(
                names, batch_service_roles, instance_roles, vpcs,
                security_groups, spot_fleet_roles, instance_types,
                resource_types, min_vcpus, max_vcpus, desired_vcpus,
                image_ids, ec2_key_pairs, tags, bid_percentages
        ):
            ce = ck.aws.ComputeEnvironment(
                name=n, batch_service_role=bsr, instance_role=ir, vpc=v,
                security_group=sg, spot_fleet_role=sfr, instance_types=it,
                resource_type=rt, min_vcpus=minv, max_vcpus=maxv,
                desired_vcpus=desv, image_id=im_id, ec2_key_pair=ec2_key,
                tags=t, bid_percentage=bp
            )

            # Use boto3 to confirm their existence and properties
            assert not ce.pre_existing
            assert ce.name == n
            assert ce.batch_service_role == bsr
            assert ce.batch_service_arn == bsr.arn
            assert ce.instance_role == ir
            assert ce.instance_role_arn == ir.instance_profile_arn
            assert ce.vpc == v
            assert ce.subnets == v.subnet_ids
            assert ce.security_group == sg
            assert ce.security_group_ids == [sg.security_group_id]
            assert ce.spot_fleet_role == sfr
            if sfr:
                assert ce.spot_fleet_role_arn == sfr.arn
            else:
                assert ce.spot_fleet_role_arn is None
            if isinstance(it, str):
                assert ce.instance_types == [it]
            else:
                assert ce.instance_types == it
            assert ce.resource_type == rt
            minv = minv if minv else 0
            assert ce.min_vcpus == minv
            maxv = maxv if maxv else 256
            assert ce.max_vcpus == maxv
            desv = desv if desv else 8
            assert ce.desired_vcpus == desv
            assert ce.image_id == im_id
            assert ce.ec2_key_pair == ec2_key
            if rt == 'EC2':
                assert ce.tags == t
            else:
                assert ce.tags is None
            if bp:
                bp = min(max(bp, 0), 100)
            assert ce.bid_percentage == bp

            # Confirm that they exist in the config file
            config.read(config_file)
            assert ce.name in config.options('compute-environments')

            # Clobber security group
            ce.clobber()

            # Assert that it was removed from AWS
            response = batch.describe_compute_environments(
                computeEnvironments=[ce.arn]
            )
            response_ce = response.get('computeEnvironments')
            assert (not response_ce or response_ce[0]['status'] == 'DELETING')

            # Assert that they were removed from the config file
            # If we just re-read the config file, config will keep the union
            # of the in memory values and the file values, updating the
            # intersection of the two with the file values. So we must set
            # config to None and then re-read the file
            config = None
            config = configparser.ConfigParser()
            config.read(config_file)
            assert ce.name not in config.options('compute-environments')

        # Test for correct handling of incorrect input
        # ValueError for neither arn or name
        with pytest.raises(ValueError) as e:
            ck.aws.ComputeEnvironment()

        # Value Error for both arn and name
        with pytest.raises(ValueError) as e:
            ck.aws.ComputeEnvironment(
                arn=get_unit_test_error_assertion_name(),
                name=get_unit_test_error_assertion_name()
            )

        # ValueError for 'SPOT' resource with no spot_fleet_role
        with pytest.raises(ValueError) as e:
            ck.aws.ComputeEnvironment(
                name=get_unit_test_error_assertion_name(),
                batch_service_role=pars.batch_service_role,
                instance_role=pars.ecs_instance_role, vpc=pars.vpc,
                security_group=pars.security_group,
                resource_type='SPOT', bid_percentage=50
            )

        # ValueError for 'SPOT' resource with no bid_percentage
        with pytest.raises(ValueError) as e:
            ck.aws.ComputeEnvironment(
                name=get_unit_test_error_assertion_name(),
                batch_service_role=pars.batch_service_role,
                instance_role=pars.ecs_instance_role, vpc=pars.vpc,
                security_group=pars.security_group,
                spot_fleet_role=pars.spot_fleet_role,
                resource_type='SPOT'
            )

        # ValueError for bad batch_service_role
        with pytest.raises(ValueError) as e:
            ck.aws.ComputeEnvironment(
                name=get_unit_test_error_assertion_name(),
                batch_service_role=pars.ecs_instance_role,
                instance_role=pars.ecs_instance_role, vpc=pars.vpc,
                security_group=pars.security_group
            )

        # ValueError for bad instance_role
        with pytest.raises(ValueError) as e:
            ck.aws.ComputeEnvironment(
                name=get_unit_test_error_assertion_name(),
                batch_service_role=pars.batch_service_role,
                instance_role=pars.batch_service_role, vpc=pars.vpc,
                security_group=pars.security_group
            )

        # ValueError for bad vpc
        with pytest.raises(ValueError) as e:
            ck.aws.ComputeEnvironment(
                name=get_unit_test_error_assertion_name(),
                batch_service_role=pars.batch_service_role,
                instance_role=pars.ecs_instance_role,
                vpc=pars.security_group,
                security_group=pars.security_group
            )

        # ValueError for bad security_group
        with pytest.raises(ValueError) as e:
            ck.aws.ComputeEnvironment(
                name=get_unit_test_error_assertion_name(),
                batch_service_role=pars.batch_service_role,
                instance_role=pars.ecs_instance_role,
                vpc=pars.vpc,
                security_group=pars.vpc
            )

        # ValueError for bad spot_fleet_role
        with pytest.raises(ValueError) as e:
            ck.aws.ComputeEnvironment(
                name=get_unit_test_error_assertion_name(),
                batch_service_role=pars.batch_service_role,
                instance_role=pars.ecs_instance_role,
                vpc=pars.vpc,
                security_group=pars.security_group,
                spot_fleet_role=pars.batch_service_role
            )

        # ValueError for bad instance_types
        for instance_type in [[5, 4], 'bad-instance-type-string']:
            with pytest.raises(ValueError) as e:
                ck.aws.ComputeEnvironment(
                    name=get_unit_test_error_assertion_name(),
                    batch_service_role=pars.batch_service_role,
                    instance_role=pars.ecs_instance_role,
                    vpc=pars.vpc,
                    security_group=pars.security_group,
                    instance_types=instance_type
                )

        # ValueError for bad resource_type
        with pytest.raises(ValueError) as e:
            ck.aws.ComputeEnvironment(
                name=get_unit_test_error_assertion_name(),
                batch_service_role=pars.batch_service_role,
                instance_role=pars.ecs_instance_role,
                vpc=pars.vpc,
                security_group=pars.security_group,
                resource_type='BAD'
            )

        # ValueError for bad min_vcpus
        with pytest.raises(ValueError) as e:
            ck.aws.ComputeEnvironment(
                name=get_unit_test_error_assertion_name(),
                batch_service_role=pars.batch_service_role,
                instance_role=pars.ecs_instance_role,
                vpc=pars.vpc,
                security_group=pars.security_group,
                min_vcpus=-42
            )

        # ValueError for bad max_vcpus
        with pytest.raises(ValueError) as e:
            ck.aws.ComputeEnvironment(
                name=get_unit_test_error_assertion_name(),
                batch_service_role=pars.batch_service_role,
                instance_role=pars.ecs_instance_role,
                vpc=pars.vpc,
                security_group=pars.security_group,
                max_vcpus=-42
            )

        # ValueError for bad desired_vcpus
        with pytest.raises(ValueError) as e:
            ck.aws.ComputeEnvironment(
                name=get_unit_test_error_assertion_name(),
                batch_service_role=pars.batch_service_role,
                instance_role=pars.ecs_instance_role,
                vpc=pars.vpc,
                security_group=pars.security_group,
                desired_vcpus=-42
            )

        # ValueError for bad image_id
        with pytest.raises(ValueError) as e:
            ck.aws.ComputeEnvironment(
                name=get_unit_test_error_assertion_name(),
                batch_service_role=pars.batch_service_role,
                instance_role=pars.ecs_instance_role,
                vpc=pars.vpc,
                security_group=pars.security_group,
                image_id=42
            )

        # ValueError for bad ec2_key_pair
        with pytest.raises(ValueError) as e:
            ck.aws.ComputeEnvironment(
                name=get_unit_test_error_assertion_name(),
                batch_service_role=pars.batch_service_role,
                instance_role=pars.ecs_instance_role,
                vpc=pars.vpc,
                security_group=pars.security_group,
                ec2_key_pair=-42
            )

        # ValueError for bad ec2_key_pair
        with pytest.raises(ValueError) as e:
            ck.aws.ComputeEnvironment(
                name=get_unit_test_error_assertion_name(),
                batch_service_role=pars.batch_service_role,
                instance_role=pars.ecs_instance_role,
                vpc=pars.vpc,
                security_group=pars.security_group,
                tags=-42
            )
        # Clean up the PARS
        # pars.clobber()

    except Exception as e:  # pragma: nocover
        # Clean up compute environments from AWS
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
            response = batch.describe_job_definitions(
                status='ACTIVE',
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
            batch.update_compute_environment(
                computeEnvironment=ce['arn'],
                state='DISABLED'
            )

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
                batch.update_job_queue(jobQueue=arn, state='DISABLED')

                ck.aws.wait_for_job_queue(
                    name=name, log=False, max_wait_time=180
                )

                # Delete the job queue
                batch.delete_job_queue(jobQueue=arn)

                # Clean up config file
                config.remove_option('job-queues', name)

        requires_deletion = list(filter(
            lambda d: d['status'] not in ['DELETED', 'DELETING'],
            unit_test_CEs
        ))

        for ce in requires_deletion:
            ck.aws.wait_for_compute_environment(
                arn=ce['arn'], name=ce['name'], log=False
            )

            # Delete the compute environment
            batch.delete_compute_environment(computeEnvironment=ce['arn'])

            # Clean up config file
            config.remove_option('compute-environments', ce['name'])

        with open(config_file, 'w') as f:
            config.write(f)

        # Clean up the PARS
        # pars.clobber()

        # Pass the exception through
        raise e


def test_JobQueue():
    pass


def test_BatchJob():
    pass


def test_DockerImage():
    pass
