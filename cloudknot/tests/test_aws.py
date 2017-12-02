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

import cloudknot as ck
import configparser
import errno
import json
import os
import os.path as op
import pytest
import shutil
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

    iam.delete_policy(PolicyArn=arn)


@pytest.fixture(scope='module')
def pars(bucket_cleanup):
    p = ck.Pars(name='unit-test')
    yield p
    p.clobber()


def test_wait_for_compute_environment(pars):
    # Create a ComputeEnvironment to test the function
    ce = None
    try:
        ce = ck.aws.ComputeEnvironment(
            name=get_testing_name(),
            batch_service_role=pars.batch_service_role,
            instance_role=pars.ecs_instance_role, vpc=pars.vpc,
            security_group=pars.security_group,
            spot_fleet_role=pars.spot_fleet_role
        )

        ck.aws.wait_for_compute_environment(arn=ce.arn, name=ce.name, log=True)

        with pytest.raises(SystemExit):
            ck.aws.wait_for_compute_environment(
                arn=ce.arn, name=ce.name,
                log=True, max_wait_time=0
            )
    finally:  # pragma: nocover
        # Cleanup
        if ce:
            ce.clobber()


def test_wait_for_job_queue(pars):
    # Create a ComputeEnvironment and JobQueue to test the function
    ce = None
    jq = None
    try:
        ce = ck.aws.ComputeEnvironment(
            name=get_testing_name(),
            batch_service_role=pars.batch_service_role,
            instance_role=pars.ecs_instance_role, vpc=pars.vpc,
            security_group=pars.security_group,
            spot_fleet_role=pars.spot_fleet_role
        )

        ck.aws.wait_for_compute_environment(arn=ce.arn, name=ce.name, log=True)

        jq = ck.aws.JobQueue(name=get_testing_name(), compute_environments=ce)

        with pytest.raises(SystemExit):
            ck.aws.wait_for_job_queue(name=jq.name, log=True, max_wait_time=0)
    finally:  # pragma: nocover
        # Cleanup
        if jq:
            jq.clobber()

        if ce:
            ce.clobber()


def test_get_region(bucket_cleanup):
    # Save environment variables for restoration later
    try:
        old_region_env = os.environ['AWS_DEFAULT_REGION']
    except KeyError:
        old_region_env = None

    old_region = ck.get_region()

    try:
        old_config_file = os.environ['CLOUDKNOT_CONFIG_FILE']
    except KeyError:
        old_config_file = None

    try:
        # With empty config file, get_region should return the
        # environment variable AWS_DEFAULT_REGION
        with tempfile.NamedTemporaryFile(mode='w+') as tmp:
            os.environ['CLOUDKNOT_CONFIG_FILE'] = tmp.name

            region = 'test-region-0'
            os.environ['AWS_DEFAULT_REGION'] = region
            assert ck.get_region() == region
            del os.environ['AWS_DEFAULT_REGION']

        # With region in a temporary config file, region should simply
        # read the config file
        with tempfile.NamedTemporaryFile(mode='w+') as tmp:
            os.environ['CLOUDKNOT_CONFIG_FILE'] = tmp.name

            region = 'test-region-1'
            tmp.file.write('[aws]\n')
            tmp.file.write('region = {region:s}\n'.format(region=region))
            tmp.file.flush()
            os.fsync(tmp.file.fileno())
            assert ck.get_region() == region

        # With no cloudknot config file and no environment variable
        # get_region should return region in aws config file
        with tempfile.NamedTemporaryFile(mode='w+') as tmp:
            os.environ['CLOUDKNOT_CONFIG_FILE'] = tmp.name

            aws_config_file = op.join(op.expanduser('~'), '.aws', 'config')

            try:
                if op.isfile(aws_config_file):
                    if op.isfile(aws_config_file + '.bak'):
                        raise Exception(
                            'Backup aws config file already exists.'
                        )
                    shutil.move(aws_config_file, aws_config_file + '.bak')

                assert ck.get_region() == 'us-east-1'
            finally:
                if op.isfile(aws_config_file + '.bak'):
                    shutil.move(aws_config_file + '.bak', aws_config_file)

        with tempfile.NamedTemporaryFile(mode='w+') as tmp:
            os.environ['CLOUDKNOT_CONFIG_FILE'] = tmp.name

            aws_config_file = op.join(op.expanduser('~'), '.aws', 'config')

            try:
                if op.isfile(aws_config_file):
                    if op.isfile(aws_config_file + '.bak'):
                        raise Exception(
                            'Backup aws config file already exists.'
                        )
                    shutil.move(aws_config_file, aws_config_file + '.bak')
                else:
                    # Create the config directory if it doesn't exist
                    aws_config_dir = op.dirname(aws_config_file)
                    try:
                        os.makedirs(aws_config_dir)
                    except OSError as e:
                        pre_existing = (e.errno == errno.EEXIST
                                        and op.isdir(aws_config_dir))
                        if pre_existing:
                            pass
                        else:
                            raise e

                region = 'test-region-2'

                with open(aws_config_file, 'w') as f:
                    f.write('[default]\n')
                    f.write('region = {region:s}\n'.format(region=region))
                    f.flush()
                    os.fsync(f.fileno())

                assert ck.get_region() == region
            finally:
                if op.isfile(aws_config_file + '.bak'):
                    shutil.move(aws_config_file + '.bak', aws_config_file)
                elif op.isfile(aws_config_file):
                    os.remove(aws_config_file)
    finally:
        ck.set_region(old_region)

        # Restore old environment variables
        if old_config_file:
            os.environ['CLOUDKNOT_CONFIG_FILE'] = old_config_file
        else:
            try:
                del os.environ['CLOUDKNOT_CONFIG_FILE']
            except KeyError:
                pass

        if old_region_env:
            os.environ['AWS_DEFAULT_REGION'] = old_region_env
        else:
            try:
                del os.environ['AWS_DEFAULT_REGION']
            except KeyError:
                pass

        ck.refresh_clients()


def test_set_region(bucket_cleanup):
    with pytest.raises(ValueError):
        ck.set_region(region='not a valid region name')

    old_region = ck.get_region()

    try:
        old_config_file = os.environ['CLOUDKNOT_CONFIG_FILE']
    except KeyError:
        old_config_file = None

    try:
        with tempfile.NamedTemporaryFile() as tmp:
            os.environ['CLOUDKNOT_CONFIG_FILE'] = tmp.name

            region = 'us-west-1'
            ck.set_region(region)

            assert ck.get_region() == region

            for service, client in ck.aws.clients.items():
                if service == 'iam':
                    assert client.meta.region_name == 'aws-global'
                else:
                    assert client.meta.region_name == region
    finally:
        ck.set_region(old_region)
        if old_config_file:
            os.environ['CLOUDKNOT_CONFIG_FILE'] = old_config_file
        else:
            try:
                del os.environ['CLOUDKNOT_CONFIG_FILE']
            except KeyError:
                pass

        ck.refresh_clients()


def test_list_profiles(bucket_cleanup):
    try:
        old_credentials_file = os.environ['AWS_SHARED_CREDENTIALS_FILE']
    except KeyError:
        old_credentials_file = None

    try:
        old_aws_config_file = os.environ['AWS_CONFIG_FILE']
    except KeyError:
        old_aws_config_file = None

    ref_dir = op.join(data_path, 'profiles_ref_data')
    try:
        cred_file = op.join(ref_dir, 'credentials_with_default')
        os.environ['AWS_SHARED_CREDENTIALS_FILE'] = cred_file

        config_file = op.join(ref_dir, 'config')
        os.environ['AWS_CONFIG_FILE'] = config_file

        profile_info = ck.list_profiles()
        assert profile_info.credentials_file == cred_file
        assert profile_info.aws_config_file == config_file
        assert set(profile_info.profile_names) == set(
            ['name-{i:d}'.format(i=i) for i in range(7)] + ['default']
        )
    finally:
        if old_credentials_file:
            os.environ['AWS_SHARED_CREDENTIALS_FILE'] = old_credentials_file
        else:
            try:
                del os.environ['AWS_SHARED_CREDENTIALS_FILE']
            except KeyError:
                pass

        if old_aws_config_file:
            os.environ['AWS_CONFIG_FILE'] = old_aws_config_file
        else:
            try:
                del os.environ['AWS_CONFIG_FILE']
            except KeyError:
                pass


def test_get_profile(bucket_cleanup):
    try:
        old_credentials_file = os.environ['AWS_SHARED_CREDENTIALS_FILE']
    except KeyError:
        old_credentials_file = None

    try:
        old_aws_config_file = os.environ['AWS_CONFIG_FILE']
    except KeyError:
        old_aws_config_file = None

    try:
        old_ck_config_file = os.environ['CLOUDKNOT_CONFIG_FILE']
    except KeyError:
        old_ck_config_file = None

    ref_dir = op.join(data_path, 'profiles_ref_data')
    ck_config_with_profile = op.join(ref_dir, 'cloudknot_with_profile')
    ck_config_without_profile = op.join(ref_dir, 'cloudknot_without_profile')

    shutil.copy(ck_config_with_profile, ck_config_with_profile + '.bak')
    shutil.copy(ck_config_without_profile, ck_config_without_profile + '.bak')
    try:
        os.environ['CLOUDKNOT_CONFIG_FILE'] = ck_config_with_profile

        assert ck.get_profile() == 'profile_from_cloudknot_config'

        os.environ['CLOUDKNOT_CONFIG_FILE'] = ck_config_without_profile

        config_file = op.join(ref_dir, 'config')
        os.environ['AWS_CONFIG_FILE'] = config_file

        cred_file = op.join(ref_dir, 'credentials_without_default')
        os.environ['AWS_SHARED_CREDENTIALS_FILE'] = cred_file

        assert ck.get_profile(fallback=None) is None
        assert ck.get_profile() == 'from-env'

        cred_file = op.join(ref_dir, 'credentials_with_default')
        os.environ['AWS_SHARED_CREDENTIALS_FILE'] = cred_file

        assert ck.get_profile() == 'default'
    finally:
        shutil.move(ck_config_with_profile + '.bak', ck_config_with_profile)
        shutil.move(ck_config_without_profile + '.bak',
                    ck_config_without_profile)

        if old_credentials_file:
            os.environ['AWS_SHARED_CREDENTIALS_FILE'] = old_credentials_file
        else:
            try:
                del os.environ['AWS_SHARED_CREDENTIALS_FILE']
            except KeyError:
                pass

        if old_aws_config_file:
            os.environ['AWS_CONFIG_FILE'] = old_aws_config_file
        else:
            try:
                del os.environ['AWS_CONFIG_FILE']
            except KeyError:
                pass

        if old_ck_config_file:
            os.environ['CLOUDKNOT_CONFIG_FILE'] = old_ck_config_file
        else:
            try:
                del os.environ['CLOUDKNOT_CONFIG_FILE']
            except KeyError:
                pass

        ck.refresh_clients()


def test_set_profile(bucket_cleanup):
    try:
        old_credentials_file = os.environ['AWS_SHARED_CREDENTIALS_FILE']
    except KeyError:
        old_credentials_file = None

    try:
        old_aws_config_file = os.environ['AWS_CONFIG_FILE']
    except KeyError:
        old_aws_config_file = None

    try:
        old_ck_config_file = os.environ['CLOUDKNOT_CONFIG_FILE']
    except KeyError:
        old_ck_config_file = None

    ref_dir = op.join(data_path, 'profiles_ref_data')
    ck_config_file = op.join(ref_dir, 'cloudknot_without_profile')
    shutil.copy(ck_config_file, ck_config_file + '.bak')
    try:
        os.environ['CLOUDKNOT_CONFIG_FILE'] = ck_config_file

        config_file = op.join(ref_dir, 'config')
        os.environ['AWS_CONFIG_FILE'] = config_file

        cred_file = op.join(ref_dir, 'credentials_without_default')
        os.environ['AWS_SHARED_CREDENTIALS_FILE'] = cred_file

        with pytest.raises(ValueError):
            ck.set_profile(profile_name='not_in_list_of_profiles')

        profile = 'name-5'
        ck.set_profile(profile_name=profile)
        assert ck.get_profile() == profile
    finally:
        shutil.move(ck_config_file + '.bak', ck_config_file)

        if old_credentials_file:
            os.environ['AWS_SHARED_CREDENTIALS_FILE'] = old_credentials_file
        else:
            try:
                del os.environ['AWS_SHARED_CREDENTIALS_FILE']
            except KeyError:
                pass

        if old_aws_config_file:
            os.environ['AWS_CONFIG_FILE'] = old_aws_config_file
        else:
            try:
                del os.environ['AWS_CONFIG_FILE']
            except KeyError:
                pass

        if old_ck_config_file:
            os.environ['CLOUDKNOT_CONFIG_FILE'] = old_ck_config_file
        else:
            try:
                del os.environ['CLOUDKNOT_CONFIG_FILE']
            except KeyError:
                pass

        ck.refresh_clients()


def test_ObjectWithUsernameAndMemory(bucket_cleanup):
    for mem in [-42, 'not-an-int']:
        with pytest.raises(ValueError):
            ck.aws.base_classes.ObjectWithUsernameAndMemory(
                name=get_testing_name(),
                memory=mem
            )


def test_IamRole(bucket_cleanup):
    iam = ck.aws.clients['iam']
    config = configparser.ConfigParser()
    config_file = ck.config.get_config_file()
    role_section_name = 'roles ' + ck.get_profile() + ' global'

    try:
        # Use boto3 to create a role
        name = get_testing_name()

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
        assert set(role.policies) == {policy['name']}

        # Confirm that the role is in the config file
        config = configparser.ConfigParser()
        with ck.config.rlock:
            config.read(config_file)

        assert name in config.options(role_section_name)

        # Clobber the role
        role.clobber()

        # Assert that it was removed from AWS
        with pytest.raises(iam.exceptions.NoSuchEntityException):
            iam.get_role(RoleName=name)

        # Assert that it was removed from the config file
        # If we just re-read the config file, config will keep the union
        # of the in memory values and the file values, updating the
        # intersection of the two with the file values. So we must clear
        # config and then re-read the file
        config = configparser.ConfigParser()
        with ck.config.rlock:
            config.read(config_file)

        assert name not in config.options(role_section_name)

        # Assert that reading the instance_profile_arn property raises error
        with pytest.raises(ck.aws.ResourceClobberedException):
            instance_profile_arn = role.instance_profile_arn  # noqa: F841

        # Try to retrieve a role that does not exist
        name = get_testing_name()
        with pytest.raises(ck.aws.ResourceDoesNotExistException) as e:
            ck.aws.IamRole(name=name)

        assert e.value.resource_id == name

        # Create two roles, one with an instance profile and one without.
        names = [get_testing_name() for i in range(2)]
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
            p = (p,) if isinstance(p, six.string_types) else tuple(p)
            bucket = ck.get_s3_bucket()
            assert set(role.policies) == (
                set(p) | {ck.aws.base_classes.get_s3_policy_name(bucket)}
            )
            if i:
                assert role.instance_profile_arn
            else:
                assert role.instance_profile_arn is None

            # Confirm that they exist in the config file
            config = configparser.ConfigParser()
            with ck.config.rlock:
                config.read(config_file)

            assert n in config.options(role_section_name)

            # Clobber roles and use boto3 to confirm that they don't exist
            role.clobber()
            with pytest.raises(iam.exceptions.NoSuchEntityException):
                iam.get_role(RoleName=n)

            # Assert that they were removed from the config file
            # If we just re-read the config file, config will keep the union
            # of the in memory values and the file values, updating the
            # intersection of the two with the file values. So we must clear
            # config and then re-read the file
            config = configparser.ConfigParser()
            with ck.config.rlock:
                config.read(config_file)

            assert n not in config.options(role_section_name)

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

        name = get_testing_name()
        response = iam.create_instance_profile(
            InstanceProfileName=name
        )

        arn = response.get('InstanceProfile')['Arn']
        role = ck.aws.IamRole(name=name, service='ec2',
                              add_instance_profile=True)

        assert role.instance_profile_arn == arn

        role.clobber()

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
        config = configparser.ConfigParser()
        with ck.config.rlock:
            config.read(config_file)
            for role_name in config.options(role_section_name):
                if UNIT_TEST_PREFIX in role_name:
                    config.remove_option(role_section_name, role_name)
            with open(config_file, 'w') as f:
                config.write(f)

        # Pass the exception through
        raise e


def test_DockerRepo(bucket_cleanup):
    ecr = ck.aws.clients['ecr']
    config = configparser.ConfigParser()
    config_file = ck.config.get_config_file()
    repo_section_name = 'docker-repos ' + ck.get_profile() \
                        + ' ' + ck.get_region()

    try:
        name = get_testing_name()

        # Use boto3 to create an ECR repo
        response = ecr.create_repository(repositoryName=name)

        repo_name = response['repository']['repositoryName']
        repo_uri = response['repository']['repositoryUri']
        repo_registry_id = response['repository']['registryId']

        # Retrieve that same repo with cloudknot
        dr = ck.aws.DockerRepo(name=name)

        assert dr.name == repo_name
        assert dr.repo_uri == repo_uri
        assert dr.repo_registry_id == repo_registry_id

        # Confirm that the docker repo is in the config file
        config = configparser.ConfigParser()
        with ck.config.rlock:
            config.read(config_file)

        assert name in config.options(repo_section_name)

        # Clobber the docker repo
        dr.clobber()

        retry = tenacity.Retrying(
            wait=tenacity.wait_exponential(max=16),
            stop=tenacity.stop_after_delay(180),
            retry=tenacity.retry_unless_exception_type(
                ecr.exceptions.RepositoryNotFoundException
            )
        )

        # Assert that it was removed from AWS
        with pytest.raises(ecr.exceptions.RepositoryNotFoundException):
            retry.call(ecr.describe_repositories, repositoryNames=[name])

        # Assert that it was removed from the config file
        # If we just re-read the config file, config will keep the union
        # of the in memory values and the file values, updating the
        # intersection of the two with the file values. So we must clear
        # config and then re-read the file
        config = configparser.ConfigParser()
        with ck.config.rlock:
            config.read(config_file)

        assert name not in config.options(repo_section_name)

        # Now create a new repo using only cloudknot
        name = get_testing_name()
        dr = ck.aws.DockerRepo(name=name)

        # Confirm that it exists on AWS and retrieve its properties
        retry = tenacity.Retrying(
            wait=tenacity.wait_exponential(max=16),
            stop=tenacity.stop_after_delay(60),
            retry=tenacity.retry_if_exception_type(
                ecr.exceptions.RepositoryNotFoundException
            )
        )

        response = retry.call(ecr.describe_repositories,
                              repositoryNames=[name])

        repo_name = response['repositories'][0]['repositoryName']
        repo_uri = response['repositories'][0]['repositoryUri']
        repo_registry_id = response['repositories'][0]['registryId']

        assert dr.name == repo_name
        assert dr.repo_uri == repo_uri
        assert dr.repo_registry_id == repo_registry_id

        # Confirm that the docker repo is in the config file
        config = configparser.ConfigParser()
        with ck.config.rlock:
            config.read(config_file)

        assert name in config.options(repo_section_name)

        # Delete the repo from AWS before clobbering
        ecr.delete_repository(
            registryId=repo_registry_id, repositoryName=repo_name, force=True
        )

        # Clobber the docker repo
        dr.clobber()

        retry = tenacity.Retrying(
            wait=tenacity.wait_exponential(max=16),
            stop=tenacity.stop_after_delay(180),
            retry=tenacity.retry_unless_exception_type(
                ecr.exceptions.RepositoryNotFoundException
            )
        )

        # Assert that it was removed from AWS
        with pytest.raises(ecr.exceptions.RepositoryNotFoundException):
            retry.call(ecr.describe_repositories, repositoryNames=[name])

        # Assert that it was removed from the config file
        # If we just re-read the config file, config will keep the union
        # of the in memory values and the file values, updating the
        # intersection of the two with the file values. So we must clear
        # config and then re-read the file
        config = configparser.ConfigParser()
        with ck.config.rlock:
            config.read(config_file)

        assert name not in config.options(repo_section_name)
    except Exception as e:
        response = ecr.describe_repositories()

        # Get all repos with unit test prefix in the name
        repos = [r for r in response.get('repositories')
                 if UNIT_TEST_PREFIX in r['repositoryName']]

        # Delete the AWS ECR repo
        for r in repos:
            ecr.delete_repository(
                registryId=r['registryId'],
                repositoryName=r['repositoryName'],
                force=True
            )

        # Clean up config file
        config = configparser.ConfigParser()
        with ck.config.rlock:
            config.read(config_file)
            for name in config.options(repo_section_name):
                if UNIT_TEST_PREFIX in name:
                    config.remove_option(repo_section_name, name)
            with open(config_file, 'w') as f:
                config.write(f)

        raise e


def test_Vpc(bucket_cleanup):
    ec2 = ck.aws.clients['ec2']
    config = configparser.ConfigParser()
    config_file = ck.config.get_config_file()
    vpc_section_name = 'vpc ' + ck.get_profile() + ' ' + ck.get_region()

    try:
        # Use boto3 to create a VPC
        name = get_testing_name()
        ipv4_cidr = '172.31.0.0/16'
        instance_tenancy = 'default'

        response = ec2.create_vpc(
            CidrBlock=ipv4_cidr,
            InstanceTenancy=instance_tenancy
        )

        vpc_id = response.get('Vpc')['VpcId']

        # Wait for VPC to exist and be available
        wait_for_vpc = ec2.get_waiter('vpc_exists')
        wait_for_vpc.wait(VpcIds=[vpc_id])
        wait_for_vpc = ec2.get_waiter('vpc_available')
        wait_for_vpc.wait(VpcIds=[vpc_id])

        retry = tenacity.Retrying(
            wait=tenacity.wait_exponential(max=16),
            stop=tenacity.stop_after_delay(60),
            retry=tenacity.retry_if_exception_type(
                ec2.exceptions.ClientError
            )
        )

        # Tag the VPC
        retry.call(
            ec2.create_tags,
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

        def tag_does_not_yet_exist(res):
            if res.get('Tags'):
                return False
            else:
                return True

        retry = tenacity.Retrying(
            wait=tenacity.wait_exponential(max=16),
            stop=tenacity.stop_after_delay(120),
            retry=tenacity.retry_if_result(tag_does_not_yet_exist)
        )

        retry.call(
            ec2.describe_tags,
            Filters=[
                {'Name': 'resource-type', 'Values': ['vpc']},
                {'Name': 'key', 'Values': ['Name']},
                {'Name': 'value', 'Values': [name]}
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

        # Confirm that the VPC is in the config file
        config = configparser.ConfigParser()
        with ck.config.rlock:
            config.read(config_file)

        assert vpc_id in config.options(vpc_section_name)

        # Clobber the VPC
        vpc.clobber()

        retry = tenacity.Retrying(
            wait=tenacity.wait_exponential(max=16),
            stop=tenacity.stop_after_delay(180),
            retry=tenacity.retry_unless_exception_type(
                ec2.exceptions.ClientError
            )
        )

        # Assert that it was removed from AWS
        with pytest.raises(ec2.exceptions.ClientError) as e:
            retry.call(ec2.describe_vpcs, VpcIds=[vpc_id])

        assert e.value.response.get('Error')['Code'] == 'InvalidVpcID.NotFound'

        # Assert that it was removed from the config file
        # If we just re-read the config file, config will keep the union
        # of the in memory values and the file values, updating the
        # intersection of the two with the file values. So we must set
        # config to None and then re-read the file
        config = configparser.ConfigParser()
        with ck.config.rlock:
            config.read(config_file)

        assert vpc_id not in config.options(vpc_section_name)

        # Try to retrieve a VPC that does not exist
        vpc_id = get_testing_name()
        with pytest.raises(ck.aws.ResourceDoesNotExistException) as e:
            ck.aws.Vpc(vpc_id=vpc_id)

        assert e.value.resource_id == vpc_id

        # Create Vpc instances, with different input types
        names = [get_testing_name() for i in range(3)]
        ipv4s = ['11.0.0.0/16', '10.1.0.0/16', None]
        instance_tenancies = ['default', 'dedicated', None]

        for (n, ip, it) in zip(names, ipv4s, instance_tenancies):
            vpc = ck.aws.Vpc(name=n, ipv4_cidr=ip, instance_tenancy=it)

            # Use boto3 to confirm their existence and properties
            assert not vpc.pre_existing
            assert vpc.name == n
            ip = ip if ip else '172.31.0.0/16'
            assert vpc.ipv4_cidr == ip
            it = it if it else 'default'
            assert vpc.instance_tenancy == it
            assert vpc.subnet_ids

            # Confirm that they exist in the config file
            config = configparser.ConfigParser()
            with ck.config.rlock:
                config.read(config_file)

            assert vpc.vpc_id in config.options(vpc_section_name)

            # Clobber the VPC
            vpc.clobber()

            # Assert that it was removed from the config file
            # If we just re-read the config file, config will keep the union
            # of the in memory values and the file values, updating the
            # intersection of the two with the file values. So we must clear
            # config and then re-read the file
            config = configparser.ConfigParser()
            with ck.config.rlock:
                config.read(config_file)

            assert vpc.vpc_id not in config.options(vpc_section_name)

            retry = tenacity.Retrying(
                wait=tenacity.wait_exponential(max=16),
                stop=tenacity.stop_after_delay(180),
                retry=tenacity.retry_unless_exception_type(
                    ec2.exceptions.ClientError
                )
            )

            # Assert that it was removed from AWS
            with pytest.raises(ec2.exceptions.ClientError) as e:
                retry.call(ec2.describe_vpcs, VpcIds=[vpc.vpc_id])

            error_code = e.value.response.get('Error')['Code']
            assert error_code == 'InvalidVpcID.NotFound'

        # Create another vpc without a Name tag
        response = ec2.create_vpc(
            CidrBlock=ipv4_cidr,
            InstanceTenancy=instance_tenancy
        )

        # Get the VPC ID
        vpc_id = response.get('Vpc')['VpcId']

        # Wait for VPC to exist and be available
        wait_for_vpc = ec2.get_waiter('vpc_exists')
        wait_for_vpc.wait(VpcIds=[vpc_id])
        wait_for_vpc = ec2.get_waiter('vpc_available')
        wait_for_vpc.wait(VpcIds=[vpc_id])

        # And wait for the VPC to show up via describe_vpcs call
        retry = tenacity.Retrying(
            wait=tenacity.wait_exponential(max=16),
            stop=tenacity.stop_after_delay(120),
            retry=tenacity.retry_if_exception_type(
                ec2.exceptions.ClientError
            )
        )
        retry.call(ec2.describe_vpcs, VpcIds=[vpc_id])

        # Use cloudknot to retrieve this VPC
        vpc = ck.aws.Vpc(vpc_id=vpc_id)

        # And confirm that cloudknot filled in a Name tag
        response = ec2.describe_vpcs(VpcIds=[vpc_id])
        tags = response.get('Vpcs')[0]['Tags']
        name_tag = list(filter(lambda d: d['Key'] == 'Name', tags))[0]
        assert name_tag['Value'] == 'cloudknot-acquired-pre-existing-vpc'

        # Now associate a security group
        sg = ck.aws.SecurityGroup(name=get_testing_name(), vpc=vpc)

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
            ck.aws.Vpc(vpc_id=get_testing_name(), name=get_testing_name())

        # Assert ValueError on invalid ipv4_cidr
        with pytest.raises(ValueError):
            ck.aws.Vpc(name=get_testing_name(), ipv4_cidr='not-valid')

        # Assert ValueError on invalid instance tenancy
        with pytest.raises(ValueError):
            ck.aws.Vpc(name=get_testing_name(), instance_tenancy='not-valid')

        # Assert ResourceDoesNotExistException on invalid vpc_id
        name = get_testing_name()
        with pytest.raises(ck.aws.ResourceDoesNotExistException) as e:
            ck.aws.Vpc(vpc_id=name)

        assert e.value.resource_id == name

    except Exception as e:  # pragma: nocover
        # Clean up VPCs from AWS
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

            retry = tenacity.Retrying(
                wait=tenacity.wait_exponential(max=16),
                stop=tenacity.stop_after_delay(60),
                retry=tenacity.retry_if_exception_type(
                    ec2.exceptions.ClientError
                )
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
                        retry.call(ec2.delete_subnet, SubnetId=subnet_id)

                    response = ec2.describe_network_acls(Filters=[
                        {'Name': 'vpc-id', 'Values': [vpc['VpcId']]},
                        {'Name': 'default', 'Values': ['false']}
                    ])

                    network_acl_ids = [n['NetworkAclId']
                                       for n in response.get('NetworkAcls')]

                    # Delete the network ACL
                    for net_id in network_acl_ids:
                        retry.call(ec2.delete_network_acl, NetworkAclId=net_id)

                    response = ec2.describe_route_tables(Filters=[
                        {'Name': 'vpc-id', 'Values': [vpc['VpcId']]},
                        {'Name': 'association.main', 'Values': ['false']}
                    ])

                    route_table_ids = [rt['RouteTableId']
                                       for rt in response.get('RouteTables')]

                    # Delete the route table
                    for rt_id in route_table_ids:
                        retry.call(ec2.delete_route_table, RouteTableId=rt_id)

                    # Detach and delete the internet gateway
                    response = ec2.describe_internet_gateways(Filters=[{
                        'Name': 'attachment.vpc-id',
                        'Values': [vpc['VpcId']]
                    }])

                    gateway_ids = [g['InternetGatewayId']
                                   for g in response.get('InternetGateways')]

                    for gid in gateway_ids:
                        retry.call(ec2.detach_internet_gateway,
                                   InternetGatewayId=gid,
                                   VpcId=vpc['VpcId'])
                        retry.call(ec2.delete_internet_gateway,
                                   InternetGatewayId=gid)

                    # delete the VPC
                    retry.call(ec2.delete_vpc, VpcId=vpc['VpcId'])

                    # Clean up config file
                    try:
                        config.remove_option(vpc_section_name, vpc['VpcId'])
                    except configparser.NoSectionError:
                        pass

            with open(config_file, 'w') as f:
                config.write(f)

        # Pass the exception through
        raise e


def test_SecurityGroup(bucket_cleanup):
    ec2 = ck.aws.clients['ec2']
    config = configparser.ConfigParser()
    config_file = ck.config.get_config_file()
    vpc_section_name = 'vpc ' + ck.get_profile() + ' ' + ck.get_region()
    sg_section_name = 'security-groups ' + ck.get_profile() \
                      + ' ' + ck.get_region()

    try:
        # Use boto3 to create a security group
        name = get_testing_name()
        description = 'Security group for cloudknot unit testing'

        # Create a VPC to attach the security group to
        response = ec2.create_vpc(CidrBlock='172.31.0.0/16')
        vpc_id = response.get('Vpc')['VpcId']

        response = ec2.create_security_group(
            GroupName=name,
            Description=description,
            VpcId=vpc_id
        )
        group_id = response.get('GroupId')

        retry = tenacity.Retrying(
            wait=tenacity.wait_exponential(max=16),
            stop=tenacity.stop_after_delay(60),
            retry=tenacity.retry_if_exception_type(
                ec2.exceptions.ClientError
            )
        )

        # Tag the VPC and security group for easy cleanup later
        retry.call(
            ec2.create_tags,
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

        # Confirm that the security group has the right properties.
        assert sg.pre_existing
        assert sg.vpc is None
        assert sg.vpc_id == vpc_id
        assert sg.description == description
        assert sg.security_group_id == group_id

        # Confirm that the security group is in the config file
        config = configparser.ConfigParser()
        with ck.config.rlock:
            config.read(config_file)

        assert group_id in config.options(sg_section_name)

        # Clobber the security group
        sg.clobber()

        # Assert that it was removed from the config file
        # If we just re-read the config file, config will keep the union
        # of the in memory values and the file values, updating the
        # intersection of the two with the file values. So we must clear
        # config and then re-read the file
        config = configparser.ConfigParser()
        with ck.config.rlock:
            config.read(config_file)

        assert group_id not in config.options(sg_section_name)

        retry = tenacity.Retrying(
            wait=tenacity.wait_exponential(max=16),
            stop=tenacity.stop_after_delay(300),
            retry=tenacity.retry_unless_exception_type(
                ec2.exceptions.ClientError
            )
        )

        # Assert that it was removed from AWS
        with pytest.raises(ec2.exceptions.ClientError) as e:
            retry.call(ec2.describe_security_groups, GroupIds=[group_id])

        assert e.value.response.get('Error')['Code'] == 'InvalidGroup.NotFound'

        # Try to retrieve a security group that does not exist
        group_id = get_testing_name()
        with pytest.raises(ck.aws.ResourceDoesNotExistException) as e:
            ck.aws.SecurityGroup(security_group_id=group_id)

        assert e.value.resource_id == group_id

        # Create SecurityGroup instances, one with description and one without
        names = [get_testing_name() for i in range(2)]
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
            config = configparser.ConfigParser()
            with ck.config.rlock:
                config.read(config_file)

            assert sg.security_group_id in config.options(sg_section_name)

            # Clobber security group
            sg.clobber()

            retry = tenacity.Retrying(
                wait=tenacity.wait_exponential(max=16),
                stop=tenacity.stop_after_delay(300),
                retry=tenacity.retry_unless_exception_type(
                    ec2.exceptions.ClientError
                )
            )

            # Assert that it was removed from AWS
            with pytest.raises(ec2.exceptions.ClientError) as e:
                retry.call(ec2.describe_security_groups,
                           GroupIds=[sg.security_group_id])

            error_code = e.value.response.get('Error')['Code']
            assert error_code == 'InvalidGroup.NotFound'

            # Assert that they were removed from the config file
            # If we just re-read the config file, config will keep the union
            # of the in memory values and the file values, updating the
            # intersection of the two with the file values. So we must clear
            # config and then re-read the file
            config = configparser.ConfigParser()
            with ck.config.rlock:
                config.read(config_file)

            assert sg.security_group_id not in config.options(sg_section_name)

        # Test for correct handling of incorrect input
        # Assert ValueError on no input
        with pytest.raises(ValueError) as e:
            ck.aws.SecurityGroup()

        # Assert ValueError on name and group_id input
        with pytest.raises(ValueError) as e:
            ck.aws.SecurityGroup(
                security_group_id=get_testing_name(),
                name=get_testing_name()
            )

        # Assert ValueError on invalid vpc input
        with pytest.raises(ValueError) as e:
            ck.aws.SecurityGroup(name=get_testing_name(), vpc=5)

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

        config = configparser.ConfigParser()
        with ck.config.rlock:
            config.read(config_file)

            for sg in unit_test_sgs:
                # Delete role
                ec2.delete_security_group(GroupId=sg['id'])

                # Clean up config file
                try:
                    config.remove_option(sg_section_name, sg['id'])
                except configparser.NoSectionError:
                    pass

            # Find all VPCs with tag
            # owner = 'cloudknot-security-group-unit-test'
            response = ec2.describe_vpcs(
                Filters=[{
                    'Name': 'tag:owner',
                    'Values': ['cloudknot-security-group-unit-test']
                }]
            )

            for vpc in response.get('Vpcs'):
                ec2.delete_vpc(VpcId=vpc['VpcId'])

                # Clean up config file
                try:
                    config.remove_option(vpc_section_name, vpc['VpcId'])
                except configparser.NoSectionError:
                    pass

            with open(config_file, 'w') as f:
                config.write(f)

        # Pass the exception through
        raise e


def test_JobDefinition(pars):
    batch = ck.aws.clients['batch']
    config = configparser.ConfigParser()
    config_file = ck.config.get_config_file()
    jd_section_name = 'job-definitions ' + ck.get_profile() \
                      + ' ' + ck.get_region()

    try:
        # Use boto3 to create a job definition
        name = get_testing_name()
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
        assert jd.job_role is None
        assert jd.job_role_arn == pars.batch_service_role.arn
        assert jd.docker_image == image
        assert jd.vcpus == vcpus
        assert jd.memory == memory
        assert jd.username == user
        assert jd.retries == retries
        assert jd.arn == arn

        # Confirm that the role is in the config file
        config = configparser.ConfigParser()
        with ck.config.rlock:
            config.read(config_file)

        assert name in config.options(jd_section_name)

        # Assert that clobber raises RegionException if we change the region
        old_region = ck.get_region()
        if old_region != 'us-east-2':
            ck.set_region(region='us-east-2')
        else:
            ck.set_region(region='us-east-1')

        with pytest.raises(ck.aws.RegionException):
            jd.clobber()

        ck.set_region(region=old_region)

        # Clobber the role
        jd.clobber()

        # Assert that it was removed from AWS
        response = batch.describe_job_definitions(jobDefinitions=[arn])
        assert len(response.get('jobDefinitions')) == 1
        assert response.get('jobDefinitions')[0]['status'] == 'INACTIVE'

        # Assert that it was removed from the config file
        # If we just re-read the config file, config will keep the union
        # of the in memory values and the file values, updating the
        # intersection of the two with the file values. So we must clear
        # config and then re-read the file
        config = configparser.ConfigParser()
        with ck.config.rlock:
            config.read(config_file)

        assert name not in config.options(jd_section_name)

        # The previous job def should be INACTIVE, so try to retrieve it
        # and assert that we get a ResourceExistsException
        with pytest.raises(ck.aws.ResourceExistsException) as e:
            ck.aws.JobDefinition(arn=arn)

        assert e.value.resource_id == arn

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

        names = [get_testing_name() for i in range(2)]
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
            assert jd.job_role_arn == jr.arn
            assert jd.docker_image == di
            v = v if v else 1
            assert jd.vcpus == v
            r = r if r else 1
            assert jd.retries == r
            m = m if m else 8000
            assert jd.memory == m

            # assert arn

            # Confirm that they exist in the config file
            config = configparser.ConfigParser()
            with ck.config.rlock:
                config.read(config_file)

            assert jd.name in config.options(jd_section_name)

            # Clobber the job definition
            jd.clobber()

            # Assert that it was removed from AWS
            response = batch.describe_job_definitions(jobDefinitions=[jd.arn])
            assert len(response.get('jobDefinitions')) == 1
            assert response.get('jobDefinitions')[0]['status'] == 'INACTIVE'

            # Assert that they were removed from the config file
            # If we just re-read the config file, config will keep the union
            # of the in memory values and the file values, updating the
            # intersection of the two with the file values. So we must clear
            # config and then re-read the file
            config = configparser.ConfigParser()
            with ck.config.rlock:
                config.read(config_file)

            assert jd.name not in config.options(jd_section_name)

        # Test for correct handling of incorrect input
        with pytest.raises(ValueError) as e:
            ck.aws.JobDefinition()
        with pytest.raises(ValueError) as e:
            ck.aws.JobDefinition(
                arn=get_testing_name(),
                name=get_testing_name()
            )
        with pytest.raises(ValueError) as e:
            ck.aws.JobDefinition(
                name=get_testing_name(),
                job_role=5, docker_image='ubuntu'
            )
        with pytest.raises(ValueError) as e:
            ck.aws.JobDefinition(
                name=get_testing_name(),
                job_role=pars.batch_service_role,
                docker_image=5
            )
        with pytest.raises(ValueError) as e:
            ck.aws.JobDefinition(
                name=get_testing_name(),
                job_role=pars.batch_service_role,
                docker_image='ubuntu',
                vcpus=-2
            )
        with pytest.raises(ValueError) as e:
            ck.aws.JobDefinition(
                name=get_testing_name(),
                job_role=pars.batch_service_role,
                docker_image='ubuntu',
                retries=0
            )
        with pytest.raises(ValueError) as e:
            ck.aws.JobDefinition(
                name=get_testing_name(),
                job_role=pars.batch_service_role,
                docker_image='ubuntu',
                retries=100
            )
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

        config = configparser.ConfigParser()
        with ck.config.rlock:
            config.read(config_file)

            for jd in unit_test_jds:
                # Deregister the job definition
                batch.deregister_job_definition(jobDefinition=jd['arn'])

                # Clean up config file
                try:
                    config.remove_option(jd_section_name, jd['name'])
                except configparser.NoSectionError:
                    pass

            with open(config_file, 'w') as f:
                config.write(f)

        # Pass the exception through
        raise e


def test_ComputeEnvironment(pars):
    batch = ck.aws.clients['batch']
    config = configparser.ConfigParser()
    config_file = ck.config.get_config_file()
    ce_section_name = 'compute-environments ' + ck.get_profile() \
                      + ' ' + ck.get_region()
    jq_section_name = 'job-queues ' + ck.get_profile() \
                      + ' ' + ck.get_region()

    try:
        # Use boto3 to create a compute environment
        name = get_testing_name()

        resource_type = 'EC2'
        min_vcpus = 1
        max_vcpus = 256
        instance_types = ['optimal']

        compute_resources = {
            'type': resource_type,
            'minvCpus': min_vcpus,
            'maxvCpus': max_vcpus,
            'instanceTypes': instance_types,
            'subnets': pars.vpc.subnet_ids,
            'securityGroupIds': [pars.security_group.security_group_id],
            'instanceRole': pars.ecs_instance_role.instance_profile_arn,
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
        assert ce.batch_service_role_arn == pars.batch_service_role.arn
        assert ce.instance_role is None
        assert (ce.instance_role_arn ==
                pars.ecs_instance_role.instance_profile_arn)
        assert ce.vpc is None
        assert ce.subnets == pars.vpc.subnet_ids
        assert ce.security_group is None
        assert ce.security_group_ids == [pars.security_group.security_group_id]
        assert ce.spot_fleet_role is None
        assert ce.spot_fleet_role_arn is None
        assert ce.instance_types == instance_types
        assert ce.resource_type == resource_type
        assert ce.min_vcpus == min_vcpus
        assert ce.max_vcpus == max_vcpus
        # desired_vcpus defaults to 1
        assert ce.desired_vcpus == 1
        assert ce.image_id is None
        assert ce.ec2_key_pair is None
        assert not ce.tags
        assert ce.bid_percentage is None
        assert ce.arn == arn

        # Confirm that the role is in the config file
        config = configparser.ConfigParser()
        with ck.config.rlock:
            config.read(config_file)

        assert name in config.options(ce_section_name)

        # Before clobbering, associate this compute environment with a
        # job queue in order to test the job queue disassociation statements
        # in ComputeEnvironment().clobber()
        ck.aws.wait_for_compute_environment(
            arn=ce.arn, name=ce.name, log=False
        )

        jq = ck.aws.JobQueue(name=get_testing_name(), compute_environments=ce)

        # Clobber the compute environment first, then the job queue
        with pytest.raises(ck.aws.CannotDeleteResourceException) as e:
            ce.clobber()

        assert e.value.resource_id[0]['jobQueueName'] == jq.name

        # Assert that IamRole raises exception if we try to delete the
        # batch service role on which this compute environment is based
        with pytest.raises(ck.aws.CannotDeleteResourceException):
            pars.batch_service_role.clobber()

        # Assert that clobber raises RegionException if we change the region
        old_region = ck.get_region()
        if old_region != 'us-east-2':
            ck.set_region(region='us-east-2')
        else:
            ck.set_region(region='us-east-1')

        with pytest.raises(ck.aws.RegionException):
            ce.clobber()

        ck.set_region(region=old_region)

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
        # intersection of the two with the file values. So we must clear
        # config and then re-read the file
        config = configparser.ConfigParser()
        with ck.config.rlock:
            config.read(config_file)

        assert name not in config.options(ce_section_name)

        # Try to retrieve a compute environment that does not exist
        nonexistent_arn = arn.replace(
            UNIT_TEST_PREFIX,
            UNIT_TEST_PREFIX + '-nonexistent'
        )
        with pytest.raises(ck.aws.ResourceDoesNotExistException) as e:
            ck.aws.ComputeEnvironment(arn=nonexistent_arn)

        assert e.value.resource_id == nonexistent_arn

        # Create four compute environments with different parameters

        names = [get_testing_name() for i in range(4)]
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
            assert ce.batch_service_role_arn == bsr.arn
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
            if isinstance(it, six.string_types):
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
            config = configparser.ConfigParser()
            with ck.config.rlock:
                config.read(config_file)

            assert ce.name in config.options(ce_section_name)

            # Clobber compute environment
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
            # intersection of the two with the file values. So we must clear
            # config and then re-read the file
            config = configparser.ConfigParser()
            with ck.config.rlock:
                config.read(config_file)

            assert ce.name not in config.options(ce_section_name)

        # Test for correct handling of incorrect input
        # ValueError for neither arn or name
        with pytest.raises(ValueError) as e:
            ck.aws.ComputeEnvironment()

        # Value Error for both arn and name
        with pytest.raises(ValueError) as e:
            ck.aws.ComputeEnvironment(
                arn=get_testing_name(),
                name=get_testing_name()
            )

        # ValueError for 'SPOT' resource with no spot_fleet_role
        with pytest.raises(ValueError) as e:
            ck.aws.ComputeEnvironment(
                name=get_testing_name(),
                batch_service_role=pars.batch_service_role,
                instance_role=pars.ecs_instance_role, vpc=pars.vpc,
                security_group=pars.security_group,
                resource_type='SPOT', bid_percentage=50
            )

        # ValueError for 'SPOT' resource with no bid_percentage
        with pytest.raises(ValueError) as e:
            ck.aws.ComputeEnvironment(
                name=get_testing_name(),
                batch_service_role=pars.batch_service_role,
                instance_role=pars.ecs_instance_role, vpc=pars.vpc,
                security_group=pars.security_group,
                spot_fleet_role=pars.spot_fleet_role,
                resource_type='SPOT'
            )

        # ValueError for bad batch_service_role
        with pytest.raises(ValueError) as e:
            ck.aws.ComputeEnvironment(
                name=get_testing_name(),
                batch_service_role=pars.ecs_instance_role,
                instance_role=pars.ecs_instance_role, vpc=pars.vpc,
                security_group=pars.security_group
            )

        # ValueError for bad instance_role
        with pytest.raises(ValueError) as e:
            ck.aws.ComputeEnvironment(
                name=get_testing_name(),
                batch_service_role=pars.batch_service_role,
                instance_role=pars.batch_service_role, vpc=pars.vpc,
                security_group=pars.security_group
            )

        # ValueError for bad vpc
        with pytest.raises(ValueError) as e:
            ck.aws.ComputeEnvironment(
                name=get_testing_name(),
                batch_service_role=pars.batch_service_role,
                instance_role=pars.ecs_instance_role,
                vpc=pars.security_group,
                security_group=pars.security_group
            )

        # ValueError for bad security_group
        with pytest.raises(ValueError) as e:
            ck.aws.ComputeEnvironment(
                name=get_testing_name(),
                batch_service_role=pars.batch_service_role,
                instance_role=pars.ecs_instance_role,
                vpc=pars.vpc,
                security_group=pars.vpc
            )

        # ValueError for bad spot_fleet_role
        with pytest.raises(ValueError) as e:
            ck.aws.ComputeEnvironment(
                name=get_testing_name(),
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
                    name=get_testing_name(),
                    batch_service_role=pars.batch_service_role,
                    instance_role=pars.ecs_instance_role,
                    vpc=pars.vpc,
                    security_group=pars.security_group,
                    instance_types=instance_type
                )

        # ValueError for bad resource_type
        with pytest.raises(ValueError) as e:
            ck.aws.ComputeEnvironment(
                name=get_testing_name(),
                batch_service_role=pars.batch_service_role,
                instance_role=pars.ecs_instance_role,
                vpc=pars.vpc,
                security_group=pars.security_group,
                resource_type='BAD'
            )

        # ValueError for bad min_vcpus
        with pytest.raises(ValueError) as e:
            ck.aws.ComputeEnvironment(
                name=get_testing_name(),
                batch_service_role=pars.batch_service_role,
                instance_role=pars.ecs_instance_role,
                vpc=pars.vpc,
                security_group=pars.security_group,
                min_vcpus=-42
            )

        # ValueError for bad max_vcpus
        with pytest.raises(ValueError) as e:
            ck.aws.ComputeEnvironment(
                name=get_testing_name(),
                batch_service_role=pars.batch_service_role,
                instance_role=pars.ecs_instance_role,
                vpc=pars.vpc,
                security_group=pars.security_group,
                max_vcpus=-42
            )

        # ValueError for bad desired_vcpus
        with pytest.raises(ValueError) as e:
            ck.aws.ComputeEnvironment(
                name=get_testing_name(),
                batch_service_role=pars.batch_service_role,
                instance_role=pars.ecs_instance_role,
                vpc=pars.vpc,
                security_group=pars.security_group,
                desired_vcpus=-42
            )

        # ValueError for bad image_id
        with pytest.raises(ValueError) as e:
            ck.aws.ComputeEnvironment(
                name=get_testing_name(),
                batch_service_role=pars.batch_service_role,
                instance_role=pars.ecs_instance_role,
                vpc=pars.vpc,
                security_group=pars.security_group,
                image_id=42
            )

        # ValueError for bad ec2_key_pair
        with pytest.raises(ValueError) as e:
            ck.aws.ComputeEnvironment(
                name=get_testing_name(),
                batch_service_role=pars.batch_service_role,
                instance_role=pars.ecs_instance_role,
                vpc=pars.vpc,
                security_group=pars.security_group,
                ec2_key_pair=-42
            )

        # ValueError for bad ec2_key_pair
        with pytest.raises(ValueError) as e:
            ck.aws.ComputeEnvironment(
                name=get_testing_name(),
                batch_service_role=pars.batch_service_role,
                instance_role=pars.ecs_instance_role,
                vpc=pars.vpc,
                security_group=pars.security_group,
                tags=-42
            )
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
            batch.update_compute_environment(
                computeEnvironment=ce['arn'],
                state='DISABLED'
            )

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
                    ck.aws.wait_for_job_queue(
                        name=name, log=True, max_wait_time=180
                    )
                    retry = tenacity.Retrying(
                        wait=tenacity.wait_exponential(max=16),
                        stop=tenacity.stop_after_delay(120),
                        retry=tenacity.retry_if_exception_type(
                            batch.exceptions.ClientException
                        )
                    )
                    retry.call(
                        batch.update_job_queue, jobQueue=arn, state='DISABLED'
                    )

                    # Delete the job queue
                    ck.aws.wait_for_job_queue(
                        name=name, log=True, max_wait_time=180
                    )
                    batch.delete_job_queue(jobQueue=arn)

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
                ck.aws.wait_for_compute_environment(
                    arn=ce['arn'], name=ce['name'], log=False
                )

                # Delete the compute environment
                batch.delete_compute_environment(computeEnvironment=ce['arn'])

                # Clean up config file
                try:
                    config.remove_option(ce_section_name, ce['name'])
                except configparser.NoSectionError:
                    pass

            with open(config_file, 'w') as f:
                config.write(f)

        # Pass the exception through
        raise e


def test_JobQueue(pars):
    batch = ck.aws.clients['batch']
    config = configparser.ConfigParser()
    config_file = ck.config.get_config_file()
    ce_section_name = 'compute-environments ' + ck.get_profile() \
                      + ' ' + ck.get_region()
    jq_section_name = 'job-queues ' + ck.get_profile() \
                      + ' ' + ck.get_region()

    try:
        ce = ck.aws.ComputeEnvironment(
            name=get_testing_name(),
            batch_service_role=pars.batch_service_role,
            instance_role=pars.ecs_instance_role, vpc=pars.vpc,
            security_group=pars.security_group,
            spot_fleet_role=pars.spot_fleet_role,
        )

        ce2 = ck.aws.ComputeEnvironment(
            name=get_testing_name(),
            batch_service_role=pars.batch_service_role,
            instance_role=pars.ecs_instance_role, vpc=pars.vpc,
            security_group=pars.security_group,
            spot_fleet_role=pars.spot_fleet_role,
        )

        ck.aws.wait_for_compute_environment(
            arn=ce.arn, name=ce.name, log=False
        )

        # Use boto3 to create a job queue
        name = get_testing_name()
        state = 'ENABLED'
        priority = 1
        compute_environment_arns = [
            {
                'order': 0,
                'computeEnvironment': ce.arn
            }
        ]

        response = batch.create_job_queue(
            jobQueueName=name,
            state=state,
            priority=priority,
            computeEnvironmentOrder=compute_environment_arns
        )

        arn = response['jobQueueArn']

        # Create a JobQueue instance with same name but different priority.
        # Confirm that ComputeEnvironment raises a ResourceExistsException.
        with pytest.raises(ck.aws.ResourceExistsException) as e:
            ck.aws.JobQueue(
                name=name,
                compute_environments=ce,
                priority=5
            )

        assert e.value.resource_id == arn

        # Then create a JobQueue with only that arn to have
        # cloudknot retrieve that job definition.
        jq = ck.aws.JobQueue(arn=arn)

        # Confirm that the instance has the right properties.
        assert jq.pre_existing
        assert jq.name == name
        assert jq.compute_environments is None
        assert jq.compute_environment_arns == compute_environment_arns
        assert jq.priority == priority
        assert jq.arn == arn

        # Confirm that the role is in the config file
        config = configparser.ConfigParser()
        with ck.config.rlock:
            config.read(config_file)

        assert name in config.options(jq_section_name)

        # Assert ValueError on invalid status in get_jobs() method
        with pytest.raises(ValueError):
            jq.get_jobs(status='INVALID')

        assert jq.get_jobs() == []
        assert jq.get_jobs(status='STARTING') == []

        # Assert that clobber raises RegionException if we change the region
        old_region = ck.get_region()
        if old_region != 'us-east-2':
            ck.set_region(region='us-east-2')
        else:
            ck.set_region(region='us-east-1')

        with pytest.raises(ck.aws.RegionException):
            jq.clobber()

        with pytest.raises(ck.aws.RegionException):
            jobs = jq.get_jobs()  # noqa: F841

        ck.set_region(region=old_region)

        # Clobber the job queue
        jq.clobber()

        # Assert that we can no longer get jobs after clobbering
        with pytest.raises(ck.aws.ResourceClobberedException):
            jobs = jq.get_jobs()  # noqa: F841

        # Assert that it was removed from AWS
        response = batch.describe_job_queues(jobQueues=[arn])
        response_jq = response.get('jobQueues')
        assert (not response_jq or response_jq[0]['status'] == 'DELETING')

        # Assert that it was removed from the config file
        # If we just re-read the config file, config will keep the union
        # of the in memory values and the file values, updating the
        # intersection of the two with the file values. So we must clear
        # config and then re-read the file
        config = configparser.ConfigParser()
        with ck.config.rlock:
            config.read(config_file)

        assert name not in config.options(jq_section_name)

        # Try to retrieve a job queue that does not exist
        nonexistent_arn = arn.replace(
            UNIT_TEST_PREFIX,
            UNIT_TEST_PREFIX + '-nonexistent'
        )
        with pytest.raises(ck.aws.ResourceDoesNotExistException) as e:
            ck.aws.JobQueue(arn=nonexistent_arn)

        assert e.value.resource_id == nonexistent_arn

        # Create four job queues with different parameters
        names = [get_testing_name() for i in range(2)]
        compute_environments = [ce, (ce, ce2)]
        priorities = [4, None]

        for (n, c_env, p) in zip(names, compute_environments, priorities):
            jq = ck.aws.JobQueue(
                name=n, compute_environments=c_env, priority=p
            )

            # Use boto3 to confirm their existence and properties
            assert not jq.pre_existing
            assert jq.name == n
            if isinstance(c_env, ck.aws.ComputeEnvironment):
                c_env = (c_env,)
            assert jq.compute_environments == c_env
            assert jq.compute_environment_arns == [
                {
                    'order': i,
                    'computeEnvironment': c.arn
                } for i, c in enumerate(c_env)
            ]
            p = p if p else 1
            assert jq.priority == p

            # Confirm that they exist in the config file
            config = configparser.ConfigParser()
            with ck.config.rlock:
                config.read(config_file)

            assert jq.name in config.options(jq_section_name)

            # Clobber job queue
            jq.clobber()

            # Assert that it was removed from AWS
            response = batch.describe_job_queues(
                jobQueues=[jq.arn]
            )
            response_jq = response.get('jobQueues')
            assert (not response_jq or response_jq[0]['status'] == 'DELETING')

            # Assert that they were removed from the config file
            # If we just re-read the config file, config will keep the union
            # of the in memory values and the file values, updating the
            # intersection of the two with the file values. So we must clear
            # config and then re-read the file
            config = configparser.ConfigParser()
            with ck.config.rlock:
                config.read(config_file)

            assert jq.name not in config.options(jq_section_name)

        ce.clobber()
        ce2.clobber()

        # Test for correct handling of incorrect input
        # ValueError for neither arn or name
        with pytest.raises(ValueError) as e:
            ck.aws.JobQueue()

        # Value Error for both arn and name
        with pytest.raises(ValueError) as e:
            ck.aws.JobQueue(arn=get_testing_name(), name=get_testing_name())

        # Value Error for negative priority
        with pytest.raises(ValueError) as e:
            ck.aws.JobQueue(
                name=get_testing_name(),
                compute_environments=ce,
                priority=-42
            )

        # Value Error for invalid compute environments
        with pytest.raises(ValueError) as e:
            ck.aws.JobQueue(
                name=get_testing_name(),
                compute_environments=[42, -42]
            )
    except Exception as e:  # pragma: nocover
        # Clean up job queues and compute environments from AWS
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
            batch.update_compute_environment(
                computeEnvironment=ce['arn'],
                state='DISABLED'
            )

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
                    ck.aws.wait_for_job_queue(
                        name=name, log=True, max_wait_time=180
                    )
                    batch.update_job_queue(jobQueue=arn, state='DISABLED')

                    # Delete the job queue
                    ck.aws.wait_for_job_queue(
                        name=name, log=True, max_wait_time=180
                    )
                    batch.delete_job_queue(jobQueue=arn)

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
                ck.aws.wait_for_compute_environment(
                    arn=ce['arn'], name=ce['name'], log=False
                )

                # Delete the compute environment
                batch.delete_compute_environment(computeEnvironment=ce['arn'])

                # Clean up config file
                try:
                    config.remove_option(ce_section_name, ce['name'])
                except configparser.NoSectionError:
                    pass

            with open(config_file, 'w') as f:
                config.write(f)

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
            batch.update_job_queue(jobQueue=jq['arn'], state='DISABLED')

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
                batch.delete_job_queue(jobQueue=jq['arn'])

                # Clean up config file
                try:
                    config.remove_option(jq_section_name, jq['name'])
                except configparser.NoSectionError:
                    pass

            with open(config_file, 'w') as f:
                config.write(f)

        # Pass the exception through
        raise e


def test_BatchJob(pars):
    """Test only the input validation of BatchJob.

    If we tested anything else, it would cost money to submit the batch jobs.
    """
    job_def = None
    compute_environment = None
    job_queue = None

    try:
        # Make job definition for input testing
        job_def = ck.aws.JobDefinition(
            name=get_testing_name(),
            job_role=pars.batch_service_role,
            docker_image='ubuntu',
        )

        # Make compute environment for input into job_queue
        compute_environment = ck.aws.ComputeEnvironment(
            name=get_testing_name(),
            batch_service_role=pars.batch_service_role,
            instance_role=pars.ecs_instance_role, vpc=pars.vpc,
            security_group=pars.security_group,
            spot_fleet_role=pars.spot_fleet_role,
        )

        # Make job_queue for input testing
        job_queue = ck.aws.JobQueue(
            name=get_testing_name(),
            compute_environments=compute_environment,
            priority=1
        )

        # Assert ValueError on insufficient input
        with pytest.raises(ValueError):
            ck.aws.BatchJob()

        # Assert ValueError on over-specified input
        with pytest.raises(ValueError):
            ck.aws.BatchJob(
                job_id=42,
                name=get_testing_name()
            )

        # Assert ValueError on invalid job_queue
        with pytest.raises(ValueError):
            ck.aws.BatchJob(
                name=get_testing_name(),
                input=42,
                job_queue=42
            )

        # Assert ValueError on invalid job_definition
        with pytest.raises(ValueError):
            ck.aws.BatchJob(
                name=get_testing_name(),
                input=42,
                job_queue=job_queue,
                job_definition=42
            )

        # Assert ValueError on invalid environment variable
        with pytest.raises(ValueError):
            ck.aws.BatchJob(
                name=get_testing_name(),
                input=42,
                job_queue=job_queue,
                job_definition=job_def,
                environment_variables=[42]
            )

        job_queue.clobber()
        compute_environment.clobber()
        job_def.clobber()
    except Exception as e:
        if job_queue:
            job_queue.clobber()

        if compute_environment:
            compute_environment.clobber()

        if job_def:
            job_def.clobber()

        raise e
