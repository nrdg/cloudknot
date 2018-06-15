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
import os
import os.path as op
import pytest
import shutil
import tempfile
import tenacity
import uuid

UNIT_TEST_PREFIX = 'cloudknot-unit-test'
data_path = op.join(ck.__path__[0], 'data')


def test_NamedObject():
    named = ck.aws.NamedObject(name='test_test')
    assert named.name == 'test-test'

    with pytest.raises(ck.aws.CloudknotInputError):
        ck.aws.NamedObject(name='42test')


def get_testing_name():
    u = str(uuid.uuid4()).replace('-', '')[:8]
    name = UNIT_TEST_PREFIX + '-' + u
    return name


@pytest.fixture(scope='module')
def bucket_cleanup():
    config_file = ck.config.get_config_file()
    config = configparser.ConfigParser()

    with ck.config.rlock:
        config.read(config_file)

    option = 's3-bucket'
    if config.has_section('aws') and config.has_option('aws', option):
        old_s3_params = ck.get_s3_params()
    else:
        old_s3_params = None

    new_bucket = 'cloudknot-travis-build-45814031-351c-4b27-9a40-672c971f7e83'
    ck.set_s3_params(bucket=new_bucket)

    yield None

    s3_params = ck.get_s3_params()
    bucket_policy = s3_params.policy

    if (old_s3_params is None) or bucket_policy == old_s3_params.policy:
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

        # Delete the non-default versions
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

        try:
            iam.delete_policy(PolicyArn=arn)
        except Exception:
            pass

    if old_s3_params:
        ck.set_s3_params(
            bucket=old_s3_params.bucket,
            policy=old_s3_params.policy,
            sse=old_s3_params.sse
        )


@pytest.fixture(scope='module')
def pars(bucket_cleanup):
    p = ck.Pars(name='unit-test')
    yield p
    p.clobber()


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
    with pytest.raises(ck.aws.CloudknotInputError):
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


# def test_set_profile(bucket_cleanup):
#     try:
#         old_credentials_file = os.environ['AWS_SHARED_CREDENTIALS_FILE']
#     except KeyError:
#         old_credentials_file = None
#
#     try:
#         old_aws_config_file = os.environ['AWS_CONFIG_FILE']
#     except KeyError:
#         old_aws_config_file = None
#
#     try:
#         old_ck_config_file = os.environ['CLOUDKNOT_CONFIG_FILE']
#     except KeyError:
#         old_ck_config_file = None
#
#     ref_dir = op.join(data_path, 'profiles_ref_data')
#     ck_config_file = op.join(ref_dir, 'cloudknot_without_profile')
#     shutil.copy(ck_config_file, ck_config_file + '.bak')
#     try:
#         os.environ['CLOUDKNOT_CONFIG_FILE'] = ck_config_file
#
#         config_file = op.join(ref_dir, 'config')
#         os.environ['AWS_CONFIG_FILE'] = config_file
#
#         cred_file = op.join(ref_dir, 'credentials_without_default')
#         os.environ['AWS_SHARED_CREDENTIALS_FILE'] = cred_file
#
#         with pytest.raises(ck.aws.CloudknotInputError):
#             ck.set_profile(profile_name='not_in_list_of_profiles')
#
#         profile = 'name-5'
#         ck.set_profile(profile_name=profile)
#         assert ck.get_profile() == profile
#     finally:
#         shutil.move(ck_config_file + '.bak', ck_config_file)
#
#         if old_credentials_file:
#             os.environ['AWS_SHARED_CREDENTIALS_FILE'] = old_credentials_file
#         else:
#             try:
#                 del os.environ['AWS_SHARED_CREDENTIALS_FILE']
#             except KeyError:
#                 pass
#
#         if old_aws_config_file:
#             os.environ['AWS_CONFIG_FILE'] = old_aws_config_file
#         else:
#             try:
#                 del os.environ['AWS_CONFIG_FILE']
#             except KeyError:
#                 pass
#
#         if old_ck_config_file:
#             os.environ['CLOUDKNOT_CONFIG_FILE'] = old_ck_config_file
#         else:
#             try:
#                 del os.environ['CLOUDKNOT_CONFIG_FILE']
#             except KeyError:
#                 pass
#
#         ck.refresh_clients()


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
            try:
                for name in config.options(repo_section_name):
                    if UNIT_TEST_PREFIX in name:
                        config.remove_option(repo_section_name, name)
            except configparser.NoSectionError:
                pass

            with open(config_file, 'w') as f:
                config.write(f)

        raise e


# def test_BatchJob(pars):
#     """Test only the input validation of BatchJob.
#
#     If we tested anything else, it would cost money to submit the batch jobs.
#     """
#     job_def = None
#     compute_environment = None
#     job_queue = None
#
#     try:
#         # Make job definition for input testing
#         job_def = ck.aws.JobDefinition(
#             name=get_testing_name(),
#             docker_image='ubuntu',
#         )
#
#         # Make compute environment for input into job_queue
#         compute_environment = ck.aws.ComputeEnvironment(
#             name=get_testing_name(),
#             batch_service_role=pars.batch_service_role,
#             instance_profile=pars.ecs_instance_profile,
#             subnets=pars.subnets,
#             security_group=pars.security_group,
#             spot_fleet_role=pars.spot_fleet_role,
#         )
#
#         # Make job_queue for input testing
#         job_queue = ck.aws.JobQueue(
#             name=get_testing_name(),
#             compute_environments=compute_environment,
#             priority=1
#         )
#
#         # Assert ck.aws.CloudknotInputError on insufficient input
#         with pytest.raises(ck.aws.CloudknotInputError):
#             ck.aws.BatchJob()
#
#         # Assert ck.aws.CloudknotInputError on over-specified input
#         with pytest.raises(ck.aws.CloudknotInputError):
#             ck.aws.BatchJob(
#                 job_id=42,
#                 name=get_testing_name()
#             )
#
#         # Assert ck.aws.CloudknotInputError on invalid job_queue
#         with pytest.raises(ck.aws.CloudknotInputError):
#             ck.aws.BatchJob(
#                 name=get_testing_name(),
#                 input_=42,
#                 job_queue=42
#             )
#
#         # Assert ck.aws.CloudknotInputError on invalid job_definition
#         with pytest.raises(ck.aws.CloudknotInputError):
#             ck.aws.BatchJob(
#                 name=get_testing_name(),
#                 input_=42,
#                 job_queue=job_queue,
#                 job_definition=42
#             )
#
#         # Assert ck.aws.CloudknotInputError on invalid environment variable
#         with pytest.raises(ck.aws.CloudknotInputError):
#             ck.aws.BatchJob(
#                 name=get_testing_name(),
#                 input_=42,
#                 job_queue=job_queue,
#                 job_definition=job_def,
#                 environment_variables=[42]
#             )
#
#         job_queue.clobber()
#         compute_environment.clobber()
#         job_def.clobber()
#     except Exception as e:
#         if job_queue:
#             job_queue.clobber()
#
#         if compute_environment:
#             compute_environment.clobber()
#
#         if job_def:
#             job_def.clobber()
#
#         raise e
