from __future__ import absolute_import, division, print_function

import cloudknot as ck
import configparser
import os.path as op
import pytest
import uuid


UNIT_TEST_PREFIX = 'ck-unit-test'
data_path = op.join(ck.__path__[0], 'data')


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


def test_knot(cleanup_repos):
    config_file = ck.config.get_config_file()
    knot = None

    try:
        pars = ck.Pars(name=get_testing_name(), use_default_vpc=False)
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
        func_name = unit_testing_func.__name__.replace('_', '-')
        assert knot.docker_image.name == func_name
        assert knot.docker_repo.name == 'cloudknot'
        pre = name + '-cloudknot-'
        assert knot.job_definition.name == pre + 'job-definition'

        # Delete the stack using boto3 to check for an error from Pars
        # on reinstantiation
        ck.aws.clients['cloudformation'].delete_stack(
            StackName=knot.stack_id
        )

        waiter = ck.aws.clients['cloudformation'].get_waiter(
            'stack_delete_complete'
        )
        waiter.wait(StackName=knot.stack_id, WaiterConfig={'Delay': 10})

        # Confirm error on retrieving the deleted stack
        with pytest.raises(ck.aws.ResourceDoesNotExistException) as e:
            ck.Knot(name=name)

        assert e.value.resource_id == knot.stack_id

        # Confirm that the previous error deleted
        # the stack from the config file
        config_file = ck.config.get_config_file()
        config = configparser.ConfigParser()
        with ck.config.rlock:
            config.read(config_file)
            assert knot.knot_name not in config.sections()

        name = get_testing_name()
        knot = ck.Knot(name=name, func=unit_testing_func)
        knot.clobber(clobber_pars=True, clobber_image=True, clobber_repo=True)
        assert knot.clobbered

        # Clobbering twice shouldn't be a problem
        knot.clobber()

        response = ck.aws.clients['cloudformation'].describe_stacks(
            StackName=knot.stack_id
        )

        status = response.get('Stacks')[0]['StackStatus']
        assert status in ['DELETE_IN_PROGRESS', 'DELETE_COMPLETE']

        waiter = ck.aws.clients['cloudformation'].get_waiter(
            'stack_delete_complete'
        )
        waiter.wait(StackName=knot.stack_id, WaiterConfig={'Delay': 10})

        # Confirm that clobber deleted the stack from the config file
        config_file = ck.config.get_config_file()
        config = configparser.ConfigParser()
        with ck.config.rlock:
            config.read(config_file)
            assert knot.knot_name not in config.sections()

    except Exception as e:
        try:
            if knot:
                knot.clobber(
                    clobber_pars=True,
                    clobber_image=True,
                    clobber_repo=True
                )
        except Exception:
            pass

        raise e


def test_knot_errors(cleanup_repos):
    # Test Exceptions on invalid input
    # --------------------------------
    # Assert ck.aws.CloudknotInputError on invalid name
    with pytest.raises(ck.aws.CloudknotInputError):
        ck.Knot(name=42)

    # Assert ck.aws.CloudknotInputError on invalid pars input
    with pytest.raises(ck.aws.CloudknotInputError):
        ck.Knot(func=unit_testing_func, pars=42)

    # Assert ck.aws.CloudknotInputError on redundant docker_image and func
    with pytest.raises(ck.aws.CloudknotInputError):
        ck.Knot(func=unit_testing_func, docker_image=42)

    # Assert ck.aws.CloudknotInputError on invalid docker_image input
    with pytest.raises(ck.aws.CloudknotInputError):
        ck.Knot(docker_image=42)

    # Assert ck.aws.CloudknotInputError on invalid retries
    with pytest.raises(ck.aws.CloudknotInputError):
        ck.Knot(retries=0)

    # Assert ck.aws.CloudknotInputError on invalid retries
    with pytest.raises(ck.aws.CloudknotInputError):
        ck.Knot(retries=11)

    # Assert ck.aws.CloudknotInputError on invalid memory
    with pytest.raises(ck.aws.CloudknotInputError):
        ck.Knot(memory=0)

    # Assert ck.aws.CloudknotInputError on invalid job_def_vcpus
    with pytest.raises(ck.aws.CloudknotInputError):
        ck.Knot(job_def_vcpus=-42)

    # Assert ck.aws.CloudknotInputError on invalid priority
    with pytest.raises(ck.aws.CloudknotInputError):
        ck.Knot(priority=-42)

    # Assert ck.aws.CloudknotInputError on SPOT without bid percentage
    with pytest.raises(ck.aws.CloudknotInputError):
        ck.Knot(resource_type='SPOT')

    # Assert ck.aws.CloudknotInputError on invalid min_vcpus
    with pytest.raises(ck.aws.CloudknotInputError):
        ck.Knot(min_vcpus=-1)

    # Assert ck.aws.CloudknotInputError on invalid desired_vcpus
    with pytest.raises(ck.aws.CloudknotInputError):
        ck.Knot(desired_vcpus=-1)

    # Assert ck.aws.CloudknotInputError on invalid max_vcpus
    with pytest.raises(ck.aws.CloudknotInputError):
        ck.Knot(max_vcpus=-1)

    # Assert ck.aws.CloudknotInputError on invalid instance_types
    with pytest.raises(ck.aws.CloudknotInputError):
        ck.Knot(instance_types=[42])

    # Assert ck.aws.CloudknotInputError on invalid instance_types
    with pytest.raises(ck.aws.CloudknotInputError):
        ck.Knot(instance_types='not a valid instance')

    # Assert ck.aws.CloudknotInputError on invalid instance_types
    with pytest.raises(ck.aws.CloudknotInputError):
        ck.Knot(instance_types=['not', 'a', 'valid', 'instance'])

    # Assert ck.aws.CloudknotInputError on invalid image_id
    with pytest.raises(ck.aws.CloudknotInputError):
        ck.Knot(image_id=42)

    # Assert ck.aws.CloudknotInputError on invalid ec2_key_pair
    with pytest.raises(ck.aws.CloudknotInputError):
        ck.Knot(ec2_key_pair=42)
