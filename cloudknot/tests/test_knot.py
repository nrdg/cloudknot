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
    ck.set_s3_params(bucket='cloudknot-travis-build-45814031-351c-'
                            '4b27-9a40-672c971f7e83')
    yield None
    s3_params = ck.get_s3_params()
    bucket = s3_params.bucket
    bucket_policy = s3_params.policy

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

        with pytest.raises(ck.aws.CloudknotInputError):
            knot = ck.Knot(
                name=get_testing_name(),
                func=unit_testing_func,
                job_definition_name=jd.name,
                job_def_vcpus=42
            )

        with pytest.raises(ck.aws.CloudknotInputError):
            knot = ck.Knot(
                name=get_testing_name(),
                func=unit_testing_func,
                compute_environment_name=ce.name,
                desired_vcpus=42
            )

        with pytest.raises(ck.aws.CloudknotInputError):
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
    # Assert ck.aws.CloudknotInputError on invalid name
    with pytest.raises(ck.aws.CloudknotInputError):
        ck.Knot(name=42)

    # Assert ck.aws.CloudknotInputError on invalid pars input
    with pytest.raises(ck.aws.CloudknotInputError):
        ck.Knot(func=unit_testing_func, pars=42)
