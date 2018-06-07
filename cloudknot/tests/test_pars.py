from __future__ import absolute_import, division, print_function

import cloudknot as ck
import configparser
import os.path as op
import pytest
import tenacity
import uuid

from moto import mock_cloudformation, mock_ec2, mock_iam, mock_sts, mock_s3

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
def cleanup():
    """Use this fixture to delete all unit testing resources
    regardless of of the failure or success of the test"""
    yield None
    response = ck.aws.clients['cloudformation'].list_stacks(
        StackStatusFilter=[
            'CREATE_IN_PROGRESS',
            'CREATE_FAILED',
            'CREATE_COMPLETE',
            'ROLLBACK_IN_PROGRESS',
            'ROLLBACK_FAILED',
            'ROLLBACK_COMPLETE',
            'DELETE_FAILED',
            'UPDATE_IN_PROGRESS',
            'UPDATE_COMPLETE_CLEANUP_IN_PROGRESS',
            'UPDATE_COMPLETE',
            'UPDATE_ROLLBACK_IN_PROGRESS',
            'UPDATE_ROLLBACK_FAILED',
            'UPDATE_ROLLBACK_COMPLETE_CLEANUP_IN_PROGRESS',
            'UPDATE_ROLLBACK_COMPLETE',
            'REVIEW_IN_PROGRESS',
        ]
    )

    stacks = response.get('StackSummaries')
    for stack in stacks:
        ck.aws.clients['cloudformation'].delete_stack(
            StackName=stack['StackId']
        )

    # Clean up config file
    config_file = ck.config.get_config_file()
    config = configparser.ConfigParser()
    with ck.config.rlock:
        config.read(config_file)
        for section in config:
            if UNIT_TEST_PREFIX in section:
                config.remove_section(section)

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


def test_pars_errors(cleanup):
    name = get_testing_name()

    # Confirm name input validation
    with pytest.raises(ck.aws.CloudknotInputError):
        ck.Pars(name=42)

    # Confirm batch_service_role_name input validation
    with pytest.raises(ck.aws.CloudknotInputError):
        ck.Pars(name=name, batch_service_role_name=42)

    # Confirm error on redundant VPC input
    with pytest.raises(ck.aws.CloudknotInputError):
        ck.Pars(name=name, ipv4_cidr='172.31.0.0/16')

    # Confirm error on invalid VPC CIDR
    with pytest.raises(ck.aws.CloudknotInputError):
        ck.Pars(name=name, use_default_vpc=False, ipv4_cidr=42)

    # Confirm error on invalid VPC instance tenancy
    with pytest.raises(ck.aws.CloudknotInputError):
        ck.Pars(name=name, use_default_vpc=False, instance_tenancy=42)


def test_pars_with_default_vpc(cleanup):
    pass


def test_pars_with_new_vpc(cleanup):
    name = get_testing_name()

    p = ck.Pars(name=name, use_default_vpc=False)

    response = ck.aws.clients['cloudformation'].describe_stacks(
        StackName=name + '-pars',
    )
    stack_id = response.get('Stacks')[0]['StackId']
    assert stack_id == p.stack_id

    response = ck.aws.clients['iam'].get_role(
        RoleName=name + '-batch-service-role'
    )
    bsr_arn = response.get('Role')['Arn']
    assert bsr_arn == p.batch_service_role

    response = ck.aws.clients['iam'].get_role(
        RoleName=name + '-ecs-instance-role'
    )
    ecs_arn = response.get('Role')['Arn']
    assert ecs_arn == p.ecs_instance_role

    response = ck.aws.clients['iam'].get_role(
        RoleName=name + '-spot-fleet-role'
    )
    sfr_arn = response.get('Role')['Arn']
    assert sfr_arn == p.spot_fleet_role

    response = ck.aws.clients['iam'].list_instance_profiles_for_role(
        RoleName=name + '-ecs-instance-role',
    )
    ecs_profile_arn = response.get('InstanceProfiles')[0]['Arn']
    assert ecs_profile_arn == p.ecs_instance_profile

    # Check for a VPC with the tag "Name: name"
    response = ck.aws.clients['ec2'].describe_tags(
        Filters=[
            {'Name': 'resource-type', 'Values': ['vpc']},
            {'Name': 'key', 'Values': ['Name']},
            {'Name': 'value', 'Values': [p.name]}
        ]
    )

    vpc_id = response.get('Tags')[0]['ResourceId']
    assert vpc_id == p.vpc

    response = ck.aws.clients['ec2'].describe_subnets(Filters=[{
        'Name': 'vpc-id',
        'Values': [vpc_id]
    }])

    subnet_ids = [d['SubnetId'] for d in response.get('Subnets')]
    assert set(subnet_ids) == set(p.subnets)

    response = ck.aws.clients['ec2'].describe_security_groups(
        Filters=[{'Name': 'vpc-id', 'Values': [vpc_id]},
                 {'Name': 'tag-key', 'Values': ['Name']},
                 {'Name': 'tag-value', 'Values': [p.name]}]
    )

    sg_id = response.get('SecurityGroups')[0]['GroupId']
    assert sg_id == p.security_group

    # Now, confirm input validation for pre-existing PARS
    with pytest.raises(ck.aws.CloudknotInputError):
        ck.Pars(name=name, batch_service_role_name='error-test')

    p = ck.Pars(name=name)

    assert stack_id == p.stack_id
    assert bsr_arn == p.batch_service_role
    assert ecs_arn == p.ecs_instance_role
    assert sfr_arn == p.spot_fleet_role
    assert ecs_profile_arn == p.ecs_instance_profile
    assert vpc_id == p.vpc
    assert set(subnet_ids) == set(p.subnets)
    assert sg_id == p.security_group

    p.clobber()

    response = ck.aws.clients['cloudformation'].describe_stacks(
        StackName=stack_id
    )

    status = response.get('Stacks')[0]['StackStatus']
    assert status in ['DELETE_IN_PROGRESS', 'DELETE_COMPLETE']
