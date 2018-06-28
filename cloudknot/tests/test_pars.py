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
        sections = list(config.sections())
        for section in sections:
            if UNIT_TEST_PREFIX in section:
                config.remove_section(section)

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
    name = get_testing_name()

    batch_service_role_name = 'ck-unit-test-batch-service-role'
    ecs_instance_role_name = 'ck-unit-test-ecs-instance-role'
    spot_fleet_role_name = 'ck-unit-test-spot-fleet-role'

    try:
        p = ck.Pars(name=name,
                    batch_service_role_name=batch_service_role_name,
                    ecs_instance_role_name=ecs_instance_role_name,
                    spot_fleet_role_name=spot_fleet_role_name)

        response = ck.aws.clients['cloudformation'].describe_stacks(
            StackName=name + '-pars',
        )
        stack_id = response.get('Stacks')[0]['StackId']
        assert stack_id == p.stack_id

        response = ck.aws.clients['iam'].get_role(
            RoleName=batch_service_role_name
        )
        bsr_arn = response.get('Role')['Arn']
        assert bsr_arn == p.batch_service_role

        response = ck.aws.clients['iam'].get_role(
            RoleName=ecs_instance_role_name
        )
        ecs_arn = response.get('Role')['Arn']
        assert ecs_arn == p.ecs_instance_role

        response = ck.aws.clients['iam'].get_role(
            RoleName=spot_fleet_role_name
        )
        sfr_arn = response.get('Role')['Arn']
        assert sfr_arn == p.spot_fleet_role

        response = ck.aws.clients['iam'].list_instance_profiles_for_role(
            RoleName=ecs_instance_role_name
        )
        ecs_profile_arn = response.get('InstanceProfiles')[0]['Arn']
        assert ecs_profile_arn == p.ecs_instance_profile

        # Check for a default VPC
        response = ck.aws.clients['ec2'].describe_vpcs(
            Filters=[{'Name': 'isDefault', 'Values': ['true']}]
        )

        vpc_id = response.get('Vpcs')[0]['VpcId']
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

        # Delete the stack using boto3 to check for an error from Pars
        # on reinstantiation
        ck.aws.clients['cloudformation'].delete_stack(
            StackName=p.stack_id
        )

        waiter = ck.aws.clients['cloudformation'].get_waiter(
            'stack_delete_complete'
        )
        waiter.wait(StackName=p.stack_id, WaiterConfig={'Delay': 10})

        # Confirm error on retrieving the deleted stack
        with pytest.raises(ck.aws.ResourceDoesNotExistException) as e:
            ck.Pars(name=name)

        assert e.value.resource_id == p.stack_id

        # Confirm that the previous error deleted
        # the stack from the config file
        config_file = ck.config.get_config_file()
        config = configparser.ConfigParser()
        with ck.config.rlock:
            config.read(config_file)
            assert p.pars_name not in config.sections()
    except ck.aws.CannotCreateResourceException:
        # Cannot create a default VPC in this account
        # Ignore test
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
    assert p.clobbered

    # Clobbering twice shouldn't be a problem
    p.clobber()

    response = ck.aws.clients['cloudformation'].describe_stacks(
        StackName=stack_id
    )

    status = response.get('Stacks')[0]['StackStatus']
    assert status in ['DELETE_IN_PROGRESS', 'DELETE_COMPLETE']

    waiter = ck.aws.clients['cloudformation'].get_waiter(
        'stack_delete_complete'
    )
    waiter.wait(StackName=stack_id, WaiterConfig={'Delay': 10})

    # Confirm that clobber deleted the stack from the config file
    config_file = ck.config.get_config_file()
    config = configparser.ConfigParser()
    with ck.config.rlock:
        config.read(config_file)
        assert p.pars_name not in config.sections()

    name = get_testing_name()
    instance_tenancy = 'dedicated'
    cidr = '172.32.0.0/16'
    p = ck.Pars(name=name,
                use_default_vpc=False,
                ipv4_cidr=cidr,
                instance_tenancy=instance_tenancy)

    response = ck.aws.clients['ec2'].describe_vpcs(VpcIds=[p.vpc])
    assert instance_tenancy == response.get('Vpcs')[0]['InstanceTenancy']
    assert cidr == response.get('Vpcs')[0]['CidrBlock']

    ck.aws.clients['cloudformation'].delete_stack(
        StackName=p.stack_id
    )

    # Change the stack-id in the config file to get an error
    config_file = ck.config.get_config_file()
    config = configparser.ConfigParser()
    with ck.config.rlock:
        config.read(config_file)
        stack_id = config.get(p.pars_name, 'stack-id')
        stack_id = stack_id.split('/')
        stack_id[1] = get_testing_name()
        stack_id = '/'.join(stack_id)
        config.set(p.pars_name, 'stack-id', stack_id)
        with open(config_file, 'w') as f:
            config.write(f)

    # Confirm error on retrieving the nonexistent stack
    with pytest.raises(ck.aws.ResourceDoesNotExistException) as e:
        ck.Pars(name=name)

    assert e.value.resource_id == stack_id

    # Confirm that the previous error deleted the stack from the config file
    config_file = ck.config.get_config_file()
    config = configparser.ConfigParser()
    with ck.config.rlock:
        config.read(config_file)
        assert p.pars_name not in config.sections()
