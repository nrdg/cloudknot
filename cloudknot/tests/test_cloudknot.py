from __future__ import absolute_import, division, print_function

import cloudknot as ck
import configparser
import os.path as op
import pytest
import uuid

UNIT_TEST_PREFIX = 'cloudknot-unit-test'
data_path = op.join(ck.__path__[0], 'data')


def get_testing_name():
    u = str(uuid.uuid4()).replace('-', '')[:8]
    name = UNIT_TEST_PREFIX + '-' + u
    return name


def test_Pars():
    config = configparser.ConfigParser()
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
            security_group_id=p.security_group.security_group_id
        )

        assert p.batch_service_role.name == pre + 'batch-service-role'
        assert p.ecs_instance_role.name == pre + 'ecs-instance-role'
        assert p.spot_fleet_role.name == pre + 'spot-fleet-role'
        assert p.vpc.name == pre + 'vpc'
        assert p.security_group.name == pre + 'security-group'

        # Do that last part over again but specify VPC and security group
        # names instead of IDs
        # Remove the section from config file
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
            security_group_name=p.security_group.name
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
        config.clear()
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
        config.clear()
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
        config.clear()
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
        config.clear()
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
        config.clear()
        config.read(config_file)
        assert config.get(p.pars_name, 'vpc') == vpc.vpc_id

        p.clobber()

        config.clear()
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
