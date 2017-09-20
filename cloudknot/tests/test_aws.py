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


def test_IamRole():
    # Use boto3 to create a role
    iam = boto3.client('iam')
    config = configparser.ConfigParser()
    config_file = ck.config.get_config_file()

    try:
        name = 'cloudknot-unit-test-' + str(uuid.uuid4())
        role_policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {
                        "Service": "batch.amazonaws.com"
                    },
                    "Action": "sts:AssumeRole"
                }
            ]
        }
        description = 'Role for unit testing of cloudknot.aws.IamRole().'
        policy = {
            'name': 'AWSLambdaRole',
            'arn': 'arn:aws:iam::aws:policy/service-role/AWSLambdaRole'
        }

        response = iam.create_role(
            RoleName=name,
            AssumeRolePolicyDocument=json.dumps(role_policy),
            Description=description
        )
        arn = response.get('Role')['Arn']

        iam.attach_role_policy(
            PolicyArn=policy['arn'],
            RoleName=name
        )

        # Create a IamRole with same name and different properties.
        # Confirm that IamRole raises a ResourceExistsException.
        with pytest.raises(ck.aws.ResourceExistsException) as e:
            ck.aws.IamRole(name=name, service='ec2')

        assert e.value.resource_id == name

        # Then create an IamRole with only that name or ARN to have cloudknot
        # retrieve that role.
        role = ck.aws.IamRole(name=name)

        # Confirm that the instance has the right properties.
        assert role.service is None
        assert role.description == description
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
        # Confirm that they were removed from the config file
        # If we just re-read the config file, config will keep the union
        # of the in memory values and the file values, updating the
        # intersection of the two with the file values. So we must set
        # config to None and then re-read the file
        config = None
        config = configparser.ConfigParser()
        config.read(config_file)
        assert name not in config.options('roles')

        # Create two roles, one with an instance profile and one without.
        names = ['cloudknot-unit-test-' + str(uuid.uuid4()) for i in range(2)]
        descriptions = [
            'Role #{i:d} for unit testing of cloudknot.aws.'
            'IamRole()'.format(i=i) for i in range(2)
        ]
        services = ['ec2', 'ecs-tasks']
        policy_set = ['AmazonS3FullAccess', 'AWSLambdaExecute']
        instance_profile_flags = [True, False]
        role = [None, None]

        for idx, (n, d, s, p, i) in enumerate(zip(
            names, descriptions, services, policy_set, instance_profile_flags
        )):
            role[idx] = ck.aws.IamRole(name=n, description=d, service=s,
                                       policies=p, add_instance_profile=i)

            # Use boto3 to confirm their existence and properties
            assert role[idx].name == n
            assert role[idx].description == d
            assert role[idx].service == s + '.amazonaws.com'
            assert role[idx].policies == (p,)
            assert role[idx].add_instance_profile == i

            # Confirm that they exist in the config file
            config.read(config_file)
            assert n in config.options('roles')

            # Clobber roles and use boto3 to confirm that they don't exist
            role[idx].clobber()
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

    except Exception as e:
        # Clean up roles from AWS
        # Find all unit test roles
        response = iam.list_roles()
        role_names = [d['RoleName'] for d in response.get('Roles')]
        unit_test_roles = filter(
            lambda n: 'cloudknot-unit-test' in n,
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
            if 'cloudknot-unit-test' in role_name:
                config.remove_option('roles', role_name)
        with open(config_file, 'w') as f:
            config.write(f)

        # Pass the exception through
        raise e


def test_Vpc():
    pass


def test_SecurityGroup():
    pass


def test_JobDefinition():
    pass


def test_JobQueue():
    pass


def test_ComputeEnvironment():
    pass


def test_BatchJob():
    pass


def test_DockerImage():
    pass
