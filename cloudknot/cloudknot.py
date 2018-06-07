from __future__ import absolute_import, division, print_function

import configparser
import ipaddress
import json
import logging
import os
import six
from collections import Iterable
from concurrent.futures import ThreadPoolExecutor

from . import aws
from .config import get_config_file, rlock
from . import dockerimage

__all__ = ["Pars", "Knot"]

mod_logger = logging.getLogger(__name__)


# noinspection PyPropertyAccess,PyAttributeOutsideInit
class Pars(aws.NamedObject):
    """PARS stands for Persistent AWS Resource Set

    This object collects AWS resources that could, in theory, be created only
    once for each cloudknot user and used for all of their subsequent AWS
    batch jobs. This set consists of IAM roles, a VPC with subnets for each
    availability zone, and a security group.
    """
    def __init__(self, name='default',
                 batch_service_role_name=None, ecs_instance_role_name=None,
                 spot_fleet_role_name=None,
                 policies=(), use_default_vpc=True,
                 ipv4_cidr=None, instance_tenancy=None):
        """Initialize a PARS instance.

        Parameters
        ----------
        name : str
            The name of this PARS. If `pars name` exists in the config file,
            Pars will retrieve those PARS resource parameters. Otherwise,
            Pars will create a new PARS with this name.
            Default: 'default'

        batch_service_role_name : str
            Name of this PARS' batch service IAM role. If the role already
            exists, Pars will adopt it. Otherwise, it will create it.
            Default: name + '-cloudknot-batch-service-role'

        ecs_instance_role_name : str
            Name of this PARS' ECS instance IAM role. If the role already
            exists, Pars will adopt it. Otherwise, it will create it.
            Default: name + '-cloudknot-ecs-instance-role'

        spot_fleet_role_name : str
            Name of this PARS' spot fleet IAM role. If the role already
            exists, Pars will adopt it. Otherwise, it will create it.
            Default: name + '-cloudknot-spot-fleet-role'

        policies : tuple of strings
            tuple of names of AWS policy ARNs to attach to each role
            Default: ()

        use_default_vpc : bool
            if True, create or retrieve the default VPC
            if False, use other input args to create a non-default VPC

        ipv4_cidr : string
            IPv4 CIDR block to be used for creation of a new VPC

        instance_tenancy : string
            Instance tenancy for this VPC, one of ['default', 'dedicated']
            Default: 'default'
        """
        # Validate name input
        if not isinstance(name, six.string_types):
            raise aws.CloudknotInputError(
                'PARS name must be a string. You passed a '
                '{t!s}'.format(t=type(name))
            )

        super(Pars, self).__init__(name=name)

        # Check for existence of this pars in the config file
        config = configparser.ConfigParser()
        with rlock:
            config.read(get_config_file())

        def stack_out(key, outputs):
            o = list(filter(lambda d: d['OutputKey'] == key, outputs))[0]
            return o['OutputValue']

        self._pars_name = 'pars ' + self.name
        if self._pars_name in config.sections():
            self._region = config.get(self._pars_name, 'region')
            self._profile = config.get(self._pars_name, 'profile')
            self.check_profile_and_region()

            # Pars exists, check that user did not provide any resource names
            if any([batch_service_role_name, ecs_instance_role_name,
                    spot_fleet_role_name, ipv4_cidr, instance_tenancy,
                    policies]):
                raise aws.CloudknotInputError(
                    'You provided resources for a pars that already exists in '
                    'configuration file {fn:s}.'.format(fn=get_config_file())
                )

            mod_logger.info('Found PARS {name:s} in config'.format(name=name))

            self._stack_id = config.get(self._pars_name, 'stack-id')

            try:
                response = aws.clients['cloudformation'].describe_stacks(
                    StackName=self._stack_id
                )
            except aws.clients['cloudformation'].exceptions.ClientError as e:
                error_code = e.response.get('Error').get('Message')
                no_stack_code = ('Stack with id {0:s} does not exist'
                                 ''.format(self._stack_id))
                if error_code == no_stack_code:
                    # Remove this section from the config file
                    with rlock:
                        config.read(get_config_file())
                        config.remove_section(self._pars_name)
                        with open(get_config_file(), 'w') as f:
                            config.write(f)
                    raise aws.ResourceDoesNotExistException(
                        'The PARS stack that you requested does not exist. '
                        'Cloudknot has deleted this PARS from the config '
                        'file, so you may be able to create a new one simply '
                        'by re-running your previous command.',
                        self._stack_id
                    )
                else:
                    raise e

            no_stack = (
                len(response.get('Stacks')) == 0 or
                response.get('Stacks')[0]['StackStatus'] in [
                    'CREATE_FAILED', 'ROLLBACK_COMPLETE',
                    'ROLLBACK_IN_PROGRESS', 'ROLLBACK_FAILED',
                    'DELETE_IN_PROGRESS', 'DELETE_FAILED', 'DELETE_COMPLETE',
                    'UPDATE_ROLLBACK_FAILED',
                ]
            )

            if no_stack:
                # Remove this section from the config file
                with rlock:
                    config.read(get_config_file())
                    config.remove_section(self._pars_name)
                    with open(get_config_file(), 'w') as f:
                        config.write(f)

                raise aws.ResourceDoesNotExistException(
                    'The PARS stack that you requested does not exist. '
                    'Cloudknot has deleted this PARS from the config file, '
                    'so you may be able to create a new one simply by '
                    're-running your previous command.',
                    self._stack_id
                )

            outs = response.get('Stacks')[0]['Outputs']

            self._batch_service_role = stack_out('BatchServiceRole', outs)
            self._ecs_instance_role = stack_out('EcsInstanceRole', outs)
            self._spot_fleet_role = stack_out('SpotFleetRole', outs)
            self._ecs_instance_profile = stack_out('InstanceProfile', outs)
            self._vpc = stack_out('VpcId', outs)
            self._subnets = stack_out('SubnetIds', outs).split(',')
            self._security_group = stack_out('SecurityGroupId', outs)

            conf_bsr = config.get(self._pars_name, 'batch-service-role')
            conf_sfr = config.get(self._pars_name, 'spot-fleet-role')
            conf_ecsr = config.get(self._pars_name, 'ecs-instance-role')
            conf_ecsp = config.get(self._pars_name, 'ecs-instance-profile')
            conf_vpc = config.get(self._pars_name, 'vpc')
            conf_subnets = config.get(self._pars_name, 'subnets')
            conf_sg = config.get(self._pars_name, 'security-group')

            if not all([
                self._batch_service_role == conf_bsr,
                self._ecs_instance_role == conf_ecsr,
                self._ecs_instance_profile == conf_ecsp,
                self._spot_fleet_role == conf_sfr,
                self._vpc == conf_vpc,
                ','.join(self._subnets) == conf_subnets,
                self._security_group == conf_sg
            ]):
                raise aws.CloudknotConfigurationError(
                    'The resources in the CloudFormation stack do not match '
                    'the resources in the cloudknot configuration file. '
                    'Please try a different name.'
                )
        else:
            # Pars doesn't exist, use input to create resources
            def validated_name(role_name, fallback_suffix):
                # Validate role name input
                if role_name:
                    if not isinstance(role_name, six.string_types):
                        raise aws.CloudknotInputError(
                            'if provided, role names must be strings.'
                        )
                else:
                    role_name = (
                        name + '-' + fallback_suffix
                    )

                return role_name

            batch_service_role_name = validated_name(batch_service_role_name,
                                                     'batch-service-role')
            ecs_instance_role_name = validated_name(ecs_instance_role_name,
                                                    'ecs-instance-role')
            spot_fleet_role_name = validated_name(spot_fleet_role_name,
                                                  'spot-fleet-role')

            if use_default_vpc:
                if any([ipv4_cidr, instance_tenancy]):
                    raise aws.CloudknotInputError(
                        'if using the default VPC, you cannot specify '
                        '`ipv4_cidr` or `instance_tenancy`.'
                    )

                # Retrieve the default VPC ID
                try:
                    response = aws.clients['ec2'].create_default_vpc()
                    vpc_id = response.get('Vpc').get('VpcId')
                except aws.clients['ec2'].exceptions.ClientError as e:
                    error_code = e.response.get('Error').get('Code')
                    if error_code == 'DefaultVpcAlreadyExists':
                        response = aws.clients['ec2'].describe_vpcs(Filters=[{
                            'Name': 'isDefault',
                            'Values': ['true']
                        }])
                        vpc_id = response.get('Vpcs')[0].get('VpcId')
                    elif error_code == 'UnauthorizedOperation':
                        raise aws.CannotCreateResourceException(
                            'Cannot create a default VPC because this is an '
                            'unauthorized operation. You may not have the '
                            'proper permissions to create a default VPC.'
                        )
                    elif error_code == 'OperationNotPermitted':
                        raise aws.CannotCreateResourceException(
                            'Cannot create a default VPC because this is an '
                            'unauthorized operation. You might have resources '
                            'in EC2-Classic in the current region.'
                        )
                    else:
                        raise e

                # Retrieve the subnets for the default VPC
                response = aws.clients['ec2'].describe_subnets(Filters=[{
                    'Name': 'vpc-id',
                    'Values': [vpc_id]
                }])

                subnet_ids = [d['SubnetId'] for d in response.get('Subnets')]

                template_path = os.path.abspath(os.path.join(
                    os.path.dirname(__file__),
                    'templates',
                    'pars-with-default-vpc.template'
                ))

                with open(template_path, 'r') as fp:
                    template_body = json.dumps(json.load(fp))

                s3_params = aws.get_s3_params()
                policy_list = [s3_params.policy_arn] + [
                    policy for policy in policies
                ]
                policies = ','.join(policy_list)

                response = aws.clients['cloudformation'].create_stack(
                    StackName=self.name + '-pars',
                    TemplateBody=template_body,
                    Parameters=[
                        {
                            'ParameterKey': 'BatchServiceRoleName',
                            'ParameterValue': batch_service_role_name
                        },
                        {
                            'ParameterKey': 'EcsInstanceRoleName',
                            'ParameterValue': ecs_instance_role_name
                        },
                        {
                            'ParameterKey': 'SpotFleetRoleName',
                            'ParameterValue': spot_fleet_role_name
                        },
                        {
                            'ParameterKey': 'IamPolicies',
                            'ParameterValue': policies
                        },
                        {
                            'ParameterKey': 'VpcId',
                            'ParameterValue': vpc_id
                        },
                        {
                            'ParameterKey': 'Subnets',
                            'ParameterValue': ','.join(subnet_ids)
                        },
                    ],
                    Capabilities=['CAPABILITY_NAMED_IAM'],
                    Tags=[
                        {
                            'Key': 'Name',
                            'Value': self.name,
                        },
                        {
                            'Key': 'Owner',
                            'Value': aws.get_user(),
                        },
                        {
                            'Key': 'Environment',
                            'Value': 'cloudknot',
                        },
                    ]
                )

                self._stack_id = response['StackId']

                waiter = aws.clients['cloudformation'].get_waiter(
                    'stack_create_complete'
                )
                waiter.wait(StackName=self._stack_id,
                            WaiterConfig={'Delay': 10})

                response = aws.clients['cloudformation'].describe_stacks(
                    StackName=self._stack_id
                )

                outs = response.get('Stacks')[0]['Outputs']

                self._batch_service_role = stack_out('BatchServiceRole', outs)
                self._ecs_instance_role = stack_out('EcsInstanceRole', outs)
                self._spot_fleet_role = stack_out('SpotFleetRole', outs)
                self._ecs_instance_profile = stack_out('InstanceProfile', outs)
                self._vpc = stack_out('VpcId', outs)
                self._subnets = stack_out('SubnetIds', outs).split(',')
                self._security_group = stack_out('SecurityGroupId', outs)
            else:
                # Check that ipv4 is a valid network range or set default value
                if ipv4_cidr:
                    try:
                        ipv4_cidr = str(ipaddress.IPv4Network(
                            six.text_type(ipv4_cidr)
                        ))
                    except (ipaddress.AddressValueError, ValueError):
                        raise aws.CloudknotInputError(
                            'If provided, ipv4_cidr must be a valid IPv4 '
                            'network range.'
                        )
                else:
                    ipv4_cidr = str(ipaddress.IPv4Network(u'172.31.0.0/16'))

                # Validate instance_tenancy input
                if instance_tenancy:
                    if instance_tenancy in ('default', 'dedicated'):
                        instance_tenancy = instance_tenancy
                    else:
                        raise aws.CloudknotInputError(
                            'If provided, instance tenancy must be '
                            'one of ("default", "dedicated").'
                        )
                else:
                    instance_tenancy = 'default'

                # Get subnet CIDR blocks
                # Get an IPv4Network instance representing the VPC CIDR block
                cidr = ipaddress.IPv4Network(six.text_type(ipv4_cidr))

                # Get list of subnet CIDR blocks
                subnet_ipv4_cidrs = list(cidr.subnets(new_prefix=20))

                if len(subnet_ipv4_cidrs) < 2:
                    raise aws.CloudknotInputError(
                        "If provided, ipv4_cidr must be large enough to "
                        "accomodate two subnets. If you don't know what this "
                        "means, try the default value or specify "
                        "`use_default_vpc=True`."
                    )

                subnet_ipv4_cidrs = subnet_ipv4_cidrs[:2]

                template_path = os.path.abspath(os.path.join(
                    os.path.dirname(__file__),
                    'templates',
                    'pars-with-new-vpc.template'
                ))

                with open(template_path, 'r') as fp:
                    template_body = json.dumps(json.load(fp))

                s3_params = aws.get_s3_params()
                policy_list = [s3_params.policy_arn] + [
                    policy for policy in policies
                ]
                policies = ','.join(policy_list)

                response = aws.clients['cloudformation'].create_stack(
                    StackName=self.name + '-pars',
                    TemplateBody=template_body,
                    Parameters=[
                        {
                            'ParameterKey': 'BatchServiceRoleName',
                            'ParameterValue': batch_service_role_name
                        },
                        {
                            'ParameterKey': 'EcsInstanceRoleName',
                            'ParameterValue': ecs_instance_role_name
                        },
                        {
                            'ParameterKey': 'SpotFleetRoleName',
                            'ParameterValue': spot_fleet_role_name
                        },
                        {
                            'ParameterKey': 'IamPolicies',
                            'ParameterValue': policies
                        },
                        {
                            'ParameterKey': 'VpcCidr',
                            'ParameterValue': ipv4_cidr
                        },
                        {
                            'ParameterKey': 'VpcInstanceTenancy',
                            'ParameterValue': instance_tenancy
                        },
                        {
                            'ParameterKey': 'Subnet1Cidr',
                            'ParameterValue': str(subnet_ipv4_cidrs[0])
                        },
                        {
                            'ParameterKey': 'Subnet2Cidr',
                            'ParameterValue': str(subnet_ipv4_cidrs[1])
                        },
                    ],
                    Capabilities=['CAPABILITY_NAMED_IAM'],
                    Tags=[
                        {
                            'Key': 'Name',
                            'Value': self.name,
                        },
                        {
                            'Key': 'Owner',
                            'Value': aws.get_user(),
                        },
                        {
                            'Key': 'Environment',
                            'Value': 'cloudknot',
                        },
                    ]
                )

                self._stack_id = response['StackId']

                waiter = aws.clients['cloudformation'].get_waiter(
                    'stack_create_complete'
                )
                waiter.wait(StackName=self._stack_id,
                            WaiterConfig={'Delay': 10})

                response = aws.clients['cloudformation'].describe_stacks(
                    StackName=self._stack_id
                )

                outs = response.get('Stacks')[0]['Outputs']

                self._batch_service_role = stack_out('BatchServiceRole', outs)
                self._ecs_instance_role = stack_out('EcsInstanceRole', outs)
                self._spot_fleet_role = stack_out('SpotFleetRole', outs)
                self._ecs_instance_profile = stack_out('InstanceProfile', outs)
                self._vpc = stack_out('VpcId', outs)
                self._subnets = stack_out('SubnetIds', outs).split(',')
                self._security_group = stack_out('SecurityGroupId', outs)

            # Save the new pars resources in config object
            # Use config.set() for python 2.7 compatibility
            with rlock:
                config.read(get_config_file())
                config.add_section(self._pars_name)
                config.set(self._pars_name, 'stack-id', self._stack_id)
                config.set(self._pars_name, 'region', self.region)
                config.set(self._pars_name, 'profile', self.profile)
                config.set(self._pars_name,
                           'batch-service-role', self._batch_service_role)
                config.set(self._pars_name,
                           'ecs-instance-role', self._ecs_instance_role)
                config.set(self._pars_name,
                           'spot-fleet-role', self._spot_fleet_role)
                config.set(self._pars_name,
                           'ecs-instance-profile', self._ecs_instance_profile)
                config.set(self._pars_name, 'vpc', self._vpc)
                config.set(self._pars_name, 'subnets', ','.join(self._subnets))
                config.set(self._pars_name,
                           'security-group', self._security_group)

                # Save config to file
                with open(get_config_file(), 'w') as f:
                    config.write(f)

    @property
    def pars_name(self):
        """The section name for this PARS in the cloudknot config file"""
        return self._pars_name

    @property
    def stack_id(self):
        """The Cloudformation Stack ID for this PARS"""
        return self._stack_id

    @property
    def batch_service_role(self):
        """The IAM batch service role associated with this PARS"""
        return self._batch_service_role

    @property
    def ecs_instance_role(self):
        """The IAM ECS instance role associated with this PARS"""
        return self._ecs_instance_role

    @property
    def ecs_instance_profile(self):
        """The IAM ECS instance profile associated with this PARS"""
        return self._ecs_instance_profile

    @property
    def spot_fleet_role(self):
        """The IAM spot fleet role associated with this PARS"""
        return self._spot_fleet_role

    @property
    def vpc(self):
        """The VPC ID attached to this PARS"""
        return self._vpc

    @property
    def subnets(self):
        """The VPC subnets for this PARS"""
        return self._subnets

    @property
    def security_group(self):
        """The security group ID attached to this PARS"""
        return self._security_group

    def clobber(self):
        """Delete associated AWS resources and remove section from config"""
        if self.clobbered:
            return

        self.check_profile_and_region()

        aws.clients['cloudformation'].delete_stack(StackName=self._stack_id)

        # Remove this section from the config file
        config = configparser.ConfigParser()

        with rlock:
            config.read(get_config_file())
            config.remove_section(self._pars_name)
            with open(get_config_file(), 'w') as f:
                config.write(f)

        # Set the clobbered parameter to True,
        # preventing subsequent method calls
        self._clobbered = True

        mod_logger.info('Clobbered PARS {name:s}'.format(name=self.name))


# noinspection PyPropertyAccess,PyAttributeOutsideInit
class Knot(aws.NamedObject):
    """A collection of resources and methods to submit jobs to AWS Batch

    This object collects AWS resources that should be created once for each
    type of batch run. The resource set consists of a PARS; a docker image
    made from an input function or python script; a remote docker repo to
    house said image; and an AWS batch job definition, compute environment,
    and job queue. It also contains methods to submit batch jobs for a range
    of arguments.
    """
    def __init__(self, name='default', pars=None, pars_policies=(),
                 docker_image=None, base_image=None,
                 func=None, image_script_path=None,
                 image_work_dir=None, image_github_installs=(),
                 username=None, repo_name=None,
                 image_tags=None, job_definition_name=None,
                 job_def_vcpus=None, memory=None,
                 retries=None, compute_environment_name=None,
                 instance_types=None, resource_type=None, min_vcpus=None,
                 max_vcpus=None, desired_vcpus=None, image_id=None,
                 ec2_key_pair=None, ce_tags=None, bid_percentage=None,
                 job_queue_name=None, priority=None):
        """Initialize a Knot instance

        Parameters
        ----------
        name : str, optional
            The name for this knot
            Default='default'

        pars : Pars, optional
            The PARS on which to base this knot's AWS resources
            Default: instance returned by Pars()

        pars_policies : tuple of strings
            tuple of names of AWS policies to attach to each role
            Default: ()

        docker_image : DockerImage, optional
            The pre-existing DockerImage instance to adopt. i.e.,
            you may construct your own Docker Image using
            ```
            d = cloudknot.DockerImage(*args)
            ```
            and then supply that docker image as a keyword arg using
            ```
            knot = cloudknot.Knot(..., docker_image=d)
            ```

        base_image : string
            Docker base image on which to base this Dockerfile.
            You may not specify both docker_image and base_image.
            Default: None will use the python base image for the
            current version of python

        func : function
            Python function to be dockerized

        image_script_path : str
            Path to file with python script to be dockerized

        image_work_dir : string
            Directory to store Dockerfile, requirements.txt, and python
            script with CLI
            Default: parent directory of script if `script_path` is provided
            else DockerImage creates a new directory, accessible by the
            `docker_image.build_path` property.

        image_github_installs : string or sequence of strings
            Github addresses for packages to install from github rather than
            PyPI (e.g. git://github.com/richford/cloudknot.git or
            git://github.com/richford/cloudknot.git@newfeaturebranch)
            Default: ()

        username : string
            default username created in Dockerfile and in batch job definition
            Default: 'cloudknot-user'

        repo_name : str, optional
            Name of the AWS ECR repository to store the created Docker image
            Default: return value of cloudknot.get_ecr_repo()

        image_tags : str or sequence of str
            Tags to be applied to this Docker image

        job_definition_name : str, optional
            Name for this knot's AWS Batch job definition
            Default: name + '-cloudknot-compute-environment'

        job_def_vcpus : int, optional
            number of virtual cpus to be used to this knot's job definition
            Default: 1

        memory : int, optional
            memory (MiB) to be used for this knot's job definition
            Default: 8000

        retries : int, optional
            number of times a job can be moved to 'RUNNABLE' status.
            May be between 1 and 10
            Default: 1

        compute_environment_name : str
            Name for this knot's AWS Batch compute environment
            Default: name + '-cloudknot-compute-environment'

        instance_types : string or sequence of strings, optional
            Compute environment instance types
            Default: ('optimal',)

        resource_type : 'EC2' or 'SPOT'
            Compute environment resource type, either "EC2" or "SPOT"
            Default: 'EC2'

        min_vcpus : int, optional
            minimum number of virtual cpus for instances launched in this
            compute environment
            Default: 0

        max_vcpus : int, optional
            maximum number of virtual cpus for instances launched in this
            compute environment
            Default: 256

        desired_vcpus : int, optional
            desired number of virtual cpus for instances launched in this
            compute environment
            Default: 8

        image_id : string or None, optional
            optional AMI id used for instances launched in this compute
            environment
            Default: None

        ec2_key_pair : string or None, optional
            optional EC2 key pair used for instances launched in this compute
            environment
            Default: None

        tags : dictionary or None, optional
            optional key-value pair tags to be applied to resources in this
            compute environment
            Default: None

        bid_percentage : int, optional
            Compute environment bid percentage if using spot instances
            Default: 50

        job_queue_name : str, optional
            Name for this knot's AWS Batch job queue
            Default: name + '-cloudknot-job-queue'

        priority : int, optional
            Default priority for jobs in this knot's job queue
            Default: 1
        """
        # Validate name input
        if not isinstance(name, six.string_types):
            raise aws.CloudknotInputError(
                'Knot name must be a string. You passed a '
                '{t!s}'.format(t=type(name))
            )

        super(Knot, self).__init__(name=name)
        self._knot_name = 'knot ' + name

        image_tags = image_tags if image_tags else [name]

        # Check for existence of this knot in the config file
        config = configparser.ConfigParser()

        with rlock:
            config.read(get_config_file())

        if self._knot_name in config.sections():
            if any([
                pars, pars_policies, docker_image, base_image, func,
                image_script_path, image_work_dir, username, repo_name,
                job_definition_name, job_def_vcpus, memory, retries,
                compute_environment_name, instance_types, resource_type,
                min_vcpus, max_vcpus, desired_vcpus, image_id, ec2_key_pair,
                ce_tags, bid_percentage, job_queue_name, priority
            ]):
                mod_logger.warning(
                    "You specified configuration arguments for a knot that "
                    "already exists. Cloudknot has returned the pre-existing "
                    "knot, ignoring all of your other input parameters, which "
                    "may or may not be the same. You should proceed with "
                    "caution and confirm that this knot's parameters are as "
                    "expected. If you want to be extra-safe, choose a "
                    "different name or clobber this pre-existing knot and "
                    "instantiate a new one with your input arguments."
                )

            mod_logger.info('Found knot {name:s} in config'.format(name=name))

            self._region = config.get(self._knot_name, 'region')
            self._profile = config.get(self._knot_name, 'profile')
            self.check_profile_and_region()

            pars_name = config.get(self._knot_name, 'pars')
            self._pars = Pars(name=pars_name)
            mod_logger.info('Knot {name:s} adopted PARS '
                            '{p:s}'.format(name=self.name, p=self.pars.name))

            image_name = config.get(self._knot_name, 'docker-image')
            self._docker_image = dockerimage.DockerImage(name=image_name)
            mod_logger.info('Knot {name:s} adopted docker image {dr:s}'
                            ''.format(name=self.name, dr=image_name))

            if not self.docker_image.images:
                self.docker_image.build(tags=image_tags)
                mod_logger.info(
                    'knot {name:s} built docker image {i!s}'
                    ''.format(name=self.name, i=self.docker_image.images)
                )

            if self.docker_image.repo_uri is None:
                repo_name = config.get(self._knot_name, 'docker-repo')
                self._docker_repo = aws.DockerRepo(name=repo_name)
                mod_logger.info('Knot {name:s} adopted docker repository '
                                '{dr:s}'.format(name=self.name, dr=repo_name))

                self.docker_image.push(repo=self.docker_repo)
                mod_logger.info(
                    'Knot {name:s} pushed docker image {dr:s}'
                    ''.format(name=self.name, dr=self.docker_image.name)
                )
            else:
                self._docker_repo = None

            jd_name = config.get(self._knot_name, 'job-definition')
            self._job_definition = aws.JobDefinition(name=jd_name)
            mod_logger.info('Knot {name:s} adopted job definition '
                            '{jd:s}'.format(name=self.name, jd=jd_name))

            ce_name = config.get(self._knot_name, 'compute-environment')
            self._compute_environment = aws.ComputeEnvironment(name=ce_name)
            mod_logger.info('Knot {name:s} adopted compute environment '
                            '{ce:s}'.format(name=self.name, ce=ce_name))

            jq_name = config.get(self._knot_name, 'job-queue')
            self._job_queue = aws.JobQueue(name=jq_name)
            mod_logger.info('Knot {name:s} adopted job queue {q:s}'.format(
                name=self.name, q=jq_name
            ))

            self._job_ids = config.get(self._knot_name, 'job_ids').split()
            self._jobs = [aws.BatchJob(job_id=jid) for jid in self.job_ids]
        else:
            job_definition_name = job_definition_name if job_definition_name \
                else name + '-cloudknot-job-definition'
            compute_environment_name = compute_environment_name \
                if compute_environment_name \
                else name + '-cloudknot-compute-environment'
            job_queue_name = job_queue_name if job_queue_name \
                else name + '-cloudknot-job-queue'

            if pars and not isinstance(pars, Pars):
                raise aws.CloudknotInputError('if provided, pars must be a '
                                              'Pars instance.')

            if docker_image and any([func, image_script_path, image_work_dir,
                                     base_image, image_github_installs]):
                raise aws.CloudknotInputError(
                    'you gave redundant, possibly conflicting input: '
                    '`docker_image` and one of [`func`, `base_image`, '
                    '`image_script_path`, `image_work_dir`, '
                    '`image_github_installs`]'
                )

            if docker_image and not isinstance(docker_image,
                                               dockerimage.DockerImage):
                raise aws.CloudknotInputError(
                    'docker_image must be a cloudknot DockerImage instance.'
                )

            def set_pars(knot_name, input_pars, pars_policies):
                # Validate and set the PARS
                if input_pars:
                    pars = input_pars

                    mod_logger.info('knot {name:s} adopted PARS {p:s}'.format(
                        name=knot_name, p=pars.name
                    ))
                    pars_cleanup = False
                else:
                    pars = Pars(name=knot_name, policies=pars_policies)

                    mod_logger.info('knot {name:s} created PARS {p:s}'.format(
                        name=knot_name, p=pars.name
                    ))
                    pars_cleanup = True

                return pars, pars_cleanup

            def set_dockerimage(knot_name, input_docker_image, func,
                                script_path, work_dir, base_image,
                                github_installs, username, tags, repo_name):
                if input_docker_image:
                    di = input_docker_image

                    mod_logger.info(
                        'Knot {name:s} adopted docker image {i:s}'
                        ''.format(name=knot_name, i=docker_image.name)
                    )
                else:
                    # Create and build the docker image
                    di = dockerimage.DockerImage(
                        func=func,
                        script_path=script_path,
                        dir_name=work_dir,
                        base_image=base_image,
                        github_installs=github_installs,
                        username=username
                    )

                if not di.images:
                    di.build(tags=tags)
                    mod_logger.info(
                        'knot {name:s} built docker image {i!s}'
                        ''.format(name=knot_name, i=di.images)
                    )

                if di.repo_uri is None:
                    # Create the remote repo
                    repo_name = (repo_name if repo_name
                                 else aws.get_ecr_repo())

                    # Later in __init__, we may abort this init because of
                    # inconsistent job def, compute env, or job queue
                    # parameters. If we do that, we don't want to leave a
                    # bunch of newly created resources around so keep track of
                    # whether this repo was created or adopted.
                    if config.has_option('docker-repos', repo_name):
                        # Pre-existing repo, no cleanup necessary
                        repo_cleanup = False
                    elif repo_name == aws.get_ecr_repo():
                        repo_cleanup = False
                    else:
                        # Freshly created repo, cleanup necessary
                        repo_cleanup = True

                    dr = aws.DockerRepo(name=repo_name)

                    mod_logger.info(
                        'knot {name:s} created/adopted docker repo '
                        '{r:s}'.format(name=knot_name, r=dr.name)
                    )

                    # Push to remote repo
                    di.push(repo=dr)

                    mod_logger.info(
                        "knot {name:s} pushed it's docker image to the repo "
                        "{r:s}".format(name=knot_name, r=dr.name)
                    )
                else:
                    repo_cleanup = False
                    dr = None

                return di, dr, repo_cleanup

            def set_job_def(knot_name, job_definition_name, pars, docker_image,
                            job_def_vcpus, memory, username, retries):
                try:
                    # Create job definition
                    jd = aws.JobDefinition(
                        name=job_definition_name,
                        job_role=pars.ecs_task_role,
                        docker_image=docker_image.repo_uri,
                        vcpus=job_def_vcpus,
                        memory=memory,
                        username=username,
                        retries=retries
                    )

                    mod_logger.info(
                        'knot {name:s} created job definition {jd:s}'.format(
                            name=knot_name, jd=jd.name
                        )
                    )
                    # Later in __init__, we may abort this init because of
                    # inconsistent compute env, or job queue parameters
                    # If we do that, we don't want to leave a bunch of newly
                    # created resources around so keep track of whether this
                    # job def was created or adopted. Here, we created it, so
                    # cleanup is needed
                    jd_cleanup = True
                except aws.ResourceExistsException as e:
                    # Job def already exists, retrieve it
                    jd = aws.JobDefinition(arn=e.resource_id)

                    # But confirm that all of the properties match the input
                    # or that the input was unspecified (i.e. is None)
                    eq_role = jd.job_role_arn == pars.ecs_task_role.arn
                    eq_image = jd.docker_image == docker_image.repo_uri
                    eq_vcpus = (job_def_vcpus is None
                                or jd.vcpus == job_def_vcpus)
                    eq_retries = retries is None or jd.retries == retries
                    eq_mem = memory is None or jd.memory == memory
                    eq_user = username is None or jd.username == username

                    matches = {
                        'job role matches': eq_role,
                        'docker image matches': eq_image,
                        'VCPUs match': eq_vcpus,
                        'retries match': eq_retries,
                        'memory matches': eq_mem,
                        'username matches': eq_user
                    }

                    if not all(matches.values()):
                        raise aws.CloudknotInputError(
                            'The requested job definition already exists but '
                            'does not match the input parameters. '
                            '{matches!s}'.format(matches=matches)
                        )

                    # jd_cleanup description is same as above. Here, we
                    # adopted it, so cleanup isn't needed
                    jd_cleanup = False

                    mod_logger.info(
                        'knot {name:s} adopted job definition {jd:s}'.format(
                            name=self.name, jd=jd.name
                        )
                    )

                return jd, jd_cleanup

            def set_compute_env(knot_name, compute_environment_name, pars,
                                instance_types, resource_type, min_vcpus,
                                max_vcpus, desired_vcpus, image_id,
                                ec2_key_pair, ce_tags, bid_percentage):
                try:
                    # Create compute environment
                    ce = aws.ComputeEnvironment(
                        name=compute_environment_name,
                        batch_service_role=pars.batch_service_role,
                        instance_role=pars.ecs_instance_role,
                        vpc=pars.vpc,
                        security_group=pars.security_group,
                        spot_fleet_role=pars.spot_fleet_role,
                        instance_types=instance_types,
                        resource_type=resource_type,
                        min_vcpus=min_vcpus,
                        max_vcpus=max_vcpus,
                        desired_vcpus=desired_vcpus,
                        image_id=image_id,
                        ec2_key_pair=ec2_key_pair,
                        tags=ce_tags,
                        bid_percentage=bid_percentage
                    )

                    # ce_cleanup logic same as for jd_cleanup
                    ce_cleanup = True

                    mod_logger.info(
                        'knot {name:s} created compute environment {ce:s}'
                        ''.format(name=knot_name, ce=ce.name)
                    )
                except aws.ResourceExistsException as e:
                    # Compute environment already exists, retrieve it
                    ce = aws.ComputeEnvironment(arn=e.resource_id)

                    # But confirm that all of the properties match the input
                    # or that the input was unspecified (i.e. is None)
                    eq_bsr = (ce.batch_service_role_arn
                              == pars.batch_service_role.arn)
                    eq_eir = (ce.instance_role_arn
                              == pars.ecs_instance_role.instance_profile_arn)
                    eq_vpc = set(ce.subnets) == set(pars.vpc.subnet_ids)
                    eq_sg = (ce.security_group_ids
                             == [pars.security_group.security_group_id])
                    if resource_type == 'SPOT':
                        eq_sfr = (ce.spot_fleet_role_arn
                                  == pars.spot_fleet_role.arn)
                    else:
                        eq_sfr = ce.spot_fleet_role_arn is None
                    eq_it = (instance_types is None
                             or ce.instance_types == instance_types)
                    eq_rt = (resource_type is None
                             or ce.resource_type == resource_type)
                    eq_min_vcpus = (min_vcpus is None
                                    or ce.min_vcpus == min_vcpus)
                    eq_max_vcpus = (max_vcpus is None
                                    or ce.max_vcpus == max_vcpus)
                    eq_des_vcpus = (desired_vcpus is None
                                    or ce.desired_vcpus == desired_vcpus)
                    eq_image_id = image_id is None or ce.image_id == image_id
                    eq_kp = (ec2_key_pair is None
                             or ce.ec2_key_pair == ec2_key_pair)
                    eq_tags = ce_tags is None or ce.tags == ce_tags
                    eq_bp = (bid_percentage is None
                             or ce.bid_percentage == bid_percentage)

                    matches = {
                        'batch service role matches': eq_bsr,
                        'instance profile matches': eq_eir,
                        'subnets match': eq_vpc,
                        'security groups match': eq_sg,
                        'spot fleet role matches': eq_sfr,
                        'instance types match': eq_it,
                        'resource type matches': eq_rt,
                        'min VCPUs match': eq_min_vcpus,
                        'max VCPUs match': eq_max_vcpus,
                        'desired VCPUs match': eq_des_vcpus,
                        'image ID matches': eq_image_id,
                        'EC2 key pair matches': eq_kp,
                        'tags match': eq_tags,
                        'bid percentage matches': eq_bp
                    }

                    if not all(matches.values()):
                        raise aws.CloudknotInputError(
                            'The requested compute environment already exists '
                            'but does not match the input parameters. '
                            '{matches!s}.'.format(matches=matches)
                        )

                    # ce_cleanup logic same as for jd_cleanup
                    ce_cleanup = False

                    mod_logger.info(
                        'knot {name:s} adopted compute environment {ce:s}'
                        ''.format(
                            name=self.name, ce=ce.name
                        )
                    )

                return ce, ce_cleanup

            def set_job_queue(knot_name, job_queue_name,
                              compute_environment, priority):
                try:
                    # Create job queue
                    jq = aws.JobQueue(
                        name=job_queue_name,
                        compute_environments=compute_environment,
                        priority=priority
                    )

                    # jq_cleanup logic same as for jd_cleanup
                    jq_cleanup = True

                    mod_logger.info(
                        'knot {name:s} created job queue '
                        '{jq:s}'.format(name=knot_name, jq=jq.name)
                    )
                except aws.ResourceExistsException as e:
                    # Job queue already exists, retrieve it
                    jq = aws.JobQueue(arn=e.resource_id)

                    # But confirm that all of the properties match the input
                    # or that the input was unspecified (i.e. is None)
                    ce_arns = [d['computeEnvironment']
                               for d in jq.compute_environment_arns]
                    eq_ce = ce_arns == [compute_environment.arn]
                    eq_priority = priority is None or jq.priority == priority

                    matches = {
                        'compute environment ARNS match': eq_ce,
                        'priority matches': eq_priority
                    }

                    if not all(matches.values()):
                        raise aws.CloudknotInputError(
                            'The requested job queue already exists '
                            'but does not match the input parameters. '
                            '{matches!s}'.format(matches=matches)
                        )

                    # jq_cleanup logic same as for jd_cleanup
                    jq_cleanup = False

                    mod_logger.info(
                        'knot {name:s} adopted job queue '
                        '{jq:s}'.format(name=self.name, jq=jq.name)
                    )

                return jq, jq_cleanup

            executor = ThreadPoolExecutor(10)
            futures = {}

            futures['pars'] = executor.submit(
                set_pars,
                knot_name=self.name, input_pars=pars,
                pars_policies=pars_policies
            )

            futures['docker-image'] = executor.submit(
                set_dockerimage,
                knot_name=self.name, input_docker_image=docker_image,
                func=func, script_path=image_script_path,
                work_dir=image_work_dir,
                base_image=base_image,
                github_installs=image_github_installs, username=username,
                tags=image_tags, repo_name=repo_name
            )

            self._pars, pars_cleanup = futures['pars'].result()

            futures['compute-environment'] = executor.submit(
                set_compute_env,
                knot_name=self.name,
                compute_environment_name=compute_environment_name,
                pars=self.pars, instance_types=instance_types,
                resource_type=resource_type, min_vcpus=min_vcpus,
                max_vcpus=max_vcpus, desired_vcpus=desired_vcpus,
                image_id=image_id, ec2_key_pair=ec2_key_pair, ce_tags=ce_tags,
                bid_percentage=bid_percentage
            )

            try:
                self._compute_environment, ce_cleanup = \
                    futures['compute-environment'].result()
            except aws.CloudknotInputError as e:
                if pars_cleanup:
                    self.pars.clobber()
                raise e

            futures['job-queue'] = executor.submit(
                set_job_queue,
                knot_name=self.name, job_queue_name=job_queue_name,
                compute_environment=self.compute_environment, priority=priority
            )

            try:
                self._job_queue, jq_cleanup = futures['job-queue'].result()
            except aws.CloudknotInputError as e:
                if ce_cleanup:
                    self.compute_environment.clobber()
                if pars_cleanup:
                    self.pars.clobber()
                raise e

            self._docker_image, self._docker_repo, repo_cleanup = \
                futures['docker-image'].result()

            futures['job-definition'] = executor.submit(
                set_job_def,
                knot_name=self.name, job_definition_name=job_definition_name,
                pars=self.pars, docker_image=self.docker_image,
                job_def_vcpus=job_def_vcpus, memory=memory, username=username,
                retries=retries
            )

            try:
                self._job_definition, jd_cleanup = \
                    futures['job-definition'].result()
            except aws.CloudknotInputError as e:
                if jq_cleanup:
                    self.job_queue.clobber()
                if ce_cleanup:
                    self.compute_environment.clobber()
                if repo_cleanup:
                    self.docker_repo.clobber()
                if pars_cleanup:
                    self.pars.clobber()
                raise e

            if self.job_definition.username != self.docker_image.username:
                if jq_cleanup:
                    self.job_queue.clobber()
                if ce_cleanup:
                    self.compute_environment.clobber()
                if jd_cleanup:
                    self.job_definition.clobber()
                if repo_cleanup:
                    self.docker_repo.clobber()
                if pars_cleanup:
                    self.pars.clobber()

                raise aws.CloudknotInputError(
                    "The username for this knot's job definition does not "
                    "match the username for this knot's Docker image."
                )

            executor.shutdown()

            self._jobs = []
            self._job_ids = []

            # Save the new Knot resources in config object
            # Use config.set() for python 2.7 compatibility
            config = configparser.ConfigParser()

            with rlock:
                config.read(get_config_file())
                config.add_section(self._knot_name)
                config.set(self._knot_name, 'region', self.region)
                config.set(self._knot_name, 'profile', self.profile)
                config.set(self._knot_name, 'pars', self.pars.name)
                config.set(self._knot_name, 'docker-image',
                           self.docker_image.name)
                config.set(
                    self._knot_name, 'docker-repo',
                    self.docker_repo.name if self.docker_repo else 'None'
                )
                config.set(self._knot_name, 'job-definition',
                           self.job_definition.name)
                config.set(self._knot_name, 'compute-environment',
                           self.compute_environment.name)
                config.set(self._knot_name, 'job-queue', self.job_queue.name)
                config.set(self._knot_name, 'job_ids', '')

                # Save config to file
                with open(get_config_file(), 'w') as f:
                    config.write(f)

    # Declare read-only properties
    @property
    def knot_name(self):
        """The section name for this knot in the cloudknot config file"""
        return self._knot_name

    @property
    def pars(self):
        """The Pars instance attached to this knot"""
        return self._pars

    @property
    def docker_image(self):
        """The DockerImage instance attached to this knot"""
        return self._docker_image

    @property
    def docker_repo(self):
        """The DockerRepo instance attached to this knot"""
        return self._docker_repo

    @property
    def job_definition(self):
        """The JobDefinition instance attached to this knot"""
        return self._job_definition

    @property
    def job_queue(self):
        """The JobQueue instance attached to this knot"""
        return self._job_queue

    @property
    def compute_environment(self):
        """The ComputeEnvironment instance attached to this knot"""
        return self._compute_environment

    @property
    def jobs(self):
        """List of BatchJob instances that this knot has launched"""
        return self._jobs

    @property
    def job_ids(self):
        """List of batch job IDs that this knot has launched"""
        return self._job_ids

    def map(self, iterdata, env_vars=None, max_threads=64,
            starmap=False, job_type='array'):
        """Submit batch jobs for a range of commands and environment vars

        Each item of `iterdata` is assumed to be a single input for the
        python function in this knot's docker image. If your function takes
        multiple arguments, pre-zip the arguments into a tuple, so that
        iterdata is an iterable of tuples, and set `starmap=True`.

        map returns a list of futures, which can return their result when
        the jobs are complete.

        Parameters
        ----------
        iterdata :
            An iteratable of input data

        env_vars : sequence of dicts
            Additional environment variables for the Batch environment
            Each dict must have only 'name' and 'value' keys. The same
            environment variables are applied for each item in `iterdata`.
            Default: None

        max_threads : int
            Maximum number of threads used to invoke.
            Default: 64

        starmap : bool
            If True, assume argument parameters are already grouped in
            tuples from a single iterable. This behavior is similar to
            `itertools.starmap()`. If False, assume argument parameters
            have not been "pre-zipped". Then the behavior is similar to
            python's built-in `map()` method.

        job_type : string, 'array' or 'independent'
            Type of batch job to submit. If 'array', then an array job is
            submitted (see
            https://docs.aws.amazon.com/batch/latest/userguide/array_jobs.html)
            with one child job for each input element and map returns one
            future for the entire results list. If job_type is 'independent'
            then one independent batch job is submitted for each input
            element and map returns a list of futures for each element of
            the results.
            Default: 'array'

        Returns
        -------
        map : future or list of futures
            If `job_type` is 'array', a future for the list of results.
            If `job_type` is 'independent', list of futures for each job
        """
        if job_type not in ['array', 'independent']:
            raise ValueError("`job_type` must be 'array' or 'independent'.")

        if self.clobbered:
            raise aws.ResourceClobberedException(
                'This Knot has already been clobbered.',
                self.name
            )

        self.check_profile_and_region()

        if not isinstance(iterdata, Iterable):
            raise TypeError('iterdata must be an iterable.')

        # env_vars should be a sequence of sequences of dicts
        if env_vars and not all(isinstance(s, dict) for s in env_vars):
            raise aws.CloudknotInputError('env_vars must be a sequence of '
                                          'dicts')

        # and each dict should have only 'name' and 'value' keys
        if env_vars and not all(set(d.keys()) == {'name', 'value'}
                                for d in env_vars):
            raise aws.CloudknotInputError('each dict in env_vars must have '
                                          'keys "name" and "value"')

        these_jobs = []

        if job_type == 'independent':
            for input_ in iterdata:
                job = aws.BatchJob(
                    input_=input_,
                    starmap=starmap,
                    name='{n:s}-{i:d}'.format(
                        n=self.name, i=len(self.job_ids)
                    ),
                    job_queue=self.job_queue,
                    job_definition=self.job_definition,
                    environment_variables=env_vars,
                    array_job=False
                )

                these_jobs.append(job)
                self._jobs.append(job)
                self._job_ids.append(job.job_id)
        else:
            job = aws.BatchJob(
                input_=iterdata,
                starmap=starmap,
                name='{n:s}-{i:d}'.format(n=self.name, i=len(self.job_ids)),
                job_queue=self.job_queue,
                job_definition=self.job_definition,
                environment_variables=env_vars,
                array_job=True
            )

            these_jobs.append(job)
            self._jobs.append(job)
            self._job_ids.append(job.job_id)

        if not these_jobs:
            return []

        config = configparser.ConfigParser()

        with rlock:
            config.read(get_config_file())
            config.set(self._knot_name, 'job_ids', ' '.join(self.job_ids))
            # Save config to file
            with open(get_config_file(), 'w') as f:
                config.write(f)

        # Increase the max_pool_connections in the boto3 clients to prevent
        # https://github.com/boto/botocore/issues/766
        aws.refresh_clients(max_pool=max_threads)

        executor = ThreadPoolExecutor(
            max(min(len(these_jobs), max_threads), 2)
        )

        futures = [executor.submit(lambda j: j.result(), jb)
                   for jb in these_jobs]

        # Shutdown the executor but do not wait to return the futures
        executor.shutdown(wait=False)

        if job_type == 'independent':
            return futures
        else:
            return futures[0]

    def view_jobs(self):
        """Print the job_id, name, and status of all jobs in self.jobs"""
        if self.clobbered:
            raise aws.ResourceClobberedException(
                'This Knot has already been clobbered.',
                self.name
            )

        self.check_profile_and_region()

        order = {'SUBMITTED': 0, 'PENDING': 1, 'RUNNABLE': 2, 'STARTING': 3,
                 'RUNNING': 4, 'FAILED': 5, 'SUCCEEDED': 6}

        response = aws.clients['batch'].describe_jobs(jobs=self.job_ids)
        sorted_jobs = sorted(response.get('jobs'),
                             key=lambda j: order[j['status']])

        fmt = '{jobId:12s}        {jobName:20s}        {status:9s}'
        header = fmt.format(jobId='Job ID', jobName='Name', status='Status')
        print(header)
        print('-' * len(header))

        for job in sorted_jobs:
            print(fmt.format(**job))

    def clobber(self, clobber_pars=False, clobber_repo=False,
                clobber_image=False):
        """Delete associated AWS resources and remove section from config

        Parameters
        ----------
        clobber_pars : boolean
            If true, clobber the associated Pars instance
            Default: False

        clobber_repo : boolean
            If true, clobber the associated DockerRepo instance
            Default: False

        clobber_image : boolean
            If true, clobber the associated DockerImage instance
            Default: False
        """
        if self.clobbered:
            return

        self.check_profile_and_region()

        # Delete all associated AWS resources
        def clobber_jq_then_ce(jq, ce):
            jq.clobber()
            ce.clobber()

        with ThreadPoolExecutor(32) as e:
            # Iterate over copy of self.jobs since we are
            # removing from the list while iterating
            for job in list(self.jobs):
                e.submit(job.clobber)
                self._jobs.remove(job)
            e.submit(clobber_jq_then_ce,
                     self.job_queue, self.compute_environment)
            e.submit(self.job_definition.clobber)
            if clobber_repo:
                dr = self.docker_repo
                if dr and dr.name != aws.get_ecr_repo():
                    # if the docker repo instance exists and it is not the
                    # default cloudknot ECR repo, then clobber it
                    e.submit(self.docker_repo.clobber)
                else:
                    # Either the repo instance is unavailable or this is in
                    # the default cloudknot ECR repo.
                    uri = self.docker_image.repo_uri
                    repo_name = uri.split('amazonaws.com/')[-1].split(':')[0]
                    if repo_name == aws.get_ecr_repo():
                        # This is in the default ECR repo. So just delete the
                        # image from the remote repo, leaving other images
                        # untouched.
                        registry_id = uri.split('.')[0]
                        tag = uri.split(':')[-1]

                        e.submit(aws.clients['ecr'].batch_delete_image,
                                 registryId=registry_id,
                                 repositoryName=repo_name,
                                 imageIds=[{'imageTag': tag}])
                    else:
                        # This is not the default repo, feel free to clobber
                        repo = aws.DockerRepo(name=repo_name)
                        e.submit(repo.clobber)

            if clobber_image:
                e.submit(self.docker_image.clobber)
            if clobber_pars:
                e.submit(self.pars.clobber)

        # Remove this section from the config file
        config = configparser.ConfigParser()

        with rlock:
            config.read(get_config_file())
            config.remove_section(self._knot_name)
            with open(get_config_file(), 'w') as f:
                config.write(f)

        # Set the clobbered parameter to True,
        # preventing subsequent method calls
        self._clobbered = True

        mod_logger.info('Clobbered Knot {name:s}'.format(name=self.name))
