from __future__ import absolute_import, division, print_function

import cloudknot.config
import cloudpickle
from datetime import datetime
import logging
import pickle
import six
import tenacity
import time
from collections import namedtuple

from .base_classes import NamedObject, ObjectWithArn, \
    ObjectWithUsernameAndMemory, clients, \
    ResourceExistsException, ResourceDoesNotExistException, \
    ResourceClobberedException, CannotDeleteResourceException, \
    BatchJobFailedError, CKTimeoutError, \
    wait_for_job_queue, get_s3_bucket
from .ec2 import Vpc, SecurityGroup
from .ecr import DockerRepo
from .iam import IamRole

__all__ = ["JobDefinition", "JobQueue", "ComputeEnvironment", "BatchJob"]

mod_logger = logging.getLogger(__name__)


# noinspection PyPropertyAccess,PyAttributeOutsideInit
class JobDefinition(ObjectWithUsernameAndMemory):
    """Class for defining AWS Batch Job Definitions"""
    def __init__(self, arn=None, name=None, job_role=None, docker_image=None,
                 vcpus=None, memory=None, username=None, retries=None):
        """Initialize an AWS Batch job definition object.

        Parameters
        ----------
        arn : string
            ARN of the job definition to retrieve

        name : string
            Name of the job definition to retrieve or create

        job_role : IamRole
            IamRole instance for the AWS IAM job role to be used in this
            job definition

        docker_image : DockerRepo or string
            DockerRepo instance for the container to be used in this job
            definition
            or string containing location of docker image on Docker Hub or
            other repository

        vcpus : int
            number of virtual cpus to be used to this job definition
            Default: 1

        memory : int
            memory (MiB) to be used for this job definition
            Default: 8000

        username : string
            username for be used for this job definition
            Default: cloudknot-user

        retries : int
            number of times a job can be moved to 'RUNNABLE' status.
            May be between 1 and 10
            Default: 1
        """
        # Validate for minimum input
        if not (arn or name):
            raise ValueError('You must supply either an arn or name for this '
                             'job definition.')

        # Validate to prevent over-specified input
        if arn and any([
            name, job_role, docker_image, vcpus, memory, username, retries
        ]):
            raise ValueError('You may supply either an arn or other job '
                             'definition details. Not both.')

        # Determine whether the user supplied only an arn or only a name
        arn_or_name_only = (arn or (name and not any([
            job_role, docker_image, vcpus, memory, username, retries
        ])))

        resource = self._exists_already(arn=arn, name=name)
        self._pre_existing = resource.exists

        if resource.exists and resource.status != 'INACTIVE':
            # Resource exists, if user tried to specify resource parameters
            # for an active job def, then throw error
            if any([job_role, docker_image, vcpus, memory, username, retries]):
                raise ResourceExistsException(
                    'You provided input parameters for a job definition that '
                    'already exists. If you would like to create a new job '
                    'definition, please use a different name. If you would '
                    'like to retrieve the details of this job definition, use '
                    'JobDefinition(arn={arn:s})'.format(arn=resource.arn),
                    resource.arn
                )

            # Fill parameters with queried values
            super(JobDefinition, self).__init__(
                name=resource.name, memory=resource.memory,
                username=resource.username
            )

            self._job_role = None
            self._job_role_arn = resource.job_role_arn
            self._docker_image = resource.docker_image
            self._vcpus = resource.vcpus
            self._retries = resource.retries
            self._arn = resource.arn
            self._output_bucket = resource.output_bucket

            # Add to config file
            self._section_name = self._get_section_name('job-definitions')
            cloudknot.config.add_resource(
                self._section_name, self.name, self.arn
            )

            mod_logger.info(
                'Retrieved pre-existing job definition {name:s}'.format(
                    name=self.name
                )
            )
        elif (resource.exists and resource.status == 'INACTIVE'
              and arn_or_name_only):
            raise ResourceExistsException(
                'You retrieved an inactive job definition and cloudknot '
                'has no way to reactivate it. Instead of retrieving the '
                'job definition using an ARN, create a new one with your '
                'desired properties.',
                resource.arn
            )
        else:
            # If user supplied only a name or only an arn, expecting to
            # retrieve info on pre-existing job definition, throw error
            if arn or (name and not all([job_role, docker_image])):
                raise ResourceDoesNotExistException(
                    'The job definition you requested does not exist.',
                    arn
                )

            # Otherwise, validate input and set parameters
            username = username if username else 'cloudknot-user'
            memory = memory if memory else 8000

            super(JobDefinition, self).__init__(
                name=name, memory=memory, username=username
            )

            # Validate job role input
            if not isinstance(job_role, IamRole):
                raise ValueError('job_role must be an instance of IamRole')
            self._job_role = job_role
            self._job_role_arn = job_role.arn

            # Validate docker_image input
            if not (isinstance(docker_image, DockerRepo)
                    or isinstance(docker_image, six.string_types)):
                raise ValueError(
                    'docker_image must be an instance of DockerRepo '
                    'or a string'
                )
            self._docker_image = docker_image
            self._output_bucket = get_s3_bucket()

            # Validate vcpus input
            if vcpus:
                cpus = int(vcpus)
                if cpus < 1:
                    raise ValueError('vcpus must be positive')
                else:
                    self._vcpus = cpus
            else:
                self._vcpus = 1

            # Validate retries input
            if retries is not None:
                retries_int = int(retries)
                if retries_int < 1:
                    raise ValueError('retries must be positive')
                elif retries_int > 10:
                    raise ValueError('retries must be less than 10')
                else:
                    self._retries = retries_int
            else:
                self._retries = 1

            self._arn = self._create()

    # Declare read-only parameters
    @property
    def pre_existing(self):
        """Boolean flag to indicate whether this resource was pre-existing

        True if resource was retrieved from AWS,
        False if it was created on __init__.
        """
        return self._pre_existing

    @property
    def job_role(self):
        """IAM job role for this job definition."""
        return self._job_role

    @property
    def job_role_arn(self):
        """The ARN for this job definition's IAM job role."""
        return self._job_role_arn

    @property
    def docker_image(self):
        """DockerRepo instance for the container to be used in this job
        definition or string containing location of docker image on Docker
        Hub or other repository
        """
        return self._docker_image

    @property
    def output_bucket(self):
        """Amazon S3 bucket where output will be stored"""
        return self._output_bucket

    @property
    def vcpus(self):
        """The number of vCPUS for this job definition."""
        return self._vcpus

    @property
    def retries(self):
        """The number of times a job can be moved to 'RUNNABLE' status."""
        return self._retries

    def _exists_already(self, arn, name):
        """Check if an AWS Job Definition exists already

        If definition exists, return namedtuple with job definition info.
        Otherwise, set the namedtuple's `exists` field to `False`. The
        remaining fields default to `None`.

        Returns
        -------
        namedtuple RoleExists
            A namedtuple with fields
            ['exists', 'name', 'status', 'job_role', 'output_bucket',
            'docker_image', 'vcpus', 'memory', 'username', 'retries', 'arn']
        """
        # define a namedtuple for return value type
        ResourceExists = namedtuple(
            'ResourceExists',
            ['exists', 'name', 'status', 'job_role_arn', 'docker_image',
             'vcpus', 'memory', 'username', 'retries', 'arn',
             'output_bucket']
        )
        # make all but the first value default to None
        ResourceExists.__new__.__defaults__ = \
            (None,) * (len(ResourceExists._fields) - 1)

        if arn:
            # Retrieve using ARN
            response = clients['batch'].describe_job_definitions(
                jobDefinitions=[arn]
            )
        else:
            # Retrieve using name
            response = clients['batch'].describe_job_definitions(
                jobDefinitionName=name
            )

        if response.get('jobDefinitions'):
            # Get active job definitions
            active_job_defs = [jd for jd in response.get('jobDefinitions')
                               if jd['status'] == 'ACTIVE']
            if active_job_defs:
                job_def = sorted(active_job_defs, key=lambda j: j['revision'],
                                 reverse=True)[0]
            else:
                job_def = response.get('jobDefinitions')[0]

            # Job def exists. Get job def details
            job_def_name = job_def['jobDefinitionName']
            job_def_status = job_def['status']
            job_def_arn = job_def['jobDefinitionArn']
            retries = job_def['retryStrategy']['attempts']

            container_properties = job_def['containerProperties']
            username = container_properties['user']
            memory = container_properties['memory']
            vcpus = container_properties['vcpus']
            job_role_arn = container_properties['jobRoleArn']
            container_image = container_properties['image']
            try:
                environment = container_properties['environment']
            except KeyError:  # pragma: nocover
                environment = None

            bucket_envs = [e for e in environment
                           if e['name'] == 'CLOUDKNOT_JOBS_S3_BUCKET']

            output_bucket = bucket_envs[0]['value'] if bucket_envs else None

            mod_logger.info('Job definition {name:s} already exists.'.format(
                name=job_def_name
            ))

            return ResourceExists(
                exists=True, name=job_def_name, status=job_def_status,
                job_role_arn=job_role_arn, docker_image=container_image,
                vcpus=vcpus, memory=memory, username=username,
                retries=retries, arn=job_def_arn, output_bucket=output_bucket
            )
        else:
            return ResourceExists(exists=False)

    def _create(self):
        """Create AWS job definition using instance parameters

        Returns
        -------
        string
            Amazon Resource Number (ARN) for the created job definition
        """
        # If docker_image is a string, assume it contains the image URI
        # Else it's a DockerRepo instance, get the uri property
        image = self.docker_image \
            if isinstance(self.docker_image, six.string_types) \
            else self.docker_image.repo_uri

        job_container_properties = {
            'image': image,
            'vcpus': self.vcpus,
            'memory': self.memory,
            'command': [],
            'jobRoleArn': self.job_role_arn,
            'user': self.username,
            'environment': [
                {
                    'name': 'CLOUDKNOT_JOBS_S3_BUCKET',
                    'value': self.output_bucket
                },
                {
                    'name': 'CLOUDKNOT_S3_JOBDEF_KEY',
                    'value': self.name
                }
            ],
        }

        # Register the job def
        response = clients['batch'].register_job_definition(
            jobDefinitionName=self.name,
            type='container',
            containerProperties=job_container_properties,
            retryStrategy={'attempts': self.retries}
        )

        arn = response['jobDefinitionArn']

        # Add this job def to the list of job definitions in the config file
        self._section_name = self._get_section_name('job-definitions')
        cloudknot.config.add_resource(self._section_name, self.name, arn)

        mod_logger.info('Created AWS batch job definition {name:s}'.format(
            name=self.name
        ))

        return arn

    def clobber(self):
        """Deregister this AWS batch job definition"""
        if self.clobbered:
            return

        self.check_profile_and_region()

        clients['batch'].deregister_job_definition(jobDefinition=self.arn)

        # Remove this job def from the list of job defs in the config file
        cloudknot.config.remove_resource(self._section_name, self.name)

        # Set the clobbered parameter to True,
        # preventing subsequent method calls
        self._clobbered = True

        mod_logger.info('Deregistered job definition {name:s}'.format(
            name=self.name
        ))


# noinspection PyPropertyAccess,PyAttributeOutsideInit
class ComputeEnvironment(ObjectWithArn):
    """Class for defining AWS Compute Environments"""
    def __init__(self, arn=None, name=None, batch_service_role=None,
                 instance_role=None, vpc=None, security_group=None,
                 spot_fleet_role=None, instance_types=None, resource_type=None,
                 min_vcpus=None, max_vcpus=None, desired_vcpus=None,
                 image_id=None, ec2_key_pair=None, tags=None,
                 bid_percentage=None):
        """Initialize an AWS Batch job definition object.

        Parameters
        ----------
        arn : string
            Amazon Resource Number of this compute environment

        name : string
            Name of the compute environment

        batch_service_role : IamRole
            IamRole instance for the AWS IAM batch service role

        instance_role : IamRole
            IamRole instance for the AWS IAM instance role

        vpc: Vpc
            Vpc instance for the AWS virtual private cloud that this
            compute environment will use

        security_group: SecurityGroup
            SecurityGroup instance for the AWS security group that this
            compute environment will use

        spot_fleet_role : IamRole
            optional IamRole instance for the AWS IAM spot fleet role.
            Default: None

        instance_types : string or sequence of strings
            instance types that may be launched in this compute environment.
            Default: ('optimal',)

        resource_type : string
            Resource type, either "EC2" or "SPOT"

        min_vcpus : int
            minimum number of virtual cpus for instances launched in this
            compute environment. CAREFUL HERE: If you specify min_vcpus
            greater than 0, your ECS cluster will keep instances spinning
            even when there is no work to do. We strongly recommend
            keeping min_vpucs set at 0.
            Default: 0

        max_vcpus : int
            maximum number of virtual cpus for instances launched in this
            compute environment.
            Default: 256

        desired_vcpus : int
            desired number of virtual cpus for instances launched in this
            compute environment.
            Default: 8

        image_id : string
            optional AMI id used for instances launched in this compute
            environment.
            Default: None

        ec2_key_pair : string
            optional EC2 key pair used for instances launched in this compute
            environment.
            Default: None

        tags : dictionary
            optional key-value pair tags to be applied to resources in this
            compute environment.
            Default: None

        bid_percentage : int
            bid percentage if using spot instances.
            Default: 50
        """
        # Validate for minimum input
        if not (arn or name):
            raise ValueError(
                'You must supply either an arn or name for this '
                'compute environment.'
            )

        # Validate in case of over-specified input
        if arn and any([
            name, batch_service_role, instance_role, vpc, security_group,
            spot_fleet_role, instance_types, resource_type, min_vcpus,
            max_vcpus, desired_vcpus, image_id, ec2_key_pair, tags,
            bid_percentage
        ]):
            raise ValueError(
                'You may supply either an arn or compute '
                'environment parameters, but not both.'
            )

        # Check if this compute environment already exists
        resource = self._exists_already(arn=arn, name=name)
        self._pre_existing = resource.exists

        if resource.exists:
            # If pre-existing, then user supplied either arn or name. Above,
            # we raised error if user provided arn plus input parameters.
            # Now, check that they did not provide a pre-existing name plus
            # input parameters
            if name and any([
                batch_service_role, instance_role, vpc, security_group,
                spot_fleet_role, instance_types, resource_type, min_vcpus,
                max_vcpus, desired_vcpus, image_id, ec2_key_pair, tags,
                bid_percentage
            ]):
                raise ResourceExistsException(
                    'You provided input parameters for a compute environment '
                    'that already exists. If you would like to create a new '
                    'compute environment, please use a different name. If '
                    'you would like to retrieve the details of this compute '
                    'environment, use ComputeEnvironment('
                    'arn={arn:s})'.format(arn=resource.arn),
                    resource.arn
                )

            # Fill parameters with queried values
            super(ComputeEnvironment, self).__init__(name=resource.name)

            self._batch_service_role = None
            self._batch_service_role_arn = resource.batch_service_role_arn

            self._instance_role = None
            self._instance_role_arn = resource.instance_role_arn

            self._vpc = None
            self._subnets = resource.subnets

            self._security_group = None
            self._security_group_ids = resource.security_group_ids

            self._spot_fleet_role = None
            self._spot_fleet_role_arn = resource.spot_fleet_role_arn

            self._instance_types = resource.instance_types
            self._resource_type = resource.resource_type
            self._min_vcpus = resource.min_vcpus
            self._max_vcpus = resource.max_vcpus
            self._desired_vcpus = resource.desired_vcpus
            self._image_id = resource.image_id
            self._ec2_key_pair = resource.ec2_key_pair
            self._tags = resource.tags
            self._bid_percentage = resource.bid_percentage
            self._arn = resource.arn

            self._section_name = self._get_section_name('compute-environments')
            cloudknot.config.add_resource(
                self._section_name, self.name, self.arn
            )

            mod_logger.info(
                'Retrieved pre-existing compute environment {name:s}'.format(
                    name=self.name
                )
            )
        else:
            # If user supplied only a name or only an arn, expecting to
            # retrieve info on pre-existing job queue, throw error
            if arn or (name and not all([
                batch_service_role, instance_role, vpc, security_group
            ])):
                raise ResourceDoesNotExistException(
                    'The job queue you requested does not exist.',
                    arn
                )

            # Otherwise, validate input and set parameters
            super(ComputeEnvironment, self).__init__(name=name)

            # If resource type is 'SPOT', user must also specify
            # a bid percentage and a spot fleet IAM role
            if not bid_percentage and resource_type == 'SPOT':
                raise ValueError(
                    'if resource_type is "SPOT", bid_percentage '
                    'must be set.'
                )

            if not spot_fleet_role and resource_type == 'SPOT':
                raise ValueError(
                    'if resource_type is "SPOT", spot_fleet_role '
                    'must be set.'
                )

            # Validate batch_service_role is actually a batch role
            if not (isinstance(batch_service_role, IamRole)
                    and 'batch' in batch_service_role.service):
                raise ValueError(
                    'batch_service_role must be an IamRole '
                    'instance with service type "batch"'
                )
            self._batch_service_role = batch_service_role
            self._batch_service_role_arn = batch_service_role.arn

            # Validate instance_role is actually an instance role
            if not (isinstance(instance_role, IamRole)
                    and instance_role.instance_profile_arn):
                raise ValueError(
                    'instance_role must be an IamRole instance '
                    'with an instance profile ARN'
                )
            self._instance_role = instance_role
            self._instance_role_arn = instance_role.instance_profile_arn

            # Validate vpc input
            if not isinstance(vpc, Vpc):
                raise ValueError('vpc must be an instance of Vpc')
            self._vpc = vpc
            self._subnets = vpc.subnet_ids

            # Validate security group input
            if not isinstance(security_group, SecurityGroup):
                raise ValueError(
                    'security_group must be an instance of '
                    'SecurityGroup'
                )
            self._security_group = security_group
            self._security_group_ids = [security_group.security_group_id]

            if spot_fleet_role:
                # Validate that spot_fleet_role is actually a spot fleet role
                if not (isinstance(spot_fleet_role, IamRole)
                        and 'spotfleet' in spot_fleet_role.service):
                    raise ValueError(
                        'if provided, spot_fleet_role must be an '
                        'IamRole instance with service type '
                        '"spotfleet"'
                    )
                self._spot_fleet_role = spot_fleet_role
                self._spot_fleet_role_arn = spot_fleet_role.arn
            else:
                self._spot_fleet_role = None
                self._spot_fleet_role_arn = None

            # Default instance type is 'optimal'
            instance_types = instance_types if instance_types else ['optimal']
            if isinstance(instance_types, six.string_types):
                self._instance_types = [instance_types]
            elif all(isinstance(x, six.string_types) for x in instance_types):
                self._instance_types = list(instance_types)
            else:
                raise ValueError(
                    'instance_types must be a string or a '
                    'sequence of strings.'
                )

            # Validate instance types
            valid_instance_types = {
                'optimal', 'm3', 'm4', 'c3', 'c4', 'r3', 'i2', 'd2', 'g2',
                'p2', 'x1', 'm3.medium', 'm3.large', 'm3.xlarge', 'm3.2xlarge',
                'm4.large', 'm4.xlarge', 'm4.2xlarge', 'm4.4xlarge',
                'm4.10xlarge', 'm4.16xlarge', 'c3.8xlarge', 'c3.4xlarge',
                'c3.2xlarge', 'c3.xlarge', 'c3.large', 'c4.8xlarge',
                'c4.4xlarge', 'c4.2xlarge', 'c4.xlarge', 'c4.large',
                'r3.8xlarge', 'r3.4xlarge', 'r3.2xlarge', 'r3.xlarge',
                'r3.large', 'i2.8xlarge', 'i2.4xlarge', 'i2.2xlarge',
                'i2.xlarge', 'g2.2xlarge', 'g2.8xlarge', 'p2.large',
                'p2.8xlarge', 'p2.16xlarge', 'd2.8xlarge', 'd2.4xlarge',
                'd2.2xlarge', 'd2.xlarge', 'x1.32xlarge'
            }
            if not set(self._instance_types) < valid_instance_types:
                raise ValueError(
                    'instance_types must be a subset of {types!s}'.format(
                        types=valid_instance_types
                    )
                )

            # Validate resource type, default to 'EC2'
            resource_type = resource_type if resource_type else 'EC2'
            if resource_type not in ('EC2', 'SPOT'):
                raise ValueError('resource_type must be "EC2" or "SPOT"')
            self._resource_type = resource_type

            # Validate min_vcpus, default to 0
            min_vcpus = min_vcpus if min_vcpus else 0
            cpus = int(min_vcpus)
            if cpus < 0:
                raise ValueError('min_vcpus must be non-negative')
            else:
                self._min_vcpus = cpus

            if self._min_vcpus > 0:
                mod_logger.warning(
                    'min_vcpus is greater than zero. This means that your '
                    'compute environment will maintain some EC2 vCPUs, '
                    'regardless of job demand, potentially resulting in '
                    'unnecessary AWS charges. We strongly recommend using '
                    'a compute environment with min_vcpus set to zero.'
                )

            # Validate max_vcpus, default to 256
            max_vcpus = max_vcpus if max_vcpus else 256
            cpus = int(max_vcpus)
            if cpus < 0:
                raise ValueError('max_vcpus must be non-negative')
            else:
                self._max_vcpus = cpus

            # Validate desired_vcpus input, default to 8
            desired_vcpus = desired_vcpus if desired_vcpus else 8
            cpus = int(desired_vcpus)
            if cpus < 0:
                raise ValueError('desired_vcpus must be non-negative')
            else:
                self._desired_vcpus = cpus

            # Validate image_id input
            if image_id:
                if not isinstance(image_id, six.string_types):
                    raise ValueError('if provided, image_id must be a string')
                self._image_id = image_id
            else:
                self._image_id = None

            # Validate ec2_key_pair input
            if ec2_key_pair:
                if not isinstance(ec2_key_pair, six.string_types):
                    raise ValueError(
                        'if provided, ec2_key_pair must be a string'
                    )
                self._ec2_key_pair = ec2_key_pair
            else:
                self._ec2_key_pair = None

            # Validate tags input
            if tags:
                if not isinstance(tags, dict):
                    raise ValueError(
                        'if provided, tags must be an instance of dict'
                    )
                elif self.resource_type == 'SPOT':
                    mod_logger.warning(
                        'Tags are not supported for compute environment of '
                        'type "SPOT". Ignoring input tags'
                    )
                    self._tags = None
                else:
                    self._tags = tags
            else:
                self._tags = None

            # Validate bid_percentage input
            if bid_percentage:
                bp_int = int(bid_percentage)
                if bp_int < 0:
                    self._bid_percentage = 0
                elif bp_int > 100:
                    self._bid_percentage = 100
                else:
                    self._bid_percentage = bp_int
            else:
                self._bid_percentage = None

            self._arn = self._create()

    # Declare read-only properties
    @property
    def pre_existing(self):
        """Boolean flag to indicate whether this resource was pre-existing

        True if resource was retrieved from AWS,
        False if it was created on __init__.
        """
        return self._pre_existing

    @property
    def batch_service_role(self):
        """IamRole instance for the AWS IAM batch service role"""
        return self._batch_service_role

    @property
    def batch_service_role_arn(self):
        """ARN for this compute environment's IAM batch service role"""
        return self._batch_service_role_arn

    @property
    def instance_role(self):
        """IamRole instance for the AWS IAM instance role"""
        return self._instance_role

    @property
    def instance_role_arn(self):
        """ARN for this compute environment's IAM instance role"""
        return self._instance_role_arn

    @property
    def vpc(self):
        """Vpc instance that this compute environment will use"""
        return self._vpc

    @property
    def subnets(self):
        """VPC subnets that this compute environment will use"""
        return self._subnets

    @property
    def security_group(self):
        """SecurityGroup instance that this compute environment will use"""
        return self._security_group

    @property
    def security_group_ids(self):
        """Security group IDs for this compute environment"""
        return self._security_group_ids

    @property
    def spot_fleet_role(self):
        """optional IamRole instance for the AWS IAM spot fleet role"""
        return self._spot_fleet_role

    @property
    def spot_fleet_role_arn(self):
        """ARN for this compute environment's IAM spot fleet role"""
        return self._spot_fleet_role_arn

    @property
    def instance_types(self):
        """Instance types that may be launched in this compute environment"""
        return self._instance_types

    @property
    def resource_type(self):
        """Resource type, either 'EC2' or 'SPOT'"""
        return self._resource_type

    @property
    def min_vcpus(self):
        """Minimum number of vCPUs for instances in this compute environment"""
        return self._min_vcpus

    @property
    def max_vcpus(self):
        """Maximum number of vCPUs for instances in this compute environment"""
        return self._max_vcpus

    @property
    def desired_vcpus(self):
        """Desired number of vCPUs for instances in this compute environment"""
        return self._desired_vcpus

    @property
    def image_id(self):
        """Optional AMI id used for instances in this compute environment"""
        return self._image_id

    @property
    def ec2_key_pair(self):
        """Optional EC2 key pair for instances in this compute environment"""
        return self._ec2_key_pair

    @property
    def tags(self):
        """Optional tags to apply to resources in this compute environment"""
        return self._tags

    @property
    def bid_percentage(self):
        """Bid percentage if using spot instances"""
        return self._bid_percentage

    def _exists_already(self, arn, name):
        """Check if a compute environment exists already

        If compute environment exists, return namedtuple with compute
        environment info. Otherwise, set the namedtuple's `exists` field to
        `False`. The remaining fields default to `None`.

        Returns
        -------
        namedtuple ResourceExists
            A namedtuple with fields
            ['exists', 'name', 'batch_service_role_arn', 'instance_role_arn',
             'subnets', 'security_group_ids', 'spot_fleet_role_arn',
             'instance_types', 'resource_type', 'min_vcpus', 'max_vcpus',
             'desired_vcpus', 'image_id', 'ec2_key_pair', 'tags',
             'bid_percentage', 'arn']
        """
        # define a namedtuple for return value type
        ResourceExists = namedtuple(
            'ResourceExists',
            ['exists', 'name', 'batch_service_role_arn', 'instance_role_arn',
             'subnets', 'security_group_ids', 'spot_fleet_role_arn',
             'instance_types', 'resource_type', 'min_vcpus', 'max_vcpus',
             'desired_vcpus', 'image_id', 'ec2_key_pair', 'tags',
             'bid_percentage', 'arn']
        )
        # make all but the first value default to None
        ResourceExists.__new__.__defaults__ = \
            (None,) * (len(ResourceExists._fields) - 1)

        if arn:
            # Search by ARN
            response = clients['batch'].describe_compute_environments(
                computeEnvironments=[arn]
            )
        else:
            # Search by name
            response = clients['batch'].describe_compute_environments(
                computeEnvironments=[name]
            )

        if response.get('computeEnvironments'):
            ce = response.get('computeEnvironments')[0]
            ce_name = ce['computeEnvironmentName']
            batch_service_role_arn = ce['serviceRole']
            ce_arn = ce['computeEnvironmentArn']

            cr = ce['computeResources']
            instance_role_arn = cr['instanceRole']
            subnets = cr['subnets']
            security_group_ids = cr['securityGroupIds']
            instance_types = cr['instanceTypes']
            resource_type = cr['type']
            min_vcpus = cr['minvCpus']
            max_vcpus = cr['maxvCpus']

            # Some retrieved compute environments will be missing optional
            # parameters, so try/catch for KeyErrors for the following.
            try:
                desired_vcpus = cr['desiredvCpus']
            except KeyError:  # pragma: nocover
                desired_vcpus = None

            try:
                image_id = cr['imageId']
            except KeyError:
                image_id = None

            try:
                ec2_key_pair = cr['ec2KeyPair']
            except KeyError:
                ec2_key_pair = None

            try:
                tags = cr['tags']
            except KeyError:  # pragma: nocover
                tags = None

            try:
                bid_percentage = cr['bidPercentage']
            except KeyError:
                bid_percentage = None

            try:
                spot_fleet_role_arn = cr['spotIamFleetRole']
            except KeyError:
                spot_fleet_role_arn = None

            mod_logger.info(
                'Compute environment {name:s} already exists.'.format(
                    name=ce_name
                )
            )

            return ResourceExists(
                exists=True, name=ce_name,
                batch_service_role_arn=batch_service_role_arn,
                instance_role_arn=instance_role_arn, subnets=subnets,
                security_group_ids=security_group_ids,
                spot_fleet_role_arn=spot_fleet_role_arn,
                instance_types=instance_types,
                resource_type=resource_type, min_vcpus=min_vcpus,
                max_vcpus=max_vcpus, desired_vcpus=desired_vcpus,
                image_id=image_id, ec2_key_pair=ec2_key_pair, tags=tags,
                bid_percentage=bid_percentage, arn=ce_arn
            )
        else:
            return ResourceExists(exists=False)

    def _create(self):
        """Create AWS compute environment using instance parameters

        Returns
        -------
        string
            Amazon Resource Number (ARN) for the created compute environment
        """
        compute_resources = {
            'type': self.resource_type,
            'minvCpus': self.min_vcpus,
            'maxvCpus': self.max_vcpus,
            'desiredvCpus': self.desired_vcpus,
            'instanceTypes': self.instance_types,
            'subnets': self.subnets,
            'securityGroupIds': self.security_group_ids,
            'instanceRole': self.instance_role_arn,
        }

        # If using spot instances, include the relevant key/value pairs
        if self.resource_type == 'SPOT':
            compute_resources['bidPercentage'] = self.bid_percentage
            compute_resources['spotIamFleetRole'] = self.spot_fleet_role_arn

        # If tags, imageId, or ec2KeyPair are provided, include them too
        if self.tags:
            compute_resources['tags'] = self.tags

        if self.image_id:
            compute_resources['imageId'] = self.image_id

        if self.ec2_key_pair:
            compute_resources['ec2KeyPair'] = self.ec2_key_pair

        response = clients['batch'].create_compute_environment(
            computeEnvironmentName=self.name,
            type='MANAGED',
            state='ENABLED',
            computeResources=compute_resources,
            serviceRole=self.batch_service_role_arn
        )

        arn = response['computeEnvironmentArn']

        # Add this compute env to the list of compute envs in the config file
        self._section_name = self._get_section_name('compute-environments')
        cloudknot.config.add_resource(self._section_name, self.name, arn)

        mod_logger.info('Created compute environment {name:s}'.format(
            name=self.name
        ))

        return arn

    def clobber(self):
        """Delete this compute environment"""
        if self.clobbered:
            return

        self.check_profile_and_region()

        retry = tenacity.Retrying(
            wait=tenacity.wait_exponential(max=16),
            stop=tenacity.stop_after_delay(180),
            retry=tenacity.retry_if_exception_type(
                clients['batch'].exceptions.ClientException
            )
        )

        # First set the state to disabled
        retry.call(
            clients['batch'].update_compute_environment,
            computeEnvironment=self.arn,
            state='DISABLED'
        )

        # Now get the associated ECS cluster
        response = clients['batch'].describe_compute_environments(
            computeEnvironments=[self.arn]
        )
        cluster_arn = response.get('computeEnvironments')[0]['ecsClusterArn']

        # Get container instances
        response = clients['ecs'].list_container_instances(
            cluster=cluster_arn,
        )
        instances = response.get('containerInstanceArns')

        for i in instances:
            clients['ecs'].deregister_container_instance(
                cluster=cluster_arn,
                containerInstance=i,
                force=True
            )

        retry_if_exception = tenacity.Retrying(
            wait=tenacity.wait_exponential(max=16),
            stop=tenacity.stop_after_delay(300),
            retry=tenacity.retry_if_exception_type()
        )
        retry_if_exception.call(
            clients['ecs'].delete_cluster,
            cluster=cluster_arn
        )

        # Wait for any associated job queues to finish updating
        response = clients['batch'].describe_job_queues()
        associated_queues = list(filter(
            lambda q: self.arn in [
                ce['computeEnvironment'] for ce
                in q['computeEnvironmentOrder']
            ],
            response.get('jobQueues')
        ))

        try:
            retry.call(
                clients['batch'].delete_compute_environment,
                computeEnvironment=self.arn
            )
        except clients['batch'].exceptions.ClientException as error:
            error_message = error.response['Error']['Message']
            if error_message == 'Cannot delete, found existing ' \
                                'JobQueue relationship':  # pragma: nocover
                raise CannotDeleteResourceException(
                    'Could not delete this compute environment '
                    'because it has job queue(s) associated with it. '
                    'If you want to delete this compute environment, '
                    'first delete the job queues with the following '
                    'ARNS: {queues!s}'.format(queues=associated_queues),
                    resource_id=associated_queues
                )
        except tenacity.RetryError as e:
            try:
                e.reraise()
            except clients['batch'].exceptions.ClientException as error:
                error_message = error.response['Error']['Message']
                if error_message == 'Cannot delete, found existing ' \
                                    'JobQueue relationship':  # pragma: nocover
                    raise CannotDeleteResourceException(
                        'Could not delete this compute environment '
                        'because it has job queue(s) associated with it. '
                        'If you want to delete this compute environment, '
                        'first delete the job queues with the following '
                        'ARNS: {queues!s}'.format(queues=associated_queues),
                        resource_id=associated_queues
                    )

        # Remove this compute env from the list of compute envs in config file
        cloudknot.config.remove_resource(self._section_name, self.name)

        # Set the clobbered parameter to True,
        # preventing subsequent method calls
        self._clobbered = True

        mod_logger.info('Clobbered compute environment {name:s}'.format(
            name=self.name
        ))


# noinspection PyPropertyAccess,PyAttributeOutsideInit
class JobQueue(ObjectWithArn):
    """Class for defining AWS Batch Job Queues"""
    def __init__(self, arn=None, name=None, compute_environments=None,
                 priority=None):
        """Initialize an AWS Batch job definition object.

        Parameters
        ----------
        arn : string
            Amazon Resource Number of the job definition

        name : string
            Name of the job definition

        compute_environments : ComputeEnvironment or tuple(ComputeEnvironments)
            ComputeEnvironment instance or sequence of ComputeEnvironment
            instances (in order of priority) for this job queue to use

        priority : int
            priority for jobs in this queue
            Default: 1
        """
        # Test for minimum input
        if not (arn or name):
            raise ValueError(
                'You must supply either an arn or name for this '
                'job queue.'
            )

        # Test for over-specified input
        if arn and any([name, compute_environments, priority]):
            raise ValueError(
                'You may supply either an arn or (name, '
                'compute_environments, and priority), but not '
                'both.'
            )

        # Check if this job queue already exists
        resource = self._exists_already(arn=arn, name=name)
        self._pre_existing = resource.exists

        if resource.exists:
            # If pre-existing, then user supplied either arn or name. Above,
            # we raised error if user provided arn plus input parameters.
            # Now, check that they did not provide a pre-existing name plus
            # input parameters
            if name and any([compute_environments, priority]):
                raise ResourceExistsException(
                    'You provided input parameters for a job queue that '
                    'already exists. If you would like to create a new job '
                    'queue, please use a different name. If you would like '
                    'to retrieve the details of this job queue, use JobQueue('
                    'arn={arn:s})'.format(arn=resource.arn),
                    resource.arn
                )

            # Fill parameters with queried values
            super(JobQueue, self).__init__(name=resource.name)
            self._compute_environments = None
            self._compute_environment_arns = resource.compute_environment_arns
            self._priority = resource.priority
            self._arn = resource.arn

            self._section_name = self._get_section_name('job-queues')
            cloudknot.config.add_resource(
                self._section_name, self.name, self.arn
            )

            mod_logger.info('Retrieved pre-existing job queue {name:s}'.format(
                name=self.name
            ))
        else:
            # If user supplied only a name or only an arn, expecting to
            # retrieve info on pre-existing job queue, throw error
            if arn or (name and not compute_environments):
                raise ResourceDoesNotExistException(
                    'The job queue you requested does not exist.',
                    arn
                )

            super(JobQueue, self).__init__(name=name)
            # Otherwise, validate input and set parameters
            # Validate compute environments
            if isinstance(compute_environments, ComputeEnvironment):
                self._compute_environments = (compute_environments,)
            elif all(isinstance(x, ComputeEnvironment)
                     for x in compute_environments
                     ):
                self._compute_environments = tuple(compute_environments)
            else:
                raise ValueError(
                    'compute_environments must be a '
                    'ComputeEnvironment instance or a sequence '
                    'of ComputeEnvironment instances.'
                )

            # Assign compute environment arns,
            # based on ComputeEnvironment input
            self._compute_environment_arns = []
            for i, ce in enumerate(self._compute_environments):
                self._compute_environment_arns.append({
                    'order': i,
                    'computeEnvironment': ce.arn
                })

            # Validate priority
            if priority:
                p_int = int(priority)
                if p_int < 1:
                    raise ValueError('priority must be positive')
                else:
                    self._priority = p_int
            else:
                self._priority = 1

            # Create job queue and assign arn
            self._arn = self._create()

    # Declare properties
    @property
    def pre_existing(self):
        """Boolean flag to indicate whether this resource was pre-existing

        True if resource was retrieved from AWS,
        False if it was created on __init__.
        """
        return self._pre_existing

    @property
    def compute_environments(self):
        """ComputeEnvironment instances for this job queue to use"""
        return self._compute_environments

    @property
    def compute_environment_arns(self):
        """Dictionary of this queue's compute environments and priorities"""
        return self._compute_environment_arns

    @property
    def priority(self):
        """Priority for jobs in this queue"""
        return self._priority

    def _exists_already(self, arn, name):
        """Check if an AWS job queue exists already

        If job queue exists, return namedtuple with job queue info.
        Otherwise, set the namedtuple's `exists` field to `False`.
        The remaining fields default to `None`.

        Returns
        -------
        namedtuple RoleExists
            A namedtuple with fields
            ['exists', 'name', 'compute_environment_arns', 'priority', 'arn']
        """
        # define a namedtuple for return value type
        ResourceExists = namedtuple(
            'ResourceExists',
            ['exists', 'name', 'compute_environment_arns', 'priority', 'arn']
        )
        # make all but the first value default to None
        ResourceExists.__new__.__defaults__ = \
            (None,) * (len(ResourceExists._fields) - 1)

        if arn:
            # Search by ARN
            response = clients['batch'].describe_job_queues(
                jobQueues=[arn]
            )
        else:
            # Search by name
            response = clients['batch'].describe_job_queues(
                jobQueues=[name]
            )

        q = response.get('jobQueues')
        if q:
            arn = q[0]['jobQueueArn']
            name = q[0]['jobQueueName']
            compute_environment_arns = q[0]['computeEnvironmentOrder']
            priority = q[0]['priority']

            mod_logger.info('Job Queue {name:s} already exists.'.format(
                name=name
            ))

            return ResourceExists(
                exists=True, priority=priority, name=name, arn=arn,
                compute_environment_arns=compute_environment_arns
            )
        else:
            return ResourceExists(exists=False)

    def _create(self):
        """Create AWS batch job queue using instance parameters

        Returns
        -------
        string
            Amazon Resource Number (ARN) for the created job queue
        """
        # The job queue depends on a compute environment that may still be
        # updating or in the process of creation. Use tenacity.Retrying to
        # overcome this latency
        retry = tenacity.Retrying(
            wait=tenacity.wait_exponential(max=16),
            stop=tenacity.stop_after_delay(60),
            retry=tenacity.retry_if_exception_type(
                clients['batch'].exceptions.ClientException
            )
        )

        response = retry.call(
            clients['batch'].create_job_queue,
            jobQueueName=self.name,
            state='ENABLED',
            priority=self.priority,
            computeEnvironmentOrder=self.compute_environment_arns
        )

        arn = response['jobQueueArn']

        # Wait for job queue to be in VALID state
        wait_for_job_queue(name=self.name, max_wait_time=180)

        # Add this job queue to the list of job queues in the config file
        self._section_name = self._get_section_name('job-queues')
        cloudknot.config.add_resource(self._section_name, self.name, arn)

        mod_logger.info('Created job queue {name:s}'.format(name=self.name))

        return arn

    def get_jobs(self, status='ALL'):
        """Get jobs in this job queue

        Parameters
        ----------
        status : string
            The status on which to filter job results
            Default: 'ALL'

        Returns
        -------
        job_ids : list
            A list of job-IDs for jobs in this queue
        """
        if self.clobbered:
            raise ResourceClobberedException(
                'This job queue has already been clobbered.',
                self.arn
            )

        self.check_profile_and_region()

        # Validate input
        allowed_statuses = ['ALL', 'SUBMITTED', 'PENDING', 'RUNNABLE',
                            'STARTING', 'RUNNING', 'SUCCEEDED', 'FAILED']
        if status not in allowed_statuses:
            raise ValueError('status must be one of ', allowed_statuses)

        if status == 'ALL':
            # status == 'ALL' is equivalent to not specifying a status at all
            response = clients['batch'].list_jobs(jobQueue=self.arn)
        else:
            # otherwise, filter on status
            response = clients['batch'].list_jobs(
                jobQueue=self.arn, jobStatus=status
            )

        # Return list of job_ids
        return response.get('jobSummaryList')

    def clobber(self):
        """Delete this batch job queue"""
        if self.clobbered:
            return

        self.check_profile_and_region()

        # First, disable submissions to the queue
        retry = tenacity.Retrying(
            wait=tenacity.wait_exponential(max=16),
            stop=tenacity.stop_after_delay(60),
            retry=tenacity.retry_if_exception_type(
                clients['batch'].exceptions.ClientException
            )
        )

        retry.call(
            clients['batch'].update_job_queue,
            jobQueue=self.arn,
            state='DISABLED'
        )

        # Next, terminate all jobs that have not completed
        for status in [
            'SUBMITTED', 'PENDING', 'RUNNABLE', 'STARTING', 'RUNNING'
        ]:  # pragma: nocover
            # No unit test coverage here since it costs money to submit,
            # and then terminate, batch jobs
            jobs = self.get_jobs(status=status)
            for job in jobs:
                jid = job['jobId']
                retry.call(
                    clients['batch'].terminate_job,
                    jobId=jid,
                    reason='Terminated to force job queue deletion'
                )

                mod_logger.info('Terminated job {jid:s}'.format(jid=jid))

        # Finally, delete the job queue
        retry.call(clients['batch'].delete_job_queue, jobQueue=self.arn)

        # Remove this job queue from the list of job queues in config file
        cloudknot.config.remove_resource(self._section_name, self.name)

        # Set the clobbered parameter to True,
        # preventing subsequent method calls
        self._clobbered = True

        mod_logger.info('Clobbered job queue {name:s}'.format(name=self.name))


# noinspection PyPropertyAccess,PyAttributeOutsideInit
class BatchJob(NamedObject):
    """Class for defining AWS Batch Job"""
    def __init__(self, job_id=None, name=None, job_queue=None,
                 job_definition=None, input=None, starmap=False,
                 environment_variables=None):
        """Initialize an AWS Batch Job object.

        If requesting information on a pre-existing job, `job_id` is required.
        Otherwise, `name`, `job_queue`, and `job_definition` are required to
        submit a new job.

        Parameters
        ----------
        job_id: string
            The AWS jobID, if requesting a job that already exists

        name : string
            Name of the job

        job_queue : JobQueue
            JobQueue instance specifying the job queue to which this job
            will be submitted

        job_definition : JobDefinition
            JobDefinition instance specifying the job definition on which
            to base this job

        input :
            The input to be pickled and sent to the batch job via S3

        starmap : bool
            If True, assume input is already grouped in
            tuples from a single iterable.

        environment_variables : list of dict
            list of key/value pairs representing environment variables
            sent to the container
        """
        has_input = input is not None
        if not (job_id or all([name, job_queue, has_input, job_definition])):
            raise ValueError('You must supply either job_id or (name, '
                             'input, job_queue, and job_definition).')

        if job_id and any([name, job_queue, has_input, job_definition]):
            raise ValueError('You may supply either job_id or (name, '
                             'input, job_queue, and job_definition), '
                             'not both.')

        self._starmap = starmap

        if job_id:
            job = self._exists_already(job_id=job_id)
            if not job.exists:
                raise ResourceDoesNotExistException(
                    'jobId {id:s} does not exists'.format(id=job_id),
                    job_id
                )

            super(BatchJob, self).__init__(name=job.name)

            self._job_queue = None
            self._job_queue_arn = job.job_queue_arn
            self._job_definition_arn = job.job_definition_arn
            self._job_definition = JobDefinition(arn=self._job_definition_arn)
            self._environment_variables = job.environment_variables
            self._job_id = job.job_id

            bucket = self._job_definition.output_bucket
            key = '/'.join([
                'cloudknot.jobs',
                self._job_definition.name,
                self._job_id,
                'input.pickle'
            ])

            try:
                response = clients['s3'].get_object(Bucket=bucket, Key=key)
                self._input = pickle.loads(response.get('Body').read())
            except (clients['s3'].exceptions.NoSuchBucket,
                    clients['s3'].exceptions.NoSuchKey):
                self._input = None

            self._section_name = self._get_section_name('batch-jobs')
            cloudknot.config.add_resource(
                self._section_name, self.job_id, self.name
            )

            mod_logger.info('Retrieved pre-existing batch job {id:s}'.format(
                id=self.job_id
            ))
        else:
            super(BatchJob, self).__init__(name=name)

            if not isinstance(job_queue, JobQueue):
                raise ValueError('job_queue must be a JobQueue instance')
            self._job_queue = job_queue
            self._job_queue_arn = job_queue.arn

            if not isinstance(job_definition, JobDefinition):
                raise ValueError('job_queue must be a JobQueue instance')
            self._job_definition = job_definition
            self._job_definition_arn = job_definition.arn

            if environment_variables:
                if not all(isinstance(s, dict) for s in environment_variables):
                    raise ValueError('env_vars must be a sequence of dicts')
                if not all(set(d.keys()) == {'name', 'value'}
                           for d in environment_variables):
                    raise ValueError('each dict in env_vars must have '
                                     'keys "name" and "value"')
                self._environment_variables = environment_variables
            else:
                self._environment_variables = None

            self._input = input
            self._job_id = self._create()

    @property
    def job_queue(self):
        """JobQueue instance to which this job will be submitted"""
        return self._job_queue

    @property
    def job_queue_arn(self):
        """ARN for the job queue to which this job will be submitted"""
        return self._job_queue_arn

    @property
    def job_definition(self):
        """JobDefinition instance on which to base this job"""
        return self._job_definition

    @property
    def job_definition_arn(self):
        """The ARN for the job definition on which to base this job"""
        return self._job_definition_arn

    @property
    def environment_variables(self):
        """Key/value pairs for environment variables sent to the container"""
        return self._environment_variables

    @property
    def input(self):
        """The input to be pickled and sent to the batch job via S3"""
        return self._input

    @property
    def starmap(self):
        """Boolean flag to indicate whether input was 'pre-zipped'"""
        return self._starmap

    @property
    def job_id(self):
        """This job's AWS jobID"""
        return self._job_id

    def _exists_already(self, job_id):
        """Check if an AWS batch job exists already

        If batch job exists, return namedtuple with batch job info.
        Otherwise, set the namedtuple's `exists` field to
        `False`. The remaining fields default to `None`.

        Returns
        -------
        namedtuple JobExists
            A namedtuple with fields
            ['exists', 'name', 'job_id', 'job_queue_arn',
             'job_definition_arn', 'environment_variables']
        """
        # define a namedtuple for return value type
        JobExists = namedtuple(
            'JobExists',
            ['exists', 'name', 'job_id', 'job_queue_arn',
             'job_definition_arn', 'environment_variables']
        )
        # make all but the first value default to None
        JobExists.__new__.__defaults__ = \
            (None,) * (len(JobExists._fields) - 1)

        response = clients['batch'].describe_jobs(jobs=[job_id])

        if response.get('jobs'):
            job = response.get('jobs')[0]
            name = job['jobName']
            job_queue_arn = job['jobQueue']
            job_definition_arn = job['jobDefinition']
            environment_variables = job['container']['environment']

            mod_logger.info('Job {id:s} exists.'.format(id=job_id))

            return JobExists(
                exists=True, name=name, job_id=job_id,
                job_queue_arn=job_queue_arn,
                job_definition_arn=job_definition_arn,
                environment_variables=environment_variables
            )
        else:
            return JobExists(exists=False)

    def _create(self):  # pragma: nocover
        """Create AWS batch job using instance parameters

        Returns
        -------
        string
            job ID for the created batch job
        """
        # no coverage since actually submitting a batch job for
        # unit testing would be expensive
        bucket = self.job_definition.output_bucket
        pickled_input = cloudpickle.dumps(self.input)

        command = [self.job_definition.output_bucket]
        if self.starmap:
            command = ['--starmap'] + command

        if self.environment_variables:
            container_overrides = {
                'environment': self.environment_variables,
                'command': command
            }
        else:
            container_overrides = {
                'command': command
            }

        # We have to submit before uploading the input in order to get the
        # jobID first.
        response = clients['batch'].submit_job(
            jobName=self.name,
            jobQueue=self.job_queue_arn,
            jobDefinition=self.job_definition_arn,
            containerOverrides=container_overrides
        )

        job_id = response['jobId']
        key = '/'.join([
            'cloudknot.jobs', self.job_definition.name, job_id, 'input.pickle'
        ])

        # Upload the input pickle
        clients['s3'].put_object(Bucket=bucket, Body=pickled_input, Key=key)

        # Add this job to the list of jobs in the config file
        self._section_name = self._get_section_name('batch-jobs')
        cloudknot.config.add_resource(
            self._section_name, job_id, self.name
        )

        mod_logger.info(
            'Submitted batch job {name:s} with jobID '
            '{job_id:s}'.format(name=self.name, job_id=job_id)
        )

        return job_id

    @property
    def status(self):
        """Query AWS batch job status using instance parameter `self.job_id`

        Returns
        -------
        status : dict
            dictionary with keys: {status, statusReason, attempts}
            for this AWS batch job
        """
        if self.clobbered:
            raise ResourceClobberedException(
                'This batch job has already been clobbered.',
                self.job_id
            )

        self.check_profile_and_region()

        # Query the job_id
        response = clients['batch'].describe_jobs(jobs=[self.job_id])
        job = response.get('jobs')[0]

        # Return only a subset of the job dictionary
        status = {k: job.get(k)
                  for k in ('status', 'statusReason', 'attempts')}

        return status

    @ property
    def log_urls(self):
        """Return the urls of the batch job logs on AWS Cloudwatch

        Returns
        -------
        log_urls : list
            A list of log urls for each attempt number. If the job has
            not yet run, this will return an empty list
        """
        attempts = sorted(self.status['attempts'],
                          key=lambda a: a['startedAt'])

        log_stream_names = [a['container'].get('logStreamName')
                            for a in attempts]

        def log_name2url(log_name):
            return 'https://console.aws.amazon.com/cloudwatch/home?region=' \
                   '{region:s}#logEventViewer:group=/aws/batch/job;' \
                   'stream={log_name:s}'.format(region=self.region,
                                                log_name=log_name)

        log_urls = [log_name2url(log) for log in log_stream_names]

        return log_urls

    @property
    def done(self):
        """Return True if the job is done.

        In this case, "done" means the job status is SUCCEEDED or that it is
        FAILED and the job has exceeded the max number of retry attempts
        """
        stat = self.status
        done = (stat['status'] == 'SUCCEEDED'
                or (stat['status'] == 'FAILED'
                    and len(stat['attempts']) >= self.job_definition.retries))

        return done

    def result(self, timeout=None):
        """Return the result of the latest attempt

        If the call hasn't yet completed then this method will wait up to
        timeout seconds. If the call hasn't completed in timeout seconds,
        then a CKTimeoutError is raised. If the batch job is in FAILED status
        then a BatchJobFailedError is raised.

        Parameters
        ----------
        timeout: int or float
            timeout time in seconds. If timeout is not specified or None,
            there is no limit to the wait time.
            Default: None

        Returns
        -------
        result:
            The result of the AWS Batch job
        """
        # Set start time for timeout period
        start_time = datetime.now()

        def time_diff():
            return (datetime.now() - start_time).seconds

        while not self.done and (timeout is None or time_diff() < timeout):
            time.sleep(5)

        if not self.done:
            raise CKTimeoutError(self.job_id)

        status = self.status
        if status['status'] == 'FAILED':
            raise BatchJobFailedError(self.job_id)
        else:
            bucket = self.job_definition.output_bucket
            key = '/'.join([
                'cloudknot.jobs', self.job_definition.name, self.job_id,
                '{0:3d}'.format(len(status['attempts'])), 'output.pickle'
            ])

            response = clients['s3'].get_object(Bucket=bucket, Key=key)
            return pickle.loads(response.get('Body').read())

    def terminate(self, reason):
        """Kill AWS batch job using instance parameter `self.job_id`

        kill() combines the cancel and terminate AWS CLI commands. Jobs that
        are in the SUBMITTED, PENDING, or RUNNABLE state must be cancelled,
        while jobs that are in the STARTING or RUNNING state must be
        terminated.

        Parameters
        ----------
        reason : string
            A message to attach to the job that explains the reason for
            cancelling/terminating it. This message is returned by future
            DescribeJobs operations on the job. This message is also recorded
            in the AWS Batch activity logs.
        """
        if self.clobbered:
            raise ResourceClobberedException(
                'This batch job has already been clobbered.',
                self.job_id
            )

        self.check_profile_and_region()

        # Require the user to supply a reason for job termination
        if not isinstance(reason, six.string_types):
            raise ValueError('reason must be a string.')

        state = self.status['status']

        if state in ['SUBMITTED', 'PENDING', 'RUNNABLE']:
            clients['batch'].cancel_job(jobId=self.job_id, reason=reason)
            mod_logger.info(
                'Cancelled job {name:s} with jobID {job_id:s}'.format(
                    name=self.name, job_id=self.job_id
                )
            )
        elif state in ['STARTING', 'RUNNING']:
            clients['batch'].terminate_job(jobId=self.job_id, reason=reason)
            mod_logger.info(
                'Terminated job {name:s} with jobID {job_id:s}'.format(
                    name=self.name, job_id=self.job_id
                )
            )

    def clobber(self):
        """Kill an batch job and remove it's info from config"""
        if self.clobbered:
            return

        self.check_profile_and_region()

        self.terminate(reason='Cloudknot job killed after calling '
                              'BatchJob.clobber()')

        # Set the clobbered parameter to True,
        # preventing subsequent method calls
        self._clobbered = True

        # Remove this job from the list of jobs in the config file
        cloudknot.config.remove_resource(self._section_name, self.job_id)
