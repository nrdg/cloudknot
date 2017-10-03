from __future__ import absolute_import, division, print_function

import cloudknot.config
import logging
import operator
import tenacity
from collections import namedtuple

from .base_classes import NamedObject, ObjectWithArn, \
    ObjectWithUsernameAndMemory, BATCH, \
    ResourceExistsException, ResourceDoesNotExistException, \
    CannotDeleteResourceException, wait_for_compute_environment, \
    wait_for_job_queue
from .ec2 import Vpc, SecurityGroup
from .ecr import DockerImage
from .iam import IamRole

__all__ = ["JobDefinition", "JobQueue",
           "ComputeEnvironment", "BatchJob"]


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

        docker_image : DockerImage or string
            DockerImage instance for the container to be used in this job
            definition
            or string containing location of docker image on Docker Hub or
            other repository

        vcpus : int
            number of virtual cpus to be used to this job definition
            Default: 1

        memory : int
            memory (MiB) to be used for this job definition
            Default: 32000

        username : string
            username for be used for this job definition
            Default: cloudknot-user

        retries : int
            number of times a job can be moved to 'RUNNABLE' status.
            May be between 1 and 10
            Default: 3
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

        resource = self._exists_already(arn=arn, name=name)
        self._pre_existing = resource.exists

        if resource.exists:
            # Resource exists, if user tried to specify resource parameters,
            # throw error
            if any([
                job_role, docker_image, vcpus, memory, username, retries
            ]):
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

            self._job_role = resource.job_role
            self._docker_image = resource.docker_image
            self._vcpus = resource.vcpus
            self._retries = resource.retries
            self._arn = resource.arn

            if resource.status == 'INACTIVE':
                raise ResourceExistsException(
                    'You retrieved an inactive job definition and cloudknot '
                    'has no way to reactivate it. Instead of retrieving the '
                    'job definition using an ARN, create a new one with your '
                    'desired properties.',
                    resource.arn
                )

            # Add to config file
            cloudknot.config.add_resource(
                'job-definitions', self.name, self.arn
            )

            logging.info(
                'Retrieved pre-existing job definition {name:s}'.format(
                    name=self.name
                )
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
            memory = memory if memory else 32000

            super(JobDefinition, self).__init__(
                name=name, memory=memory, username=username
            )

            # Validate job role input
            if not isinstance(job_role, IamRole):
                raise ValueError('job_role must be an instance of IamRole')
            self._job_role = job_role

            # Validate docker_image input
            if not (isinstance(docker_image, DockerImage)
                    or isinstance(docker_image, str)):
                raise ValueError(
                    'docker_image must be an instance of DockerImage '
                    'or a string'
                )
            self._docker_image = docker_image

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
                self._retries = 3

            self._arn = self._create()

    # Declare read-only parameters
    pre_existing = property(operator.attrgetter('_pre_existing'))
    job_role = property(operator.attrgetter('_job_role'))
    docker_image = property(operator.attrgetter('_docker_image'))
    vcpus = property(operator.attrgetter('_vcpus'))
    retries = property(operator.attrgetter('_retries'))

    def _exists_already(self, arn, name):
        """Check if an AWS Job Definition exists already

        If definition exists, return namedtuple with job definition info.
        Otherwise, set the namedtuple's `exists` field to `False`. The
        remaining fields default to `None`.

        Returns
        -------
        namedtuple RoleExists
            A namedtuple with fields ['exists', 'name', 'status', 'job_role',
            'docker_image', 'vcpus', 'memory', 'username', 'retries', 'arn']
        """
        # define a namedtuple for return value type
        ResourceExists = namedtuple(
            'ResourceExists',
            ['exists', 'name', 'status', 'job_role', 'docker_image', 'vcpus',
             'memory', 'username', 'retries', 'arn']
        )
        # make all but the first value default to None
        ResourceExists.__new__.__defaults__ = \
            (None,) * (len(ResourceExists._fields) - 1)

        if arn:
            # Retrieve using ARN
            response = BATCH.describe_job_definitions(jobDefinitions=[arn])
        else:
            # Retrieve using name
            response = BATCH.describe_job_definitions(jobDefinitionName=name)

        if response.get('jobDefinitions'):
            # Job def exists. Get job def details
            job_def = response.get('jobDefinitions')[0]
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

            logging.info('Job definition {name:s} already exists.'.format(
                name=job_def_name
            ))

            return ResourceExists(
                exists=True, name=job_def_name, status=job_def_status,
                job_role=job_role_arn, docker_image=container_image,
                vcpus=vcpus, memory=memory, username=username,
                retries=retries, arn=job_def_arn
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
        # Else it's a DockerImage instance, get the uri property
        image = self.docker_image if isinstance(self.docker_image, str) \
            else self.docker_image.uri

        job_container_properties = {
            'image': image,
            'vcpus': self.vcpus,
            'memory': self.memory,
            'command': [],
            'jobRoleArn': self.job_role.arn,
            'user': self.username
        }

        # Register the job def
        response = BATCH.register_job_definition(
            jobDefinitionName=self.name,
            type='container',
            containerProperties=job_container_properties,
            retryStrategy={'attempts': self.retries}
        )

        arn = response['jobDefinitionArn']

        # Add this job def to the list of job definitions in the config file
        cloudknot.config.add_resource('job-definitions', self.name, arn)

        logging.info('Created AWS batch job definition {name:s}'.format(
            name=self.name
        ))

        return arn

    def clobber(self):
        """Deregister this AWS batch job definition

        Returns
        -------
        None
        """
        BATCH.deregister_job_definition(jobDefinition=self.arn)

        # Remove this job def from the list of job defs in the config file
        cloudknot.config.remove_resource('job-definitions', self.name)

        logging.info('Deregistered job definition {name:s}'.format(
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
            optional IamRole instance for the AWS IAM spot fleet role
            Default: None

        instance_types : string or sequence of strings
            instance types that may be launched in this compute environment
            Default: ('optimal',)

        resource_type : string
            Resource type, either "EC2" or "SPOT"

        min_vcpus : int
            minimum number of virtual cpus for instances launched in this
            compute environment
            Default: 0

        max_vcpus : int
            maximum number of virtual cpus for instances launched in this
            compute environment
            Default: 256

        desired_vcpus : int
            desired number of virtual cpus for instances launched in this
            compute environment
            Default: 8

        image_id : string
            optional AMI id used for instances launched in this compute
            environment
            Default: None

        ec2_key_pair : string
            optional EC2 key pair used for instances launched in this compute
            environment
            Default: None

        tags : dictionary
            optional key-value pair tags to be applied to resources in this
            compute environment
            Default: None

        bid_percentage : int
            bid percentage if using spot instances
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
            self._batch_service_arn = resource.batch_service_arn

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

            cloudknot.config.add_resource(
                'compute-environments', self.name, self.arn
            )

            logging.info(
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
            self._batch_service_arn = batch_service_role.arn

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
            instance_types = instance_types if instance_types else ('optimal',)
            if isinstance(instance_types, str):
                self._instance_types = [instance_types]
            elif all(isinstance(x, str) for x in instance_types):
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
                    'instance_types must be a subset of {types:s}'.format(
                        types=str(valid_instance_types)
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
                if not isinstance(image_id, str):
                    raise ValueError('if provided, image_id must be a string')
                self._image_id = image_id
            else:
                self._image_id = None

            # Validate ec2_key_pair input
            if ec2_key_pair:
                if not isinstance(ec2_key_pair, str):
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
                    logging.warning(
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
    pre_existing = property(operator.attrgetter('_pre_existing'))
    batch_service_role = property(operator.attrgetter('_batch_service_role'))
    batch_service_arn = property(operator.attrgetter('_batch_service_arn'))

    instance_role = property(operator.attrgetter('_instance_role'))
    instance_role_arn = property(operator.attrgetter('_instance_role_arn'))

    vpc = property(operator.attrgetter('_vpc'))
    subnets = property(operator.attrgetter('_subnets'))

    security_group = property(operator.attrgetter('_security_group'))
    security_group_ids = property(operator.attrgetter('_security_group_ids'))

    spot_fleet_role = property(operator.attrgetter('_spot_fleet_role'))
    spot_fleet_role_arn = property(operator.attrgetter('_spot_fleet_role_arn'))

    instance_types = property(operator.attrgetter('_instance_types'))
    resource_type = property(operator.attrgetter('_resource_type'))
    min_vcpus = property(operator.attrgetter('_min_vcpus'))
    max_vcpus = property(operator.attrgetter('_max_vcpus'))
    desired_vcpus = property(operator.attrgetter('_desired_vcpus'))
    image_id = property(operator.attrgetter('_image_id'))
    ec2_key_pair = property(operator.attrgetter('_ec2_key_pair'))
    tags = property(operator.attrgetter('_tags'))
    bid_percentage = property(operator.attrgetter('_bid_percentage'))

    def _exists_already(self, arn, name):
        """Check if a compute environment exists already

        If compute environment exists, return namedtuple with compute
        environment info. Otherwise, set the namedtuple's `exists` field to
        `False`. The remaining fields default to `None`.

        Returns
        -------
        namedtuple ResourceExists
            A namedtuple with fields
            ['exists', 'name', 'batch_service_arn', 'instance_role_arn',
             'subnets', 'security_group_ids', 'spot_fleet_role_arn',
             'instance_types', 'resource_type', 'min_vcpus', 'max_vcpus',
             'desired_vcpus', 'image_id', 'ec2_key_pair', 'tags',
             'bid_percentage', 'arn']
        """
        # define a namedtuple for return value type
        ResourceExists = namedtuple(
            'ResourceExists',
            ['exists', 'name', 'batch_service_arn', 'instance_role_arn',
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
            response = BATCH.describe_compute_environments(
                computeEnvironments=[arn]
            )
        else:
            # Search by name
            response = BATCH.describe_compute_environments(
                computeEnvironments=[name]
            )

        if response.get('computeEnvironments'):
            ce = response.get('computeEnvironments')[0]
            ce_name = ce['computeEnvironmentName']
            batch_service_arn = ce['serviceRole']
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

            logging.info('Compute environment {name:s} already exists.'.format(
                name=ce_name
            ))

            return ResourceExists(
                exists=True, name=ce_name, batch_service_arn=batch_service_arn,
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

        response = BATCH.create_compute_environment(
            computeEnvironmentName=self.name,
            type='MANAGED',
            state='ENABLED',
            computeResources=compute_resources,
            serviceRole=self.batch_service_arn
        )

        arn = response['computeEnvironmentArn']

        # Add this compute env to the list of compute envs in the config file
        cloudknot.config.add_resource('compute-environments', self.name, arn)

        logging.info('Created compute environment {name:s}'.format(
            name=self.name
        ))

        return arn

    def clobber(self):
        """Delete this compute environment

        Returns
        -------
        None
        """
        # First set the state to disabled
        wait_for_compute_environment(arn=self.arn, name=self.name)
        BATCH.update_compute_environment(
            computeEnvironment=self.arn,
            state='DISABLED'
        )

        # Wait for any associated job queues to finish updating
        response = BATCH.describe_job_queues()
        associated_queues = list(filter(
            lambda q: self.arn in [
                ce['computeEnvironment'] for ce
                in q['computeEnvironmentOrder']
            ],
            response.get('jobQueues')
        ))

        for queue in associated_queues:
            wait_for_job_queue(name=queue['jobQueueName'])

        retry = tenacity.Retrying(
            wait=tenacity.wait_exponential(max=60),
            stop=tenacity.stop_after_delay(30),
            retry=tenacity.retry_if_exception_type(
                BATCH.exceptions.ClientException
            )
        )

        wait_for_compute_environment(arn=self.arn, name=self.name)
        try:
            retry.call(
                BATCH.delete_compute_environment,
                computeEnvironment=self.arn
            )
        except tenacity.RetryError as e:
            try:
                e.reraise()
            except BATCH.exceptions.ClientException as error:
                error_message = e.response['Error']['Message']
                if error_message == 'Cannot delete, found existing ' \
                                    'JobQueue relationship':
                    raise CannotDeleteResourceException(
                        'Could not delete this compute environment '
                        'because it has job queue(s) associated with it. '
                        'If you want to delete this compute environment, '
                        'first delete the job queues with the following '
                        'ARNS: {queues:s}'.format(
                            queues=str(associated_queues)
                        ),
                        resource_id=associated_queues
                    )

        # Remove this compute env from the list of compute envs
        # in config file
        cloudknot.config.remove_resource('compute-environments', self.name)

        logging.info('Clobbered compute environment {name:s}'.format(
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

            cloudknot.config.add_resource('job-queues', self.name, self.arn)

            logging.info('Retrieved pre-existing job queue {name:s}'.format(
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
    pre_existing = property(operator.attrgetter('_pre_existing'))
    compute_environments = property(
        operator.attrgetter('_compute_environments')
    )
    compute_environment_arns = property(
        operator.attrgetter('_compute_environment_arns')
    )
    priority = property(operator.attrgetter('_priority'))

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
            response = BATCH.describe_job_queues(
                jobQueues=[arn]
            )
        else:
            # Search by name
            response = BATCH.describe_job_queues(
                jobQueues=[name]
            )

        q = response.get('jobQueues')
        if q:
            arn = q[0]['jobQueueArn']
            name = q[0]['jobQueueName']
            compute_environment_arns = q[0]['computeEnvironmentOrder']
            priority = q[0]['priority']

            logging.info('Job Queue {name:s} already exists.'.format(
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
        response = BATCH.create_job_queue(
            jobQueueName=self.name,
            state='ENABLED',
            priority=self.priority,
            computeEnvironmentOrder=self.compute_environment_arns
        )

        arn = response['jobQueueArn']

        # Wait for job queue to be in VALID state
        wait_for_job_queue(name=self.name, max_wait_time=180)

        # Add this job queue to the list of job queues in the config file
        cloudknot.config.add_resource('job-queues', self.name, arn)

        logging.info('Created job queue {name:s}'.format(name=self.name))

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
        # Validate input
        allowed_statuses = ['ALL', 'SUBMITTED', 'PENDING', 'RUNNABLE',
                            'STARTING', 'RUNNING', 'SUCCEEDED', 'FAILED']
        if status not in allowed_statuses:
            raise ValueError('status must be one of ', allowed_statuses)

        if status == 'ALL':
            # status == 'ALL' is equivalent to not specifying a status at all
            response = BATCH.list_jobs(jobQueue=self.arn)
        else:
            # otherwise, filter on status
            response = BATCH.list_jobs(jobQueue=self.arn, jobStatus=status)

        # Return list of job_ids
        return response.get('jobSummaryList')

    def clobber(self):
        """Delete this batch job queue

        Returns
        -------
        None
        """
        # First, disable submissions to the queue
        wait_for_job_queue(self.name, max_wait_time=180)
        retry = tenacity.Retrying(
            wait=tenacity.wait_exponential(max=60),
            stop=tenacity.stop_after_delay(500),
            retry=tenacity.retry_if_exception_type(
                BATCH.exceptions.ClientException
            )
        )
        retry.call(BATCH.update_job_queue, jobQueue=self.arn, state='DISABLED')

        # Next, terminate all jobs that have not completed
        for status in [
            'SUBMITTED', 'PENDING', 'RUNNABLE', 'STARTING', 'RUNNING'
        ]:  # pragma: nocover
            # No unit test coverage here since it costs money to submit,
            # and then terminate, batch jobs
            jobs = self.get_jobs(status=status)
            for job_id in jobs:
                BATCH.terminate_job(
                    jobId=job_id,
                    reason='Terminated to force job queue deletion'
                )

                logging.info('Terminated job {id:s}'.format(id=job_id))

        wait_for_job_queue(self.name, max_wait_time=180)

        # Finally, delete the job queue
        BATCH.delete_job_queue(jobQueue=self.arn)

        # Remove this job queue from the list of job queues in config file
        cloudknot.config.remove_resource('job-queues', self.name)

        logging.info('Clobbered job queue {name:s}'.format(name=self.name))


# noinspection PyPropertyAccess,PyAttributeOutsideInit
class BatchJob(NamedObject):
    """Class for defining AWS Batch Job"""
    def __init__(self, job_id=None, name=None, job_queue=None,
                 job_definition=None, commands=None,
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

        commands : string or sequence of strings
            command sent to the container for this job.
            Split multi-word commands on spaces.
            e.g. `echo hello` becomes ['echo', 'hello']

        environment_variables : list of dict
            list of key/value pairs representing environment variables
            sent to the container
        """
        if not (job_id or all([name, job_queue, job_definition])):
            raise ValueError('You must supply either job_id or (name, '
                             'job_queue, and job_definition).')

        if job_id and any([name, job_queue, job_definition]):
            raise ValueError('You may supply either job_id or (name, '
                             'job_queue, and job_definition), not both.')

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
            self._job_definition = None
            self._job_definition_arn = job.job_definition_arn
            self._commands = job.commands
            self._environment_variables = job.environment_variables
            self._job_id = job.job_id

            cloudknot.config.add_resource('jobs', self.job_id, self.name)

            logging.info('Retrieved pre-existing batch job {id:s}'.format(
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

            if commands:
                if isinstance(commands, str):
                    self._commands = [commands]
                elif all(isinstance(x, str) for x in commands):
                    self._commands = list(commands)
                else:
                    raise ValueError('if provided, commands must be a string '
                                     'or a sequence of strings.')
            else:
                self._commands = None

            if environment_variables:
                if not isinstance(environment_variables, dict):
                    raise ValueError('if provided, environment_variables must '
                                     'be an instance of dict')
                self._environment_variables = environment_variables
            else:
                self._environment_variables = None

            self._job_id = self._create()

    job_queue = property(operator.attrgetter('_job_queue'))
    job_queue_arn = property(operator.attrgetter('_job_queue_arn'))

    job_definition = property(operator.attrgetter('_job_definition_arn'))
    job_definition_arn = property(operator.attrgetter('_job_definition'))

    commands = property(operator.attrgetter('_commands'))
    environment_variables = property(
        operator.attrgetter('_environment_variables')
    )
    job_id = property(operator.attrgetter('_job_id'))

    def _exists_already(self, job_id):
        """Check if an AWS batch job exists already

        If batch job exists, return namedtuple with batch job info.
        Otherwise, set the namedtuple's `exists` field to
        `False`. The remaining fields default to `None`.

        Returns
        -------
        namedtuple JobExists
            A namedtuple with fields
            ['exists', 'name', 'job_queue_arn', 'job_definition_arn',
            'commands', 'environment_variables']
        """
        # define a namedtuple for return value type
        JobExists = namedtuple(
            'JobExists',
            ['exists', 'name', 'job_queue_arn', 'job_definition_arn',
             'commands', 'environment_variables']
        )
        # make all but the first value default to None
        JobExists.__new__.__defaults__ = \
            (None,) * (len(JobExists._fields) - 1)

        response = BATCH.describe_jobs(jobs=[job_id])

        if response.get('jobs'):
            job = response.get('jobs')[0]
            name = job['jobName']
            job_queue_arn = job['jobQueue']
            job_definition_arn = job['jobDefinition']
            commands = job['container']['command']
            environment_variables = job['container']['environment']

            logging.info('Job {id:s} exists.'.format(id=job_id))

            return JobExists(
                exists=True, name=name, job_queue_arn=job_queue_arn,
                job_definition_arn=job_definition_arn,
                commands=commands, environment_variables=environment_variables
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
        container_overrides = {
            'environment': self.environment_variables,
            'command': self.commands
        }

        response = BATCH.submit_job(
            jobName=self.name,
            jobQueue=self.job_queue_arn,
            jobDefinition=self.job_definition_arn,
            containerOverrides=container_overrides
        )

        job_id = response['jobId']

        # Add this job to the list of jobs in the config file
        cloudknot.config.add_resource('jobs', job_id, self.name)

        logging.info(
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
        # Query the job_id
        response = BATCH.describe_jobs(jobs=[self.job_id])
        job = response.get('jobs')[0]

        # Return only a subset of the job dictionary
        status = {k: job[k] for k in ('status', 'statusReason', 'attempts')}

        return status

    def terminate(self, reason):
        """Terminate AWS batch job using instance parameter `self.job_id`

        Parameters
        ----------
        reason : string
            A message to attach to the job that explains the reason for
            cancelling it. This message is returned by future DescribeJobs
            operations on the job. This message is also recorded in the AWS
            Batch activity logs.
        """
        # Require the user to supply a reason for job termination
        if not isinstance(reason, str):
            raise ValueError('reason must be a string.')

        BATCH.terminate_job(jobId=self.job_id, reason=reason)

        logging.info('Terminated job {name:s} with jobID {job_id:s}'.format(
            name=self.name, job_id=self.job_id
        ))
