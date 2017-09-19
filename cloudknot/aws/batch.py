import operator
import sys
import time

from .. import config
from .base_classes import NamedObject, ObjectWithArn, \
    ObjectWithUsernameAndMemory, BATCH, \
    ResourceExistsException, ResourceDoesNotExistException
from .iam import IamRole
from .ec2 import Vpc, SecurityGroup
from .ecr import DockerImage
from collections import namedtuple

__all__ = ["JobDefinition", "JobQueue", "ComputeEnvironment", "BatchJob"]


# noinspection PyPropertyAccess,PyAttributeOutsideInit
class JobDefinition(ObjectWithUsernameAndMemory):
    """Class for defining AWS Batch Job Definitions"""
    def __init__(self, arn=None, name=None, job_role=None, docker_image=None,
                 vcpus=None, memory=None, username=None, retries=None):
        """ Initialize an AWS Batch job definition object.

        Parameters
        ----------
        name : string
            Name of the job definition

        job_role : IamRole
            IamRole instance for the AWS IAM job role to be used in this
            job definition

        docker_image : DockerImage
            DockerImage instance for the container to be used in this job
            definition

        vcpus : int
            number of virtual cpus to be used to this job definition
            Default: 1

        memory : int
            memory (MiB) to be used for this job definition
            Default: 32000

        username : string
            username for be used for this job definition
            Default: cloudknot-user
        """
        if not (arn or name):
            raise ValueError('You must supply either an arn or name for this '
                             'job definition.')

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
            config.add_resource('job definitions', self.name, self.arn)
        else:
            # If user supplied only a name or only an arn, expecting to
            # retrieve info on pre-existing job definition, throw error
            if arn or (name and not all([job_role, docker_image])):
                raise ResourceDoesNotExistException(
                    'The job queue you requested does not exist.',
                    arn
                )

            # Otherwise, validate input and set parameters
            username = username if username else 'cloudknot-user'
            memory = memory if memory else 32000

            super(JobDefinition, self).__init__(
                name=name, memory=memory, username=username
            )

            if not isinstance(job_role, IamRole):
                raise ValueError('job_role must be an instance of IamRole')
            self._job_role = job_role

            if not isinstance(docker_image, DockerImage):
                raise ValueError(
                    'docker_image must be an instance of DockerImage')
            self._docker_image = docker_image

            if vcpus:
                cpus = int(vcpus)
                if cpus < 1:
                    raise ValueError('vcpus must be positive')
                else:
                    self._vcpus = cpus
            else:
                self._vcpus = 1

            if retries:
                retries_int = int(retries)
                if retries_int < 1:
                    raise ValueError('retries must be positive')
                else:
                    self._retries = retries_int
            else:
                self._retries = 3

            self._arn = self._create()

    pre_existing = property(operator.attrgetter('_pre_existing'))
    job_role = property(operator.attrgetter('_job_role'))
    docker_image = property(operator.attrgetter('_docker_image'))
    vcpus = property(operator.attrgetter('_vcpus'))
    retries = property(operator.attrgetter('_retries'))

    def _exists_already(self, arn, name):
        """ Check if an AWS Job Definition exists already

        If definition exists, return namedtuple with job definition info.
        Otherwise, set the namedtuple's `exists` field to `False`. The
        remaining fields default to `None`.

        Returns
        -------
        namedtuple RoleExists
            A namedtuple with fields ['exists', 'name', 'job_role',
            'docker_image', 'vcpus', 'memory', 'username', 'retries', 'arn']
        """
        # define a namedtuple for return value type
        ResourceExists = namedtuple(
            'ResourceExists',
            ['exists', 'name', 'job_role', 'docker_image', 'vcpus',
             'memory', 'username', 'retries', 'arn']
        )
        # make all but the first value default to None
        ResourceExists.__new__.__defaults__ = \
            (None,) * (len(ResourceExists._fields) - 1)

        if arn:
            response = BATCH.describe_job_definitions(jobDefinitionName=arn)
        else:
            response = BATCH.describe_job_definitions(jobDefinitionName=name)

        if response.get('jobDefinitions'):
            job_def = response.get('jobDefinitions')[0]
            job_def_name = job_def['jobDefinitionName']
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
                exists=True, name=job_def_name, job_role=job_role_arn,
                docker_image=container_image, vcpus=vcpus, memory=memory,
                username=username, retries=retries, arn=job_def_arn
            )
        else:
            return ResourceExists(exists=False)

    def _create(self):
        """ Create AWS job definition using instance parameters

        Returns
        -------
        string
            Amazon Resource Number (ARN) for the created job definition
        """
        job_container_properties = {
            'image': self.docker_image.uri,
            'vcpus': self.vcpus,
            'memory': self.memory,
            'command': [],
            'jobRoleArn': self.job_role.arn,
            'user': self.username
        }

        response = BATCH.register_job_definition(
            jobDefinitionName=self.name,
            type='container',
            containerProperties=job_container_properties,
            retryStrategy={'attempts': self.retries}
        )

        logging.info('Created AWS batch job definition {name:s}'.format(
            name=self.name
        ))

        arn = response['jobDefinitionArn']

        # Add this job def to the list of job definitions in the config file
        config.add_resource('job definitions', self.name, arn)

        return arn

    def clobber(self):
        """ Deregister this AWS batch job definition

        Returns
        -------
        None
        """
        BATCH.deregister_job_definition(jobDefinition=self.arn)

        logging.info('Deregistered job definition {name:s}'.format(
            name=self.name
        ))

        # Remove this job def from the list of job defs in the config file
        config.remove_resource('job definitions', self.name, arn)


# noinspection PyPropertyAccess,PyAttributeOutsideInit
class ComputeEnvironment(ObjectWithArn):
    """Class for defining AWS Compute Environments"""
    def __init__(self, arn=None, name=None, batch_service_role=None,
                 instance_role=None, vpc=None, security_group=None,
                 spot_fleet_role=None, instance_types=None, resource_type=None,
                 min_vcpus=None, max_vcpus=None, desired_vcpus=None,
                 image_id=None, ec2_key_pair=None, tags=None,
                 bid_percentage=None):
        """ Initialize an AWS Batch job definition object.

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
        if not (arn or name):
            raise ValueError(
                'You must supply either an arn or name for this '
                'compute environment.'
            )

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
            config.add_resource('compute environments', self.name, self.arn)
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

            if not (isinstance(batch_service_role, IamRole)
                    and batch_service_role.service == 'batch'):
                raise ValueError(
                    'batch_service_role must be an IamRole '
                    'instance with service type "batch"'
                )
            self._batch_service_role = batch_service_role
            self._batch_service_arn = batch_service_role.arn

            if not (isinstance(instance_role, IamRole)
                    and instance_role.instance_profile_arn):
                raise ValueError(
                    'instance_role must be an IamRole instance '
                    'with an instance profile ARN'
                )
            self._instance_role = instance_role
            self._instance_role_arn = instance_role.instance_profile_arn

            if not isinstance(vpc, Vpc):
                raise ValueError('vpc must be an instance of Vpc')
            self._vpc = vpc
            self._subnets = vpc.subnets

            if not isinstance(security_group, SecurityGroup):
                raise ValueError(
                    'security_group must be an instance of '
                    'SecurityGroup'
                )
            self._security_group = security_group
            self._security_group_ids = [security_group.security_group_id]

            if spot_fleet_role:
                if not (isinstance(spot_fleet_role, IamRole)
                        and spot_fleet_role.service == 'spotfleet'):
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

            instance_types = instance_types if instance_types else ('optimal',)
            if isinstance(instance_types, str):
                self._instance_types = (instance_types,)
            elif all(isinstance(x, str) for x in instance_types):
                self._instance_types = list(instance_types)
            else:
                raise ValueError(
                    'instance_types must be a string or a '
                    'sequence of strings.'
                )

            resource_type = resource_type if resource_type else 'EC2'
            if resource_type not in ('EC2', 'SPOT'):
                raise ValueError('resource_type must be "EC2" or "SPOT"')
            self._resource_type = resource_type

            min_vcpus = min_vcpus if min_vcpus else 0
            cpus = int(min_vcpus)
            if cpus < 0:
                raise ValueError('min_vcpus must be non-negative')
            else:
                self._min_vcpus = cpus

            max_vcpus = max_vcpus if max_vcpus else 256
            cpus = int(max_vcpus)
            if cpus < 0:
                raise ValueError('max_vcpus must be non-negative')
            else:
                self._max_vcpus = cpus

            desired_vcpus = desired_vcpus if desired_vcpus else 8
            cpus = int(desired_vcpus)
            if cpus < 0:
                raise ValueError('desired_vcpus must be non-negative')
            else:
                self._desired_vcpus = cpus

            if image_id:
                if not isinstance(image_id, str):
                    raise ValueError('if provided, image_id must be a string')
                self._image_id = image_id
            else:
                self._image_id = None

            if ec2_key_pair:
                if not isinstance(ec2_key_pair, str):
                    raise ValueError(
                        'if provided, ec2_key_pair must be a string'
                    )
                self._ec2_key_pair = ec2_key_pair
            else:
                self._ec2_key_pair = None

            if tags:
                if not isinstance(tags, dict):
                    raise ValueError(
                        'if provided, tags must be an instance of dict'
                    )
                self._tags = tags
            else:
                self._tags = None

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
        """ Check if a compute environment exists already

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
            response = BATCH.describe_compute_environments(
                computeEnvironments=[arn]
            )
        else:
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
            spot_fleet_role_arn = cr['spotIamFleetRole']
            instance_types = cr['instanceTypes']
            resource_type = cr['type']
            min_vcpus = cr['minvCpus']
            max_vcpus = cr['maxvCpus']
            desired_vcpus = cr['desiredvCpus']
            image_id = cr['imageId']
            ec2_key_pair = cr['ec2KeyPair']
            tags = cr['tags']
            bid_percentage = cr['bidPercentage']

            logging.info('Compute environment {name:s} already exists.'.format(
                name=self.name
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
        """ Create AWS compute environment using instance parameters

        Returns
        -------
        string
            Amazon Resource Number (ARN) for the created compute environment
        """
        compute_resources = {
            'type': self.resource_type,
            'minvCpus': self.min_vcpu,
            'maxvCpus': self.max_vcpu,
            'desiredvCpus': self.desired_vcpu,
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
        config.add_resource('compute environments', self.name, arn)

        return arn

    def clobber(self):
        """ Delete this compute environment

        Returns
        -------
        None
        """
        # First set the state to disabled
        BATCH.update_compute_environment(
            computeEnvironment=self.arn,
            state='DISABLED'
        )

        # Then disassociate from any job queues
        response = BATCH.describe_job_queues()
        for queue in response.get('jobQueues'):
            arn = queue['jobQueueArn']
            ce_order = queue['computeEnvironmentOrder']
            # If this queue is associated with our compute environment
            if self.arn in [ce['computeEnvironment'] for ce in ce_order]:
                # Construct new computeEnvironmentOrder with this
                # compute environment removed
                new_ce_order = [
                    ce for ce in ce_order
                    if ce['computeEnvironment'] != self.arn
                ]

                # Get the order number of the offending compute environment
                bad_order = [
                    ce for ce in ce_order
                    if ce['computeEnvironment'] == self.arn
                ][0]['order']

                # Fix the gap in the order numbers
                for ce in new_ce_order:
                    if ce['order'] > bad_order:
                        ce['order'] -= 1

                # Update the job queue with the new compute environment order
                BATCH.update_job_queue(
                    jobQueue=arn,
                    computeEnvironmentOrder=new_ce_order
                )

        # Finally, delete the compute environment
        BATCH.delete_compute_environment(computeEnvironment=self.arn)

        logging.info('Deleted compute environment {name:s}'.format(
            name=self.name
        ))

        # Remove this compute env from the list of compute envs in config file
        config.remove_resource('compute environments', self.name)


# noinspection PyPropertyAccess,PyAttributeOutsideInit
class JobQueue(ObjectWithArn):
    """Class for defining AWS Batch Job Queues"""
    def __init__(self, arn=None, name=None, compute_environments=None,
                 priority=None):
        """ Initialize an AWS Batch job definition object.

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
        super(JobQueue, self).__init__(name=name)

        if not (arn or name):
            raise ValueError(
                'You must supply either an arn or name for this '
                'job queue.'
            )

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
            self._compute_environments = None
            self._compute_environment_arns = resource.compute_environment_arns
            self._priority = resource.priority
            self._arn = resource.arn
            config.add_resource('job queues', self.name, self.arn)
        else:
            # If user supplied only a name or only an arn, expecting to
            # retrieve info on pre-existing job queue, throw error
            if arn or (name and not compute_environments):
                raise ResourceDoesNotExistException(
                    'The job queue you requested does not exist.',
                    arn
                )

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
        """ Check if an AWS job queue exists already

        If job queue exists, return namedtuple with job queue info.
        Otherwise, set the namedtuple's `exists` field to `False`.
        The remaining fields default to `None`.

        Returns
        -------
        namedtuple RoleExists
            A namedtuple with fields
            ['exists', 'compute_environment_arns', 'priority', 'arn']
        """
        # define a namedtuple for return value type
        ResourceExists = namedtuple(
            'ResourceExists',
            ['exists', 'compute_environment_arns', 'priority', 'arn']
        )
        # make all but the first value default to None
        ResourceExists.__new__.__defaults__ = \
            (None,) * (len(ResourceExists._fields) - 1)

        if arn:
            response = BATCH.describe_job_queues(
                jobQueues=[arn]
            )
        else:
            response = BATCH.describe_job_queues(
                jobQueues=[name]
            )

        q = response.get('JobQueues')
        if q:
            arn = q[0]['jobQueueArn']
            compute_environment_arns = q[0]['computeEnvironmentOrder']
            priority = q[0]['priority']

            logging.info('Job Queue {name:s} already exists.'.format(
                name=self.name
            ))

            return ResourceExists(
                exists=True, priority=priority, arn=arn,
                compute_environment_arns=compute_environment_arns
            )
        else:
            return ResourceExists(exists=False)

    def _create(self):
        """ Create AWS batch job queue using instance parameters

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

        # Wait for job queue to be in VALID state
        waiting = True
        num_waits = 0
        while waiting:
            logging.info(
                'Waiting for AWS to create job queue '
                '{name:s}.'.format(name=self.name)
            )
            response = BATCH.describe_job_queues(jobQueues=[self.name])
            waiting = (response.get('jobQueues')[0]['status'] != 'VALID')
            time.sleep(3)
            num_waits += 1
            if num_waits > 60:
                sys.exit('Waiting too long to create job queue. Aborting.')

        logging.info('Created job queue {name:s}'.format(name=self.name))

        arn = response.get('jobQueues')[0]['jobQueueArn']

        # Add this job queue to the list of job queues in the config file
        config.add_resource('job queues', self.name, arn)

        return arn

    @property
    def jobs(self, status='ALL'):
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
        """ Delete this batch job queue

        Returns
        -------
        None
        """
        # First, disable submissions to the queue
        BATCH.update_job_queue(jobQueue=self.arn, state='DISABLED')

        # Next, terminate all jobs that have not completed
        for status in [
            'SUBMITTED', 'PENDING', 'RUNNABLE', 'STARTING', 'RUNNING'
        ]:
            jobs = self.jobs(status=status)
            for job_id in jobs:
                BATCH.terminate_job(
                    jobId=job_id,
                    reason='Terminated to force job queue deletion'
                )

        # Finally, delete the job queue
        BATCH.delete_job_queue(jobQueue=self.arn)

        logging.info('Deleted job queue {name:s}'.format(name=self.name))

        # Remove this job queue from the list of job queues in config file
        config.remove_resource('job queues', self.name)


# noinspection PyPropertyAccess,PyAttributeOutsideInit
class BatchJob(NamedObject):
    """Class for defining AWS Batch Job"""
    def __init__(self, job_id=None, name=None, job_queue=None,
                 job_definition=None, commands=None,
                 environment_variables=None):
        """ Initialize an AWS Batch Job object.

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
            config.add_resource('jobs', self.job_id, self.name)
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
        """ Check if an AWS batch job exists already

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

    def _create(self):
        """ Create AWS batch job using instance parameters

        Returns
        -------
        string
            job ID for the created batch job
        """
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

        logging.info(
            'Submitted batch job {name:s} with jobID '
            '{job_id:s}'.format(name=self.name, job_id=response['jobId'])
        )

        job_id = response['jobId']

        # Add this job to the list of jobs in the config file
        config.add_resource('jobs', job_id, self.name)

        return job_id

    @property
    def status(self):
        """ Query AWS batch job status using instance parameter `self.job_id`

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
        """ Terminate AWS batch job using instance parameter `self.job_id`

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
