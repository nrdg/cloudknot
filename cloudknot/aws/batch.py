import operator
import sys
import time
from .base_classes import ObjectWithNameAndVerbosity, ObjectWithArn, \
    ObjectWithUsernameAndMemory, BATCH
from .iam import IamRole
from .ec2 import Vpc, SecurityGroup
from .ecr import DockerImage
from collections import namedtuple

__all__ = ["JobDefinition", "JobQueue", "ComputeEnvironment", "BatchJob"]


# noinspection PyPropertyAccess,PyAttributeOutsideInit
class JobDefinition(ObjectWithUsernameAndMemory):
    """Class for defining AWS Batch Job Definitions"""
    def __init__(self, name, job_role, docker_image, vcpus=1,
                 memory=32000, username='cloudknot-user', retries=3,
                 verbosity=0):
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

        verbosity : int
            verbosity level [0, 1, 2]
        """
        super(JobDefinition, self).__init__(name=name, memory=memory,
                                            username=username,
                                            verbosity=verbosity)

        resource_exists = self._exists_already()
        self._pre_existing = resource_exists.exists

        if resource_exists.exists:
            self._job_role = resource_exists.job_role
            self._docker_image = resource_exists.docker_image
            self._vcpus = resource_exists.vcpus
            self._memory = resource_exists.memory
            self._username = resource_exists.username
            self._retries = resource_exists.retries
            self._arn = resource_exists.arn
        else:
            if not isinstance(job_role, IamRole):
                raise Exception('job_role must be an instance of IamRole')
            self._job_role = job_role

            if not isinstance(docker_image, DockerImage):
                raise Exception(
                    'docker_image must be an instance of DockerImage')
            self._docker_image = docker_image

            try:
                cpus = int(vcpus)
                if cpus < 1:
                    raise Exception('vcpus must be positive')
                else:
                    self._vcpus = cpus
            except ValueError:
                raise Exception('vcpus must be an integer')

            try:
                retries_int = int(retries)
                if retries_int < 1:
                    raise Exception('retries must be positive')
                else:
                    self._retries = retries_int
            except ValueError:
                raise Exception('retries must be an integer')

            self._arn = self._create()

    pre_existing = property(operator.attrgetter('_pre_existing'))
    job_role = property(operator.attrgetter('_job_role'))
    docker_image = property(operator.attrgetter('_docker_image'))
    vcpus = property(operator.attrgetter('_vcpus'))
    retries = property(operator.attrgetter('_retries'))

    def _exists_already(self):
        """ Check if an AWS Job Definition exists already

        If definition exists, return namedtuple with job definition info.
        Otherwise, set the namedtuple's `exists` field to `False`. The
        remaining fields default to `None`.

        Returns
        -------
        namedtuple RoleExists
            A namedtuple with fields ['exists', 'job_role', 'docker_image',
            'vcpus', 'memory', 'username', 'retries', 'arn']
        """
        # define a namedtuple for return value type
        ResourceExists = namedtuple(
            'ResourceExists',
            ['exists', 'job_role', 'docker_image', 'vcpus',
             'memory', 'username', 'retries', 'arn']
        )
        # make all but the first value default to None
        ResourceExists.__new__.__defaults__ = \
            (None,) * (len(ResourceExists._fields) - 1)

        response = BATCH.describe_job_definitions(jobDefinitionName=self.name)
        if response.get('jobDefinitions'):
            job_def = response.get('jobDefinitions')[0]
            arn = job_def['jobDefinitionArn']
            retries = job_def['retryStrategy']['attempts']

            container_properties = job_def['containerProperties']
            username = container_properties['user']
            memory = container_properties['memory']
            vcpus = container_properties['vcpus']
            job_role_arn = container_properties['jobRoleArn']
            container_image = container_properties['image']

            if self.verbosity > 0:
                print('Job definition {name:s} already exists.'.format(
                    name=self.name
                ))

            return ResourceExists(
                exists=True, job_role=job_role_arn,
                docker_image=container_image, vcpus=vcpus, memory=memory,
                username=username, retries=retries, arn=arn
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

        if self.verbosity > 0:
            print('Created AWS batch job definition {name:s}'.format(
                name=self.name))

        return response['jobDefinitionArn']

    def remove_aws_resource(self):
        """ Deregister this AWS batch job definition

        Returns
        -------
        None
        """
        BATCH.deregister_job_definition(jobDefinition=self.arn)

        if self.verbosity > 0:
            print('Deregistered job definition {name:s}'.format(
                name=self.name
            ))


# noinspection PyPropertyAccess,PyAttributeOutsideInit
class ComputeEnvironment(ObjectWithUsernameAndMemory):
    """Class for defining AWS Compute Environments"""
    def __init__(self, name, batch_service_role=None, instance_role=None,
                 vpc=None, security_group=None,
                 spot_fleet_role=None, instance_types=('optimal',),
                 resource_type='EC2', min_vcpus=0, max_vcpus=256,
                 desired_vcpus=8, memory=32000, username='cloudknot-user',
                 image_id=None, ec2_key_pair=None, tags=None,
                 bid_percentage=None, verbosity=0):
        """ Initialize an AWS Batch job definition object.

        Parameters
        ----------
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

        memory : int
            memory (MiB) to be used for this compute environment
            Default: 32000

        username : string
            username for be used for this compute environment
            Default: cloudknot-user

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

        verbosity : int
            verbosity level [0, 1, 2]
        """
        super(ComputeEnvironment, self).__init__(name=name, memory=memory,
                                                 username=username,
                                                 verbosity=verbosity)

        resource_exists = self._exists_already()
        self._pre_existing = resource_exists.exists

        if resource_exists.exists:
            self._batch_service_role = None
            self._batch_service_arn = resource_exists.batch_service_arn

            self._instance_role = None
            self._instance_role_arn = resource_exists.instance_role_arn

            self._vpc = None
            self._subnets = resource_exists.subnets

            self._security_group = None
            self._security_group_ids = resource_exists.security_group_ids

            self._spot_fleet_role = None
            self._spot_fleet_role_arn = resource_exists.spot_fleet_role_arn

            self._instance_types = resource_exists.instance_types
            self._resource_type = resource_exists.resource_type
            self._min_vcpus = resource_exists.min_vcpus
            self._max_vcpus = resource_exists.max_vcpus
            self._desired_vcpus = resource_exists.desired_vcpus
            self._image_id = resource_exists.image_id
            self._ec2_key_pair = resource_exists.ec2_key_pair
            self._tags = resource_exists.tags
            self._bid_percentage = resource_exists.bid_percentage
            self._arn = resource_exists.arn
        else:
            if not bid_percentage and resource_type == 'SPOT':
                raise Exception('if resource_type is "SPOT", bid_percentage '
                                'must be set.')

            if not spot_fleet_role and resource_type == 'SPOT':
                raise Exception('if resource_type is "SPOT", spot_fleet_role '
                                'must be set.')

            if not (isinstance(batch_service_role, IamRole)
                    and batch_service_role.service == 'batch'):
                raise Exception('batch_service_role must be an IamRole '
                                'instance with service type "batch"')
            self._batch_service_role = batch_service_role
            self._batch_service_arn = batch_service_role.arn

            if not (isinstance(instance_role, IamRole)
                    and instance_role.instance_profile_arn):
                raise Exception('instance_role must be an IamRole instance '
                                'with an instance profile ARN')
            self._instance_role = instance_role
            self._instance_role_arn = instance_role.instance_profile_arn

            if not isinstance(vpc, Vpc):
                raise Exception('vpc must be an instance of Vpc')
            self._vpc = vpc
            self._subnets = vpc.subnets

            if not isinstance(security_group, SecurityGroup):
                raise Exception('security_group must be an instance of '
                                'SecurityGroup')
            self._security_group = security_group
            self._security_group_ids = [security_group.security_group_id]

            if spot_fleet_role:
                if not (isinstance(spot_fleet_role, IamRole)
                        and spot_fleet_role.service == 'spotfleet'):
                    raise Exception('if provided, spot_fleet_role must be an '
                                    'IamRole instance with service type '
                                    '"spotfleet"')
                self._spot_fleet_role = spot_fleet_role
                self._spot_fleet_role_arn = spot_fleet_role.arn
            else:
                self._spot_fleet_role = None
                self._spot_fleet_role_arn = None

            if isinstance(instance_types, str):
                self._instance_types = (instance_types,)
            elif all(isinstance(x, str) for x in instance_types):
                self._instance_types = list(instance_types)
            else:
                raise Exception('instance_types must be a string or a '
                                'sequence of strings.')

            if resource_type not in ('EC2', 'SPOT'):
                raise Exception('resource_type must be either "EC2" or "SPOT"')

            self._resource_type = resource_type

            try:
                cpus = int(min_vcpus)
                if cpus < 0:
                    raise Exception('min_vcpus must be non-negative')
                else:
                    self._min_vcpus = cpus
            except ValueError:
                raise Exception('min_vcpus must be an integer')

            try:
                cpus = int(max_vcpus)
                if cpus < 0:
                    raise Exception('max_vcpus must be non-negative')
                else:
                    self._max_vcpus = cpus
            except ValueError:
                raise Exception('max_vcpus must be an integer')

            try:
                cpus = int(desired_vcpus)
                if cpus < 0:
                    raise Exception('desired_vcpus must be non-negative')
                else:
                    self._desired_vcpus = cpus
            except ValueError:
                raise Exception('desired_vcpus must be an integer')

            if image_id:
                if not isinstance(image_id, str):
                    raise Exception('if provided, image_id must be a string')
                self._image_id = image_id
            else:
                self._image_id = None

            if ec2_key_pair:
                if not isinstance(ec2_key_pair, str):
                    raise Exception('if provided, ec2_key_pair must be a '
                                    'string')
                self._ec2_key_pair = ec2_key_pair
            else:
                self._ec2_key_pair = None

            if tags:
                if not isinstance(tags, dict):
                    raise Exception('if provided, tags must be an instance of '
                                    'dict')
                self._tags = tags
            else:
                self._tags = None

            if bid_percentage:
                try:
                    bp_int = int(bid_percentage)
                    if bp_int < 0:
                        self._bid_percentage = 0
                    elif bp_int > 100:
                        self._bid_percentage = 100
                    else:
                        self._bid_percentage = bp_int
                except ValueError:
                    raise Exception('if provided, bid_percentage must be an '
                                    'int')
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

    def _exists_already(self):
        """ Check if an IAM Role exists already

        If role exists, return namedtuple with role info. Otherwise, set the
        namedtuple's `exists` field to `False`. The remaining fields default
        to `None`.

        Returns
        -------
        namedtuple ResourceExists
            A namedtuple with fields
            ['exists', 'batch_service_arn', 'instance_role_arn', 'subnets',
             'security_group_ids', 'spot_fleet_role_arn', 'instance_types',
             'resource_type', 'min_vcpus', 'max_vcpus', 'desired_vcpus',
             'image_id', 'ec2_key_pair', 'tags', 'bid_percentage', 'arn']
        """
        # define a namedtuple for return value type
        ResourceExists = namedtuple(
            'ResourceExists',
            ['exists', 'batch_service_arn', 'instance_role_arn', 'subnets',
             'security_group_ids', 'spot_fleet_role_arn', 'instance_types',
             'resource_type', 'min_vcpus', 'max_vcpus', 'desired_vcpus',
             'image_id', 'ec2_key_pair', 'tags', 'bid_percentage', 'arn']
        )
        # make all but the first value default to None
        ResourceExists.__new__.__defaults__ = \
            (None,) * (len(ResourceExists._fields) - 1)

        response = BATCH.describe_compute_environments(
            computeEnvironments=[self.name]
        )

        if response.get('computeEnvironments'):
            ce = response.get('computeEnvironments')[0]
            batch_service_arn = ce['serviceRole']
            arn = ce['computeEnvironmentArn']

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

            if self.verbosity > 0:
                print('Compute environment {name:s} already exists.'.format(
                    name=self.name
                ))

            return ResourceExists(
                exists=True, batch_service_arn=batch_service_arn,
                instance_role_arn=instance_role_arn, subnets=subnets,
                security_group_ids=security_group_ids,
                spot_fleet_role_arn=spot_fleet_role_arn,
                instance_types=instance_types,
                resource_type=resource_type, min_vcpus=min_vcpus,
                max_vcpus=max_vcpus, desired_vcpus=desired_vcpus,
                image_id=image_id, ec2_key_pair=ec2_key_pair, tags=tags,
                bid_percentage=bid_percentage, arn=arn
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

        return response['computeEnvironmentArn']

    def remove_aws_resource(self):
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

        if self.verbosity > 0:
            print('Deleted compute environment {name:s}'.format(
                name=self.name
            ))


# noinspection PyPropertyAccess,PyAttributeOutsideInit
class JobQueue(ObjectWithArn):
    """Class for defining AWS Batch Job Queues"""
    def __init__(self, name, compute_environments, priority=1, verbosity=0):
        """ Initialize an AWS Batch job definition object.

        Parameters
        ----------
        name : string
            Name of the job definition

        compute_environments : ComputeEnvironment or tuple(ComputeEnvironments)
            ComputeEnvironment instance or sequence of ComputeEnvironment
            instances (in order of priority) for this job queue to use

        priority : int
            priority for jobs in this queue
            Default: 1

        verbosity : int
            verbosity level [0, 1, 2]
        """
        super(JobQueue, self).__init__(name=name, verbosity=verbosity)

        # Check if this job queue already exists
        resource_exists = self._exists_already()
        self._pre_existing = resource_exists.exists

        if resource_exists.exists:
            # If pre-existing, ignore input and fill parameters
            # with queried values
            self._compute_environments = None
            self._compute_environment_arns = \
                resource_exists.compute_environment_arns
            self._priority = resource_exists.priority
            self._arn = resource_exists.arn
        else:
            # Otherwise, validate input and set parameters
            # Validate compute environments
            if isinstance(compute_environments, ComputeEnvironment):
                self._compute_environments = (compute_environments,)
            elif all(isinstance(x, ComputeEnvironment)
                     for x in compute_environments
                     ):
                self._compute_environments = tuple(compute_environments)
            else:
                raise Exception('compute_environments must be a '
                                'ComputeEnvironment instance or a sequence '
                                'of ComputeEnvironment instances.')

            # Assign compute environment arns,
            # based on ComputeEnvironment input
            self._compute_environment_arns = []
            for i, ce in enumerate(self._compute_environments):
                self._compute_environment_arns.append({
                    'order': i,
                    'computeEnvironment': ce.arn
                })

            # Validate priority
            try:
                p_int = int(priority)
                if p_int < 1:
                    raise Exception('priority must be positive')
                else:
                    self._priority = p_int
            except ValueError:
                raise Exception('priority must be an integer')

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

    def _exists_already(self):
        """ Check if an AWS compute environment exists already

        If compute environment exists, return namedtuple with compute
        environment info. Otherwise, set the namedtuple's `exists` field to
        `False`. The remaining fields default to `None`.

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

        response = BATCH.describe_job_queues(
            jobQueues=[self.name]
        )

        q = response.get('JobQueues')
        if q:
            arn = q[0]['jobQueueArn']
            compute_environment_arns = q[0]['computeEnvironmentOrder']
            priority = q[0]['priority']

            if self.verbosity > 0:
                print('Job Queue {name:s} already exists.'.format(
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
            if self.priority > 0:
                print('Waiting for AWS to create job queue {name:s}.'.format(
                    name=self.name))
            response = BATCH.describe_job_queues(jobQueues=[self.name])
            waiting = (response.get('jobQueues')[0]['status'] != 'VALID')
            time.sleep(3)
            num_waits += 1
            if num_waits > 60:
                sys.exit('Waiting too long to create job queue. Aborting.')

        if self.priority > 0:
            print('Created job queue {name:s}'.format(name=self.name))

        return response.get('jobQueues')[0]['jobQueueArn']

    @property
    def jobs(self, status='ALL'):
        # Validate input
        allowed_statuses = ['ALL', 'SUBMITTED', 'PENDING', 'RUNNABLE',
                            'STARTING', 'RUNNING', 'SUCCEEDED', 'FAILED']
        if status not in allowed_statuses:
            raise Exception('status must be one of ', allowed_statuses)

        if status == 'ALL':
            # status == 'ALL' is equivalent to not specifying a status at all
            response = BATCH.list_jobs(jobQueue=self.arn)
        else:
            # otherwise, filter on status
            response = BATCH.list_jobs(jobQueue=self.arn, jobStatus=status)

        # Return list of job_ids
        return response.get('jobSummaryList')

    def remove_aws_resource(self):
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

        if self.verbosity > 0:
            print('Deleted job queue {name:s}'.format(
                name=self.name
            ))


# noinspection PyPropertyAccess,PyAttributeOutsideInit
class BatchJob(ObjectWithNameAndVerbosity):
    """Class for defining AWS Batch Job"""
    def __init__(self, job_id=None, name=None, job_queue=None,
                 job_definition=None, commands=None,
                 environment_variables=None, verbosity=0):
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

        verbosity : int
            verbosity level [0, 1, 2]
        """
        if not (job_id or (name and job_queue and job_definition)):
            raise Exception('must supply either job_id or name, job_queue, '
                            'and job_definition')

        if job_id:
            job_exists = self._exists_already(job_id)
            if not job_exists.exists:
                raise Exception('jobId {id:s} does not exists'.format(
                    id=job_id)
                )

            super(BatchJob, self).__init__(
                name=job_exists.name,
                verbosity=verbosity
            )

            self._job_queue = None
            self._job_queue_arn = job_exists.job_queue_arn
            self._job_definition = None
            self._job_definition_arn = job_exists.job_definition_arn
            self._commands = job_exists.commands
            self._environment_variables = job_exists.environment_variables
            self._job_id = job_exists.job_id
        else:
            super(BatchJob, self).__init__(name=name, verbosity=verbosity)

            if not isinstance(job_queue, JobQueue):
                raise Exception('job_queue must be a JobQueue instance')
            self._job_queue = job_queue
            self._job_queue_arn = job_queue.arn

            if not isinstance(job_definition, JobDefinition):
                raise Exception('job_queue must be a JobQueue instance')
            self._job_definition = job_definition
            self._job_definition_arn = job_definition.arn

            if commands:
                if isinstance(commands, str):
                    self._commands = [commands]
                elif all(isinstance(x, str) for x in commands):
                    self._commands = list(commands)
                else:
                    raise Exception('if provided, commands must be a string '
                                    'or a sequence of strings.')
            else:
                self._commands = None

            if environment_variables:
                if not isinstance(environment_variables, dict):
                    raise Exception('if provided, environment_variables must '
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

            if self.verbosity > 0:
                print('Job {id:s} exists.'.format(id=job_id))

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

        if self.verbosity > 0:
            print('Submitted batch job {name:s} with jobID {job_id:s}'.format(
                name=self.name, job_id=response['jobId']
            ))

        return response['jobId']

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
            raise Exception('reason must be a string.')

        BATCH.terminate_job(jobId=self.job_id, reason=reason)

        if self.verbosity > 0:
            print('Terminated job {name:s} with jobID {job_id:s}'.format(
                name=self.name, job_id=self.job_id
            ))
