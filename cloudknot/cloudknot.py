from __future__ import absolute_import, division, print_function

import json
import operator
import os
import shutil
import subprocess
import sys
import time
from collections import namedtuple

import boto3
import docker

from .due import due, Doi

__all__ = ["DockerImage", "IamRole", "JobDefinition", "ComputeEnvironment", "JobQueue"]


# Use duecredit (duecredit.org) to provide a citation to relevant work to
# be cited. This does nothing, unless the user has duecredit installed,
# And calls this with duecredit (as in `python -m duecredit script.py`):
due.cite(Doi(""),
         description="",
         tags=[""],
         path='cloudknot')


# noinspection PyPropertyAccess,PyAttributeOutsideInit
class ObjectWithNameAndVerbosity(object):
    """Base class for building objects with name and verbosity properties"""
    def __init__(self, name, verbosity=0):
        """ Initialize a base class with name and verbosity level

        Parameters
        ----------
        name : string
            Name of the object

        verbosity : int
            verbosity level [0, 1, 2]
        """
        self.name = name
        self.verbosity = verbosity

    name = property(operator.attrgetter('_name'))

    @name.setter
    def name(self, n):
        if not n:
            raise Exception('name cannot be empty')
        self._name = str(n)

    verbosity = property(operator.attrgetter('_verbosity'))

    @verbosity.setter
    def verbosity(self, v):
        try:
            ver = int(v)
            if ver < 1:
                self._verbosity = 0
            else:
                self._verbosity = ver
        except ValueError:
            raise Exception('verbosity must be an integer')


# noinspection PyPropertyAccess,PyAttributeOutsideInit
class ObjectWithArn(ObjectWithNameAndVerbosity):
    """ Base class for building objects with an Amazon Resource Name (ARN)
    Inherits from ObjectWithNameAndVerbosity
    """
    def __init__(self, name, verbosity=0):
        """ Initialize a base class with name and verbosity level

        Parameters
        ----------
        name : string
            Name of the object

        verbosity : int
            verbosity level [0, 1, 2]
        """
        super(ObjectWithArn, self).__init__(name=name, verbosity=verbosity)
        self.__arn = None

    def get_arn(self):
        return self.__arn

    arn = property(get_arn)


# noinspection PyPropertyAccess,PyAttributeOutsideInit
class ObjectWithUsernameAndMemory(ObjectWithArn):
    """ Base class for building objects with properties memory and username
    Inherits from ObjectWithArn
    """
    def __init__(self, name, memory, username, verbosity=0):
        """ Initialize a base class with name and verbosity level

        Parameters
        ----------
        name : string
            Name of the object

        memory : int
            memory (MiB) to be used for this job definition
            Default: 32000

        username : string
            username for be used for this job definition
            Default: cloudknot-user

        verbosity : int
            verbosity level [0, 1, 2]
        """
        super(ObjectWithUsernameAndMemory, self).__init__(name=name, verbosity=verbosity)
        self.memory = memory
        self.username = username

    memory = property(operator.attrgetter('_memory'))

    @memory.setter
    def memory(self, m):
        try:
            mem = int(m)
            if mem < 1:
                raise Exception('memory must be positive')
            else:
                self._memory = mem
        except ValueError:
            raise Exception('memory must be an integer')

    username = property(operator.attrgetter('_username'))

    @username.setter
    def username(self, u):
        self._username = str(u)


# noinspection PyPropertyAccess,PyAttributeOutsideInit
class DockerImage(ObjectWithNameAndVerbosity):
    """Class for building, tagging, and pushing docker containers"""
    def __init__(self, name, build_path='.',
                 dockerfile=os.path.join('.', 'Dockerfile'),
                 requirements=None, tags=('latest',), verbosity=0):
        """ Initialize a Docker image object.

        Parameters
        ----------
        name : string
            Name of the image

        build_path : string
            Path to an existing directory in which to build docker image
            Default: '.'

        dockerfile : string
            Path to an existing Dockerfile
            Default: './Dockerfile'

        requirements : string
            Path to an existing requirements.txt file to build dependencies
            Default: None (i.e. assumes no dependencies)

        tags : list
            tuple of strings of desired image tags
            Default: ['latest']

        verbosity : int
            verbosity level [0, 1, 2]
        """
        super(DockerImage, self).__init__(name=name, verbosity=verbosity)
        self.build_path = build_path
        self.dockerfile = dockerfile
        self.requirements = requirements
        self.tags = tags
        self.__uri = None

    build_path = property(operator.attrgetter('_build_path'))

    @build_path.setter
    def build_path(self, p):
        if not os.path.isdir(p):
            raise Exception('build_path must be an existing directory')
        self._build_path = os.path.abspath(p)

    dockerfile = property(operator.attrgetter('_dockerfile'))

    @dockerfile.setter
    def dockerfile(self, f):
        if not os.path.isfile(f):
            raise Exception('dockerfile must be an existing regular file')
        self._dockerfile = os.path.abspath(f)

    requirements = property(operator.attrgetter('_requirements'))

    @requirements.setter
    def requirements(self, f):
        if not f:
            self._requirements = None
        elif not os.path.isfile(f):
            raise Exception('requirements must be an existing regular file')
        else:
            self._requirements = os.path.abspath(f)

    tags = property(operator.attrgetter('_tags'))

    @tags.setter
    def tags(self, tag_collection):
        if tag_collection:
            tmp_tags = tuple([t for t in tag_collection])
            if 'latest' not in tmp_tags:
                tmp_tags = tmp_tags + ('latest',)
            self._tags = tmp_tags
        else:
            self._tags = None

    verbosity = property(operator.attrgetter('_verbosity'))

    def build(self):
        """
        Build a DockerContainer image
        """
        req_build_path = os.path.join(self.build_path + 'requirements.txt')
        if self.requirements and not os.path.isfile(req_build_path):
            shutil.copyfile(self.requirements, req_build_path)
            cleanup = True
        else:
            cleanup = False

        c = docker.from_env()
        for tag in self.tags:
            if self.verbosity > 0:
                print('Building image {name:s} with tag {tag:s}'.format(
                    name=self.name, tag=tag))
            build_result = c.build(path=self.build_path,
                                   dockerfile=self.dockerfile,
                                   tag=self.name + ':' + tag)
            if self.verbosity > 1:
                for line in build_result:
                    print(line)

        if cleanup:
            os.remove(req_build_path)

    def create_repo(self, repo_name):
        # Refresh the aws ecr login credentials
        login_cmd = subprocess.check_output(['aws', 'ecr', 'get-login',
                                             '--no-include-email', '--region',
                                             'us-east-1'])
        login_result = subprocess.call(
            login_cmd.decode('ASCII').rstrip('\n').split(' '))

        if login_result:
            raise Exception(
                'Unable to login to AWS ECR using `{login:s}`'.format(
                    login=login_cmd))

        ecr_client = boto3.client('ecr')

        # Get repository uri
        try:
            # First, check to see if it already exists
            response = ecr_client.describe_repositories(
                repositoryNames=[repo_name])
            repo_uri = response['repositories'][0]['repositoryUri']
            if self.verbosity > 0:
                print('Repository {name:s} already exists at {uri:s}'.format(
                    name=repo_name, uri=repo_uri))
        except ecr_client.exceptions.RepositoryNotFoundException:
            # If it doesn't create it
            response = ecr_client.create_repository(
                repositoryName=repo_name)
            repo_uri = response['repository']['repositoryUri']
            if self.verbosity > 0:
                print('Created repository {name:s} at {uri:s}'.format(
                    name=repo_name, uri=repo_uri))

        self.__uri = repo_uri

    def get_uri(self):
        return self.__uri

    uri = property(get_uri)

    def tag(self, repo_name):
        """
        Tag a DockerContainer image
        """
        self.create_repo(repo_name=repo_name)
        c = docker.from_env()
        for tag in self.tags:
            if self.verbosity > 0:
                print('Tagging image {name:s} with tag {tag:s}'.format(
                    name=self.name, tag=tag))
            c.tag(image=self.name + ':' + self.tag,
                  repository=self.uri, tag=tag)

    def push(self, repo_name):
        """
        Push a DockerContainer image to a repository

        Parameters
        ----------
        repo_name : string
            Repository name
        """
        self.create_repo(repo_name=repo_name)
        c = docker.from_env()
        for tag in self.tags:
            if self.verbosity > 0:
                print('Pushing image {name:s} with tag {tag:s}'.format(
                    name=self.name, tag=tag))
            push_result = c.push(
                repository=self.uri, tag=tag, stream=(self.verbosity > 1))
            if self.verbosity > 1:
                for line in push_result:
                    print(line)


# noinspection PyPropertyAccess,PyAttributeOutsideInit
class IamRole(ObjectWithArn):
    """Class for defining AWS IAM Roles"""
    def __init__(self, name, description='', service='ecs-tasks',
                 policies=(), verbosity=0):
        """ Initialize an AWS IAM Role object.

        Parameters
        ----------
        name : string
            Name of the IAM role

        description : string
            description of this IAM role
            Default: ''

        service : string
            service role on which this AWS IAM role should be based. Must be
            one of ['batch', 'ec2', 'ecs-tasks', 'lambda', 'spotfleet']
            Default: 'ecs-tasks'

        policies : tuple of strings
            tuple of names of AWS policies to attach to this role
            Default: ()

        verbosity : int
            verbosity level [0, 1, 2]
        """
        super(IamRole, self).__init__(name=name, verbosity=verbosity)
        self.description = description
        self.service = service
        self.policies = policies
        self.__allowed_services = ['batch', 'ec2', 'ecs-tasks', 'lambda', 'spotfleet']

    description = property(operator.attrgetter('_description'))

    @description.setter
    def description(self, d):
        if not d:
            self._description = 'cloudknot_role'
        else:
            self._description = str(d)

    service = property(operator.attrgetter('_service'))

    @service.setter
    def service(self, s):
        if s not in self.__allowed_services:
            raise Exception('service must be in ', self.__allowed_services)
        else:
            self._service = s + '.amazonaws.com'

    policies = property(operator.attrgetter('_policies'))

    @policies.setter
    def policies(self, pols):
        # Remove redundant entries
        input_policies = set(pols)
        iam = boto3.client('iam')
        response = iam.list_policies(Scope='AWS')
        aws_policies = [d['PolicyName'] for d in response.get('Policies')]
        if not (input_policies < set(aws_policies)):
            raise Exception('each policy must be an AWS managed policy: ',
                            aws_policies)
        else:
            self._policies = tuple(input_policies)

    def get_role_policy_document(self):
        role_policy = {
            "Version": "2012-10-17",
            "Statement": {
                "Sid": "",
                "Effect": "Allow",
                "Principal": {
                    "Service": self.service
                },
                "Action": "sts:AssumeRole"
            }
        }
        return role_policy

    role_policy_document = property(get_role_policy_document)

    def create(self):
        iam = boto3.client('iam')
        try:
            response = iam.create_role(
                RoleName=self.name,
                AssumeRolePolicyDocument=json.dumps(self.role_policy_document),
                Description=self.description
            )
            role_arn = response.get('Role')['Arn']
            if self.verbosity > 0:
                print('Created role {name:s} with arn {arn:s}'.format(
                    name=self.name, arn=role_arn))
        except iam.exceptions.EntityAlreadyExistsException:
            response = iam.get_role(RoleName=self.name)
            role_arn = response.get('Role')['Arn']
            if self.verbosity > 0:
                print('Role {name:s} already exists with arn {arn:s}'.format(
                    name=self.name, arn=role_arn))

        policy_response = iam.list_policies(Scope='AWS')
        for policy in self.policies:
            policy_filter = list(filter(lambda p: p['PolicyName'] == policy,
                                        policy_response.get('Policies')))
            policy_arn = policy_filter[0]['Arn']
            iam.attach_role_policy(
                PolicyArn=policy_arn,
                RoleName=self.name)
            if self.verbosity > 0:
                print('Attached policy {policy:s} to role {role:s}'.format(
                    policy=policy, role=self.name))

        self.__arn = role_arn

        RoleInfo = namedtuple('RoleInfo', ['name', 'arn'])
        return RoleInfo(name=self.name, arn=role_arn)


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
        self.job_role = job_role
        self.docker_image = docker_image
        self.vcpus = vcpus
        self.retries = retries

    job_role = property(operator.attrgetter('_job_role'))

    @job_role.setter
    def job_role(self, j):
        if not isinstance(j, IamRole):
            raise Exception('job_role must be an instance of IamRole')
        self._job_role = j

    docker_image = property(operator.attrgetter('_docker_image'))

    @docker_image.setter
    def docker_image(self, i):
        if not isinstance(i, DockerImage):
            raise Exception(
                'docker_image must be an instance of DockerImage')
        self._docker_image = i

    vcpus = property(operator.attrgetter('_vcpus'))

    @vcpus.setter
    def vcpus(self, c):
        try:
            cpus = int(c)
            if cpus < 1:
                raise Exception('vcpus must be positive')
            else:
                self._vcpus = cpus
        except ValueError:
            raise Exception('vcpus must be an integer')

    retries = property(operator.attrgetter('_retries'))

    @retries.setter
    def retries(self, r):
        try:
            retries_int = int(r)
            if retries_int < 1:
                raise Exception('retries must be positive')
            else:
                self._retries = retries_int
        except ValueError:
            raise Exception('retries must be an integer')

    def create(self):
        batch = boto3.client('batch')

        job_container_properties = {
            'image': self.docker_image.uri,
            'vcpus': self.vcpus,
            'memory': self.memory,
            'command': [],
            'jobRoleArn': self.job_role.arn,
            'user': self.username
        }

        response = batch.register_job_definition(
            jobDefinitionName=self.name,
            type='container',
            containerProperties=job_container_properties,
            retryStrategy={'attempts': self.retries}
        )

        if self.verbosity > 0:
            print('Created AWS batch job definition {name:s}'.format(
                name=self.name))

        self.__arn = response['jobDefinitionArn']

        JobDefInfo = namedtuple('JobDefInfo', ['name', 'arn'])
        return JobDefInfo(name=self.name, arn=response['jobDefinitionArn'])


# noinspection PyPropertyAccess,PyAttributeOutsideInit
class ComputeEnvironment(ObjectWithUsernameAndMemory):
    """Class for defining AWS Compute Environments"""
    def __init__(self, name, spot_fleet_role, resource_type='EC2', min_vcpus=0,
                 max_vcpus=256, desired_vcpus=8, memory=32000, username='cloudknot-user',
                 bid_percentage=50, verbosity=0):
        """ Initialize an AWS Batch job definition object.

        Parameters
        ----------
        name : string
            Name of the compute environment

        spot_fleet_role : IamRole
            IamRole instance for the AWS IAM spot fleet role

        resource_type : string
            Resource type, either "EC2" or "SPOT"

        min_vcpus : int
            minimum number of virtual cpus to be used to this compute
            environment
            Default: 0

        max_vcpus : int
            maximum number of virtual cpus to be used to this compute
            environment
            Default: 256

        desired_vcpus : int
            desired number of virtual cpus to be used to this compute
            environment
            Default: 8

        memory : int
            memory (MiB) to be used for this compute environment
            Default: 32000

        username : string
            username for be used for this compute environment
            Default: cloudknot-user

        bid_percentage : int
            bid percentage if using spot instances
            Default: 50

        verbosity : int
            verbosity level [0, 1, 2]
        """
        super(ComputeEnvironment, self).__init__(name=name, memory=memory,
                                                 username=username,
                                                 verbosity=verbosity)
        self.spot_fleet_role = spot_fleet_role
        self.resource_type = resource_type
        self.min_vcpu = min_vcpus
        self.max_vcpu = max_vcpus
        self.desired_vcpu = desired_vcpus
        self.bid_percentage = bid_percentage

    spot_fleet_role = property(operator.attrgetter('_spot_fleet_role'))

    @spot_fleet_role.setter
    def spot_fleet_role(self, sfr):
        if not (isinstance(sfr, IamRole) or sfr.service == 'spotfleet'):
            raise Exception('spot_fleet_role must be an IamRole instance with service type "spotfleet"')
        self._spot_fleet_role = sfr

    resource_type = property(operator.attrgetter('_resource_type'))

    @resource_type.setter
    def resource_type(self, rt):
        if rt not in ('EC2', 'SPOT'):
            raise Exception('resource_type must be either "EC2" or "SPOT"')
        self._resource_type = rt

    min_vcpus = property(operator.attrgetter('_min_vcpus'))

    @min_vcpus.setter
    def min_vcpus(self, c):
        try:
            cpus = int(c)
            if cpus < 0:
                raise Exception('min_vcpus must be non-negative')
            else:
                self._min_vcpus = cpus
        except ValueError:
            raise Exception('min_vcpus must be an integer')

    max_vcpus = property(operator.attrgetter('_max_vcpus'))

    @max_vcpus.setter
    def max_vcpus(self, c):
        try:
            cpus = int(c)
            if cpus < 0:
                raise Exception('max_vcpus must be non-negative')
            else:
                self._max_vcpus = cpus
        except ValueError:
            raise Exception('max_vcpus must be an integer')

    desired_vcpus = property(operator.attrgetter('_desired_vcpus'))

    @desired_vcpus.setter
    def desired_vcpus(self, c):
        try:
            cpus = int(c)
            if cpus < 0:
                raise Exception('desired_vcpus must be non-negative')
            else:
                self._desired_vcpus = cpus
        except ValueError:
            raise Exception('desired_vcpus must be an integer')

    bid_percentage = property(operator.attrgetter('_bid_percentage'))

    @bid_percentage.setter
    def bid_percentage(self, bp):
        try:
            bp_int = int(bp)
            if bp_int < 0:
                self._bid_percentage = 0
            elif bp_int > 100:
                self._bid_percentage = 100
            else:
                self._bid_percentage = bp_int
        except ValueError:
            raise Exception('bid_percentage must be an integer')

    def create(self):
        batch = boto3.client('batch')

        compute_resources = {
            'type': self.resource_type,
            'minvCpus': self.min_vcpu,
            'maxvCpus': self.max_vcpu,
            'desiredvCpus': self.desired_vcpu,
            'instanceTypes': [
                'optimal',
            ],
            'imageId': 'string',
            'subnets': [
                'string',
            ],
            'securityGroupIds': [
                'string',
            ],
            'ec2KeyPair': 'string',
            'instanceRole': 'string',
            'tags': {
                'string': 'string'
            },
            'bidPercentage': self.bid_percentage,
            'spotIamFleetRole': self.spot_fleet_role.arn
        }

        response = batch.create_compute_environment(
            computeEnvironmentName=self.name,
            type='MANAGED',
            state='ENABLED',
            computeResources=compute_resources,
            serviceRole='',
        )


# noinspection PyPropertyAccess,PyAttributeOutsideInit
class JobQueue(ObjectWithArn):
    """Class for defining AWS Batch Job Queues"""
    def __init__(self, name, compute_environment, priority=1, verbosity=0):
        """ Initialize an AWS Batch job definition object.

        Parameters
        ----------
        name : string
            Name of the job definition

        compute_environment : ComputeEnvironment or tuple of ComputeEnvironment
            ComputeEnvironment instance or sequence of ComputeEnvironment
            instances (in order of priority) for this job queue to use

        priority : int
            priority for jobs in this queue
            Default: 1

        verbosity : int
            verbosity level [0, 1, 2]
        """
        super(JobQueue, self).__init__(name=name, verbosity=verbosity)
        self.compute_environment = compute_environment
        self.priority = priority

    compute_environment = property(operator.attrgetter('_compute_environment'))

    @compute_environment.setter
    def compute_environment(self, ce):
        if not (isinstance(ce, ComputeEnvironment)
                and all(isinstance(x, ComputeEnvironment) for x in ce)):
            raise Exception(
                'compute_environment must be an instance of ComputeEnvironment')
        elif isinstance(ce, ComputeEnvironment):
            self._compute_environment = (ce,)
        else:
            self._compute_environment = tuple(ce)

    priority = property(operator.attrgetter('_priority'))

    @priority.setter
    def priority(self, p):
        try:
            p_int = int(p)
            if p_int < 1:
                raise Exception('priority must be positive')
            else:
                self._priority = p_int
        except ValueError:
            raise Exception('priority must be an integer')

    def create(self):
        batch = boto3.client('batch')

        compute_environment_order = []
        for i, ce in enumerate(self.compute_environment):
            compute_environment_order.append({
                'order': i,
                'computeEnvironment': ce
            })

        response = batch.create_job_queue(
            jobQueueName=self.name,
            state='ENABLED',
            priority=self.priority,
            computeEnvironmentOrder=compute_environment_order
        )

        # Wait for job queue to be in VALID state
        waiting = True
        num_waits = 0
        while waiting:
            if self.priority > 0:
                print('Waiting for AWS to create job queue {name:s} ...'.format(
                    name=self.name))
            response = batch.describe_job_queues(jobQueues=[self.name])
            waiting = (response.get('jobQueues')[0]['status'] != 'VALID')
            time.sleep(3)
            num_waits += 1
            if num_waits > 60:
                sys.exit('Waiting too long to create job queue. Aborting.')

        arn = response.get('jobQueues')[0]['jobQueueArn']
        self.__arn = arn

        JobQueueInfo = namedtuple('JobQueueInfo', ['name', 'arn'])
        return JobQueueInfo(name=self.name, arn=arn)
