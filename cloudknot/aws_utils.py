from __future__ import absolute_import, division, print_function

import boto3
import docker
import ipaddress
import json
import operator
import os
import shutil
import subprocess
import sys
import time
import warnings
from collections import namedtuple

__all__ = ["DockerImage", "IamRole", "JobDefinition", "Vpc", "SecurityGroup",
           "ComputeEnvironment", "JobQueue"]


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
        if not name:
            raise Exception('name cannot be empty')
        self._name = str(name)

        try:
            ver = int(verbosity)
            if ver < 1:
                self._verbosity = 0
            else:
                self._verbosity = ver
        except ValueError:
            raise Exception('verbosity must be an integer')

    name = property(operator.attrgetter('_name'))
    verbosity = property(operator.attrgetter('_verbosity'))


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
        self._arn = None

    @property
    def arn(self):
        return self._arn


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
        super(ObjectWithUsernameAndMemory, self).__init__(
            name=name, verbosity=verbosity
        )

        try:
            mem = int(memory)
            if mem < 1:
                raise Exception('memory must be positive')
            else:
                self._memory = mem
        except ValueError:
            raise Exception('memory must be an integer')

        self._username = str(username)

    memory = property(operator.attrgetter('_memory'))
    username = property(operator.attrgetter('_username'))


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

        if not os.path.isdir(build_path):
            raise Exception('build_path must be an existing directory')
        self._build_path = os.path.abspath(build_path)

        if not os.path.isfile(dockerfile):
            raise Exception('dockerfile must be an existing regular file')
        self._dockerfile = os.path.abspath(dockerfile)

        if not requirements:
            self._requirements = None
        elif not os.path.isfile(requirements):
            raise Exception('requirements must be an existing regular file')
        else:
            self._requirements = os.path.abspath(requirements)

        if tags:
            tmp_tags = tuple([t for t in tags])
            if 'latest' not in tmp_tags:
                tmp_tags = tmp_tags + ('latest',)
            self._tags = tmp_tags
        else:
            self._tags = None

        self._uri = None

    build_path = property(operator.attrgetter('_build_path'))
    dockerfile = property(operator.attrgetter('_dockerfile'))
    requirements = property(operator.attrgetter('_requirements'))
    tags = property(operator.attrgetter('_tags'))

    def _build(self):
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

    def _create_repo(self, repo_name):
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
                repositoryNames=[repo_name]
            )

            repo_uri = response['repositories'][0]['repositoryUri']

            if self.verbosity > 0:
                print('Repository {name:s} already exists at {uri:s}'.format(
                    name=repo_name, uri=repo_uri))
        except ecr_client.exceptions.RepositoryNotFoundException:
            # If it doesn't exists already, then create it
            response = ecr_client.create_repository(
                repositoryName=repo_name
            )

            repo_uri = response['repository']['repositoryUri']
            if self.verbosity > 0:
                print('Created repository {name:s} at {uri:s}'.format(
                    name=repo_name, uri=repo_uri))

        self._uri = repo_uri

    @property
    def uri(self):
        return self._uri

    def _tag(self, repo_name):
        """
        Tag a DockerContainer image
        """
        self._create_repo(repo_name=repo_name)
        c = docker.from_env()
        for tag in self.tags:
            if self.verbosity > 0:
                print('Tagging image {name:s} with tag {tag:s}'.format(
                    name=self.name, tag=tag))
            c.tag(image=self.name + ':' + self.tag,
                  repository=self.uri, tag=tag)

    def _push(self, repo_name):
        """
        Push a DockerContainer image to a repository

        Parameters
        ----------
        repo_name : string
            Repository name
        """
        self._create_repo(repo_name=repo_name)
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
    def __init__(self, name, description=None, service='ecs-tasks',
                 policies=(), add_instance_role=False, verbosity=0):
        """ Initialize an AWS IAM Role object.

        Parameters
        ----------
        name : string
            Name of the IAM role

        description : string
            description of this IAM role
            If description == None (default), then it is reset to
            "This role was generated by cloudknot"
            Default: None

        service : {'ecs-tasks', 'batch', 'ec2', 'lambda', 'spotfleet'}
            service role on which this AWS IAM role should be based.
            Default: 'ecs-tasks'

        policies : tuple of strings
            tuple of names of AWS policies to attach to this role
            Default: ()

        add_instance_role : boolean
            flag to create an AWS instance profile and attach this role to it
            Default: False

        verbosity : int
            verbosity level [0, 1, 2]
        """
        super(IamRole, self).__init__(name=name, verbosity=verbosity)

        role_exists = self._exists_already()
        self._pre_existing = role_exists.exists

        if role_exists.exists:
            self._description = role_exists.description
            self._service = None
            self._role_policy_document = role_exists.role_policy_document
            self._policies = role_exists.policies
            self._add_instance_role = role_exists.add_instance_role
            self._arn = role_exists.arn
        else:
            if description:
                self._description = str(description)
            else:
                self._description = 'This role was generated by cloudknot'

            if service in self._allowed_services:
                self._service = service + '.amazonaws.com'
            else:
                raise Exception('service must be in ', self._allowed_services)

            role_policy = {
                "Version": "2012-10-17",
                "Statement": [{
                    "Sid": "",
                    "Effect": "Allow",
                    "Principal": {
                        "Service": self._service
                    },
                    "Action": "sts:AssumeRole"
                }]
            }
            self._role_policy_document = role_policy

            # Check the user supplied policies against the available policies
            iam = boto3.client('iam')

            # Remove redundant entries
            response = iam.list_policies()
            aws_policies = [d['PolicyName'] for d in response.get('Policies')]

            if isinstance(policies, str):
                input_policies = set((policies,))
            elif all(isinstance(x, str) for x in policies):
                input_policies = set(list(policies))
            else:
                raise Exception('policies must be a string or a '
                                'sequence of strings.')

            if not (input_policies < set(aws_policies)):
                raise Exception('each policy must be an AWS managed policy: ',
                                aws_policies)
            else:
                self._policies = tuple(input_policies)

            if isinstance(add_instance_role, bool):
                self._add_instance_role = add_instance_role
            else:
                raise Exception('add_instance_role is a boolean input')

            self._arn = self._create()

    _allowed_services = ['batch', 'ec2', 'ecs-tasks', 'lambda', 'spotfleet']

    pre_existing = property(operator.attrgetter('_pre_existing'))
    description = property(operator.attrgetter('_description'))
    service = property(operator.attrgetter('_service'))
    role_policy_document = property(
        operator.attrgetter('_role_policy_document')
    )
    add_instance_role = property(operator.attrgetter('_add_instance_role'))
    policies = property(operator.attrgetter('_policies'))

    def _exists_already(self):
        """ Check if an IAM Role exists already

        If role exists, return namedtuple with role info. Otherwise, set the
        namedtuple's `exists` field to `False`. The remaining fields default
        to `None`.

        Returns
        -------
        namedtuple RoleExists
            A namedtuple with fields ['exists', 'description',
            'role_policy_document', 'policies', 'add_instance_role', 'arn']
        """
        # define a namedtuple for return value type
        RoleExists = namedtuple(
            'RoleExists',
            ['exists', 'description', 'role_policy_document', 'policies',
             'add_instance_role', 'arn']
        )
        # make all but the first value default to None
        RoleExists.__new__.__defaults__ = \
            (None,) * (len(RoleExists._fields) - 1)

        iam = boto3.client('iam')

        try:
            response = iam.get_role(RoleName=self.name)
            arn = response.get('Role')['Arn']
            try:
                description = response.get('Role')['Description']
            except KeyError:
                description = ''
            role_policy = response.get('Role')['AssumeRolePolicyDocument']

            response = iam.list_attached_role_policies(RoleName=self.name)
            attached_policies = response.get('AttachedPolicies')
            policies = tuple([d['PolicyName'] for d in attached_policies])

            if self.verbosity > 0:
                print('IAM role {name:s} already exists: {arn:s}'.format(
                    name=self.name, arn=arn
                ))

            return RoleExists(
                exists=True, description=description,
                role_policy_document=role_policy, policies=policies,
                add_instance_role=False, arn=arn
            )
        except iam.exceptions.NoSuchEntityException:
            return RoleExists(exists=False)

    def _create(self):
        """ Create AWS IAM role using instance parameters

        Returns
        -------
        string
            Amazon Resource Number (ARN) for the created IAM role
        """
        iam = boto3.client('iam')

        response = iam.create_role(
            RoleName=self.name,
            AssumeRolePolicyDocument=json.dumps(self.role_policy_document),
            Description=self.description
        )
        role_arn = response.get('Role')['Arn']
        if self.verbosity > 0:
            print('Created role {name:s} with arn {arn:s}'.format(
                name=self.name, arn=role_arn
            ))

        policy_response = iam.list_policies()
        for policy in self.policies:
            policy_filter = list(filter(
                lambda p: p['PolicyName'] == policy,
                policy_response.get('Policies')
            ))

            policy_arn = policy_filter[0]['Arn']

            iam.attach_role_policy(
                PolicyArn=policy_arn,
                RoleName=self.name
            )

            if self.verbosity > 0:
                print('Attached policy {policy:s} to role {role:s}'.format(
                    policy=policy, role=self.name
                ))

        if self.add_instance_role:
            instance_profile_name = self.name + '-instance-profile'
            iam.create_instance_profile(
                InstanceProfileName=instance_profile_name
            )

            iam.add_role_to_instance_profile(
                InstanceProfileName=instance_profile_name,
                RoleName=self.name
            )

        return role_arn

    @property
    def instance_profile_arn(self):
        iam = boto3.client('iam')

        response = iam.list_instance_profiles_for_role(RoleName=self.name)

        if response.get('InstanceProfiles'):
            # This role has instance profiles, return the first
            arn = response.get('InstanceProfiles')[0]['Arn']
            return arn
        else:
            # This role has no instance profiles, return None
            return None


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

        batch = boto3.client('batch')

        response = batch.describe_job_definitions(jobDefinitionName=self.name)
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

        return response['jobDefinitionArn']


# noinspection PyPropertyAccess,PyAttributeOutsideInit
class Vpc(ObjectWithNameAndVerbosity):
    """Class for defining an Amazon Virtual Private Cloud (VPC)"""
    def __init__(self, name, ipv4='10.0.0.0/16', amazon_provided_ipv6=True,
                 instance_tenancy='default', subnet_ipv4=('10.0.0.0/24',),
                 verbosity=0):
        super(Vpc, self).__init__(name=name, verbosity=verbosity)

        resource_exists = self._exists_already()
        self._pre_existing = resource_exists.exists

        if resource_exists.exists:
            self._ipv4 = resource_exists.job_role
            self._amazon_provided_ipv6 = resource_exists.docker_image
            self._instance_tenancy = resource_exists.vcpus
            self._subnet_ipv4 = resource_exists.memory
            self._vpc_id = resource_exists.username
            self._subnets = resource_exists.retries
        else:
            try:
                ip_net = ipaddress.IPv4Network(ipv4)
                self._ipv4 = str(ip_net)
            except:
                raise Exception('ipv4 must be a valid IPv4 network range.')

            if isinstance(amazon_provided_ipv6, bool):
                self._amazon_provided_ipv6 = amazon_provided_ipv6
            else:
                raise Exception('amazon_provided_ipv6 is a boolean input')

            if instance_tenancy in ('default', 'dedicated', 'host'):
                self._instance_tenancy = instance_tenancy
            else:
                raise Exception('instance tenancy must be one of ("default", '
                                '"dedicated", "host")')

            try:
                self._subnet_ipv4 = [
                    str(ipaddress.IPv4Network(ip)) for ip in subnet_ipv4
                ]
            except:
                raise Exception(
                    'subnet_ipv4 must be a sequence of valid IPv4 '
                    'network range.'
                )

            n_subnets = len(subnet_ipv4)
            if n_subnets > 1:
                warnings.warn(
                    'provided {n:d} subnet'.format(n=n_subnets) + ' '
                    'This object will ignore all but the first subnet.'
                )

            self._vpc_id = self._create()
            self._subnets = []
            self._subnets.append(self._add_subnet)

    pre_existing = property(operator.attrgetter('_pre_existing'))
    ipv4 = property(operator.attrgetter('_ipv4'))
    amazon_provided_ipv6 = property(
        operator.attrgetter('_amazon_provided_ipv6')
    )
    instance_tenancy = property(operator.attrgetter('_instance_tenancy'))
    subnet_ipv4 = property(operator.attrgetter('_subnet_ipv4'))
    vpc_id = property(operator.attrgetter('_vpc_id'))
    subnets = property(operator.attrgetter('_subnets'))

    def _exists_already(self):
        """ Check if an AWS VPC exists already

        If VPC exists, return namedtuple with VPC info. Otherwise, set the
        namedtuple's `exists` field to `False`. The remaining fields default
        to `None`.

        Returns
        -------
        namedtuple RoleExists
            A namedtuple with fields ['exists', 'ipv4', 'instance_tenancy',
            'subnet_ipv4', 'vpc_id', 'subnets']
        """
        # define a namedtuple for return value type
        ResourceExists = namedtuple(
            'ResourceExists',
            ['exists', 'ipv4', 'instance_tenancy', 'subnet_ipv4',
             'vpc_id', 'subnets']
        )
        # make all but the first value default to None
        ResourceExists.__new__.__defaults__ = \
            (None,) * (len(ResourceExists._fields) - 1)

        ec2 = boto3.client('ec2')
        response = ec2.describe_vpcs(
            Filters=[
                {
                    'Name': 'cidr',
                    'Values': [self.ipv4]
                },
            ]
        )

        if response.get('Vpcs'):
            vpc = response.get('Vpcs')[0]
            ipv4 = vpc['CidrBlock']
            vpc_id = vpc['VpcId']
            instance_tenancy = vpc['InstanceTenancy']

            response = ec2.describe_subnets(
                Filters=[
                    {
                        'Name': 'vpc-id',
                        'Values': [vpc_id]
                    }
                ]
            )

            subnets = [d['SubnetId'] for d in response.get('Subnets')]
            subnet_ipv4 = [d['CidrBlock'] for d in response.get('Subnets')]

            if self.verbosity > 0:
                print('VPC {vpcid:s} already exists.'.format(vpcid=vpc_id))

            return ResourceExists(
                exists=True, ipv4=ipv4, instance_tenancy=instance_tenancy,
                subnet_ipv4=subnet_ipv4, vpc_id=vpc_id, subnets=subnets
            )
        else:
            return ResourceExists(exists=False)

    def _create(self):
        """ Create AWS virtual private cloud (VPC) using instance parameters

        Returns
        -------
        string
            VPC-ID for the created VPC
        """
        ec2 = boto3.client('ec2')

        response = ec2.create_vpc(
            CidrBlock=self.ipv4,
            AmazonProvidedIpv6CidrBlock=self.amazon_provided_ipv6,
            InstanceTenancy=self.instance_tenancy
        )

        vpc_id = response.get('Vpc')['VpcId']

        if self.verbosity > 0:
            print('Created VPC {vpcid:s}.'.format(vpcid=vpc_id))

        return vpc_id

    def _add_subnet(self):
        ec2 = boto3.client('ec2')

        # Assign IPv6 block for subnet using CIDR provided by Amazon,
        # except use different size (must use /64)
        response = ec2.describe_vpcs(VpcIds=[self.vpc_id])
        ipv6_set = response.get('Vpcs')[0]['Ipv6CidrBlockAssociationSet'][0]
        subnet_ipv6 = ipv6_set['Ipv6CidrBlock'][:-2] + '64'

        response = ec2.create_subnet(
            CidrBlock=self.subnet_ipv4[0],
            Ipv6CidrBlock=subnet_ipv6,
            VpcId=self.vpc_id
        )

        return response.get('Subnet')['SubnetId']


# noinspection PyPropertyAccess,PyAttributeOutsideInit
class SecurityGroup(ObjectWithNameAndVerbosity):
    """Class for defining an AWS Security Group"""
    def __init__(self, name, vpc, description=None, verbosity=0):
        """ Initialize an AWS Security Group.

        Parameters
        ----------
        name : string
            Name of the security group

        vpc : Vpc
            Amazon virtual private cloud in which to establish this
            security group

        description : string
            description of this security group
            if description == None (default), then description is set to
            "This security group was generated by cloudknot"
            Default: None

        verbosity : int
            verbosity level [0, 1, 2]
        """
        super(SecurityGroup, self).__init__(name=name, verbosity=verbosity)

        if not isinstance(vpc, Vpc):
            raise Exception('vpc must be an instance of Vpc.')

        resource_exists = self._exists_already(vpc.vpc_id)
        self._pre_existing = resource_exists.exists

        if resource_exists.exists:
            self._vpc = None
            self._vpc_id = resource_exists.vpc_id
            self._description = resource_exists.description
            self._security_group_id = resource_exists.security_group_id
        else:
            self._vpc = vpc
            self._vpc_id = vpc.vpc_id

            if not description:
                self._description = 'This role was generated by cloudknot'
            else:
                self._description = str(description)

            self._security_group_id = self._create()

    pre_existing = property(operator.attrgetter('_pre_existing'))
    vpc = property(operator.attrgetter('_vpc'))
    description = property(operator.attrgetter('_description'))
    security_group_id = property(operator.attrgetter('_security_group_id'))

    def _exists_already(self, vpc_id):
        """ Check if an AWS security group exists already

        If security group exists, return namedtuple with security group info.
        Otherwise, set the namedtuple's `exists` field to `False`. The
        remaining fields default to `None`.

        Returns
        -------
        namedtuple RoleExists
            A namedtuple with fields
            ['exists', 'vpc_id', 'description', 'security_group_id']
        """
        # define a namedtuple for return value type
        ResourceExists = namedtuple(
            'ResourceExists',
            ['exists', 'vpc_id', 'description', 'security_group_id']
        )
        # make all but the first value default to None
        ResourceExists.__new__.__defaults__ = \
            (None,) * (len(ResourceExists._fields) - 1)

        ec2 = boto3.client('ec2')
        response = ec2.describe_security_groups(
            Filters=[
                {
                    'Name': 'group-name',
                    'Values': [self.name]
                },
                {
                    'Name': 'vpc-id',
                    'Values': [vpc_id]
                }
            ]
        )

        sg = response.get('SecurityGroups')
        if sg:
            description = sg[0]['Description']
            group_id = sg[0]['GroupId']
            return ResourceExists(
                exists=True, vpc_id=vpc_id, description=description,
                security_group_id=group_id
            )
        else:
            return ResourceExists(exists=False)

    def _create(self):
        """ Create AWS security group using instance parameters

        Returns
        -------
        string
            security group ID for the created security group
        """
        ec2 = boto3.client('ec2')

        # Create the security group
        response = ec2.create_security_group(
            GroupName=self.name,
            Description=self.description,
            VpcId=self.vpc.vpc_id
        )

        group_id = response.get('GroupId')

        # Add ingress rules to the security group
        ipv4_ranges = [{
            'CidrIp': '0.0.0.0/0'
        }]

        ipv6_ranges = [{
            'CidrIpv6': '::/0'
        }]

        ip_permissions = [{
            'IpProtocol': 'TCP',
            'FromPort': 80,
            'ToPort': 80,
            'IpRanges': ipv4_ranges,
            'Ipv6Ranges': ipv6_ranges
        }, {
            'IpProtocol': 'TCP',
            'FromPort': 22,
            'ToPort': 22,
            'IpRanges': ipv4_ranges,
            'Ipv6Ranges': ipv6_ranges
        }]

        ec2.authorize_security_group_ingress(
            GroupId=group_id,
            IpPermissions=ip_permissions
        )

        if self.verbosity > 0:
            print('Created security group {id:s}'.format(id=group_id))

        return group_id


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
        namedtuple RoleExists
            A namedtuple with fields ['exists', 'description',
            'role_policy_document', 'policies', 'add_instance_role', 'arn']
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

        batch = boto3.client('batch')
        response = batch.describe_compute_environments(
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
        batch = boto3.client('batch')

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

        response = batch.create_compute_environment(
            computeEnvironmentName=self.name,
            type='MANAGED',
            state='ENABLED',
            computeResources=compute_resources,
            serviceRole=self.batch_service_arn
        )

        return response['computeEnvironmentArn']


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

        batch = boto3.client('batch')
        response = batch.describe_job_queues(
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
        batch = boto3.client('batch')

        response = batch.create_job_queue(
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
            response = batch.describe_job_queues(jobQueues=[self.name])
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

        batch = boto3.client('batch')

        if status == 'ALL':
            # status == 'ALL' is equivalent to not specifying a status at all
            response = batch.list_jobs(jobQueue=self.arn)
        else:
            # otherwise, filter on status
            response = batch.list_jobs(jobQueue=self.arn, jobStatus=status)

        # Return list of job_ids
        return response.get('jobSummaryList')


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

        batch = boto3.client('batch')
        response = batch.describe_jobs(jobs=[job_id])

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
        batch = boto3.client('batch')

        container_overrides = {
            'environment': self.environment_variables,
            'command': self.commands
        }

        response = batch.submit_job(
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
        batch = boto3.client('batch')

        # Query the job_id
        response = batch.describe_jobs(jobs=[self.job_id])
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

        batch = boto3.client('batch')

        batch.terminate_job(jobId=self.job_id, reason=reason)

        if self.verbosity > 0:
            print('Terminated job {name:s} with jobID {job_id:s}'.format(
                name=self.name, job_id=self.job_id
            ))
