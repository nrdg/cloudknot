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
from botocore.exceptions import ClientError
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
        super(ObjectWithUsernameAndMemory, self).__init__(name=name,
                                                          verbosity=verbosity)
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
        self._uri = None

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

        service : string
            service role on which this AWS IAM role should be based. Must be
            one of ['batch', 'ec2', 'ecs-tasks', 'lambda', 'spotfleet']
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
        if role_exists.exists:
            self._pre_existing = role_exists.exists
            self._description = role_exists.description
            self._service = None
            self._role_policy_document = role_exists.role_policy_document
            self._policies = role_exists.policies
            self._add_instance_role = role_exists.add_instance_role
            self._arn = role_exists.arn
        else:
            self._pre_existing = role_exists.exists

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
                "Statement": {
                    "Sid": "",
                    "Effect": "Allow",
                    "Principal": {
                        "Service": self._service
                    },
                    "Action": "sts:AssumeRole"
                }
            }
            self._role_policy_document = role_policy

            # Check the user supplied policies against the available policies
            iam = boto3.client('iam')

            # Remove redundant entries
            input_policies = set(policies)
            response = iam.list_policies()
            aws_policies = [d['PolicyName'] for d in response.get('Policies')]

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

    def _exists_already(self):
        iam = boto3.client('iam')
        RoleExists = namedtuple(
            'RoleExists',
            ['exists', 'description', 'role_policy_document', 'policies',
             'add_instance_role', 'arn']
        )
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
            return RoleExists(exists=True, description=description,
                              role_policy_document=role_policy,
                              policies=policies, add_instance_role=False,
                              arn=arn)
        except iam.exceptions.NoSuchEntityException:
            return RoleExists(exists=False, description=None,
                              role_policy_document=None, policies=None,
                              add_instance_role=None, arn=None)

    description = property(operator.attrgetter('_description'))
    service = property(operator.attrgetter('_service'))
    role_policy_document = property(
        operator.attrgetter('_role_policy_document')
    )
    add_instance_role = property(operator.attrgetter('_add_instance_role'))
    policies = property(operator.attrgetter('_policies'))

    def _create(self):
        iam = boto3.client('iam')

        response = iam.create_role(
            RoleName=self.name,
            AssumeRolePolicyDocument=json.dumps(self.role_policy_document),
            Description=self.description
        )
        role_arn = response.get('Role')['Arn']
        if self.verbosity > 0:
            print('Created role {name:s} with arn {arn:s}'.format(
                name=self.name, arn=role_arn))

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
                    policy=policy, role=self.name))

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

        self._arn = response['jobDefinitionArn']

        JobDefInfo = namedtuple('JobDefInfo', ['name', 'arn'])
        return JobDefInfo(name=self.name, arn=response['jobDefinitionArn'])


# noinspection PyPropertyAccess,PyAttributeOutsideInit
class Vpc(ObjectWithNameAndVerbosity):
    """Class for defining an Amazon Virtual Private Cloud (VPC)"""
    def __init__(self, name, ipv4='10.0.0.0/16', amazon_provided_ipv6=True,
                 instance_tenancy='default', subnet_ipv4='10.0.0.0/24',
                 verbosity=0):
        super(Vpc, self).__init__(name=name, verbosity=verbosity)
        self.ipv4 = ipv4
        self.amazon_provided_ipv6 = amazon_provided_ipv6
        self.instance_tenancy = instance_tenancy
        self.subnet_ipv4 = subnet_ipv4
        self._vpc_id = None
        self._subnets = []

    ipv4 = property(operator.attrgetter('_ipv4'))

    @ipv4.setter
    def ipv4(self, ip):
        try:
            ip_net = ipaddress.IPv4Network(ip)
            self._ipv4 = str(ip_net)
        except:
            raise Exception('ipv4 must be a valid IPv4 network range.')

    amazon_provided_ipv6 = property(
        operator.attrgetter('_amazon_provided_ipv6')
    )

    @amazon_provided_ipv6.setter
    def amazon_provided_ipv6(self, b):
        if isinstance(b, bool):
            self._amazon_provided_ipv6 = b
        else:
            raise Exception('amazon_provided_ipv6 is a boolean input')

    instance_tenancy = property(operator.attrgetter('_instance_tenancy'))

    @instance_tenancy.setter
    def instance_tenancy(self, it):
        if it in ('default', 'dedicated', 'host'):
            self._instance_tenancy = it
        else:
            raise Exception('instance tenancy must be one of ("default", '
                            '"dedicated", "host")')

    subnet_ipv4 = property(operator.attrgetter('_subnet_ipv4'))

    @subnet_ipv4.setter
    def subnet_ipv4(self, subnet_ip):
        try:
            subnet_ip_net = ipaddress.IPv4Network(subnet_ip)
            self._subnet_ipv4 = str(subnet_ip_net)
        except:
            raise Exception('subnet_ipv4 must be a valid IPv4 network range.')

    @property
    def vpc_id(self):
        return self._vpc_id

    @property
    def subnets(self):
        return self._subnets

    def create(self):
        ec2 = boto3.client('ec2')

        response = ec2.create_vpc(
            CidrBlock=self.ipv4,
            AmazonProvidedIpv6CidrBlock=self.amazon_provided_ipv6,
            InstanceTenancy=self.instance_tenancy
        )

        self._vpc_id = response.get('Vpc')['VpcId']

    def add_subnet(self):
        ec2 = boto3.client('ec2')

        # Assign IPv6 block for subnet using CIDR provided by Amazon,
        # except use different size (must use /64)
        response = ec2.describe_vpcs(VpcIds=[self.vpc_id])
        ipv6_set = response.get('Vpcs')[0]['Ipv6CidrBlockAssociationSet'][0]
        subnet_ipv6 = ipv6_set['Ipv6CidrBlock'][:-2] + '64'

        response = ec2.create_subnet(
            CidrBlock=self.subnet_ipv4,
            Ipv6CidrBlock=subnet_ipv6,
            VpcId=self.vpc_id
        )

        self._subnets.append(response.get('Subnet')['SubnetId'])


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
        self.vpc = vpc
        self.description = description
        self._security_group_id = None

    vpc = property(operator.attrgetter('_vpc'))

    @vpc.setter
    def vpc(self, v):
        if not isinstance(v, Vpc):
            raise Exception('vpc must be an instance of Vpc.')

    description = property(operator.attrgetter('_description'))

    @description.setter
    def description(self, d):
        if not d:
            self._description = 'This role was generated by cloudknot'
        else:
            self._description = str(d)

    @property
    def security_group_id(self):
        return self._security_group_id

    def create(self):
        ec2 = boto3.client('ec2')

        try:
            # Create the security group
            response = ec2.create_security_group(
                GroupName=self.name,
                Description=self.description,
                VpcId=self.vpc.vpc_id
            )

            self._security_group_id = response.get('GroupId')

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
                GroupId=self.security_group_id,
                IpPermissions=ip_permissions
            )
        except ClientError as e:
            print(e)


# noinspection PyPropertyAccess,PyAttributeOutsideInit
class ComputeEnvironment(ObjectWithUsernameAndMemory):
    """Class for defining AWS Compute Environments"""
    def __init__(self, name, batch_service_role, instance_role,
                 vpc, security_group,
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
        if not bid_percentage and resource_type == 'SPOT':
            error = 'if resource_type is "SPOT", bid_percentage must be set.'
            raise Exception(error)
        super(ComputeEnvironment, self).__init__(name=name, memory=memory,
                                                 username=username,
                                                 verbosity=verbosity)
        self.batch_service_role = batch_service_role
        self.instance_role = instance_role
        self.vpc = vpc
        self.security_group = security_group
        self.spot_fleet_role = spot_fleet_role
        self.instance_types = instance_types
        self.resource_type = resource_type
        self.min_vcpu = min_vcpus
        self.max_vcpu = max_vcpus
        self.desired_vcpu = desired_vcpus
        self.image_id = image_id
        self.ec2_key_pair = ec2_key_pair
        self.tags = tags
        self.bid_percentage = bid_percentage

    batch_service_role = property(operator.attrgetter('_batch_service_role'))

    @batch_service_role.setter
    def batch_service_role(self, bsr):
        if not (isinstance(bsr, IamRole) and bsr.service == 'batch'):
            raise Exception('batch_service_role must be an IamRole instance '
                            'with service type "batch"')
        self._batch_service_role = bsr

    instance_role = property(operator.attrgetter('_instance_role'))

    @instance_role.setter
    def instance_role(self, ir):
        if not (isinstance(ir, IamRole) and ir.service == 'ec2'):
            raise Exception('instance_role must be an IamRole instance with '
                            'service type "ec2"')
        self._instance_role = ir

    vpc = property(operator.attrgetter('_vpc'))

    @vpc.setter
    def vpc(self, v):
        if not isinstance(v, Vpc):
            raise Exception('vpc must be an instance of Vpc')
        self._vpc = v

    security_group = property(operator.attrgetter('_security_group'))

    @security_group.setter
    def security_group(self, sg):
        if not isinstance(sg, SecurityGroup):
            raise Exception('security_group must be an instance of '
                            'SecurityGroup')
        self._security_group = sg

    spot_fleet_role = property(operator.attrgetter('_spot_fleet_role'))

    @spot_fleet_role.setter
    def spot_fleet_role(self, sfr):
        if sfr:
            if not (isinstance(sfr, IamRole) and sfr.service == 'spotfleet'):
                raise Exception('if provided, spot_fleet_role must be an '
                                'IamRole instance with service type '
                                '"spotfleet"')
            self._spot_fleet_role = sfr
        else:
            self._spot_fleet_role = None

    instance_types = property(operator.attrgetter('_instance_types'))

    @instance_types.setter
    def instance_types(self, it):
        if isinstance(it, str):
            self._instance_types = (it,)
        elif all(isinstance(x, str) for x in it):
            self._instance_types = list(it)
        else:
            error = 'instance_types must be a string or a sequence of strings.'
            raise Exception(error)

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

    image_id = property(operator.attrgetter('_image_id'))

    @image_id.setter
    def image_id(self, im_id):
        if im_id:
            if not isinstance(im_id, str):
                raise Exception('if provided, image_id must be a string')
            self._image_id = im_id
        else:
            self._image_id = None

    ec2_key_pair = property(operator.attrgetter('_ec2_key_pair'))

    @ec2_key_pair.setter
    def ec2_key_pair(self, ec2kp):
        if ec2kp:
            if not isinstance(ec2kp, str):
                raise Exception('if provided, ec2_key_pair must be a string')
            self._ec2_key_pair = ec2kp
        else:
            self._ec2_key_pair = None

    tags = property(operator.attrgetter('_tags'))

    @tags.setter
    def tags(self, tgs):
        if tgs:
            if not isinstance(tgs, dict):
                raise Exception('if provided, tags must be an instance of '
                                'dict')
            self._tags = tgs
        else:
            self._tags = None

    bid_percentage = property(operator.attrgetter('_bid_percentage'))

    @bid_percentage.setter
    def bid_percentage(self, bp):
        if bp:
            try:
                bp_int = int(bp)
                if bp_int < 0:
                    self._bid_percentage = 0
                elif bp_int > 100:
                    self._bid_percentage = 100
                else:
                    self._bid_percentage = bp_int
            except ValueError:
                raise Exception('if provided, bid_percentage must be an int')
        else:
            self._bid_percentage = None

    def create(self):
        batch = boto3.client('batch')

        compute_resources = {
            'type': self.resource_type,
            'minvCpus': self.min_vcpu,
            'maxvCpus': self.max_vcpu,
            'desiredvCpus': self.desired_vcpu,
            'instanceTypes': self.instance_types,
            'subnets': self.vpc.subnets,
            'securityGroupIds': [self.security_group.security_group_id],
            'instanceRole': self.instance_role.instance_profile_arn,
        }

        # If using spot instances, include the relevant key/value pairs
        if self.resource_type == 'SPOT':
            compute_resources['bidPercentage'] = self.bid_percentage
            compute_resources['spotIamFleetRole'] = self.spot_fleet_role.arn

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
            serviceRole=self.batch_service_role.arn
        )

        return response


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
        if isinstance(ce, ComputeEnvironment):
            self._compute_environment = (ce,)
        elif all(isinstance(x, ComputeEnvironment) for x in ce):
            self._compute_environment = tuple(ce)
        else:
            raise Exception('compute_environment must be a ComputeEnvironment '
                            'instance or a sequence of ComputeEnvironment '
                            'instances.')

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
                print('Waiting for AWS to create job queue {name:s}.'.format(
                    name=self.name))
            response = batch.describe_job_queues(jobQueues=[self.name])
            waiting = (response.get('jobQueues')[0]['status'] != 'VALID')
            time.sleep(3)
            num_waits += 1
            if num_waits > 60:
                sys.exit('Waiting too long to create job queue. Aborting.')

        arn = response.get('jobQueues')[0]['jobQueueArn']
        self._arn = arn

        JobQueueInfo = namedtuple('JobQueueInfo', ['name', 'arn'])
        return JobQueueInfo(name=self.name, arn=arn)
