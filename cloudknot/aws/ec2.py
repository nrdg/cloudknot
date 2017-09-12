import ipaddress
import operator
import warnings
from .base_classes import ObjectWithNameAndVerbosity, EC2
from collections import namedtuple

__all__ = ["Vpc", "SecurityGroup"]


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
            except Exception:
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
            except Exception:
                raise Exception(
                    'subnet_ipv4 must be a sequence of valid IPv4 '
                    'network range.'
                )

            n_subnets = len(subnet_ipv4)
            if n_subnets > 1:
                warnings.warn(
                    'provided {n:d} subnets'.format(n=n_subnets) + ' '
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

        response = EC2.describe_vpcs(
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

            response = EC2.describe_subnets(
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
        response = EC2.create_vpc(
            CidrBlock=self.ipv4,
            AmazonProvidedIpv6CidrBlock=self.amazon_provided_ipv6,
            InstanceTenancy=self.instance_tenancy
        )

        vpc_id = response.get('Vpc')['VpcId']

        if self.verbosity > 0:
            print('Created VPC {vpcid:s}.'.format(vpcid=vpc_id))

        return vpc_id

    def _add_subnet(self):
        # Assign IPv6 block for subnet using CIDR provided by Amazon,
        # except use different size (must use /64)
        response = EC2.describe_vpcs(VpcIds=[self.vpc_id])
        ipv6_set = response.get('Vpcs')[0]['Ipv6CidrBlockAssociationSet'][0]
        subnet_ipv6 = ipv6_set['Ipv6CidrBlock'][:-2] + '64'

        response = EC2.create_subnet(
            CidrBlock=self.subnet_ipv4[0],
            Ipv6CidrBlock=subnet_ipv6,
            VpcId=self.vpc_id
        )

        return response.get('Subnet')['SubnetId']

    def remove_aws_resource(self):
        """ Delete this AWS virtual private cloud (VPC)

        Returns
        -------
        None
        """
        pass


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
                self._description = 'This security group was generated ' \
                                    'by cloudknot'
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

        response = EC2.describe_security_groups(
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
        # Create the security group
        response = EC2.create_security_group(
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

        EC2.authorize_security_group_ingress(
            GroupId=group_id,
            IpPermissions=ip_permissions
        )

        if self.verbosity > 0:
            print('Created security group {id:s}'.format(id=group_id))

        return group_id

    def remove_aws_resource(self):
        """ Delete this AWS security group

        Returns
        -------
        None
        """
        pass
