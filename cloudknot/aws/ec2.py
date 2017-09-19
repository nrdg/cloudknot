import ipaddress
import operator
import warnings

from .. import config
from .base_classes import EC2, NamedObject, \
    ResourceExistsException, ResourceDoesNotExistException
from collections import namedtuple

__all__ = ["Vpc", "SecurityGroup"]


# noinspection PyPropertyAccess,PyAttributeOutsideInit
class Vpc(object):
    """Class for defining an Amazon Virtual Private Cloud (VPC)"""
    def __init__(self, vpc_id=None, ipv4=None, amazon_provided_ipv6=None,
                 instance_tenancy=None, subnet_ipv4=None):
        # If user supplies vpc_id, then no other input is allowed
        if vpc_id and any([
            ipv4, amazon_provided_ipv6, instance_tenancy, subnet_ipv4
        ]):
            raise ValueError(
                'You must specify either a VPC id for an existing VPC or '
                'input parameters for a new VPC. You cannot do both.'
            )

        # If user supplies no vpc_id, then search based on ipv4 value
        # Check that ipv4 is a valid network range or set the default value
        if ipv4:
            try:
                ip_net = ipaddress.IPv4Network(ipv4)
            except ipaddress.AddressValueError:
                raise ValueError(
                    'If provided, ipv4 must be a valid IPv4 network range.'
                )
        else:
            ip_net = ipaddress.IPv4Network('10.0.0.0/16')

        # Check for pre-existence based on vpc_id or ipv4
        resource = self._exists_already(vpc_id, str(ip_net))
        self._pre_existing = resource.exists

        if resource.exists:
            # If resource exists and user supplied an ipv4, abort
            if ipv4:
                raise ResourceExistsException(
                    'The specified ipv4 CIDR block is already in use by '
                    'vpc {id:s}'.format(id=resource.vpc_id),
                    resource_id=resource.vpc_id
                )
            self._vpc_id = resource.vpc_id
            self._ipv4 = resource.ipv4
            self._amazon_provided_ipv6 = None
            self._instance_tenancy = resource.instance_tenancy
            self._subnet_ipv4 = resource.subnet_ipv4
            self._subnets = resource.subnets
            config.add_resource('vpcs', self.vpc_id, self.ipv4)
        else:
            if vpc_id:
                raise ResourceDoesNotExistException(
                    'You specified a vpc_id that does not exist.',
                    vpc_id
                )

            self._ipv4 = ipv4

            if amazon_provided_ipv6 is not None:
                if isinstance(amazon_provided_ipv6, bool):
                    self._amazon_provided_ipv6 = amazon_provided_ipv6
                else:
                    raise ValueError(
                        'If provided, amazon_provided_ipv6 must be a '
                        'boolean input.'
                    )
            else:
                self._amazon_provided_ipv6 = True

            if instance_tenancy:
                if instance_tenancy in ('default', 'dedicated', 'host'):
                    self._instance_tenancy = instance_tenancy
                else:
                    raise ValueError(
                        'If provided, instance tenancy must be '
                        'one of ("default", "dedicated", "host").'
                    )
            else:
                self._instance_tenancy = 'default'

            if subnet_ipv4:
                try:
                    self._subnet_ipv4 = [
                        str(ipaddress.IPv4Network(ip)) for ip in subnet_ipv4
                    ]
                except ipaddress.AddressValueError:
                    raise ValueError(
                        'subnet_ipv4 must be a sequence of valid IPv4 '
                        'network range.'
                    )

                n_subnets = len(subnet_ipv4)
                if n_subnets > 1:
                    warnings.warn(
                        'provided {n:d} subnets'.format(n=n_subnets) + ' '
                        'This object will ignore all but the first subnet.'
                    )
            else:
                self._subnet_ipv4 = ['10.0.0.0/24']

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

    def _exists_already(self, vpc_id, ipv4):
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

        if vpc_id:
            # If user supplied vpc_id, check that
            response = EC2.describe_vpcs(VpcIds=[vpc_id])
        else:
            # Check the user supplied CIDR block
            response = EC2.describe_vpcs(
                Filters=[
                    {
                        'Name': 'cidr',
                        'Values': [ipv4]
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

            logging.info('VPC {vpcid:s} already exists.'.format(vpcid=vpc_id))

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

        logging.info('Created VPC {vpcid:s}.'.format(vpcid=vpc_id))

        # Add this VPC to the list of VPCs in the config file
        config.add_resource('vpcs', vpc_id, self.ipv4)

        return vpc_id

    def _add_subnets(self):
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

    def clobber(self):
        """ Delete this AWS virtual private cloud (VPC)

        Returns
        -------
        None
        """
        # Delete the VPC
        EC2.delete_vpc(VpcId=self.vpc_id)

        # Remove this VPC from the list of VPCs in the config file
        config.remove_resource('vpcs', self.vpc_id)


# noinspection PyPropertyAccess,PyAttributeOutsideInit
class SecurityGroup(NamedObject):
    """Class for defining an AWS Security Group"""
    def __init__(self, security_group_id=None, name=None, vpc=None,
                 description=None):
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
        """
        if not (security_group_id or (name and vpc)):
            raise ValueError(
                'You must specify either a security group id for an existing '
                'security group or a name and VPC for a new security group.'
            )

        if security_group_id and any([name, vpc, description]):
            raise ValueError(
                'You must specify either a security group id for an existing '
                'security group or input parameters for a new security group. '
                'You cannot do both.'
            )

        if vpc and not isinstance(vpc, Vpc):
            raise ValueError('If provided, vpc must be an instance of Vpc.')

        vpc_id = vpc.vpc_id if vpc else None

        resource = self._exists_already(security_group_id, name, vpc_id)
        self._pre_existing = resource.exists

        if resource.exists:
            super(SecurityGroup, self).__init__(name=resource.name)

            self._vpc = None
            self._vpc_id = resource.vpc_id
            self._description = resource.description
            self._security_group_id = resource.security_group_id

            if name or vpc:
                raise ResourceExistsException(
                    'The security group name {name:s} is already in use for '
                    'VPC {vpc_id:s}. If you would like to retrieve this '
                    'security group, try SecurityGroup(security_group_id='
                    '{sg_id:s}).'.format(
                        name=self.name, vpc_id=self.vpc_id,
                        sg_id=self.security_group_id
                    ),
                    resource_id=self.security_group_id
                )

            config.add_resource(
                'security groups', self.security_group_id, self.name
            )
        else:
            if security_group_id:
                raise ResourceDoesNotExistException(
                    'The security group ID that you provided does not exist.',
                    resource_id=security_group_id
                )

            super(SecurityGroup, self).__init__(name=str(name))

            self._vpc = vpc
            self._vpc_id = vpc.vpc_id
            self._description = str(description) if description else \
                'This security group was automatically generated by cloudknot.'
            self._security_group_id = self._create()

    pre_existing = property(operator.attrgetter('_pre_existing'))
    vpc = property(operator.attrgetter('_vpc'))
    vpc_id = property(operator.attrgetter('_vpc_id'))
    description = property(operator.attrgetter('_description'))
    security_group_id = property(operator.attrgetter('_security_group_id'))

    def _exists_already(self, security_group_id, name, vpc_id):
        """ Check if an AWS security group exists already

        If security group exists, return namedtuple with security group info.
        Otherwise, set the namedtuple's `exists` field to `False`. The
        remaining fields default to `None`.

        Returns
        -------
        namedtuple RoleExists
            A namedtuple with fields
            ['exists', 'name', 'vpc_id', 'description', 'security_group_id']
        """
        # define a namedtuple for return value type
        ResourceExists = namedtuple(
            'ResourceExists',
            ['exists', 'name', 'vpc_id', 'description', 'security_group_id']
        )
        # make all but the first value default to None
        ResourceExists.__new__.__defaults__ = \
            (None,) * (len(ResourceExists._fields) - 1)

        if security_group_id:
            response = EC2.describe_security_groups(
                GroupIds=[security_group_id]
            )
        else:
            response = EC2.describe_security_groups(
                Filters=[
                    {
                        'Name': 'group-name',
                        'Values': [name]
                    },
                    {
                        'Name': 'vpc-id',
                        'Values': [vpc_id]
                    }
                ]
            )

        sg = response.get('SecurityGroups')
        if sg:
            name = sg[0]['GroupName']
            description = sg[0]['Description']
            group_id = sg[0]['GroupId']
            return ResourceExists(
                exists=True, name=name, vpc_id=vpc_id, description=description,
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

        logging.info('Created security group {id:s}'.format(id=group_id))

        # Add this security group to the list of security groups in the
        # config file
        config.add_resource('security groups', group_id, self.name)

        return group_id

    def clobber(self):
        """ Delete this AWS security group

        Returns
        -------
        None
        """
        # Delete the security group
        EC2.delete_security_group(GroupId=self.security_group_id)

        # Remove this VPC from the list of VPCs in the config file
        config.remove_resource('security groups', self.security_group_id)
