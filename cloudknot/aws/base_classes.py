from __future__ import absolute_import, division, print_function

import boto3
import configparser
import logging
import operator
import os
import sys
import time
from collections import namedtuple

from ..config import CONFIG, get_config_file

__all__ = ["ResourceDoesNotExistException",
           "ResourceExistsException", "CannotDeleteResourceException",
           "NamedObject", "ObjectWithArn", "ObjectWithUsernameAndMemory",
           "clients", "wait_for_compute_environment", "wait_for_job_queue"]


def get_region():
    """Get the default AWS region

    First, check the cloudknot config file for the region option.
    If that fails, check for the AWS_DEFAULT_REGION environment variable.
    If that fails, use the region in the AWS (not cloudknot) config file.
    If that fails, use us-east-1.

    Returns
    -------
    region : string
        default AWS region
    """
    config_file = get_config_file()
    CONFIG.clear()
    CONFIG.read(config_file)

    if CONFIG.has_section('aws') and CONFIG.has_option('aws', 'region'):
        return CONFIG.get('aws', 'region')
    else:
        # Set `region`, the fallback region in case the cloudknot
        # config file has no region set
        try:
            # Get the region from an environment variable
            region = os.environ['AWS_DEFAULT_REGION']
        except KeyError:
            # Get the default region from the AWS config file
            home = os.path.expanduser('~')
            aws_config_file = os.path.join(home, '.aws', 'config')

            fallback_region = 'us-east-1'
            if os.path.isfile(aws_config_file):
                aws_config = configparser.ConfigParser()
                aws_config.read(aws_config_file)
                try:
                    region = aws_config.get(
                        'default', 'region', fallback=fallback_region
                    )
                except TypeError:  # pragma: nocover
                    # python 2.7 compatibility
                    region = aws_config.get('default', 'region')
                    region = region if region else fallback_region
            else:
                region = fallback_region

        if not CONFIG.has_section('aws'):
            CONFIG.add_section('aws')

        CONFIG.set('aws', 'region', region)
        with open(config_file, 'w') as f:
            CONFIG.write(f)

        return region


def set_region(region='us-east-1'):
    """Set the AWS region that cloudknot will use

    Set region by modifying the cloudknot config file and clients

    Parameters
    ----------
    region : string
        An AWS region

    Returns
    -------
    None
    """
    response = clients['ec2'].describe_regions()
    region_names = [d['RegionName'] for d in response.get('Regions')]

    if region not in region_names:
        raise ValueError('`region` must be in {regions:s}'.format(
            regions=str(region_names)
        ))

    config_file = get_config_file()
    CONFIG.clear()
    CONFIG.read(config_file)

    if not CONFIG.has_section('aws'):
        CONFIG.add_section('aws')

    CONFIG.set('aws', 'region', region)
    with open(config_file, 'w') as f:
        CONFIG.write(f)

    # Update the boto3 clients so that the region change is reflected
    # throughout the package
    clients['iam'] = boto3.Session(profile_name=get_profile()).client(
        'iam', region_name=region
    )
    clients['ec2'] = boto3.Session(profile_name=get_profile()).client(
        'ec2', region_name=region
    )
    clients['batch'] = boto3.Session(profile_name=get_profile()).client(
        'batch', region_name=region
    )
    clients['ecr'] = boto3.Session(profile_name=get_profile()).client(
        'ecr', region_name=region
    )


def list_profiles():
    """Return a list of available AWS profile names

    Search the aws credentials file and the aws config file for profile names

    Returns
    -------
    profile_names : namedtuple
        A named tuple with fields: `profile_names`, a list of AWS profiles in
        the aws config file and the aws shared credentials file;
        `credentials_file`, a path to the aws shared credentials file;
        and `aws_config_file`, a path to the aws config file
    """
    aws = os.path.join(os.path.expanduser('~'), '.aws')

    try:
        # Get aws credentials file from environment variable
        env_file = os.environ['AWS_SHARED_CREDENTIALS_FILE']
        credentials_file = os.path.abspath(env_file)
    except KeyError:
        # Fallback on default credentials file path
        credentials_file = os.path.join(aws, 'credentials')

    try:
        # Get aws config file from environment variable
        env_file = os.environ['AWS_CONFIG_FILE']
        aws_config_file = os.path.abspath(env_file)
    except KeyError:
        # Fallback on default aws config file path
        aws_config_file = os.path.join(aws, 'config')

    credentials = configparser.ConfigParser()
    credentials.read(credentials_file)

    aws_config = configparser.ConfigParser()
    aws_config.read(aws_config_file)

    profile_names = [s.split()[1] for s in aws_config.sections()
                     if s.split()[0] == 'profile' and len(s.split()) == 2]

    profile_names += credentials.sections()

    # define a namedtuple for return value type
    ProfileInfo = namedtuple(
        'ProfileInfo',
        ['profile_names', 'credentials_file', 'aws_config_file']
    )

    return ProfileInfo(
        profile_names=profile_names,
        credentials_file=credentials_file,
        aws_config_file=aws_config_file
    )


def get_profile():
    """Get the AWS profile to use

    First, check the cloudknot config file for the profile option.
    If that fails, return 'default'

    Returns
    -------
    profile_name : string
        An AWS profile listed in the aws config file or aws shared
        credentials file
    """
    config_file = get_config_file()
    CONFIG.clear()
    CONFIG.read(config_file)

    if CONFIG.has_section('aws') and CONFIG.has_option('aws', 'profile'):
        return CONFIG.get('aws', 'profile')
    else:
        if 'default' in list_profiles().profile_names:
            # Set profile in cloudknot config to 'default' and return 'default'
            if not CONFIG.has_section('aws'):
                CONFIG.add_section('aws')

            CONFIG.set('aws', 'profile', 'default')
            with open(config_file, 'w') as f:
                CONFIG.write(f)

            return 'default'
        else:
            return None


def set_profile(profile_name):
    """Set the AWS profile that cloudknot will use

    Set profile by modifying the cloudknot config file and clients

    Parameters
    ----------
    profile_name : string
        An AWS profile listed in the aws config file or aws shared
        credentials file

    Returns
    -------
    None
    """
    profile_info = list_profiles()

    if profile_name not in profile_info.profile_names:
        raise ValueError(
            'The profile you specified does not exist in either the AWS '
            'config file at {conf:s} or the AWS shared credentials file at '
            '{cred:s}.'.format(
                conf=profile_info.aws_config_file,
                cred=profile_info.credentials_file
            )
        )

    config_file = get_config_file()
    CONFIG.clear()
    CONFIG.read(config_file)

    if not CONFIG.has_section('aws'):
        CONFIG.add_section('aws')

    CONFIG.set('aws', 'profile', profile_name)
    with open(config_file, 'w') as f:
        CONFIG.write(f)

    # Update the boto3 clients so that the profile change is reflected
    # throughout the package
    clients['iam'] = boto3.Session(profile_name=profile_name).client(
        'iam', region_name=get_region()
    )
    clients['ec2'] = boto3.Session(profile_name=profile_name).client(
        'ec2', region_name=get_region()
    )
    clients['batch'] = boto3.Session(profile_name=profile_name).client(
        'batch', region_name=get_region()
    )
    clients['ecr'] = boto3.Session(profile_name=profile_name).client(
        'ecr', region_name=get_region()
    )


clients = {
    'iam': boto3.Session(profile_name=get_profile()).client(
        'iam', region_name=get_region()
    ),
    'ec2': boto3.Session(profile_name=get_profile()).client(
        'ec2', region_name=get_region()
    ),
    'batch': boto3.Session(profile_name=get_profile()).client(
        'batch', region_name=get_region()
    ),
    'ecr': boto3.Session(profile_name=get_profile()).client(
        'ecr', region_name=get_region()
    )
}


def refresh_clients():
    clients['iam'] = boto3.Session(profile_name=get_profile()).client(
        'iam', region_name=get_region()
    )
    clients['ec2'] = boto3.Session(profile_name=get_profile()).client(
        'ec2', region_name=get_region()
    )
    clients['batch'] = boto3.Session(profile_name=get_profile()).client(
        'batch', region_name=get_region()
    )
    clients['ecr'] = boto3.Session(profile_name=get_profile()).client(
        'ecr', region_name=get_region()
    )


# noinspection PyPropertyAccess,PyAttributeOutsideInit
class ResourceExistsException(Exception):
    """Exception indicating that the requested AWS resource already exists"""
    def __init__(self, message, resource_id):
        """Initialize the Exception

        Parameters
        ----------
        message : string
            The error message to display to the user
        resource_id : string
            The resource ID (e.g. ARN, VPC-ID) of the requested resource
        """
        super(ResourceExistsException, self).__init__(message)
        self.resource_id = resource_id


# noinspection PyPropertyAccess,PyAttributeOutsideInit
class ResourceDoesNotExistException(Exception):
    """Exception indicating that the requested AWS resource does not exists"""
    def __init__(self, message, resource_id):
        """Initialize the Exception

        Parameters
        ----------
        message : string
            The error message to display to the user
        resource_id : string
            The resource ID (e.g. ARN, VPC-ID) of the requested resource
        """
        super(ResourceDoesNotExistException, self).__init__(message)
        self.resource_id = resource_id


# noinspection PyPropertyAccess,PyAttributeOutsideInit
class CannotDeleteResourceException(Exception):
    """Exception indicating that an AWS resource cannot be deleted"""
    def __init__(self, message, resource_id):
        """Initialize the Exception

        Parameters
        ----------
        message : string
            The error message to display to the user
        resource_id : string
            The resource ID (e.g. ARN, VPC-ID) of the requested resource
        """
        super(CannotDeleteResourceException, self).__init__(message)
        self.resource_id = resource_id


# noinspection PyPropertyAccess,PyAttributeOutsideInit
class NamedObject(object):
    """Base class for building objects with name property"""
    def __init__(self, name):
        """Initialize a base class with a name

        Parameters
        ----------
        name : string
            Name of the object
        """
        self._name = str(name)

    name = property(operator.attrgetter('_name'))


# noinspection PyPropertyAccess,PyAttributeOutsideInit
class ObjectWithArn(NamedObject):
    """Base class for building objects with an Amazon Resource Name (ARN)

    Inherits from NamedObject
    """
    def __init__(self, name):
        """Initialize a base class with name and Amazon Resource Number (ARN)

        Parameters
        ----------
        name : string
            Name of the object
        """
        super(ObjectWithArn, self).__init__(name=name)
        self._arn = None

    @property
    def arn(self):
        return self._arn


# noinspection PyPropertyAccess,PyAttributeOutsideInit
class ObjectWithUsernameAndMemory(ObjectWithArn):
    """Base class for building objects with properties memory and username

    Inherits from ObjectWithArn
    """
    def __init__(self, name, memory=32000, username='cloudknot-user'):
        """Initialize a base class with name, memory, and username properties

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
        """
        super(ObjectWithUsernameAndMemory, self).__init__(name=name)

        try:
            mem = int(memory)
            if mem < 1:
                raise ValueError('memory must be positive')
            else:
                self._memory = mem
        except ValueError:
            raise ValueError('memory must be an integer')

        self._username = str(username)

    memory = property(operator.attrgetter('_memory'))
    username = property(operator.attrgetter('_username'))


# noinspection PyPropertyAccess,PyAttributeOutsideInit
def wait_for_compute_environment(arn, name, log=True, max_wait_time=60):
    """Wait for a compute environment to finish updating or creating

    Parameters
    ----------
    arn : string
        Compute environment ARN

    name : string
        Compute environment name

    log : boolean
        Whether or not to log waiting info to the application log
        Default: True

    max_wait_time : int
        Maximum time to wait (in seconds)
        Default: 60

    Returns
    -------
    None
    """
    # Initialize waiting and num_waits for the while loop
    waiting = True
    num_waits = 0
    while waiting:
        if log:
            # Log waiting info
            logging.info(
                'Waiting for AWS to finish modifying compute environment '
                '{name:s}.'.format(name=name)
            )

        # Get compute environment info
        response = clients['batch'].describe_compute_environments(
            computeEnvironments=[arn]
        )

        # If compute environment has status == CREATING/UPDATING, keep waiting
        waiting = (response.get('computeEnvironments') == []
                   or response.get('computeEnvironments')[0]['status']
                   in ['CREATING', 'UPDATING'])

        # Wait a second
        time.sleep(1)
        num_waits += 1

        if num_waits > max_wait_time:
            # Timeout if max_wait_time exceeded
            sys.exit('Waiting too long for AWS to modify compute '
                     'environment. Aborting.')


# noinspection PyPropertyAccess,PyAttributeOutsideInit
def wait_for_job_queue(name, log=True, max_wait_time=60):
    """Wait for a job queue to finish updating or creating

    Parameters
    ----------
    name : string
        Job Queue name

    log : boolean
        Whether or not to log waiting info to the application log
        Default: True

    max_wait_time : int
        Maximum time to wait (in seconds)
        Default: 60

    Returns
    -------
    None
    """
    # Initialize waiting and num_waits for the while loop
    waiting = True
    num_waits = 0
    while waiting:
        if log:
            # Log waiting info
            logging.info(
                'Waiting for AWS to finish modifying job queue '
                '{name:s}.'.format(name=name)
            )

        # If job queue has status == CREATING/UPDATING, keep waiting
        response = clients['batch'].describe_job_queues(jobQueues=[name])
        waiting = (response.get('jobQueues') == []
                   or response.get('jobQueues')[0]['status']
                   in ['CREATING', 'UPDATING'])

        # Wait a second
        time.sleep(1)
        num_waits += 1

        if num_waits > max_wait_time:
            # Timeout if max_wait_time exceeded
            sys.exit('Waiting too long for AWS to modify job queue. '
                     'Aborting.')
