from __future__ import absolute_import, division, print_function

import boto3
import logging
import operator
import sys
import time
from cloudknot.config import get_default_region

__all__ = ["ResourceDoesNotExistException", "ResourceExistsException",
           "CannotDeleteResourceException",
           "NamedObject", "ObjectWithArn", "ObjectWithUsernameAndMemory",
           "IAM", "EC2", "ECR", "BATCH",
           "wait_for_compute_environment", "wait_for_job_queue"]

IAM = boto3.client('iam', region_name=get_default_region())
EC2 = boto3.client('ec2', region_name=get_default_region())
BATCH = boto3.client('batch', region_name=get_default_region())
ECR = boto3.client('ecr', region_name=get_default_region())


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
        response = BATCH.describe_compute_environments(
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
        response = BATCH.describe_job_queues(jobQueues=[name])
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
