import boto3
import operator

__all__ = ["NamedObject", "ObjectWithArn",
           "ObjectWithUsernameAndMemory", "IAM", "EC2", "ECR", "BATCH"]

IAM = boto3.client('iam')
EC2 = boto3.client('ec2')
BATCH = boto3.client('batch')
ECR = boto3.client('ecr')


# noinspection PyPropertyAccess,PyAttributeOutsideInit
class ResourceExistsException(Exception):
    def __init__(self, message, resource_id):
        super().__init__(message)
        self.resource_id = resource_id


# noinspection PyPropertyAccess,PyAttributeOutsideInit
class ResourceDoesNotExistException(Exception):
    def __init__(self, message, resource_id):
        super().__init__(message)
        self.resource_id = resource_id


# noinspection PyPropertyAccess,PyAttributeOutsideInit
class CannotDeleteResourceException(Exception):
    def __init__(self, message, resource_id):
        super().__init__(message)
        self.resource_id = resource_id


# noinspection PyPropertyAccess,PyAttributeOutsideInit
class NamedObject(object):
    """Base class for building objects with name property"""
    def __init__(self, name):
        """ Initialize a base class with a name

        Parameters
        ----------
        name : string
            Name of the object
        """
        self._name = str(name)

    name = property(operator.attrgetter('_name'))


# noinspection PyPropertyAccess,PyAttributeOutsideInit
class ObjectWithArn(NamedObject):
    """ Base class for building objects with an Amazon Resource Name (ARN)
    Inherits from NamedObject
    """
    def __init__(self, name):
        """ Initialize a base class with name and Amazon Resource Number (ARN)

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
    """ Base class for building objects with properties memory and username
    Inherits from ObjectWithArn
    """
    def __init__(self, name, memory=32000, username='cloudknot-user'):
        """ Initialize a base class with name, memory, and username properties

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
