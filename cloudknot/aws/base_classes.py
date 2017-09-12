import boto3
import operator

__all__ = ["ObjectWithNameAndVerbosity", "ObjectWithArn",
           "ObjectWithUsernameAndMemory", "IAM", "EC2", "ECR", "BATCH"]

IAM = boto3.client('iam')
EC2 = boto3.client('ec2')
BATCH = boto3.client('batch')
ECR = boto3.client('ecr')


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
