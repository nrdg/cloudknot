from __future__ import absolute_import, division, print_function

import boto3
import botocore
import configparser
import getpass
import json
import logging
import os
import sys
import time
import uuid
from collections import namedtuple

from ..config import get_config_file, rlock

__all__ = [
    "ResourceDoesNotExistException", "ResourceClobberedException",
    "ResourceExistsException", "CannotDeleteResourceException",
    "CannotCreateResourceException", "RegionException", "ProfileException",
    "BatchJobFailedError", "CKTimeoutError",
    "NamedObject", "ObjectWithArn", "ObjectWithUsernameAndMemory",
    "clients", "refresh_clients",
    "wait_for_compute_environment", "wait_for_job_queue",
    "get_region", "set_region",
    "get_ecr_repo", "set_ecr_repo",
    "get_s3_bucket", "set_s3_bucket", "get_s3_policy_name",
    "get_profile", "set_profile", "list_profiles",
]

mod_logger = logging.getLogger(__name__)


def get_ecr_repo():
    """Get the cloudknot ECR repository

    First, check the cloudknot config file for the ecr-repo option.
    If that fails, check for the CLOUDKNOT_ECR_REPO environment variable.
    If that fails, use 'cloudknot'

    Returns
    -------
    repo : string
        Cloudknot ECR repository name
    """
    config_file = get_config_file()
    config = configparser.ConfigParser()

    with rlock:
        config.read(config_file)

        option = 'ecr-repo'
        if config.has_section('aws') and config.has_option('aws', option):
            repo = config.get('aws', option)
        else:
            # Set `repo`, the fallback repo in case the cloudknot
            # repo environment variable is not set
            try:
                # Get the region from an environment variable
                repo = os.environ['CLOUDKNOT_ECR_REPO']
            except KeyError:
                repo = 'cloudknot'

        # Use set_ecr_repo to check for name availability
        # and write to config file
        set_ecr_repo(repo)

    return repo


def set_ecr_repo(repo):
    """Set the cloudknot ECR repo

    Set repo by modifying the cloudknot config file

    Parameters
    ----------
    repo : string
        Cloudknot ECR repo name
    """
    # Update the config file
    config_file = get_config_file()
    config = configparser.ConfigParser()

    with rlock:
        config.read(config_file)

        if not config.has_section('aws'):  # pragma: nocover
            config.add_section('aws')

        config.set('aws', 'ecr-repo', repo)
        with open(config_file, 'w') as f:
            config.write(f)

        try:
            # If repo exists, retrieve its info
            clients['ecr'].describe_repositories(
                repositoryNames=[repo]
            )
        except clients['ecr'].exceptions.RepositoryNotFoundException:
            # If it doesn't exists already, then create it
            clients['ecr'].create_repository(repositoryName=repo)


def get_s3_bucket():
    """Get the cloudknot S3 bucket

    First, check the cloudknot config file for the bucket option.
    If that fails, check for the CLOUDKNOT_S3_BUCKET environment variable.
    If that fails, use 'cloudknot-' + getpass.getuser().lower() + '-' + uuid4()

    Returns
    -------
    bucket : string
        Cloudknot S3 bucket name
    """
    config_file = get_config_file()
    config = configparser.ConfigParser()

    with rlock:
        config.read(config_file)

        option = 's3-bucket'
        if config.has_section('aws') and config.has_option('aws', option):
            bucket = config.get('aws', option)
        else:
            # Set `bucket`, the fallback bucket in case the cloudknot
            # bucket environment variable is not set
            try:
                # Get the region from an environment variable
                bucket = os.environ['CLOUDKNOT_S3_BUCKET']
            except KeyError:
                bucket = ('cloudknot-' + getpass.getuser().lower()
                          + '-' + str(uuid.uuid4()))

        # Use set_s3_bucket to check for name availability
        # and write to config file
        set_s3_bucket(bucket)

    return bucket


def set_s3_bucket(bucket):
    """Set the cloudknot S3 bucket

    Set bucket by modifying the cloudknot config file

    Parameters
    ----------
    bucket : string
        Cloudknot S3 bucket name
    """
    # Update the config file
    config_file = get_config_file()
    config = configparser.ConfigParser()

    with rlock:
        config.read(config_file)

        if not config.has_section('aws'):  # pragma: nocover
            config.add_section('aws')

        config.set('aws', 's3-bucket', bucket)
        with open(config_file, 'w') as f:
            config.write(f)

        # Create the bucket
        try:
            clients['s3'].create_bucket(Bucket=bucket)
        except clients['s3'].exceptions.BucketAlreadyOwnedByYou:
            pass
        except clients['s3'].exceptions.BucketAlreadyExists:
            raise ValueError('The requested bucket name is not available.')

        # Update the s3_policy with new bucket name
        update_s3_policy(bucket)


def get_bucket_policy(bucket):
    """Return the policy document to access an S3 bucket

    Parameters
    ----------
    bucket: string
        An Amazon S3 bucket name

    Returns
    -------
    s3_policy: dict
        A dictionary containing the AWS policy document
    """
    # Add policy statements to access to cloudknot S3 bucket
    s3_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["s3:ListBucket"],
                "Resource": ["arn:aws:s3:::{0:s}".format(bucket)]
            },
            {
                "Effect": "Allow",
                "Action": ["s3:PutObject", "s3:GetObject"],
                "Resource": ["arn:aws:s3:::{0:s}/*".format(bucket)]
            },
        ]
    }

    return s3_policy


def get_s3_policy_name(bucket):
    """Get the policy that grants access to the cloudknot S3 bucket

    First, check the cloudknot config file for the bucket-policy option.
    If that fails, use 'cloudknot-bucket-access-' + uuid4()

    Returns
    -------
    policy : string
        Cloudknot S3 bucket access policy name
    """
    config_file = get_config_file()
    config = configparser.ConfigParser()

    with rlock:
        config.read(config_file)

        option = 's3-bucket-policy'
        if config.has_section('aws') and config.has_option('aws', option):
            # Get policy name from the config file
            policy = config.get('aws', option)
        else:
            # or create new one if it doesn't exist
            policy = 'cloudknot-bucket-access-' + str(uuid.uuid4())

            if not config.has_section('aws'):
                config.add_section('aws')

            config.set('aws', option, policy)
            with open(config_file, 'w') as f:
                config.write(f)

        s3_policy = get_bucket_policy(bucket)

        try:
            # Create the policy
            clients['iam'].create_policy(
                PolicyName=policy,
                Path='/cloudknot/',
                PolicyDocument=json.dumps(s3_policy),
                Description='Grants access to S3 bucket {0:s}'.format(bucket)
            )
        except clients['iam'].exceptions.EntityAlreadyExistsException:
            # Policy already exists, do nothing
            pass

    return policy


def update_s3_policy(bucket):
    """Update the cloudknot S3 access policy with new bucket name

    Parameters
    ----------
    bucket: string
        Amazon S3 bucket name
    """
    s3_policy = get_bucket_policy(bucket)
    policy = get_s3_policy_name(bucket)

    # After calling get_s3_policy_name(), the policy already exists
    # Get the ARN
    response = clients['iam'].list_policies(
        Scope='Local',
        PathPrefix='/cloudknot/'
    )

    policy_dict = [p for p in response.get('Policies')
                   if p['PolicyName'] == policy][0]

    arn = policy_dict['Arn']

    with rlock:
        try:
            # Update the policy
            clients['iam'].create_policy_version(
                PolicyArn=arn,
                PolicyDocument=json.dumps(s3_policy),
                SetAsDefault=True
            )
        except clients['iam'].exceptions.LimitExceededException:
            # Too many policy versions. List policy versions and delete oldest
            response = clients['iam'].list_policy_versions(
                PolicyArn=arn
            )

            # Get non-default versions
            versions = [v for v in response.get('Versions')
                        if not v['IsDefaultVersion']]

            # Get the oldest version and delete it
            oldest = sorted(versions, key=lambda ver: ver['CreateDate'])[0]
            clients['iam'].delete_policy_version(
                PolicyArn=arn,
                VersionId=oldest['VersionId']
            )

            # Update the policy not that there's room for another version
            clients['iam'].create_policy_version(
                PolicyArn=arn,
                PolicyDocument=json.dumps(s3_policy),
                SetAsDefault=True
            )


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
    config = configparser.ConfigParser()

    with rlock:
        config.read(config_file)

        if config.has_section('aws') and config.has_option('aws', 'region'):
            return config.get('aws', 'region')
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

            if not config.has_section('aws'):
                config.add_section('aws')

            config.set('aws', 'region', region)
            with open(config_file, 'w') as f:
                config.write(f)

            return region


def set_region(region='us-east-1'):
    """Set the AWS region that cloudknot will use

    Set region by modifying the cloudknot config file and clients

    Parameters
    ----------
    region : string
        An AWS region.
        Default: 'us-east-1'
    """
    response = clients['ec2'].describe_regions()
    region_names = [d['RegionName'] for d in response.get('Regions')]

    if region not in region_names:
        raise ValueError('`region` must be in {regions!s}'.format(
            regions=region_names
        ))

    config_file = get_config_file()
    config = configparser.ConfigParser()

    with rlock:
        config.read(config_file)

        if not config.has_section('aws'):  # pragma: nocover
            config.add_section('aws')

        config.set('aws', 'region', region)
        with open(config_file, 'w') as f:
            config.write(f)

        # Update the boto3 clients so that the region change is reflected
        # throughout the package
        max_pool = clients['iam'].meta.config.max_pool_connections
        boto_config = botocore.config.Config(max_pool_connections=max_pool)
        session = boto3.Session(profile_name=get_profile(fallback=None))
        clients['iam'] = session.client('iam', region_name=region,
                                        config=boto_config)
        clients['ec2'] = session.client('ec2', region_name=region,
                                        config=boto_config)
        clients['batch'] = session.client('batch', region_name=region,
                                          config=boto_config)
        clients['ecr'] = session.client('ecr', region_name=region,
                                        config=boto_config)
        clients['ecs'] = session.client('ecs', region_name=region,
                                        config=boto_config)
        clients['s3'] = session.client('s3', region_name=region,
                                       config=boto_config)


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


def get_profile(fallback='from-env'):
    """Get the AWS profile to use

    First, check the cloudknot config file for the profile option.
    If that fails, return 'default'

    Parameters
    ----------
    fallback :
        The fallback value if get_profile cannot find an AWS profile.
        Default: 'from-env'
    Returns
    -------
    profile_name : string
        An AWS profile listed in the aws config file or aws shared
        credentials file
    """
    config_file = get_config_file()
    config = configparser.ConfigParser()

    with rlock:
        config.read(config_file)

        if config.has_section('aws') and config.has_option('aws', 'profile'):
            return config.get('aws', 'profile')
        else:
            if 'default' in list_profiles().profile_names:
                # Set profile in cloudknot config to 'default'
                # and return 'default'
                if not config.has_section('aws'):
                    config.add_section('aws')

                config.set('aws', 'profile', 'default')
                with open(config_file, 'w') as f:
                    config.write(f)

                return 'default'
            else:
                return fallback


def set_profile(profile_name):
    """Set the AWS profile that cloudknot will use

    Set profile by modifying the cloudknot config file and clients

    Parameters
    ----------
    profile_name : string
        An AWS profile listed in the aws config file or aws shared
        credentials file
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
    config = configparser.ConfigParser()

    with rlock:
        config.read(config_file)

        if not config.has_section('aws'):  # pragma: nocover
            config.add_section('aws')

        config.set('aws', 'profile', profile_name)
        with open(config_file, 'w') as f:
            config.write(f)

        # Update the boto3 clients so that the profile change is reflected
        # throughout the package
        max_pool = clients['iam'].meta.config.max_pool_connections
        boto_config = botocore.config.Config(max_pool_connections=max_pool)
        session = boto3.Session(profile_name=profile_name)
        clients['iam'] = session.client('iam', region_name=get_region(),
                                        config=boto_config)
        clients['ec2'] = session.client('ec2', region_name=get_region(),
                                        config=boto_config)
        clients['batch'] = session.client('batch', region_name=get_region(),
                                          config=boto_config)
        clients['ecr'] = session.client('ecr', region_name=get_region(),
                                        config=boto_config)
        clients['ecs'] = session.client('ecs', region_name=get_region(),
                                        config=boto_config)
        clients['s3'] = session.client('s3', region_name=get_region(),
                                       config=boto_config)


#: module-level dictionary of boto3 clients for IAM, EC2, Batch, ECR, ECS, S3.
clients = {
    'iam': boto3.Session(profile_name=get_profile(fallback=None)).client(
        'iam', region_name=get_region()
    ),
    'ec2': boto3.Session(profile_name=get_profile(fallback=None)).client(
        'ec2', region_name=get_region()
    ),
    'batch': boto3.Session(profile_name=get_profile(fallback=None)).client(
        'batch', region_name=get_region()
    ),
    'ecr': boto3.Session(profile_name=get_profile(fallback=None)).client(
        'ecr', region_name=get_region()
    ),
    'ecs': boto3.Session(profile_name=get_profile(fallback=None)).client(
        'ecs', region_name=get_region()
    ),
    's3': boto3.Session(profile_name=get_profile(fallback=None)).client(
        's3', region_name=get_region()
    )
}
"""module-level dictionary of boto3 clients for IAM, EC2, Batch, ECR, ECS, S3.

Storing the boto3 clients in a module-level dictionary allows us to change
the region and profile and have those changes reflected globally.

Advanced users: if you want to use cloudknot and boto3 at the same time,
you should use these clients to ensure that you have the right profile
and region.
"""


def refresh_clients(max_pool=10):
    """Refresh the boto3 clients dictionary"""
    with rlock:
        config = botocore.config.Config(max_pool_connections=max_pool)
        session = boto3.Session(profile_name=get_profile(fallback=None))
        clients['iam'] = session.client('iam', region_name=get_region(),
                                        config=config)
        clients['ec2'] = session.client('ec2', region_name=get_region(),
                                        config=config)
        clients['batch'] = session.client('batch', region_name=get_region(),
                                          config=config)
        clients['ecr'] = session.client('ecr', region_name=get_region(),
                                        config=config)
        clients['ecs'] = session.client('ecs', region_name=get_region(),
                                        config=config)
        clients['s3'] = session.client('s3', region_name=get_region(),
                                       config=config)


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
class ResourceClobberedException(Exception):
    """Exception indicating that this AWS resource has been clobbered"""
    def __init__(self, message, resource_id):
        """Initialize the Exception

        Parameters
        ----------
        message : string
            The error message to display to the user

        resource_id : string
            The resource ID (e.g. ARN, VPC-ID) of the requested resource
        """
        super(ResourceClobberedException, self).__init__(message)
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
            The resource ID (e.g. ARN, VPC-ID) of the dependent resources
        """
        super(CannotDeleteResourceException, self).__init__(message)
        self.resource_id = resource_id


# noinspection PyPropertyAccess,PyAttributeOutsideInit
class CannotCreateResourceException(Exception):
    """Exception indicating that an AWS resource cannot be created"""
    def __init__(self, message):
        """Initialize the Exception

        Parameters
        ----------
        message : string
            The error message to display to the user
        """
        super(CannotCreateResourceException, self).__init__(message)


# noinspection PyPropertyAccess,PyAttributeOutsideInit
class RegionException(Exception):
    """Exception indicating the current region is not this resource's region"""
    def __init__(self, resource_region):
        """Initialize the Exception

        Parameters
        ----------
        resource_region : string
            The resource region
        """
        super(RegionException, self).__init__(
            "This resource's region ({resource:s}) does not match the "
            "current region ({current:s})".format(
                resource=resource_region, current=get_region()
            )
        )
        self.current_region = get_region()
        self.resource_region = resource_region


# noinspection PyPropertyAccess,PyAttributeOutsideInit
class ProfileException(Exception):
    """Exception indicating the current profile isn't the resource's profile"""
    def __init__(self, resource_profile):
        """Initialize the Exception

        Parameters
        ----------
        resource_profile : string
            The resource profile
        """
        super(ProfileException, self).__init__(
            "This resource's profile ({resource:s}) does not match the "
            "current profile ({current:s})".format(
                resource=resource_profile, current=get_profile()
            )
        )
        self.current_profile = get_profile()
        self.resource_profile = resource_profile


# noinspection PyPropertyAccess,PyAttributeOutsideInit
class CKTimeoutError(Exception):
    """Cloudknot timeout error for AWS Batch job results

    Error indicating an AWS Batch job failed to return results within
    the requested time period
    """
    def __init__(self, job_id):
        """Initialize the Exception"""
        super(CKTimeoutError, self).__init__(
            'The job with job-id {jid:s} did not finish within the '
            'requested timeout period'.format(jid=job_id)
        )
        self.job_id = job_id


# noinspection PyPropertyAccess,PyAttributeOutsideInit
class BatchJobFailedError(Exception):
    """Error indicating an AWS Batch job failed"""
    def __init__(self, job_id):
        """Initialize the Exception

        Parameters
        ----------
        job_id : string
            The AWS jobId of the failed job
        """
        super(BatchJobFailedError, self).__init__(
            "AWS Batch job {job_id:s} has failed.".format(job_id=job_id)
        )
        self.job_id = job_id


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
        self._clobbered = False
        self._region = get_region()
        self._profile = get_profile()

    @property
    def name(self):
        """The name of this AWS resource"""
        return self._name

    @property
    def clobbered(self):
        """Has this instance been previously clobbered"""
        return self._clobbered

    @property
    def region(self):
        """The AWS region in which this resource was created"""
        return self._region

    @property
    def profile(self):
        """The AWS profile in which this resource was created"""
        return self._profile

    def _get_section_name(self, resource_type):
        """Return the config section name

        Append profile and region to the resource type name
        """
        return ' '.join([resource_type, self.profile, self.region])

    def check_profile(self):
        """Check for profile exception"""
        if self.profile != get_profile():
            raise ProfileException(resource_profile=self.profile)

    def check_profile_and_region(self):
        """Check for region and profile exceptions"""
        if self.region != get_region():
            raise RegionException(resource_region=self.region)

        self.check_profile()


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
        """Amazon resource number (ARN) of this resource"""
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
            memory (MiB) to be used for this resource
            Default: 32000

        username : string
            username for be used for this resource
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

    @property
    def memory(self):
        """Memory to be used for this resource"""
        return self._memory

    @property
    def username(self):
        """Username for this resource"""
        return self._username


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
    """
    # Initialize waiting and num_waits for the while loop
    waiting = True
    num_waits = 0
    while waiting:
        if log:
            # Log waiting info
            mod_logger.info(
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
    """
    # Initialize waiting and num_waits for the while loop
    waiting = True
    num_waits = 0
    while waiting:
        if log:  # pragma: nocover
            # Log waiting info
            mod_logger.info(
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
