from __future__ import absolute_import, division, print_function

import errno
import logging
import os
import subprocess

from . import aws  # noqa
from . import config  # noqa
from .aws.base_classes import get_profile, set_profile, list_profiles  # noqa
from .aws.base_classes import get_region, set_region  # noqa
from .aws.base_classes import get_ecr_repo, set_ecr_repo  # noqa
from .aws.base_classes import get_s3_params, set_s3_params  # noqa
from .aws.base_classes import refresh_clients  # noqa
from .cloudknot import *  # noqa
from .dockerimage import *  # noqa
from .version import __version__  # noqa

try:
    fnull = open(os.devnull, 'w')
    subprocess.check_call('docker version', shell=True,
                          stdout=fnull, stderr=subprocess.STDOUT)
except subprocess.CalledProcessError:
    raise ImportError(
        "It looks like you don't have Docker installed or running. Please go "
        "to https://docs.docker.com/engine/installation/ to install it. Once "
        "installed, make sure that the Docker daemon is running before using "
        "cloudknot."
    )

module_logger = logging.getLogger(__name__)

# get the log level from environment variable
if "CLOUDKNOT_LOGLEVEL" in os.environ:
    loglevel = os.environ['CLOUDKNOT_LOGLEVEL']
    module_logger.setLevel(getattr(logging, loglevel.upper()))
else:
    module_logger.setLevel(logging.WARNING)

# create a file handler
logpath = os.path.join(os.path.expanduser('~'), '.cloudknot', 'cloudknot.log')

# Create the config directory if it doesn't exist
logdir = os.path.dirname(logpath)
try:
    os.makedirs(logdir)
except OSError as e:
    pre_existing = (e.errno == errno.EEXIST and os.path.isdir(logdir))
    if pre_existing:
        pass
    else:
        raise e

handler = logging.FileHandler(logpath, mode='w')
handler.setLevel(logging.DEBUG)

# create a logging format
formatter = logging.Formatter(
    '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
handler.setFormatter(formatter)

# add the handlers to the logger
module_logger.addHandler(handler)
module_logger.info('Started new cloudknot session')

logging.getLogger('boto').setLevel(logging.WARNING)
logging.getLogger('boto3').setLevel(logging.WARNING)
logging.getLogger('botocore').setLevel(logging.WARNING)
