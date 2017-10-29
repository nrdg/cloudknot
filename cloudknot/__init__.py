from __future__ import absolute_import, division, print_function

import logging
import os

from . import aws  # noqa
from . import config  # noqa
from .aws.base_classes import get_region, set_region  # noqa
from .aws.base_classes import get_profile, set_profile, list_profiles  # noqa
from .aws.base_classes import refresh_clients  # noqa
from .cloudknot import *  # noqa
from .dockerimage import *  # noqa
from .version import __version__  # noqa

module_logger = logging.getLogger(__name__)

# get the log level from environment variable
if "CLOUDKNOT_LOGLEVEL" in os.environ:
    loglevel = os.environ['CLOUDKNOT_LOGLEVEL']
    module_logger.setLevel(getattr(logging, loglevel.upper()))
else:
    module_logger.setLevel(logging.WARNING)

# create a file handler
logpath = os.path.join(os.path.expanduser('~'), '.cloudknot', 'cloudknot.log')
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
