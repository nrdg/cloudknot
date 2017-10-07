from __future__ import absolute_import, division, print_function

import logging

from . import aws  # noqa
from . import config  # noqa
from .aws.base_classes import get_region, set_region  # noqa
from .aws.base_classes import get_profile, set_profile, list_profiles  # noqa
from .aws.base_classes import refresh_clients  # noqa
from .cloudknot import *  # noqa
from .dockerimage import *  # noqa
from .version import __version__  # noqa

module_logger = logging.getLogger(__name__).addHandler(logging.NullHandler())
module_logger.info('Started new cloudknot session')
