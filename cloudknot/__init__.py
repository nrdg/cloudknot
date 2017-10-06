from __future__ import absolute_import, division, print_function

import logging

from . import aws  # noqa
from . import config  # noqa
from .aws.base_classes import get_region, set_region  # noqa
from .cloudknot import *  # noqa
from .dockerimage import *  # noqa
from .version import __version__  # noqa

logging.getLogger(__name__).addHandler(logging.NullHandler())
logging.info('Started new cloudknot session')
