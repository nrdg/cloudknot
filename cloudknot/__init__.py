from __future__ import absolute_import, division, print_function

import docker
import errno
import logging
import os
import six
import subprocess
from concurrent.futures import ThreadPoolExecutor

from . import aws  # noqa
from . import config  # noqa
from .aws.base_classes import get_profile, set_profile, list_profiles  # noqa
from .aws.base_classes import get_region, set_region  # noqa
from .aws.base_classes import get_ecr_repo, set_ecr_repo  # noqa
from .aws.base_classes import get_s3_bucket, set_s3_bucket  # noqa
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


def pull_and_push_base_images():
    # Use docker low-level APIClient for tagging
    c = docker.from_env().api
    # And the image client for pulling and pushing
    cli = docker.from_env().images

    # Build the python base image so that later build commands are faster
    v = '3' if six.PY3 else '2'
    py_base = 'python:' + v
    ecr_tag = 'python' + v
    module_logger.info('Pulling base image {b:s}'.format(b=py_base))
    cli.pull(py_base)

    # Refresh the aws ecr login credentials
    login_cmd = subprocess.check_output([
        'aws', 'ecr', 'get-login', '--no-include-email',
        '--region', get_region()
    ])

    # Login
    subprocess.call(login_cmd.decode('ASCII').rstrip('\n').split(' '))

    repo = aws.DockerRepo(name=get_ecr_repo())

    # Log tagging info
    module_logger.info('Tagging base image {name:s}'.format(name=py_base))

    # Tag it with the most recently added image_name
    c.tag(image=py_base, repository=repo.repo_uri, tag=ecr_tag)

    # Log push info
    module_logger.info(
        'Pushing base image {name:s} to ecr repository {repo:s}'
        ''.format(name=py_base, repo=repo.repo_uri)
    )

    for l in cli.push(repository=repo.repo_uri, tag=ecr_tag, stream=True):
        module_logger.debug(l)


executor = ThreadPoolExecutor(1)
base_image_future = executor.submit(pull_and_push_base_images)
executor.shutdown(wait=False)
