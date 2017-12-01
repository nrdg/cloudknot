"""The config module contains functions to maintain the cloudknot config file

This module contains function that other cloudknot objects use to maintain the
cloudknot config file, including adding resources, removing resources, and
verifying the section headers.

Ideally, the cloudknot user should never have to use these functions to
interact with the cloudknot config file. Each cloudknot object maintains
references to its state in the config file.
"""
from __future__ import absolute_import, division, print_function

import configparser
import errno
import logging
import os
from threading import RLock

__all__ = ["get_config_file", "add_resource", "remove_resource",
           "verify_sections"]

mod_logger = logging.getLogger(__name__)
rlock = RLock()


def get_config_file():
    """Get the path to the cloudknot config file

    First, check for the CLOUDKNOT_CONFIG_FILE environment variable.
    If that fails, use ~/.aws/cloudknot. If ~/.aws/cloudknot doesn't
    exist, create it.

    Returns
    -------
    config_file : string
        Path to cloudknot config file
    """
    try:
        # Get config file from environment variable
        env_file = os.environ['CLOUDKNOT_CONFIG_FILE']
        config_file = os.path.abspath(env_file)
    except KeyError:
        # Fallback on default config file path
        home = os.path.expanduser('~')
        config_file = os.path.join(home, '.aws', 'cloudknot')

    with rlock:
        if not os.path.isfile(config_file):
            # If the config directory does not exist, create it
            configdir = os.path.dirname(config_file)
            try:
                os.makedirs(configdir)
            except OSError as e:
                pre_existing = (e.errno == errno.EEXIST
                                and os.path.isdir(configdir))
                if pre_existing:
                    pass
                else:
                    raise e

            # If the config file does not exist, create it
            with open(config_file, 'w') as f:
                f.write('# cloudknot configuration file')

            mod_logger.info(
                'Created new cloudknot config file at {path:s}'.format(
                    path=config_file
                )
            )

    mod_logger.debug('Using cloudknot config file {path:s}'.format(
        path=config_file
    ))

    return config_file


def add_resource(section, option, value):
    """Add a resource to the cloudknot config file

    Parameters
    ----------
    section : string
        Config section to which to add option:value

    option : string
        Config option to add (i.e. the key in the key:value pair)

    value : string
        Config value to add (i.e. second item in key:value pair)
    """
    config_file = get_config_file()
    config = configparser.ConfigParser()

    with rlock:
        config.read(config_file)
        if section not in config.sections():
            config.add_section(section)
        config.set(section=section, option=option, value=value)
        with open(config_file, 'w') as f:
            config.write(f)


def remove_resource(section, option):
    """Remove a resource from the cloudknot config file

    Parameters
    ----------
    section : string
        Config section from which to remove option

    option : string
        Config option to remove (i.e. the key in the key:value pair)
    """
    config_file = get_config_file()
    config = configparser.ConfigParser()

    with rlock:
        config.read(config_file)
        try:
            config.remove_option(section, option)
        except configparser.NoSectionError:
            pass
        with open(config_file, 'w') as f:
            config.write(f)


def verify_sections():
    """Verify config sections, remove ones that don't belong"""
    config_file = get_config_file()
    config = configparser.ConfigParser()
    with rlock:
        config.read(config_file)

        approved_sections = [
            'aws', 'roles', 'vpc', 'security-groups', 'docker-repos',
            'job-definitions', 'compute-environments', 'job-queues',
            'batch-jobs', 'pars', 'knot', 'docker-image'
        ]

        def section_approved(sec):
            return any([
                sec in approved_sections,
                sec.split(' ', 1)[0] in approved_sections
            ])

        for section in config.sections():
            if not section_approved(section):
                config.remove_section(section)

        with open(config_file, 'w') as f:
            config.write(f)
