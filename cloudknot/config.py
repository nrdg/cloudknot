"""The config module contains functions to maintain the cloudknot config file

This module contains function that other cloudknot objects use to maintain the
cloudknot config file, including adding resources, removing resources, and
verifying the section headers.

Ideally, the cloudknot user should never have to use these functions to
interact with the cloudknot config file. Each cloudknot object maintains
references to its state in the config file.
"""
from __future__ import absolute_import, division, print_function

import cloudknot.aws
import configparser
import logging
import os
from threading import RLock

__all__ = ["get_config_file", "add_resource", "remove_resource",
           "verify_sections", "prune"]

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


def prune():
    """Remove config items for non-existent AWS resources"""
    raise NotImplementedError('prune is not yet implemented.')
    # prune needs to be updated to use the region info in config

    verify_sections()

    config_file = get_config_file()
    config = configparser.ConfigParser()

    with rlock:
        config.read(config_file)

        # Prune roles
        for role_name in config.options('roles'):
            try:
                cloudknot.aws.iam.IamRole(name=role_name)
            except cloudknot.aws.ResourceDoesNotExistException:
                config.remove_option('roles', role_name)

        # Prune VPCs
        for vpc_id in config.options('vpc'):
            try:
                cloudknot.aws.ec2.Vpc(vpc_id=vpc_id)
            except cloudknot.aws.ResourceDoesNotExistException:
                config.remove_option('vpc', vpc_id)

        # Prune security groups
        for sg_id in config.options('security-groups'):
            try:
                cloudknot.aws.ec2.SecurityGroup(security_group_id=sg_id)
            except cloudknot.aws.ResourceDoesNotExistException:
                config.remove_option('security-groups', sg_id)

        # Prune docker containers
        for repo in config.options('docker-repos'):
            pass

        # Prune job definitions
        for job_def_name in config.options('job-definitions'):
            try:
                cloudknot.aws.iam.IamRole(name=job_def_name)
            except cloudknot.aws.ResourceDoesNotExistException:
                config.remove_option('job-definitions', job_def_name)

        # Prune compute environments
        for ce_name in config.options('compute-environments'):
            try:
                cloudknot.aws.iam.IamRole(name=ce_name)
            except cloudknot.aws.ResourceDoesNotExistException:
                config.remove_option('compute-environments', ce_name)

        # Prune job queues
        for queue_name in config.options('job-queues'):
            try:
                cloudknot.aws.iam.IamRole(name=queue_name)
            except cloudknot.aws.ResourceDoesNotExistException:
                config.remove_option('job-queues', queue_name)

        # Prune batch jobs
        for job_id in config.options('jobs'):
            try:
                cloudknot.aws.iam.IamRole(job_id=job_id)
            except cloudknot.aws.ResourceDoesNotExistException:
                config.remove_option('jobs', job_id)

        # Prune pars
        # Prune knots
        with open(config_file, 'w') as f:
            config.write(f)
