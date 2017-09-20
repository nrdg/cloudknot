from __future__ import absolute_import, division, print_function

import os
import configparser

from . import aws

CONFIG = configparser.ConfigParser()


def get_config_file():
    try:
        env_file = os.environ['CLOUDKNOT_config_FILE']
        config_file = os.path.abspath(env_file)
    except KeyError:
        home = os.path.expanduser('~')
        config_file = os.path.join(home, '.aws', 'cloudknot')

    if not os.path.isfile(config_file):
        # If the config file does not exist, create it
        with open(config_file, 'w') as f:
            f.write('# cloudknot configuration file')

    return config_file


def add_resource(section, option, value):
    config_file = get_config_file()
    CONFIG.read(config_file)
    if section not in CONFIG.sections():
        CONFIG.add_section(section)
    CONFIG.set(section=section, option=option, value=value)
    with open(config_file, 'w') as f:
        CONFIG.write(f)


def remove_resource(section, option):
    config_file = get_config_file()
    CONFIG.read(config_file)
    CONFIG.remove_option(section, option)
    with open(config_file, 'w') as f:
        CONFIG.write(f)


def verify_sections():
    config_file = get_config_file()
    CONFIG.read(config_file)
    approved_sections = [
        'roles', 'vpc', 'security-groups', 'docker-containers',
        'job-definitions', 'compute-environments', 'job-queues', 'jobs'
    ]

    def section_approved(section):
        return any([
            section in approved_sections,
            section.split(' ', 1)[0] in ['pars', 'jars']
        ])

    for section in CONFIG.sections():
        if not section_approved(section):
            CONFIG.remove_section(section)


def prune():
    verify_sections()

    config_file = get_config_file()
    CONFIG.read(config_file)

    for role_name in CONFIG.options('roles'):
        try:
            aws.iam.IamRole(name=role_name)
        except aws.ResourceDoesNotExistException:
            CONFIG.remove_option('roles', role_name)

    for vpc_id in CONFIG.options('vpc'):
        try:
            aws.ec2.Vpc(vpc_id=vpc_id)
        except aws.ResourceDoesNotExistException:
            CONFIG.remove_option('vpc', vpc_id)

    for sg_id in CONFIG.options('security-groups'):
        try:
            aws.ec2.SecurityGroup(security_group_id=sg_id)
        except aws.ResourceDoesNotExistException:
            CONFIG.remove_option('security-groups', sg_id)

    # Prune docker containers
    docker_containers = CONFIG.options('docker-containers')

    for job_def_name in CONFIG.options('job-definitions'):
        try:
            aws.iam.IamRole(name=job_def_name)
        except aws.ResourceDoesNotExistException:
            CONFIG.remove_option('job-definitions', job_def_name)

    for ce_name in CONFIG.options('compute-environments'):
        try:
            aws.iam.IamRole(name=ce_name)
        except aws.ResourceDoesNotExistException:
            CONFIG.remove_option('compute-environments', ce_name)

    for queue_name in CONFIG.options('job-queues'):
        try:
            aws.iam.IamRole(name=queue_name)
        except aws.ResourceDoesNotExistException:
            CONFIG.remove_option('job-queues', queue_name)

    for job_id in CONFIG.options('jobs'):
        try:
            aws.iam.IamRole(job_id=job_id)
        except aws.ResourceDoesNotExistException:
            CONFIG.remove_option('jobs', job_id)

    # Prune pars
    # Prune jars
