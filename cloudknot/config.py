from __future__ import absolute_import, division, print_function

import os
import configparser

from . import aws

# Set global config parser
CONFIG = configparser.ConfigParser()

def init():
    # Use default config file path unless environment variable is set
    try:
        env_file = os.environ['CLOUDKNOT_CONFIG_FILE']
        CONFIG_FILE = os.path.abspath(env_file)
    except KeyError:
        home = os.path.expanduser('~')
        CONFIG_FILE = os.path.join(home, '.aws', '.cloudknot')

    if not os.path.isfile(CONFIG_FILE):
        # If the config file does not exist, create it
        with open(CONFIG_FILE, 'w') as f:
            f.write('# cloudknot configuration file')


def add_resource(section, option, value):
    CONFIG.read(CONFIG_FILE)
    if section not in CONFIG.sections():
        CONFIG.add_section(section)
    CONFIG.set(section=section, option=option, value=value)
    with open(CONFIG_FILE, 'w') as f:
        CONFIG.write(f)


def remove_resource(section, option):
    CONFIG.read(CONFIG_FILE)
    CONFIG.remove_option(section, option)
    with open(CONFIG_FILE, 'w') as f:
        CONFIG.write(f)


def verify_sections():
    CONFIG.read(CONFIG_FILE)
    approved_sections = [
        'roles', 'vpcs', 'security groups', 'docker containers',
        'job definitions', 'compute environments', 'job queues', 'jobs'
    ]

    def section_approved(section):
        return any([
            section in approved_sections,
            section.split(' ', 1)[0] in ['nest', 'pipeline']
        ])

    for section in CONFIG.sections():
        if not section_approved(section):
            CONFIG.remove_section(section)


def prune():
    verify_sections()

    CONFIG.read(CONFIG_FILE)

    for role_name in CONFIG.options('roles'):
        try:
            aws.iam.IamRole(name=role_name)
        except aws.ResourceDoesNotExistException:
            CONFIG.remove_option('roles', role_name)

    for vpc_id in CONFIG.options('vpcs'):
        try:
            aws.ec2.Vpc(vpc_id=vpc_id)
        except aws.ResourceDoesNotExistException:
            CONFIG.remove_option('vpcs', vpc_id)

    for sg_id in CONFIG.options('security groups'):
        try:
            aws.ec2.SecurityGroup(security_group_id=sg_id)
        except aws.ResourceDoesNotExistException:
            CONFIG.remove_option('security groups', sg_id)

    # Prune docker containers
    docker_containers = CONFIG.options('docker_containers')

    for job_def_name in CONFIG.options('job definitions'):
        try:
            aws.iam.IamRole(name=job_def_name)
        except aws.ResourceDoesNotExistException:
            CONFIG.remove_option('job definitions', job_def_name)

    for ce_name in CONFIG.options('compute environments'):
        try:
            aws.iam.IamRole(name=ce_name)
        except aws.ResourceDoesNotExistException:
            CONFIG.remove_option('compute environments', ce_name)

    for queue_name in CONFIG.options('job queues'):
        try:
            aws.iam.IamRole(name=queue_name)
        except aws.ResourceDoesNotExistException:
            CONFIG.remove_option('job queues', queue_name)

    for job_id in CONFIG.options('jobs'):
        try:
            aws.iam.IamRole(job_id=job_id)
        except aws.ResourceDoesNotExistException:
            CONFIG.remove_option('jobs', job_id)

    # Prune nests
    # Prune pipelines
