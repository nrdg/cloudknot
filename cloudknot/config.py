"""
The config module contains functions to maintain the cloudknot config file.

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

from . import aws

__all__ = ["rlock", "prune_stacks", "prune"]


def registered(fn):
    __all__.append(fn.__name__)
    return fn


mod_logger = logging.getLogger(__name__)
rlock = RLock()


@registered
def get_config_file():
    """
    Get the path to the cloudknot config file.

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
        env_file = os.environ["CLOUDKNOT_CONFIG_FILE"]
        config_file = os.path.abspath(env_file)
    except KeyError:
        # Fallback on default config file path
        home = os.path.expanduser("~")
        config_file = os.path.join(home, ".aws", "cloudknot")

    with rlock:
        if not os.path.isfile(config_file):
            # If the config directory does not exist, create it
            configdir = os.path.dirname(config_file)
            try:
                os.makedirs(configdir)
            except OSError as e:
                pre_existing = e.errno == errno.EEXIST and os.path.isdir(configdir)
                if pre_existing:
                    pass
                else:
                    raise e

            # If the config file does not exist, create it
            with open(config_file, "w") as f:
                f.write("# cloudknot configuration file")

            mod_logger.info(
                "Created new cloudknot config file at {path:s}".format(path=config_file)
            )

    mod_logger.debug("Using cloudknot config file {path:s}".format(path=config_file))

    return config_file


@registered
def add_resource(section, option, value):
    """
    Add a resource to the cloudknot config file.

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
        with open(config_file, "w") as f:
            config.write(f)


@registered
def remove_resource(section, option):
    """
    Remove a resource from the cloudknot config file.

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
        with open(config_file, "w") as f:
            config.write(f)


@registered
def verify_sections():
    """Verify config sections, remove ones that don't belong."""
    config_file = get_config_file()
    config = configparser.ConfigParser()
    with rlock:
        config.read(config_file)

        approved_sections = [
            "aws",
            "docker-repos",
            "batch-jobs",
            "pars",
            "knot",
            "docker-image",
        ]

        def section_approved(sec):
            return any(
                [sec in approved_sections, sec.split(" ", 1)[0] in approved_sections]
            )

        for section in config.sections():
            if not section_approved(section):
                config.remove_section(section)

        with open(config_file, "w") as f:
            config.write(f)


def is_valid_stack(stack_id):
    try:
        response = aws.clients["cloudformation"].describe_stacks(StackName=stack_id)
    except aws.clients["cloudformation"].exceptions.ClientError as e:
        error_code = e.response.get("Error").get("Message")
        no_stack_code = "Stack with id {0:s} does not exist" "".format(stack_id)
        if error_code == no_stack_code:
            return False
        else:
            raise e

    no_stack = len(response.get("Stacks")) == 0 or response.get("Stacks")[0][
        "StackStatus"
    ] in [
        "CREATE_FAILED",
        "ROLLBACK_COMPLETE",
        "ROLLBACK_IN_PROGRESS",
        "ROLLBACK_FAILED",
        "DELETE_IN_PROGRESS",
        "DELETE_FAILED",
        "DELETE_COMPLETE",
        "UPDATE_ROLLBACK_FAILED",
    ]

    if no_stack:
        return False

    return True


def prune_stacks():
    """Clean unused pars and knots from config file.
    
    Verify that the pars/knot sections in the config file refer to actual
    CloudFormation stacks that exist on AWS. If not, remove from config file.
    """
    config_file = get_config_file()
    config = configparser.ConfigParser()
    old_profile = aws.get_profile()
    old_region = aws.get_region()

    with rlock:
        config.read(config_file)

        for section in config.sections():
            if section.split(" ", 1)[0] in ["knot", "pars"]:
                stack_id = config.get(section, "stack-id")
                profile = config.get(section, "profile")
                region = config.get(section, "region")
                aws.set_profile(profile)
                aws.set_region(region)
                if not is_valid_stack(stack_id):
                    # Remove this section from the config file
                    config.remove_section(section)
                    mod_logger.info(
                        "Removed {name:s} from your config file.".format(name=section)
                    )

        with open(config_file, "w") as f:
            config.write(f)

    aws.set_profile(old_profile)
    aws.set_region(old_region)


def prune():
    """Clean unused resources from the config file
    
    Verify that the resources in the config file refer to actual resources on
    AWS. If not, remove from config file.
    """
    prune_stacks()
