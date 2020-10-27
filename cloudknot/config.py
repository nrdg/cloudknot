"""
The config module contains functions to maintain the cloudknot config file.

This module contains function that other cloudknot objects use to maintain the
cloudknot config file, including adding resources, removing resources, and
verifying the section headers.

Ideally, the cloudknot user should never have to use these functions to
interact with the cloudknot config file. Each cloudknot object maintains
references to its state in the config file.
"""
import botocore
import configparser
import docker
import errno
import logging
import os
from threading import RLock

from . import aws

__all__ = [
    "rlock",
    "prune_stacks",
    "prune",
    "get_config_file",
    "add_resource",
    "remove_resource",
    "verify_sections",
]
mod_logger = logging.getLogger(__name__)
rlock = RLock()


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
                else:  # pragma: nocover
                    raise e

            # If the config file does not exist, create it
            with open(config_file, "w") as f:
                f.write("# cloudknot configuration file")

            mod_logger.info(
                "Created new cloudknot config file at {path:s}".format(path=config_file)
            )

    mod_logger.debug("Using cloudknot config file {path:s}".format(path=config_file))

    return config_file


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
        else:  # pragma: nocover
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
    """
    Clean unused pars and knots from config file.

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


def prune_repos():
    """
    Clean unused ECR repos from the config file.

    Verify that the ECR repo sections in the config file refer to actual
    ECR repos that exist on AWS. If not, remove from config file.
    """
    config_file = get_config_file()
    config = configparser.ConfigParser()
    old_profile = aws.get_profile()
    old_region = aws.get_region()

    config.read(config_file)

    repo_sections = [
        sec for sec in config.sections() if sec.split(" ")[0] == "docker-repos"
    ]
    for section in repo_sections:
        profile = section.split(" ")[1]
        region = section.split(" ")[2]
        aws.set_profile(profile)
        aws.set_region(region)
        for repo_name, repo_uri in config[section].items():
            remove_repo = False
            try:
                # If repo exists, retrieve its info
                response = aws.clients["ecr"].describe_repositories(
                    repositoryNames=[repo_name]
                )
                uri = response["repositories"][0]["repositoryUri"]
                if repo_uri != uri:
                    remove_repo = True
            except aws.clients["ecr"].exceptions.RepositoryNotFoundException:
                remove_repo = True
            except botocore.exceptions.ClientError as e:
                error_code = e.response["Error"]["Code"]
                message = e.response["Error"]["Message"]
                if (
                    error_code == "RepositoryNotFoundException"
                    or "RepositoryNotFoundException" in message
                ):
                    remove_repo = True
                else:  # pragma: nocover
                    raise e

            if remove_repo:
                # Remove this section from the config file
                remove_resource(section, repo_name)
                mod_logger.info(
                    "Removed ECR repo {name:s} from your config file.".format(
                        name=repo_name
                    )
                )

    aws.set_profile(old_profile)
    aws.set_region(old_region)


def prune_batch_jobs():
    """
    Clean unused batch jobs from the config file.

    Verify that the batch jobs in the config file refer to actual
    batch jobs that exist on AWS. If not, remove from config file.
    """
    config_file = get_config_file()
    config = configparser.ConfigParser()
    old_profile = aws.get_profile()
    old_region = aws.get_region()

    config.read(config_file)

    repo_sections = [
        sec for sec in config.sections() if sec.split(" ")[0] == "batch-jobs"
    ]
    for section in repo_sections:
        profile = section.split(" ")[1]
        region = section.split(" ")[2]
        aws.set_profile(profile)
        aws.set_region(region)
        for job_id in config[section].keys():
            response = aws.clients["batch"].describe_jobs(jobs=[job_id])
            if not response.get("jobs"):
                remove_resource(section, job_id)
                mod_logger.info(
                    "Removed job {jid:s} from your config file.".format(jid=job_id)
                )

    aws.set_profile(old_profile)
    aws.set_region(old_region)


def prune_images():
    """
    Clean unused docker images from the config file.

    Verify that the docker-image sections in the config file refer to actual
    docker images that refer either to local resources or to images that
    exist on AWS. If not, remove from config file.
    """
    config_file = get_config_file()
    config = configparser.ConfigParser()
    old_profile = aws.get_profile()
    old_region = aws.get_region()

    with rlock:
        config.read(config_file)

        image_sections = [
            sec for sec in config.sections() if sec.split(" ")[0] == "docker-image"
        ]
        for section in image_sections:
            exists = {"build_path": True, "local_images": True, "remote_image": True}

            build_path = config.get(section, "build-path")
            if not os.path.exists(os.path.abspath(build_path)):
                exists["build_path"] = False

            images_str = config.get(section, "images")
            images = images_str.split()
            if images:
                c = docker.from_env()
                exists["local_images"] = any(
                    [bool(c.images.list(name=im)) for im in images]
                )
            else:
                exists["local_images"] = False

            uri = config.get(section, "repo-uri")
            if uri:
                try:
                    profile = config.get(section, "profile")
                    region = config.get(section, "region")
                    aws.set_profile(profile)
                    aws.set_region(region)
                except configparser.NoOptionError:
                    pass

                try:
                    repo_info = aws.ecr._get_repo_info_from_uri(uri)
                    response = aws.clients["ecr"].list_images(
                        registryId=repo_info["registry_id"],
                        repositoryName=repo_info["repo_name"],
                        maxResults=1000,
                        filter={"tagStatus": "TAGGED"},
                    )
                    image_ids = response.get("imageIds")
                    image_ids = [
                        im for im in image_ids if im["imageTag"] == uri.split(":")[-1]
                    ]
                    exists["remote_image"] = bool(image_ids)
                except IndexError:
                    exists["remote_image"] = False
            else:
                exists["remote_image"] = False

            if not any(exists.values()):
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
    """
    Clean unused resources from the config file.

    This is a wrapper function for the more resource-specific prune_* functions.
    """
    prune_stacks()
    prune_repos()
    prune_batch_jobs()
    prune_images()
