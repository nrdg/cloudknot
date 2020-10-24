import botocore
import cloudknot.config
import logging

try:
    from collections.abc import namedtuple
except ImportError:
    from collections import namedtuple

from .base_classes import NamedObject, clients, get_ecr_repo, get_tags

__all__ = ["DockerRepo"]
mod_logger = logging.getLogger(__name__)


def _get_repo_info_from_uri(repo_uri):
    # Get all repositories
    repositories = clients["ecr"].describe_repositories(maxResults=500)["repositories"]

    _repo_uri = repo_uri.split(":")[0]
    # Filter by matching on repo_uri
    matching_repo = [
        repo for repo in repositories if repo["repositoryUri"] == _repo_uri
    ][0]

    return {
        "registry_id": matching_repo["registryId"],
        "repo_name": matching_repo["repositoryName"],
    }


# noinspection PyPropertyAccess,PyAttributeOutsideInit
class DockerRepo(NamedObject):
    """
    Class for creating and managing remote docker repositories.
    """

    def __init__(self, name, aws_resource_tags=None):
        """Initialize a Docker repo object.

        User may provide only `name` input, indicating that they would
        like to retrieve a pre-existing repo/image from AWS ECR. Or, if
        the repo does not exist, it will be created.

        Parameters
        ----------
        name : str
            Name of the remote repository.
            Must satisfy regular expression pattern: [a-zA-Z][-a-zA-Z0-9]*

        aws_resource_tags : dict or list of dicts
            Additional AWS resource tags to apply to this repository
        """
        super(DockerRepo, self).__init__(name=name)

        # Validate aws_resource_tags input before creating any resources
        self._tags = get_tags(
            name=name,
            additional_tags={"Project": "Cloudknot global config"}
            if aws_resource_tags is None
            else aws_resource_tags,
        )

        # Create repo
        repo_info = self._create_repo()
        self._repo_uri = repo_info.uri
        self._repo_registry_id = repo_info.registry_id

        # Add to config file
        self._section_name = self._get_section_name("docker-repos")
        cloudknot.config.add_resource(self._section_name, self.name, self.repo_uri)

    # Declare read only properties
    @property
    def repo_uri(self):
        """URI for this AWS ECR repository."""
        return self._repo_uri

    @property
    def tags(self):
        """AWS resource tags for this ECR repository."""
        return self._tags

    @property
    def repo_registry_id(self):
        """Registry ID for this AWS ECR repository."""
        return self._repo_registry_id

    def _create_repo(self):
        """
        Create or retrieve an AWS ECR repository.

        Returns
        -------
        RepoInfo : namedtuple
            a namedtuple with fields name, uri, and registry_id
        """
        # Flake8 will see that repo_arn is set in the try/except clauses
        # and claim that we are referencing it before assignment below
        # so we predefine it here. Also, it should be predefined as a
        # string to pass parameter validation by boto.
        repo_arn = "test"
        try:
            # If repo exists, retrieve its info
            response = clients["ecr"].describe_repositories(repositoryNames=[self.name])

            repo_arn = response["repositories"][0]["repositoryArn"]
            repo_name = response["repositories"][0]["repositoryName"]
            repo_uri = response["repositories"][0]["repositoryUri"]
            repo_registry_id = response["repositories"][0]["registryId"]
            repo_created = False
        except clients["ecr"].exceptions.RepositoryNotFoundException:
            # If it doesn't exists already, then create it
            response = clients["ecr"].create_repository(repositoryName=self.name)

            repo_arn = response["repository"]["repositoryArn"]
            repo_name = response["repository"]["repositoryName"]
            repo_uri = response["repository"]["repositoryUri"]
            repo_registry_id = response["repository"]["registryId"]
            repo_created = True
        except botocore.exceptions.ClientError as e:
            error_code = e.response["Error"]["Code"]
            message = e.response["Error"]["Message"]
            if (
                error_code == "RepositoryNotFoundException"
                or "RepositoryNotFoundException" in message
            ):
                # If it doesn't exists already, then create it
                response = clients["ecr"].create_repository(repositoryName=self.name)

                repo_arn = response["repository"]["repositoryArn"]
                repo_name = response["repository"]["repositoryName"]
                repo_uri = response["repository"]["repositoryUri"]
                repo_registry_id = response["repository"]["registryId"]
                repo_created = True

        if repo_created:
            mod_logger.info(
                "Created repository {name:s} at {uri:s}".format(
                    name=self.name, uri=repo_uri
                )
            )
        else:
            mod_logger.info(
                "Repository {name:s} already exists at "
                "{uri:s}".format(name=self.name, uri=repo_uri)
            )

        try:
            clients["ecr"].tag_resource(resourceArn=repo_arn, tags=self.tags)
        except NotImplementedError as e:
            moto_msg = "The tag_resource action has not been implemented"
            if moto_msg in e.args:
                # This exception is here for compatibility with moto
                # testing since the tag_resource action has not been
                # implemented in moto. Simply move on.
                pass
            else:
                raise e

        # Define and return namedtuple with repo info
        RepoInfo = namedtuple("RepoInfo", ["name", "uri", "registry_id"])
        return RepoInfo(name=repo_name, uri=repo_uri, registry_id=repo_registry_id)

    def clobber(self):
        """Delete this remote repository."""
        if self.clobbered:
            return

        self.check_profile_and_region()

        if self.name != get_ecr_repo():
            try:
                # Remove the remote docker image
                clients["ecr"].delete_repository(
                    registryId=self.repo_registry_id,
                    repositoryName=self.name,
                    force=True,
                )
            except clients["ecr"].exceptions.RepositoryNotFoundException:
                # It doesn't exist anyway, so carry on
                pass
            except botocore.exceptions.ClientError as e:
                error_code = e.response["Error"]["Code"]
                message = e.response["Error"]["Message"]
                if (
                    error_code == "RepositoryNotFoundException"
                    or "RepositoryNotFoundException" in message
                ):
                    pass

        # Remove from the config file
        cloudknot.config.remove_resource(self._section_name, self.name)

        # Set the clobbered parameter to True,
        # preventing subsequent method calls
        self._clobbered = True

        mod_logger.info("Clobbered docker repo {name:s}".format(name=self.name))
