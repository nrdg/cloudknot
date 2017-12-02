from __future__ import absolute_import, division, print_function

import cloudknot.config
import logging
from collections import namedtuple

from .base_classes import NamedObject, clients, get_ecr_repo

__all__ = ["DockerRepo"]

mod_logger = logging.getLogger(__name__)


# noinspection PyPropertyAccess,PyAttributeOutsideInit
class DockerRepo(NamedObject):
    """Class for creating and managing remote docker repositories"""
    def __init__(self, name):
        """Initialize a Docker repo object.

        User may provide only `name` input, indicating that they would
        like to retrieve a pre-existing repo/image from AWS ECR. Or, if
        the repo does not exist, it will be created.

        Parameters
        ----------
        name : str
            Name of the remote repository
        """
        super(DockerRepo, self).__init__(name=name)

        # Create repo
        repo_info = self._create_repo()
        self._repo_uri = repo_info.uri
        self._repo_registry_id = repo_info.registry_id

        # Add to config file
        self._section_name = self._get_section_name('docker-repos')
        cloudknot.config.add_resource(
            self._section_name, self.name, self.repo_uri
        )

    # Declare read only properties
    @property
    def repo_uri(self):
        """URI for this AWS ECR repository"""
        return self._repo_uri

    @property
    def repo_registry_id(self):
        """Registry ID for this AWS ECR repository"""
        return self._repo_registry_id

    def _create_repo(self):
        """Create or retrieve an AWS ECR repository

        Returns
        -------
        RepoInfo : namedtuple
            a namedtuple with fields name, uri, and registry_id
        """
        try:
            # If repo exists, retrieve its info
            response = clients['ecr'].describe_repositories(
                repositoryNames=[self.name]
            )

            repo_name = response['repositories'][0]['repositoryName']
            repo_uri = response['repositories'][0]['repositoryUri']
            repo_registry_id = response['repositories'][0]['registryId']

            mod_logger.info('Repository {name:s} already exists at '
                            '{uri:s}'.format(name=self.name, uri=repo_uri))
        except clients['ecr'].exceptions.RepositoryNotFoundException:
            # If it doesn't exists already, then create it
            response = clients['ecr'].create_repository(
                repositoryName=self.name
            )

            repo_name = response['repository']['repositoryName']
            repo_uri = response['repository']['repositoryUri']
            repo_registry_id = response['repository']['registryId']

            mod_logger.info('Created repository {name:s} at {uri:s}'.format(
                name=self.name, uri=repo_uri
            ))

        # Define and return namedtuple with repo info
        RepoInfo = namedtuple('RepoInfo', ['name', 'uri', 'registry_id'])
        return RepoInfo(
            name=repo_name, uri=repo_uri, registry_id=repo_registry_id
        )

    def clobber(self):
        """Delete this remote repository"""
        if self.clobbered:
            return

        self.check_profile_and_region()

        if self.name != get_ecr_repo():
            try:
                # Remove the remote docker image
                clients['ecr'].delete_repository(
                    registryId=self.repo_registry_id,
                    repositoryName=self.name,
                    force=True
                )
            except clients['ecr'].exceptions.RepositoryNotFoundException:
                # It doesn't exist anyway, so carry on
                pass

        # Remove from the config file
        cloudknot.config.remove_resource(self._section_name, self.name)

        # Set the clobbered parameter to True,
        # preventing subsequent method calls
        self._clobbered = True

        mod_logger.info(
            'Clobbered docker repo {name:s}'.format(name=self.name)
        )
