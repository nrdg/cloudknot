from __future__ import absolute_import, division, print_function

import cloudknot.config
import docker
import logging
import operator
import os
import shutil
import subprocess
from collections import namedtuple

from .base_classes import NamedObject, ECR, get_default_region, \
    ResourceDoesNotExistException

__all__ = ["DockerImage"]


# noinspection PyPropertyAccess,PyAttributeOutsideInit
class DockerImage(NamedObject):
    """Class for building, tagging, and pushing docker containers"""
    def __init__(self, name, tags=None, build_path=None,
                 dockerfile=None,
                 requirements=None):
        """ Initialize a Docker image object.

        Use may provide only `name` input, indicating that they would
        like to retrieve a pre-existing repo/image from AWS ECR. Or
        they may provide a name, tags, and build_path to build a Docker
        image locally, tag it, and push it to an AWS ECR repository.

        Parameters
        ----------
        name : string
            Name of the image

        tags : list or tuple
            tuple of strings of desired image tags. May not contain 'latest'

        build_path : string
            Path to an existing directory in which to build docker image
            Default: '.'

        dockerfile : string
            Path to an existing Dockerfile
            Default: './Dockerfile'

        requirements : string
            Path to an existing requirements.txt file to build dependencies
            Default: None (i.e. assumes no dependencies)
        """
        super(DockerImage, self).__init__(name=name)

        if name and not any([tags, build_path]):
            # Check for pre-existence based on vpc_id or name
            resource = self._exists_already()
            self._pre_existing = resource.exists

            if not self.pre_existing:
                raise ResourceDoesNotExistException(
                    'The docker repo/image that you specified does not exist. '
                    'Either supply the name of a pre-existing repo/image or '
                    'input `tags` and `build_path` to build a docker image '
                    'locally, tag it, and push it to an AWS ECR repository.',
                    self.name
                )

            self._build_path = None
            self._dockerfile = None
            self._requirements = None
            self._tags = resource.tags
            self._repo_name = resource.repo_name
            self._repo_uri = resource.repo_uri
            self._repo_registry_id = resource.repo_registry_id

            # Add to config file
            cloudknot.config.add_resource(
                'docker-images', self.name, self.repo_uri
            )
        else:
            if not all([tags, build_path]):
                raise ValueError('If building a new image, you must specify '
                                 'both `tags` and `build_path`.')
            self._pre_existing = False

            if not os.path.isdir(build_path):
                raise ValueError('build_path must be an existing '
                                 'directory')
            self._build_path = os.path.abspath(build_path)

            if dockerfile:
                if not os.path.isfile(dockerfile):
                    raise ValueError('dockerfile must be an existing '
                                     'regular file')
                self._dockerfile = os.path.abspath(dockerfile)
            else:
                self._dockerfile = os.path.join(self.build_path, 'Dockerfile')

            if not requirements:
                self._requirements = os.path.join(self.build_path,
                                                  'requirements.txt')
            elif not os.path.isfile(requirements):
                raise ValueError('requirements must be an existing '
                                 'regular file')
            else:
                self._requirements = os.path.abspath(requirements)

            if isinstance(tags, str):
                tags = [tags]
            elif all(isinstance(x, str) for x in tags):
                tags = [t for t in tags]
            else:
                raise ValueError('tags must be a string or a sequence '
                                 'of strings.')

            if 'latest' in tags:
                raise ValueError('Any tag is allowed, except for "latest."')

            self._tags = tags

            # Build, tag, and push the docker image
            self._build()
            repo_info = self._create_repo()
            self._repo_uri = repo_info.uri
            self._repo_name = repo_info.name
            self._repo_registry_id = repo_info.registry_id
            self._tag()
            self._push()

            # Add to config file
            cloudknot.config.add_resource(
                'docker-images', self.name, self.repo_uri
            )

    pre_existing = property(operator.attrgetter('_pre_existing'))
    build_path = property(operator.attrgetter('_build_path'))
    dockerfile = property(operator.attrgetter('_dockerfile'))
    requirements = property(operator.attrgetter('_requirements'))
    tags = property(operator.attrgetter('_tags'))
    repo_name = property(operator.attrgetter('_repo_name'))
    repo_uri = property(operator.attrgetter('_repo_uri'))
    repo_registry_id = property(operator.attrgetter('_repo_registry_id'))

    def _exists_already(self):
        """ Check if an AWS ECR repo exists already

        If repo exists, return namedtuple with repo info. Otherwise, set the
        namedtuple's `exists` field to `False`. The remaining fields default
        to `None`.

        Returns
        -------
        namedtuple RoleExists
            A namedtuple with fields ['exists', 'repo_name', 'repo_uri',
            'repo_registry_id', 'tags']
        """
        # define a namedtuple for return value type
        ResourceExists = namedtuple(
            'ResourceExists',
            ['exists', 'repo_name', 'repo_uri', 'repo_registry_id', 'tags']
        )
        # make all but the first value default to None
        ResourceExists.__new__.__defaults__ = \
            (None,) * (len(ResourceExists._fields) - 1)

        try:
            response = ECR.describe_repositories(repositoryNames=[self.name])
            repo = response.get('repositories')[0]
            repo_name = repo['repositoryName']
            repo_uri = repo['repositoryUri']
            registry_id = repo['registryId']

            response = ECR.describe_images(
                registryId=registry_id,
                repositoryName=repo_name
            )

            try:
                tags = response.get('imageDetails')[0]['imageTags']
            except IndexError:
                tags = []

            return ResourceExists(
                exists=True, repo_name=repo_name, repo_uri=repo_uri,
                repo_registry_id=registry_id, tags=tags
            )
        except ECR.exceptions.RepositoryNotFoundException:
            return ResourceExists(exists=False)

    def _build(self):
        """
        Build a DockerContainer image
        """
        req_build_path = os.path.join(self.build_path, 'requirements.txt')
        if not os.path.isfile(req_build_path):
            shutil.copyfile(self.requirements, req_build_path)
            cleanup = True
        else:
            cleanup = False

        c = docker.from_env()
        for tag in self.tags:
            logging.info('Building image {name:s} with tag {tag:s}'.format(
                name=self.name, tag=tag
            ))

            build_result = c.build(path=self.build_path,
                                   dockerfile=self.dockerfile,
                                   tag=self.name + ':' + tag)

            for line in build_result:
                logging.debug(line)

        if cleanup:
            os.remove(req_build_path)

    def _create_repo(self):
        # Refresh the aws ecr login credentials
        login_cmd = subprocess.check_output([
            'aws', 'ecr', 'get-login', '--no-include-email',
            '--region', get_default_region()
        ])
        login_result = subprocess.call(
            login_cmd.decode('ASCII').rstrip('\n').split(' '))

        if login_result:  # pragma: nocover
            raise ValueError(
                'Unable to login to AWS ECR using `{login:s}`'.format(
                    login=login_cmd
                )
            )

        # Get repository uri
        try:
            # First, check to see if it already exists
            response = ECR.describe_repositories(
                repositoryNames=[self.name]
            )

            repo_name = response['repositories'][0]['repositoryName']
            repo_uri = response['repositories'][0]['repositoryUri']
            repo_registry_id = response['repositories'][0]['registryId']

            logging.info('Repository {name:s} already exists at '
                         '{uri:s}'.format(name=self.name, uri=repo_uri))

        except ECR.exceptions.RepositoryNotFoundException:
            # If it doesn't exists already, then create it
            response = ECR.create_repository(
                repositoryName=self.name
            )

            repo_name = response['repository']['repositoryName']
            repo_uri = response['repository']['repositoryUri']
            repo_registry_id = response['repository']['registryId']

            logging.info('Created repository {name:s} at {uri:s}'.format(
                name=self.name, uri=repo_uri
            ))

        RepoInfo = namedtuple('RepoInfo', ['name', 'uri', 'registry_id'])
        return RepoInfo(
            name=repo_name, uri=repo_uri, registry_id=repo_registry_id
        )

    def _tag(self):
        """
        Tag a DockerContainer image
        """
        c = docker.from_env()
        for tag in self.tags:
            logging.info('Tagging image {name:s} with tag {tag:s}'.format(
                name=self.name, tag=tag
            ))

            c.tag(image=self.name + ':' + tag,
                  repository=self.repo_uri, tag=tag)

    def _push(self):
        """
        Push a DockerContainer image to a repository
        """
        c = docker.from_env()
        for tag in self.tags:
            logging.info('Pushing image {name:s} with tag {tag:s}'.format(
                name=self.name, tag=tag
            ))

            result = c.push(repository=self.repo_uri, tag=tag, stream=True)

            for line in result:
                logging.debug(line)

    def clobber(self):
        """ Delete this docker image and remove from the remote repository

        Returns
        -------
        None
        """
        # Remove the local docker image
        c = docker.from_env()
        for tag in self.tags:
            c.remove_image(self.name + ':' + tag, force=True)
            c.remove_image(self.repo_uri + ':' + tag, force=True)

        try:
            # Remove the remote docker image
            ECR.delete_repository(
                registryId=self.repo_registry_id,
                repositoryName=self.repo_name,
                force=True
            )
        except ECR.exceptions.RepositoryNotFoundException:
            # It doesn't exist anyway, so clear this exception and carry on
            pass

        # Remove from the config file
        cloudknot.config.remove_resource('docker-images', self.name)
