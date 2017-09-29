from __future__ import absolute_import, division, print_function

import docker
import logging
import operator
import os
import shutil
import subprocess

from .base_classes import NamedObject, ECR, get_default_region

__all__ = ["DockerImage"]


# noinspection PyPropertyAccess,PyAttributeOutsideInit
class DockerImage(NamedObject):
    """Class for building, tagging, and pushing docker containers"""
    def __init__(self, name, tags, build_path=None,
                 dockerfile=None,
                 requirements=None):
        """ Initialize a Docker image object.

        Parameters
        ----------
        name : string
            Name of the image

        tags : list or tuple
            tuple of strings of desired image tags

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
        prefix = 'cloudknot/'
        if name[:len(prefix)] != prefix:
            name = 'cloudknot/' + name
        super(DockerImage, self).__init__(name=name)

        if build_path:
            if not os.path.isdir(build_path):
                raise ValueError('build_path must be an existing directory')
            self._build_path = os.path.abspath(build_path)
        else:
            self._build_path = os.getcwd()

        if dockerfile:
            if not os.path.isfile(dockerfile):
                raise ValueError('dockerfile must be an existing regular file')
            self._dockerfile = os.path.abspath(dockerfile)
        else:
            self._dockerfile = os.path.join(self.build_path, 'Dockerfile')

        if not requirements:
            self._requirements = os.path.join(self.build_path, 'requirements.txt')
        elif not os.path.isfile(requirements):
            raise ValueError('requirements must be an existing regular file')
        else:
            self._requirements = os.path.abspath(requirements)

        if isinstance(tags, str):
            tags = (tags,)
        elif all(isinstance(x, str) for x in tags):
            tags = tuple([t for t in tags])
        else:
            raise ValueError('tags must be a string or a sequence of strings.')

        if 'latest' in tags:
            raise ValueError('Any tag is allowed, except for "latest."')

        self._tags = tags

        self._uri = None
        self._build()
        self._uri = self._create_repo()
        self._tag()
        self._push()

    build_path = property(operator.attrgetter('_build_path'))
    dockerfile = property(operator.attrgetter('_dockerfile'))
    requirements = property(operator.attrgetter('_requirements'))
    tags = property(operator.attrgetter('_tags'))
    uri = property(operator.attrgetter('_uri'))

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

        if login_result:
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

            repo_uri = response['repositories'][0]['repositoryUri']

            logging.info('Repository {name:s} already exists at '
                         '{uri:s}'.format(name=self.name, uri=repo_uri))

        except ECR.exceptions.RepositoryNotFoundException:
            # If it doesn't exists already, then create it
            response = ECR.create_repository(
                repositoryName=self.name
            )

            repo_uri = response['repository']['repositoryUri']

            logging.info('Created repository {name:s} at {uri:s}'.format(
                name=self.name, uri=repo_uri
            ))

        return repo_uri

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
                  repository=self.uri, tag=tag)

    def _push(self):
        """
        Push a DockerContainer image to a repository
        """
        c = docker.from_env()
        for tag in self.tags:
            logging.info('Pushing image {name:s} with tag {tag:s}'.format(
                name=self.name, tag=tag
            ))

            push_result = c.push(repository=self.uri, tag=tag, stream=True)

            for line in push_result:
                logging.debug(line)

    def clobber(self):
        """ Delete this docker image

        Returns
        -------
        None
        """
        pass
