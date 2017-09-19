import docker
import operator
import os
import shutil
import subprocess

from .. import config
from .base_classes import ObjectWithNameAndVerbosity, ECR, \
    ResourceExistsException

__all__ = ["DockerImage"]


# noinspection PyPropertyAccess,PyAttributeOutsideInit
class DockerImage(ObjectWithNameAndVerbosity):
    """Class for building, tagging, and pushing docker containers"""
    def __init__(self, name, tags, build_path='.',
                 dockerfile=os.path.join('.', 'Dockerfile'),
                 requirements=None, verbosity=0):
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

        verbosity : int
            verbosity level [0, 1, 2]
        """
        super(DockerImage, self).__init__(name=name, verbosity=verbosity)

        if not os.path.isdir(build_path):
            raise ValueError('build_path must be an existing directory')
        self._build_path = os.path.abspath(build_path)

        if not os.path.isfile(dockerfile):
            raise ValueError('dockerfile must be an existing regular file')
        self._dockerfile = os.path.abspath(dockerfile)

        if not requirements:
            self._requirements = None
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

    build_path = property(operator.attrgetter('_build_path'))
    dockerfile = property(operator.attrgetter('_dockerfile'))
    requirements = property(operator.attrgetter('_requirements'))
    tags = property(operator.attrgetter('_tags'))

    def _build(self):
        """
        Build a DockerContainer image
        """
        req_build_path = os.path.join(self.build_path + 'requirements.txt')
        if self.requirements and not os.path.isfile(req_build_path):
            shutil.copyfile(self.requirements, req_build_path)
            cleanup = True
        else:
            cleanup = False

        c = docker.from_env()
        for tag in self.tags:
            if self.verbosity > 0:
                print('Building image {name:s} with tag {tag:s}'.format(
                    name=self.name, tag=tag))
            build_result = c.build(path=self.build_path,
                                   dockerfile=self.dockerfile,
                                   tag=self.name + ':' + tag)
            if self.verbosity > 1:
                for line in build_result:
                    print(line)

        if cleanup:
            os.remove(req_build_path)

    def _create_repo(self, repo_name):
        # Refresh the aws ecr login credentials
        login_cmd = subprocess.check_output(['aws', 'ecr', 'get-login',
                                             '--no-include-email', '--region',
                                             'us-east-1'])
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
                repositoryNames=[repo_name]
            )

            repo_uri = response['repositories'][0]['repositoryUri']

            if self.verbosity > 0:
                print('Repository {name:s} already exists at {uri:s}'.format(
                    name=repo_name, uri=repo_uri))
        except ECR.exceptions.RepositoryNotFoundException:
            # If it doesn't exists already, then create it
            response = ECR.create_repository(
                repositoryName=repo_name
            )

            repo_uri = response['repository']['repositoryUri']
            if self.verbosity > 0:
                print('Created repository {name:s} at {uri:s}'.format(
                    name=repo_name, uri=repo_uri))

        self._uri = repo_uri

    @property
    def uri(self):
        return self._uri

    def _tag(self, repo_name):
        """
        Tag a DockerContainer image
        """
        self._create_repo(repo_name=repo_name)
        c = docker.from_env()
        for tag in self.tags:
            if self.verbosity > 0:
                print('Tagging image {name:s} with tag {tag:s}'.format(
                    name=self.name, tag=tag))
            c.tag(image=self.name + ':' + self.tag,
                  repository=self.uri, tag=tag)

    def _push(self, repo_name):
        """
        Push a DockerContainer image to a repository

        Parameters
        ----------
        repo_name : string
            Repository name
        """
        self._create_repo(repo_name=repo_name)
        c = docker.from_env()
        for tag in self.tags:
            if self.verbosity > 0:
                print('Pushing image {name:s} with tag {tag:s}'.format(
                    name=self.name, tag=tag))
            push_result = c.push(
                repository=self.uri, tag=tag, stream=(self.verbosity > 1))
            if self.verbosity > 1:
                for line in push_result:
                    print(line)

    def remove_aws_resource(self):
        """ Delete this docker image

        Returns
        -------
        None
        """
        pass
