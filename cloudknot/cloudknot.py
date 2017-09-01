from __future__ import absolute_import, division, print_function
import boto3
import docker
import os
import shutil
import operator
import subprocess
from collections import namedtuple
from .due import due, Doi

__all__ = ["Container",
"Model", "Fit", "opt_err_func", "transform_data", "cumgauss"]


# Use duecredit (duecredit.org) to provide a citation to relevant work to
# be cited. This does nothing, unless the user has duecredit installed,
# And calls this with duecredit (as in `python -m duecredit script.py`):
due.cite(Doi("10.1167/13.9.30"),
         description="Template project for small scientific Python projects",
         tags=["reference-implementation"],
         path='cloudknot')


def get_repo(repo_name):
    # Refresh the aws ecr login credentials
    login_cmd = subprocess.check_output(['aws', 'ecr', 'get-login',
        '--no-include-email', '--region', 'us-east-1'])
    login_result = subprocess.call(
            login_cmd.decode('ASCII').rstrip('\n').split(' '))

    ecr_client = boto3.client('ecr')

    # Get repository uri
    try:
        # First, check to see if it already exists
        response = ecr_client.describe_repositories(
                repositoryNames=[repo_name])
        repo_uri = response['repositories'][0]['repositoryUri']
        print('Repository {name:s} already exists at {uri:s}'.format(
            name=repo_name, uri=repo_uri))
    except ecr_client.exceptions.RepositoryNotFoundException:
        # If it doesn't create it
        response = ecr_client.create_repository(
                repositoryName=repo_name)
        repo_uri = response['repository']['repositoryUri']
        print('Created repository {name:s} at {uri:s}'.format(
            name=repo_name, uri=repo_uri))

    RepoInfo = namedtuple('RepoInfo', ['name', 'uri'])
    return RepoInfo(name=repo_name, uri=repo_uri)


class DockerImage(object):
    """Class for building, tagging, and pushing docker containers"""
    def __init__(self, name, build_path='.', dockerfile='./Dockerfile',
            requirements=None, tags=['latest']):
        """ Initialize a Docker image object.

        Parameters
        ----------
        name : string
            Name of the image

        build_path : string
            Path to an existing directory in which to build docker image
            Default: '.'

        dockerfile : string
            Path to an existing Dockerfile
            Default: './Dockerfile'

        requirements : string
            Path to an existing requirements.txt file to build dependencies
            Default: None (i.e. assumes no dependencies)

        tags : list
            List of strings of desired image tags
            Default: ['latest']
        """
        self.name = name
        self.build_path = buildpath
        self.dockerfile = dockerfile
        self.requirements = requirements
        self.tags = tags
        self.repository = repository

        name = property(operator.attrgetter('_name'))
        @name.setter
        def name(self, n):
            if not n:
                raise Exception('name cannot be empty')
            self._name = str(n)

        build_path = property(operator.attrgetter('_build_path'))
        @build_path.setter
        def build_path(self, p):
            if not os.path.isdir(p):
                raise Exception('build_path must be an existing directory')
            self._build_path = os.path.abspath(p)

        dockerfile = property(operator.attrgetter('_dockerfile'))
        @dockerfile.setter
        def dockerfile(self, f):
            if not os.path.isfile(f):
                raise Exception('dockerfile must be an existing regular file')
            self._dockerfile = os.path.abspath(f)

        requirements = property(operator.attrgetter('_requirements'))
        @requirements.setter
        def requirements_path(self, f):
            if f:
                if not os.path.isfile(f)):
                    raise Exception('requirements must be an existing regular file')
                self._requirements = os.path.abspath(f)
            else:
                self._requirements = None

        tags = property(operator.attrgetter('_tags'))
        @tags.setter
        def tags(self, tag_collection):
            if tag_collection:
                tmp_tags = [t for t in tag_collection]
                if 'latest' not in tmp_tags:
                    tmp_tags.append('latest')
                self._tags = tmp_tags
            else:
                self._tags = None

    def build(self, verbosity=0):
        """
        Build a DockerContainer image

        Parameters
        ----------
        verbosity : int
            Verbosity level [0, 1, 2].
        """
        req_build_path = self.build_path + '/requirements.txt'
        if (self.requirements and not os.path.isfile(req_build_path)):
            shutil.copyfile(self.requirements, req_build_path)
            cleanup = True
        else:
            cleanup = False

        c = docker.from_env()
        for tag in self.tags:
            if (verbosity > 0):
                print('Building image {name:s} with tag {tag:s}'.format(
                    name=self.name, tag=tag))
            build_result = c.build(path=self.build_path,
                    dockerfile=self.dockerfile, tag=self.name + ':' + tag)
            if (verbosity > 1):
                for line in build_result:
                    print(line)

        if cleanup:
            os.remove(req_build_path)

    def tag(self, verbosity=0):
        """
        Tag a DockerContainer image

        Parameters
        ----------
        verbosity : int
            Verbosity level [0, 1, 2].
        """
        c = docker.from_env()
        for tag in self.tags:
            if (verbosity > 0):
                print('Tagging image {name:s} with tag {tag:s}'.format(
                    name=self.name, tag=tag))
            c.tag(image=self.name + ':' + self.tag,
                    repository=self.repository, tag=tag)

    def push(self, repository, verbosity=0):
        """
        Push a DockerContainer image to a repository

        Parameters
        ----------
        repository : string
            String containing repository location
            (e.g. on Dockerhub or Amazon ECR)

        verbosity : int
            Verbosity level [0, 1, 2].
        """
        for tag in self.tags:
            if (verbosity > 0):
                print('Pushing image {name:s} with tag {tag:s}'.format(
                    name=self.name, tag=tag))
            push_result = c.push(
                    repository=repository, tag=tag, stream=(verbosity > 1))
            if (verbosity > 1):
                for line in push_result:
                    print(line)


