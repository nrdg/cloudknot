from __future__ import absolute_import, division, print_function

import configparser
import docker
import inspect
import logging
import os
import re
import six
import subprocess
import tempfile
from pipreqs import pipreqs

from . import aws
from . import config as ckconfig
from .aws.base_classes import get_region, \
    ResourceDoesNotExistException, ResourceClobberedException
from .config import get_config_file

__all__ = ["DockerImage"]

mod_logger = logging.getLogger(__name__)


# noinspection PyPropertyAccess,PyAttributeOutsideInit
class DockerImage(aws.NamedObject):
    """Class for dockerizing a python script or function

    On `__init__`, if given a python function, DockerImage will create a CLI
    version for that function, write a requirements.txt file for all import
    statements in the function, and write a Dockerfile to containerize that
    python script. If given a path to a python script, DockerImage will assume
    it has a CLI and will skip the first step, building a requirements.txt file
    and a Dockerfile as before.

    If the input script or function contains imports that cannot be identified
    by pipreqs (i.e. cannot be installed with `pip install package`, those
    packages will not be included in requirements.txt, DockerImage will throw
    a warning, and the user must install those packages by hand in the
    Dockerfile.
    """
    def __init__(self, name=None, func=None, script_path=None,
                 dir_name=None, github_installs=(), username=None):
        """Initialize a DockerImage instance

        Parameters
        ----------
        name : str
            Name of DockerImage, only used to retrieve DockerImage from
            config file info. Do not use to create new DockerImage

        func : function
            Python function to be dockerized

        script_path : string
            Path to file with python script to be dockerized

        dir_name : string
            Directory to store Dockerfile, requirements.txt, and python
            script with CLI
            Default: parent directory of script if `script_path` is provided
            else DockerImage creates a new directory, accessible by the
            `build_path` property.

        github_installs : string or sequence of strings
            Github addresses for packages to install from github rather than
            PyPI (e.g. git://github.com/richford/cloudknot.git or
            git://github.com/richford/cloudknot.git@newfeaturebranch)
            Default: ()

        username : string
            Default user created in the Dockerfile
            Default: 'cloudknot-user'
        """
        # User must specify at least `func` or `script_path`
        if name and any([func, script_path, dir_name, username]):
            raise ValueError(
                "You specified a name plus other stuff. The name parameter is "
                "only used to retrieve a pre-existing DockerImage instance. "
                "If you'd like to create a new one, do not provide a name "
                "argument."
            )

        # User must specify at least `func` or `script_path`
        if not any([name, func, script_path]):
            raise ValueError('You must suppy either `name`, `func` or '
                             '`script_path`.')

        # If both `func` and `script_path` are specified,
        # input is over-specified
        if script_path and func:
            raise ValueError('You provided `script_path` and other redundant '
                             'arguments, either `func` or `dir_name`. ')

        if name:
            # Validate name input
            if not isinstance(name, six.string_types):
                raise ValueError('Docker image name must be a string. You '
                                 'passed a {t!s}'.format(t=type(name)))

            super(DockerImage, self).__init__(name=name)

            section_name = 'docker-image ' + name

            config_file = get_config_file()
            config = configparser.ConfigParser()
            config.read(config_file)

            if section_name not in config.sections():
                raise ResourceDoesNotExistException(
                    'Could not find {name:s} in config_file '
                    '{file:s}'.format(name=section_name, file=config_file),
                    resource_id=name
                )

            self._func = None
            self._build_path = config.get(section_name, 'build-path')
            self._script_path = config.get(section_name, 'script-path')
            self._docker_path = config.get(section_name, 'docker-path')
            self._req_path = config.get(section_name, 'req-path')
            self._github_installs = config.get(section_name,
                                               'github-imports').split()
            self._username = config.get(section_name, 'username')
            self._clobber_script = config.getboolean(section_name,
                                                     'clobber-script')

            images_str = config.get(section_name, 'images')
            images_list = [s.split(':') for s in images_str.split()]
            self._images = [{'name': i[0], 'tag': i[1]}
                            for i in images_list]

            uri = config.get(section_name, 'repo-uri')
            self._repo_uri = uri if uri else None

            # Set self.pip_imports and self.missing_imports
            self._set_imports()
        else:
            self._func = func
            self._username = username if username else 'cloudknot-user'

            # Validate dir_name input
            if dir_name and not os.path.isdir(dir_name):
                raise ValueError('`dir_name` is not an existing directory')

            if script_path:
                # User supplied a pre-existing python script.
                # Ensure we don't clobber it later
                self._clobber_script = False

                # Check that it is a valid path
                if not os.path.isfile(script_path):
                    raise ValueError('If provided, `script_path` must be an '
                                     'existing regular file.')

                self._script_path = os.path.abspath(script_path)
                super(DockerImage, self).__init__(
                    name=os.path.basename(self.script_path)
                )

                # Set the parent directory
                if dir_name:
                    self._build_path = os.path.abspath(dir_name)
                else:
                    self._build_path = os.path.dirname(self.script_path)
            else:
                # We will create the script, Dockerfile, and requirements.txt
                # in a new directory
                self._clobber_script = True
                super(DockerImage, self).__init__(name=func.__name__)

                if dir_name:
                    self._build_path = os.path.abspath(dir_name)
                    self._script_path = os.path.join(self.build_path,
                                                     self.name + '.py')

                    # Confirm that we will not overwrite an existing script
                    if os.path.isfile(self._script_path):
                        raise ValueError(
                            'There is a pre-existing python script in the '
                            'directory that you provided. Either specify a '
                            'new directory, move the python script `{file:s}` '
                            'to a new directory, or delete the existing '
                            'python script if it is no longer '
                            'necessary.'.format(file=self.script_path)
                        )
                else:
                    # Create a new unique directory name
                    prefix = 'cloudknot_docker_' + self.name + '_'
                    self._build_path = tempfile.mkdtemp(prefix=prefix,
                                                        dir=os.getcwd())

                    # Store the script in the new directory
                    self._script_path = os.path.join(self.build_path,
                                                     self.name + '.py')

                self._write_script()

            # Create the Dockerfile and requirements.txt in the parent dir
            self._docker_path = os.path.join(self.build_path, 'Dockerfile')
            self._req_path = os.path.join(self.build_path, 'requirements.txt')

            # Confirm that we won't overwrite an existing Dockerfile
            if os.path.isfile(self._docker_path):
                raise ValueError(
                    'There is a pre-existing Dockerfile in the same directory '
                    'as the python script you provided or in the directory '
                    'name that you provided. Either specify a new directory, '
                    'move the Dockerfile `{file:s}` to a new directory, or '
                    'delete the existing Dockerfile if it is no longer '
                    'necessary.'.format(file=self.docker_path)
                )

            # Confirm that we won't overwrite an existing requirements.txt
            if os.path.isfile(self._req_path):
                raise ValueError(
                    'There is a pre-existing requirements.txt in the same '
                    'directory as the python script you provided or in the '
                    'directory name that you provided. Either specify a new '
                    'directory, move the requirements file`{file:s}` to its '
                    'own directory or delete the existing requirements file '
                    'if it is no longer needed.'.format(file=self.req_path)
                )

            # Validate github installs before building Dockerfile
            if isinstance(github_installs, six.string_types):
                self._github_installs = [github_installs]
            elif all(isinstance(x, six.string_types) for x in github_installs):
                self._github_installs = list(github_installs)
            else:
                raise ValueError('github_installs must be a string or a '
                                 'sequence of strings.')

            pattern = r'(https|git)(://github.com/).*/.*\.git($|@.*$)'
            for install in self._github_installs:
                match_obj = re.match(pattern, install)
                if match_obj is None:
                    raise ValueError(
                        'One of your github_installs, {i:s} is not formatted '
                        'correctly. It should look something like '
                        'git://github.com/user/repo.git, '
                        'git://github.com/user/repo.git@branch, '
                        'https://github.com/user/repo.git, or '
                        'https://github.com/user/repo.git@branch, '
                    )

            # Set self.pip_imports and self.missing_imports
            self._set_imports()

            # Write the requirements.txt file and Dockerfile
            pipreqs.generate_requirements_file(self.req_path, self.pip_imports)

            self._write_dockerfile()

            self._images = []
            self._repo_uri = None

            # Add to config file
            section_name = 'docker-image ' + self.name
            ckconfig.add_resource(section_name, 'build-path', self.build_path)
            ckconfig.add_resource(
                section_name, 'script-path', self.script_path
            )
            ckconfig.add_resource(
                section_name, 'docker-path', self.docker_path
            )
            ckconfig.add_resource(section_name, 'req-path', self.req_path)
            ckconfig.add_resource(section_name, 'github-imports',
                                  ' '.join(self.github_installs))
            ckconfig.add_resource(section_name, 'username', self.username)
            ckconfig.add_resource(section_name, 'images', '')
            ckconfig.add_resource(section_name, 'repo-uri', '')
            ckconfig.add_resource(
                section_name, 'clobber-script', str(self._clobber_script)
            )

    # Declare read-only properties
    @property
    def func(self):
        """Python function that was dockerized"""
        return self._func

    @property
    def build_path(self):
        """The build path for the docker image"""
        return self._build_path

    @property
    def script_path(self):
        """Path to the CLI version of the python function"""
        return self._script_path

    @property
    def docker_path(self):
        """Path to the generated Dockerfile"""
        return self._docker_path

    @property
    def req_path(self):
        """Path to the generated requirements.txt file"""
        return self._req_path

    @property
    def pip_imports(self):
        """List of packages in the requirements.txt file"""
        return self._pip_imports

    @property
    def github_installs(self):
        """List of packages installed from github rather than PyPI"""
        return self._github_installs

    @property
    def username(self):
        """Default username created in Dockerfile"""
        return self._username

    @property
    def missing_imports(self):
        """List of required imports that are unavailable through pip install.

        The user must edit the Dockerfile by hand to install these packages
        before using the build or push methods.
        """
        return self._missing_imports

    @property
    def images(self):
        """List of name, tag dicts for docker images built by this instance"""
        return self._images

    @property
    def repo_uri(self):
        """Location of remote repository to which the image was pushed"""
        return self._repo_uri

    def _write_script(self):
        """Write this instance's function to a script with a CLI.

        Use clize.run to create CLI
        """
        with open(self.script_path, 'w') as f:
            header_path = os.path.abspath(os.path.join(
                os.path.dirname(__file__),
                'header.py.txt'
            ))

            with open(header_path) as header:
                header_lines = header.readlines()
                f.writelines(header_lines)

            f.write(inspect.getsource(self.func))
            f.write('\n\n')
            f.write('if __name__ == "__main__":\n')
            f.write('    run({func_name:s})\n'.format(func_name=self.name))

        mod_logger.info(
            'Wrote python function {func:s} to script {script:s}'.format(
                func=self.name,
                script=self.script_path
            )
        )

    def _write_dockerfile(self):
        """Write Dockerfile to containerize this instance's python function"""
        with open(self.docker_path, 'w') as f:
            py_version_str = '3' if six.PY3 else '2'
            home_dir = '/home/{username:s}'.format(username=self.username)

            f.write('#' * 79 + '\n')
            f.write('# Dockerfile to build ' + self.name)
            f.write(' application container\n')
            f.write('# Based on python ' + py_version_str + '\n')
            f.write('#' * 79 + '\n\n')

            f.write('# Use official python base image\n')
            f.write('FROM python:' + py_version_str + '\n\n')

            f.write('# Install python dependencies\n')
            f.write('COPY requirements.txt /tmp/\n')
            f.write('RUN pip install -r /tmp/requirements.txt')
            for install in self.github_installs:
                f.write(' \\\n    && pip install git+' + install)

            f.write('\n\n')

            f.write('# Create a default user. Available via runtime flag ')
            f.write('`--user {user:s}`.\n'.format(user=self.username))
            f.write('# Add user to "staff" group.\n')
            f.write('# Give user a home directory.\n')
            f.write(
                'RUN useradd {user:s} \\\n'
                '    && addgroup {user:s} staff \\\n'
                '    && mkdir {home:s} \\\n'
                '    && chown -R {user:s}:staff {home:s}\n\n'.format(
                    user=self.username, home=home_dir)
            )

            f.write('ENV HOME {home:s}\n\n'.format(home=home_dir))

            f.write('# Copy the python script\n')
            f.write('COPY {py_script:s} {home:s}/\n\n'.format(
                py_script=os.path.basename(self.script_path),
                home=home_dir
            ))

            f.write('# Set working directory\n')
            f.write('WORKDIR {home:s}\n\n'.format(home=home_dir))

            f.write('# Set entrypoint\n')
            f.write('ENTRYPOINT ["python", "{py_script:s}"]\n'.format(
                py_script=home_dir + '/' + os.path.basename(self.script_path)
            ))

        mod_logger.info(
            'Wrote Dockerfile {path:s}'.format(path=self.docker_path)
        )

    def _set_imports(self):
        """Set required imports for the python script at self.script_path"""
        # Get the names of packages imported in the script
        import_names = pipreqs.get_all_imports(os.path.dirname(
            self.script_path
        ))

        # Of those names, store that ones that are available via pip
        self._pip_imports = pipreqs.get_imports_info(import_names)

        # If some imports were left out, store their names
        pip_names = set([i['name'] for i in self.pip_imports])
        self._missing_imports = list(set(import_names) - pip_names)

        if len(import_names) != (len(self.pip_imports)
                                 + len(self.github_installs)):
            # And warn the user
            mod_logger.warning(
                'Warning, some imports not found by pipreqs. You will '
                'need to edit the Dockerfile by hand, e.g by installing '
                'from github. You need to install the following packages '
                '{missing!s}'.format(missing=self.missing_imports)
            )

    def build(self, tags, image_name=None):
        """Build a DockerContainer image

        Parameters
        ----------
        tags : str or sequence of str
            Tags to be applied to this Docker image

        image_name : str
            Name of Docker image to be built
            Default: 'cloudknot/' + self.name
        """
        if self.clobbered:
            raise ResourceClobberedException(
                'This docker image has already been clobbered.',
                self.name
            )

        # Validate tags input
        if isinstance(tags, six.string_types):
            tags = [tags]
        elif all(isinstance(x, six.string_types) for x in tags):
            tags = [t for t in tags]
        else:
            raise ValueError('tags must be a string or a sequence '
                             'of strings.')

        # Don't allow user to put "latest" in tags.
        if 'latest' in tags:
            raise ValueError('Any tag is allowed, except for "latest."')

        image_name = image_name if image_name else 'cloudknot/' + self.name

        images = [{'name': image_name, 'tag': t} for t in tags]
        self._images += [im for im in images if im not in self.images]

        # Use docker low-level APIClient
        c = docker.from_env()
        for im in images:
            mod_logger.info('Building image {name:s} with tag {tag:s}'.format(
                name=im['name'], tag=im['tag']
            ))

            c.images.build(
                path=self.build_path,
                dockerfile=self.docker_path,
                tag=im['name'] + ':' + im['tag']
            )

        # Update the config file images list
        config_file = get_config_file()
        config = configparser.ConfigParser()
        config.read(config_file)

        # Get list of images in config file
        section_name = 'docker-image ' + self.name
        config_images_str = config.get(section_name, 'images')

        # Split config images into list
        config_images_list = config_images_str.split()

        # Convert images just build into list
        current_images_list = [i['name'] + ':' + i['tag'] for i in images]

        # Get the union of the two lists
        config_images = list(set(config_images_list)
                             | set(current_images_list))

        # Convert back to space separated list string
        config_images_str = ' '.join(config_images)

        # Reload to config file
        ckconfig.add_resource(section_name, 'images', config_images_str)

    def push(self, repo=None, repo_uri=None):
        """Tag and push a DockerContainer image to a repository

        Parameters
        ----------
        repo : DockerRepo, optional
            DockerRepo instance to which to push this image

        repo_uri : string, optional
            URI for the docker repository to which to push this instance
        """
        if self.clobbered:
            raise ResourceClobberedException(
                'This docker image has already been clobbered.',
                self.name
            )

        # User must supply either a repo object or the repo name and uri
        if not (repo or repo_uri):
            raise ValueError('You must supply either `repo=<DockerRepo '
                             'instance>` or `repo_uri`.')

        # User cannot supply both repo and repo_name or repo_uri
        if repo and repo_uri:
            raise ValueError('You may not specify both a repo object and '
                             '`repo_uri`.')

        # Make sure that the user has called build first or somehow set tags.
        if not self.images:
            raise ValueError(
                'The images property is empty, indicating that the build '
                'method has not yet been called. Call `build(tags=<tags>)` '
                'first before calling `tag()`.'
            )

        # Refresh the aws ecr login credentials
        login_cmd = subprocess.check_output([
            'aws', 'ecr', 'get-login', '--no-include-email',
            '--region', get_region()
        ])

        # Login
        login_result = subprocess.call(
            login_cmd.decode('ASCII').rstrip('\n').split(' '))

        # If login failed, pass error to user
        if login_result:  # pragma: nocover
            raise ValueError(
                'Unable to login to AWS ECR using `{login:s}`'.format(
                    login=login_cmd.decode()
                )
            )

        if repo:
            if not isinstance(repo, aws.DockerRepo):
                raise ValueError('repo must be a DockerRepo instance.')
            self._repo_uri = repo.repo_uri
        else:
            if not isinstance(repo_uri, six.string_types):
                raise ValueError('`repo_uri` must be a string.')
            self._repo_uri = repo_uri

        # Use docker low-level APIClient for tagging
        c = docker.from_env().api
        # And the image client for pushing
        cli = docker.from_env().images
        for im in self.images:
            # Log tagging info
            mod_logger.info('Tagging image {name:s} with tag {tag:s}'.format(
                name=im['name'], tag=im['tag']
            ))

            # Tag it with the most recently added image_name
            c.tag(image=im['name'] + ':' + im['tag'],
                  repository=self.repo_uri, tag=im['tag'])

            # Log push info
            mod_logger.info('Pushing image {name:s} with tag {tag:s}'.format(
                name=im['name'], tag=im['tag']
            ))

            for l in cli.push(
                    repository=self.repo_uri, tag=im['tag'], stream=True
            ):
                mod_logger.debug(l)

        self._repo_uri = self._repo_uri + ':' + self.images[-1]['tag']

        section_name = 'docker-image ' + self.name
        ckconfig.add_resource(section_name, 'repo-uri', self.repo_uri)

    def clobber(self):
        """Delete all of the files associated with this instance

        Always delete the generated requirements.txt and Dockerfile. Only
        delete the script if it was auto-generated. Only delete the parent
        directory if it is empty.

        Also delete the local docker image
        """
        if self.clobbered:
            return

        if self._clobber_script:
            os.remove(self.script_path)
            mod_logger.info('Removed {path:s}'.format(path=self.script_path))

        os.remove(self.docker_path)
        mod_logger.info('Removed {path:s}'.format(path=self.docker_path))
        os.remove(self.req_path)
        mod_logger.info('Removed {path:s}'.format(path=self.req_path))

        try:
            os.rmdir(self.build_path)
            mod_logger.info('Removed {path:s}'.format(path=self.build_path))
        except OSError:
            # Directory is not empty. There's pre-existing stuff in there
            # that we shouldn't mess with.
            pass

        cli = docker.from_env().images
        # Get local images first (lol stands for list_of_lists
        local_image_lol = [im.tags for im in cli.list()]
        # Flatten the list of lists
        local_images = [im for sublist in local_image_lol for im in sublist]

        # Use docker image client to remove local images
        for im in self.images:
            if im['name'] + ':' + im['tag'] in local_images:
                # Remove the local docker image, using the image name
                cli.remove(
                    image=im['name'] + ':' + im['tag'],
                    force=True,
                    noprune=False
                )
                # Update local_images to prevent redundant image removal
                local_image_lol = [im.tags for im in cli.list()]
                local_images = [im for sublist in local_image_lol
                                for im in sublist]

        if self.repo_uri:
            cli.remove(
                image=self.repo_uri,
                force=True,
                noprune=False
            )

        # Remove from the config file
        config_file = get_config_file()
        config = configparser.ConfigParser()
        config.read(config_file)
        config.remove_section('docker-image ' + self.name)
        with open(config_file, 'w') as f:
            config.write(f)

        self._clobbered = True

        mod_logger.info('Removed local docker images '
                        '{images!s}'.format(images=self.images))
