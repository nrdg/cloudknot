from __future__ import absolute_import, division, print_function

import docker
import inspect
import logging
import operator
import os
import six
import subprocess
import tempfile
from pipreqs import pipreqs

from . import aws
from . import config
from .aws.base_classes import get_region

__all__ = ["DockerImage"]

mod_logger = logging.getLogger(__name__)


# noinspection PyPropertyAccess,PyAttributeOutsideInit
class DockerImage(object):
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

    Attributes
    ----------
    name : string
        name of this docker image, set to the basename of the script path or
        the function name

    func : function
        python function that will be dockerized

    build_path : string
        the build path for the docker image

    script_path : string
        path to the CLI version of the python function

    docker_path : string
        path to the Dockerfile

    req_path : string
        path to the requirements.txt file

    pip_imports : list
        list of packages in the requirements.txt file

    username : string
        default username created in Dockerfile

    missing_imports : list
        list of imports required by the python script that are unavailable
        through pip install. The user must edit the Dockerfile by hand to
        install these packages before using the build or push methods.

    image_name : string
        the name of the docker image created with the build method

    tags : list
        list of tags for this docker image

    repo_uri : string
        location of remote repository to which the image was pushed with the
        push method
    """
    def __init__(self, func=None, script_path=None, dir_name=None,
                 username=None):
        """Initialize a DockerImage instance

        Parameters
        ----------
        func : function
            Python function to be dockerized

        script_path : string
            Path to file with python script to be dockerized

        dir_name : string
            Directory to store Dockerfile, requirements.txt, and python
            script with CLI
            Default: parent directory of script if `script_path` is provided
                     else DockerImage creates a new directory, accessible by
                     the `build_path` property.

        username : string
            Default user created in the Dockerfile
            Default: 'cloudknot-user'
        """
        # User must specify at least `func` or `script_path`
        if not (func or script_path):
            raise ValueError('You must suppy either `func` or `script_path`.')

        # If both `func` and `script_path` are specified,
        # input is over-specified
        if script_path and func:
            raise ValueError('You provided `script_path` and other redundant '
                             'arguments, either `func` or `dir_name`. ')

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
            self._name = os.path.basename(self.script_path)

            # Set the parent directory
            if dir_name:
                self._build_path = os.path.abspath(dir_name)
            else:
                self._build_path = os.path.dirname(self.script_path)
        else:
            # We will create the script, Dockerfile, and requirements.txt
            # in a new directory
            self._clobber_script = True
            self._name = func.__name__

            if dir_name:
                self._build_path = os.path.abspath(dir_name)
                self._script_path = os.path.join(self.build_path,
                                                 self.name + '.py')

                # Confirm that we will not overwrite an existing script
                if os.path.isfile(self._script_path):
                    raise ValueError(
                        'There is a pre-existing python script in the '
                        'directory that you provided. Either specify a new '
                        'directory, move the python script `{file:s}` to a '
                        'new directory, or delete the existing python script '
                        'if it is no longer necessary.'.format(
                            file=self.script_path
                        )
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

        # Create the Dockerfile and requirements.txt in the parent directory
        self._docker_path = os.path.join(self.build_path, 'Dockerfile')
        self._req_path = os.path.join(self.build_path, 'requirements.txt')

        # Confirm that we won't overwrite an existing Dockerfile
        if os.path.isfile(self._docker_path):
            raise ValueError(
                'There is a pre-existing Dockerfile in the same directory as '
                'the python script you provided or in the directory name that '
                'you provided. Either specify a new directory, move the '
                'Dockerfile `{file:s}` to a new directory, or delete the '
                'existing Dockerfile if it is no longer necessary.'.format(
                    file=self.docker_path
                )
            )

        # Confirm that we won't overwrite an existing requirements.txt
        if os.path.isfile(self._req_path):
            raise ValueError(
                'There is a pre-existing requirements.txt in the same '
                'directory as the python script you provided or in the '
                'directory name that you provided. Either specify a new '
                'directory, move the requirements file`{file:s}` to its own '
                'directory or delete the existing requirements file if it '
                'is no longer needed.'.format(file=self.req_path)
            )

        # Get the names of packages imported in the script
        import_names = pipreqs.get_all_imports(os.path.dirname(
            self.script_path
        ))

        # Of those names, store that ones that are available via pip
        self._pip_imports = pipreqs.get_imports_info(import_names)

        if len(import_names) != len(self.pip_imports):
            # If some imports were left out, store their names
            pip_names = [i['name'] for i in self.pip_imports]
            self._missing_imports = list(set(import_names) - set(pip_names))

            # And warn the user
            mod_logger.warning(
                'Warning, some imports not found by pipreqs. You will need '
                'to edit the Dockerfile by hand, e.g by installing from '
                'github. You need to install the following packages '
                '{missing!s}'.format(missing=self.missing_imports)
            )
        else:
            # All imports accounted for
            self._missing_imports = None

        # Write the requirements.txt file and Dockerfile
        pipreqs.generate_requirements_file(self.req_path, self.pip_imports)
        self._write_dockerfile()

        self._images = []
        self._repo_uri = None

        # Add to config file
        config.add_resource('docker-images', self.name, self.build_path)

    # Declare read-only properties
    name = property(operator.attrgetter('_name'))
    func = property(operator.attrgetter('_func'))
    build_path = property(operator.attrgetter('_build_path'))
    script_path = property(operator.attrgetter('_script_path'))
    docker_path = property(operator.attrgetter('_docker_path'))
    req_path = property(operator.attrgetter('_req_path'))
    pip_imports = property(operator.attrgetter('_pip_imports'))
    username = property(operator.attrgetter('_username'))
    missing_imports = property(operator.attrgetter('_missing_imports'))
    images = property(operator.attrgetter('_images'))
    repo_uri = property(operator.attrgetter('_repo_uri'))

    def _write_script(self):
        """Write this instance's function to a script with a CLI.

        Use clize.run to create CLI

        Returns
        -------
        None
        """
        with open(self.script_path, 'w') as f:
            f.write('from clize import run\n\n\n')
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
        """Write Dockerfile to containerize this instance's python function

        Returns
        -------
        None
        """
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
            f.write('RUN pip install -r /tmp/requirements.txt\n\n')

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

    def build(self, tags, image_name=None):
        """Build a DockerContainer image

        Parameters
        ----------
        tags : str or sequence of str
            Tags to be applied to this Docker image

        image_name : str
            Name of Docker image to be built
            Default: 'cloudknot/' + self.name

        Returns
        -------
        None
        """
        # Validate tags input
        if isinstance(tags, str):
            tags = [tags]
        elif all(isinstance(x, str) for x in tags):
            tags = [t for t in tags]
        else:
            raise ValueError('tags must be a string or a sequence '
                             'of strings.')

        # Don't allow user to put "latest" in tags.
        if 'latest' in tags:
            raise ValueError('Any tag is allowed, except for "latest."')

        image_name = image_name if image_name else 'cloudknot/' + self.name

        images = [{'name': image_name, 'tag': t} for t in tags]
        self._images += images

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
                    login=login_cmd
                )
            )

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

    def push(self, repo=None, repo_uri=None):
        """Tag and push a DockerContainer image to a repository

        Returns
        -------
        None
        """
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

        if repo:
            if not isinstance(repo, aws.DockerRepo):
                raise ValueError('repo must be a DockerRepo instance.')
            self._repo_uri = repo.repo_uri
        else:
            if not isinstance(repo_uri, str):
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

    def clobber(self):
        """Delete all of the files associated with this instance

        Always delete the generated requirements.txt and Dockerfile. Only
        delete the script if it was auto-generated. Only delete the parent
        directory if it is empty.

        Also delete the local docker image

        Returns
        -------
        None
        """
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

        if self.images:
            # Use docker image client to remove local images
            cli = docker.from_env().images
            for im in self.images:
                # Remove the local docker image, using the latest image name
                cli.remove(
                    image=im['name'] + ':' + im['tag'],
                    force=True,
                    noprune=False
                )

        if self.repo_uri:
            for tag in set([d['tag'] for d in self.images]):
                cli.remove(
                    image=self.repo_uri + ':' + tag,
                    force=True,
                    noprune=False
                )

        # Remove from the config file
        config.remove_resource('docker-images', self.name)
