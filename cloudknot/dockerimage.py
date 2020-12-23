"""Create, build, push, and manage Docker images for use in Cloudknot."""
import configparser
import docker
import inspect
import json
import logging
import os
import re
import six
import subprocess
import tempfile
from pipreqs import pipreqs
from string import Template

from . import aws
from . import config as ckconfig
from .aws.base_classes import (
    get_region,
    get_profile,
    ResourceClobberedException,
    CloudknotInputError,
    CloudknotConfigurationError,
)
from .config import get_config_file, rlock

__all__ = ["DockerImage"]


mod_logger = logging.getLogger(__name__)
is_windows = os.name == "nt"


# noinspection PyPropertyAccess,PyAttributeOutsideInit
class DockerImage(aws.NamedObject):
    """Class for dockerizing a python script or function.

    If given a python function, DockerImage will create a CLI
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

    Parameters
    ----------
    name : str
        Name of DockerImage, only used to retrieve DockerImage from
        config file info. Do not use to create new DockerImage.
        Must satisfy regular expression pattern: [a-zA-Z][-a-zA-Z0-9]*

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

    base_image : string
        Docker base image on which to base this Dockerfile
        Default: None will use the python base image for the
        current version of python

    github_installs : string or sequence of strings
        Github addresses for packages to install from github rather than
        PyPI (e.g. git://github.com/nrdg/cloudknot.git or
        git://github.com/nrdg/cloudknot.git@newfeaturebranch)
        Default: ()

    username : string
        Default user created in the Dockerfile
        Default: 'cloudknot-user'

    overwrite : bool, default=False
        If True, allow overwriting any existing Dockerfiles,
        requirements files, or python scripts previously created by
        cloudknot

    """

    def __init__(
        self,
        name=None,
        func=None,
        script_path=None,
        dir_name=None,
        base_image=None,
        github_installs=(),
        username=None,
        overwrite=False,
    ):
        """
        Initialize a DockerImage instance.

        Parameters
        ----------
        name : str
            Name of DockerImage, only used to save/retrieve DockerImage from
            config file info.
            Must satisfy regular expression pattern: [a-zA-Z][-a-zA-Z0-9]*

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

        base_image : string
            Docker base image on which to base this Dockerfile
            Default: None will use the python base image for the
            current version of python

        github_installs : string or sequence of strings
            Github addresses for packages to install from github rather than
            PyPI (e.g. git://github.com/nrdg/cloudknot.git or
            git://github.com/nrdg/cloudknot.git@newfeaturebranch)
            Default: ()

        username : string
            Default user created in the Dockerfile
            Default: 'cloudknot-user'

        overwrite : bool, default=False
            If True, allow overwriting any existing Dockerfiles,
            requirements files, or python scripts previously created by
            cloudknot
        """
        # User must specify at least `name`, `func`, or `script_path`
        if not any([name, func, script_path]):
            raise CloudknotInputError(
                "You must suppy either `name`, `func` " "or `script_path`."
            )

        # If `func` and `script_path` are specified, input is over-specified
        if script_path and func:
            raise CloudknotInputError(
                "You provided redundant and possibly conflicting arguments "
                "`script_path` and `func`. Please provide only one of those."
            )

        # Default booleans to be potentially changed in if blocks below
        params_changed = False
        clobber_script = False

        if name:
            # Validate name input
            if not isinstance(name, six.string_types):
                raise CloudknotInputError(
                    "Docker image name must be a "
                    "string. You passed a {t!s}"
                    "".format(t=type(name))
                )

            super(DockerImage, self).__init__(name=name)

            section_name = "docker-image " + name

            config_file = get_config_file()
            config = configparser.ConfigParser()

            with rlock:
                config.read(config_file)

            if section_name not in config.sections():
                params_changed = True
            else:
                self._region = config.get(section_name, "region")
                self._profile = config.get(section_name, "profile")
                self.check_profile_and_region()

                self._func = None
                function_hash = hash(config.get(section_name, "function-hash"))
                self._build_path = config.get(section_name, "build-path")
                self._script_path = config.get(section_name, "script-path")
                self._docker_path = config.get(section_name, "docker-path")
                self._req_path = config.get(section_name, "req-path")
                self._base_image = config.get(section_name, "base-image")
                self._github_installs = config.get(
                    section_name, "github-imports"
                ).split()
                self._username = config.get(section_name, "username")
                self._clobber_script = config.getboolean(section_name, "clobber-script")

                images_str = config.get(section_name, "images")
                images_list = [s.split(":") for s in images_str.split()]
                self._images = [{"name": i[0], "tag": i[1]} for i in images_list]

                uri = config.get(section_name, "repo-uri")
                self._repo_uri = uri if uri else None

                if uri:
                    repo_info = aws.ecr._get_repo_info_from_uri(repo_uri=uri)
                    self._repo_registry_id = repo_info["registry_id"]
                    self._repo_name = repo_info["repo_name"]
                else:
                    self._repo_registry_id = None
                    self._repo_name = None

                # Set self.pip_imports and self.missing_imports
                self._set_imports()

                # Do not allow script_path or dir_name for pre-existing images
                if any([script_path, dir_name]):
                    raise CloudknotInputError(
                        "You specified a name plus either a script_path or "
                        "directory_name. The name parameter is used to retrieve a "
                        "pre-existing DockerImage instance. You may retrieve a "
                        "pre-existing and change the `func`, `username`, `base_image`, "
                        "and `github_installs` parameters, but not the `script_path` or "
                        "`dir_name`. Please either remove those parameters or create a new "
                        "DockerImage with a different name."
                    )

                # Check for consistency of remaining redundant input
                if any([func, username, base_image, github_installs]):
                    input_params = {
                        "func": (hash(func), function_hash),
                        "username": (username, self._username),
                        "base_image": (base_image, self._base_image),
                        "github_installs": (github_installs, self._github_installs),
                    }

                    conflicting_params = {
                        k: v for k, v in input_params.items() if v[0] and v[1] != v[0]
                    }

                    if conflicting_params:
                        # Set flag to do all the setup stuff below, warn user
                        params_changed = True
                        mod_logger.warning(
                            "Found {name:s} in your config file but the input parameters "
                            "have changed. The updated parameters are {l}. Continuing "
                            "with the new input parameters and disregarding any old, "
                            "potentially conflicting ones.".format(
                                name=section_name, l=list(conflicting_params.keys())
                            )
                        )

                        # Use input params if provided, fall back on config values
                        username = username if username else self._username
                        base_image = base_image if base_image else self._base_image
                        github_installs = (
                            github_installs
                            if github_installs
                            else self._github_installs
                        )
                        func = func if func else self._func
                        script_path = self._script_path
                        dir_name = self._build_path
                        clobber_script = self._clobber_script

        if not name or params_changed:
            self._func = func
            self._username = username if username else "cloudknot-user"

            if base_image is not None:
                self._base_image = base_image
            else:
                py_ver = "3" if six.PY3 else "2"
                self._base_image = "python:" + py_ver

            if self._base_image in ["python:3", "python:3.8"]:
                mod_logger.warning(
                    "Warning, your Dockerfile will have a base image of python:3, "
                    "which may default to Python 3.8. This may cause dependency "
                    "conflicts. If this build fails, consider rerunning with the "
                    "`base_image='python:3.7' parameter."
                )

            # Validate dir_name input
            if dir_name and not os.path.isdir(dir_name):
                raise CloudknotInputError("`dir_name` is not an existing " "directory")

            if script_path:
                # User supplied a pre-existing python script.
                # Ensure we don't clobber it later
                self._clobber_script = False or clobber_script

                # Check that it is a valid path
                if not os.path.isfile(script_path):
                    raise CloudknotInputError(
                        "If provided, `script_path` must be an existing "
                        "regular file."
                    )

                self._script_path = os.path.abspath(script_path)
                super(DockerImage, self).__init__(
                    name=name
                    if name
                    else os.path.splitext(os.path.basename(self.script_path))[0]
                    .replace("_", "-")
                    .replace(".", "-")
                )

                # Set the parent directory
                if dir_name:
                    self._build_path = os.path.abspath(dir_name)
                else:
                    self._build_path = os.path.dirname(self.script_path)

                if self._func is not None:
                    self._write_script()
            else:
                # We will create the script, Dockerfile, and requirements.txt
                # in a new directory
                self._clobber_script = True
                super(DockerImage, self).__init__(
                    name=name if name else func.__name__.replace("_", "-")
                )

                if dir_name:
                    self._build_path = os.path.abspath(dir_name)
                    self._script_path = os.path.join(self.build_path, self.name + ".py")

                    # Confirm that we will not overwrite an existing script
                    if not overwrite and os.path.isfile(self._script_path):
                        raise CloudknotInputError(
                            "There is a pre-existing python script in the "
                            "directory that you provided. Either specify a "
                            "new directory, move the python script `{file:s}` "
                            "to a new directory, or delete the existing "
                            "python script if it is no longer "
                            "necessary.".format(file=self.script_path)
                        )
                else:
                    # Create a new unique directory name
                    prefix = "cloudknot_docker_" + self.name + "_"
                    self._build_path = tempfile.mkdtemp(prefix=prefix, dir=os.getcwd())

                    # Store the script in the new directory
                    self._script_path = os.path.join(self.build_path, self.name + ".py")

                self._write_script()

            # Create the Dockerfile and requirements.txt in the parent dir
            self._docker_path = os.path.join(self.build_path, "Dockerfile")
            self._req_path = os.path.join(self.build_path, "requirements.txt")

            # Confirm that we won't overwrite an existing Dockerfile
            if not overwrite and os.path.isfile(self._docker_path):
                raise CloudknotInputError(
                    "There is a pre-existing Dockerfile in the same directory "
                    "as the python script you provided or in the directory "
                    "name that you provided. Either specify a new directory, "
                    "move the Dockerfile `{file:s}` to a new directory, or "
                    "delete the existing Dockerfile if it is no longer "
                    "necessary.".format(file=self.docker_path)
                )

            # Confirm that we won't overwrite an existing requirements.txt
            if not overwrite and os.path.isfile(self._req_path):
                raise CloudknotInputError(
                    "There is a pre-existing requirements.txt in the same "
                    "directory as the python script you provided or in the "
                    "directory name that you provided. Either specify a new "
                    "directory, move the requirements file`{file:s}` to its "
                    "own directory or delete the existing requirements file "
                    "if it is no longer needed.".format(file=self.req_path)
                )

            # Validate github installs before building Dockerfile
            if isinstance(github_installs, six.string_types):
                self._github_installs = [github_installs]
            elif all(isinstance(x, six.string_types) for x in github_installs):
                self._github_installs = list(github_installs)
            else:
                raise CloudknotInputError(
                    "github_installs must be a string " "or a sequence of strings."
                )

            pattern = r"(https|git)(://github.com/).*/.*\.git($|@.*$|#egg=.*$)"
            for install in self._github_installs:
                match_obj = re.match(pattern, install)
                if match_obj is None:
                    raise CloudknotInputError(
                        "One of your github_installs, {i:s} is not formatted "
                        "correctly. It should look something like "
                        "git://github.com/user/repo.git, "
                        "git://github.com/user/repo.git@branch, "
                        "git://github.com/user/repo.git#egg=project[extra], "
                        "https://github.com/user/repo.git, "
                        "https://github.com/user/repo.git@branch, or"
                        "https://github.com/user/repo.git#egg=project[extra]. "
                        "See https://pip.pypa.io/en/stable/reference/pip_install/#git "
                        "for more info."
                    )

            # Set self.pip_imports and self.missing_imports
            self._set_imports()

            # Write the requirements.txt file and Dockerfile
            pipreqs.generate_requirements_file(self.req_path, self.pip_imports)

            self._write_dockerfile()

            self._images = []
            self._repo_uri = None
            self._repo_registry_id = None
            self._repo_name = None

            # Add to config file
            section_name = "docker-image " + self.name
            ckconfig.add_resource(section_name, "profile", self.profile)
            ckconfig.add_resource(section_name, "region", self.region)
            ckconfig.add_resource(section_name, "function-hash", str(hash(self._func)))
            ckconfig.add_resource(section_name, "build-path", self.build_path)
            ckconfig.add_resource(section_name, "script-path", self.script_path)
            ckconfig.add_resource(section_name, "docker-path", self.docker_path)
            ckconfig.add_resource(section_name, "req-path", self.req_path)
            ckconfig.add_resource(section_name, "base-image", self.base_image)
            ckconfig.add_resource(
                section_name, "github-imports", " ".join(self.github_installs)
            )
            ckconfig.add_resource(section_name, "username", self.username)
            ckconfig.add_resource(section_name, "images", "")
            ckconfig.add_resource(section_name, "repo-uri", "")
            ckconfig.add_resource(
                section_name, "clobber-script", str(self._clobber_script)
            )

    # Declare read-only properties
    @property
    def func(self):
        """Python function that was dockerized."""
        return self._func

    @property
    def build_path(self):
        """Return build path for the docker image."""
        return self._build_path

    @property
    def script_path(self):
        """Path to the CLI version of the python function."""
        return self._script_path

    @property
    def docker_path(self):
        """Path to the generated Dockerfile."""
        return self._docker_path

    @property
    def req_path(self):
        """Path to the generated requirements.txt file."""
        return self._req_path

    @property
    def pip_imports(self):
        """List of packages in the requirements.txt file."""
        return self._pip_imports

    @property
    def base_image(self):
        """Docker base image on which to base the docker image."""
        return self._base_image

    @property
    def github_installs(self):
        """List packages installed from github rather than PyPI."""
        return self._github_installs

    @property
    def username(self):
        """Return default username created in Dockerfile."""
        return self._username

    @property
    def missing_imports(self):
        """List required imports that are unavailable through pip install.

        The user must edit the Dockerfile by hand to install these packages
        before using the build or push methods.
        """
        return self._missing_imports

    @property
    def images(self):
        """List name, tag dicts for docker images built by this instance."""
        return self._images

    @property
    def repo_uri(self):
        """Location of remote repository to which the image was pushed."""
        return self._repo_uri

    @property
    def repo_registry_id(self):
        """Registry ID of remote repository to which the image was pushed."""
        return self._repo_registry_id

    @property
    def repo_name(self):
        """Name of remote repository to which the image was pushed."""
        return self._repo_name

    def _write_script(self):
        """Write this instance's function to a script with a CLI.

        Use the template file to insert the self.func source code and name
        """
        with open(self.script_path, "w") as f:
            template_path = os.path.abspath(
                os.path.join(os.path.dirname(__file__), "templates", "script.template")
            )

            with open(template_path, "r") as template:
                s = Template(template.read())
                f.write(
                    s.substitute(
                        func_source=inspect.getsource(self.func),
                        func_name=self.func.__name__,
                    )
                )

        mod_logger.info(
            "Wrote python function {func:s} to script {script:s}".format(
                func=self.name, script=self.script_path
            )
        )

    def _write_dockerfile(self):
        """Write Dockerfile to containerize this instance's python function."""
        with open(self.docker_path, "w") as f:
            template_path = os.path.abspath(
                os.path.join(
                    os.path.dirname(__file__), "templates", "Dockerfile.template"
                )
            )

            if self.github_installs:
                github_installs_string = "".join(
                    [
                        " \\\n    && pip install --no-cache-dir git+" + install
                        for install in self.github_installs
                    ]
                )
            else:
                github_installs_string = ""

            with open(template_path, "r") as template:
                s = Template(template.read())
                f.write(
                    s.substitute(
                        app_name=self.name,
                        username=self.username,
                        base_image=self.base_image,
                        script_base_name=os.path.basename(self.script_path),
                        github_installs_string=github_installs_string,
                    )
                )

        mod_logger.info("Wrote Dockerfile {path:s}".format(path=self.docker_path))

    def _set_imports(self):
        """Set required imports for the python script at self.script_path."""
        # Get the names of packages imported in the script
        import_names = pipreqs.get_all_imports(os.path.dirname(self.script_path))

        # Of those names, store that ones that are available via pip
        self._pip_imports = pipreqs.get_imports_info(import_names)

        # If some imports were left out, store their names
        pip_names = set([i["name"] for i in self.pip_imports])
        self._missing_imports = list(set(import_names) - pip_names)

        if len(import_names) != (len(self.pip_imports) + len(self.github_installs)):
            # And warn the user
            mod_logger.warning(
                "Warning, some imports not found by pipreqs. You will "
                "need to edit the Dockerfile by hand, e.g by installing "
                "from github. You need to install the following packages "
                "{missing!s}".format(missing=self.missing_imports)
            )

    def build(self, tags, image_name=None):
        """Build a Docker image.

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
                "This docker image has already been clobbered.", self.name
            )

        # Validate tags input
        if isinstance(tags, six.string_types):
            tags = [tags]
        elif all(isinstance(x, six.string_types) for x in tags):
            tags = [t for t in tags]
        else:
            raise CloudknotInputError(
                "tags must be a string or a sequence " "of strings."
            )

        # Don't allow user to put "latest" in tags.
        if "latest" in tags:
            raise CloudknotInputError("Any tag is allowed, except for " '"latest."')

        image_name = image_name if image_name else "cloudknot/" + self.name

        images = [{"name": image_name, "tag": t} for t in tags]
        self._images += [im for im in images if im not in self.images]

        # Use docker low-level APIClient
        c = docker.from_env()
        for im in images:
            mod_logger.info(
                "Building image {name:s} with tag {tag:s}".format(
                    name=im["name"], tag=im["tag"]
                )
            )

            c.images.build(
                path=self.build_path,
                dockerfile=self.docker_path,
                tag=im["name"] + ":" + im["tag"],
            )

        # Update the config file images list
        config_file = get_config_file()
        config = configparser.ConfigParser()
        with rlock:
            config.read(config_file)

        # Get list of images in config file
        section_name = "docker-image " + self.name
        config_images_str = config.get(section_name, "images")

        # Split config images into list
        config_images_list = config_images_str.split()

        # Convert images just build into list
        current_images_list = [i["name"] + ":" + i["tag"] for i in images]

        # Get the union of the two lists
        config_images = list(set(config_images_list) | set(current_images_list))

        # Convert back to space separated list string
        config_images_str = " ".join(config_images)

        # Reload to config file
        ckconfig.add_resource(section_name, "images", config_images_str)

    def push(self, repo=None, repo_uri=None):
        """Tag and push a Docker image to a repository.

        Parameters
        ----------
        repo : DockerRepo, optional
            DockerRepo instance to which to push this image

        repo_uri : string, optional
            URI for the docker repository to which to push this instance

        """
        if self.clobbered:
            raise ResourceClobberedException(
                "This docker image has already been clobbered.", self.name
            )

        # User must supply either a repo object or the repo name and uri
        if not (repo or repo_uri):
            raise CloudknotInputError(
                "You must supply either `repo=" "<DockerRepo instance>` or `repo_uri`."
            )

        # User cannot supply both repo and repo_name or repo_uri
        if repo and repo_uri:
            raise CloudknotInputError(
                "You may not specify both a repo object " "and `repo_uri`."
            )

        # Make sure that the user has called build first or somehow set tags.
        if not self.images:
            raise CloudknotInputError(
                "The images property is empty, indicating that the build "
                "method has not yet been called. Call `build(tags=<tags>)` "
                "first before calling `tag()`."
            )

        if repo:
            if not isinstance(repo, aws.DockerRepo):
                raise CloudknotInputError("repo must be of type DockerRepo.")
            self._repo_uri = repo.repo_uri
            self._repo_registry_id = repo.repo_registry_id
            self._repo_name = repo.name
        else:
            if not isinstance(repo_uri, six.string_types):
                raise CloudknotInputError("`repo_uri` must be a string.")
            self._repo_uri = repo_uri
            repo_info = aws.ecr._get_repo_info_from_uri(repo_uri=repo_uri)
            self._repo_registry_id = repo_info["registry_id"]
            self._repo_name = repo_info["repo_name"]

        fallback = "from_env"
        if get_profile(fallback=fallback) != fallback:
            cmd = [
                "aws",
                "ecr",
                "get-login",
                "--no-include-email",
                "--region",
                get_region(),
                "--profile",
                get_profile(),
            ]
        else:
            cmd = [
                "aws",
                "ecr",
                "get-login",
                "--no-include-email",
                "--region",
                get_region(),
            ]

        # Determine if we're running in moto for CI
        # by retrieving the account ID
        user = aws.clients["iam"].get_user()["User"]
        account_id = user["Arn"].split(":")[4]
        if account_id == "123456789012":
            # Then we are mocking using moto. Use the ecr.put_image()
            # function instead of the Docker CLI to tag, push, etc.
            # This is the manifest for one of the hello-world versions
            manifest = {
                "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
                "size": 525,
                "digest": "sha256:90659bf80b44ce6be8234e6ff90a1ac34acbeb826903b02cfa0da11c82cbc042",
                "platform": {"architecture": "amd64", "os": "linux"},
            }
            for im in self.images:
                # Log tagging info
                mod_logger.info(
                    "Tagging image {name:s} with tag {tag:s}".format(
                        name=im["name"], tag=im["tag"]
                    )
                )
                # Log push info
                mod_logger.info(
                    "Pushing image {name:s} with tag {tag:s}".format(
                        name=im["name"], tag=im["tag"]
                    )
                )
                aws.clients["ecr"].put_image(
                    registryId=self._repo_registry_id,
                    repositoryName=self._repo_name,
                    imageManifest=json.dumps(manifest),
                    imageTag=im["tag"],
                )
        else:
            # Then we're actually doing this thing. Use the Docker CLI
            # Refresh the aws ecr login credentials
            login_cmd = subprocess.check_output(cmd, shell=is_windows)

            # Login
            login_cmd_list = (
                login_cmd.decode("ASCII").rstrip("\n").rstrip("\r").split(" ")
            )
            login_result = subprocess.run(
                login_cmd_list, stdout=subprocess.PIPE, stderr=subprocess.PIPE
            )

            # If login failed, pass error to user
            if login_result.returncode:  # pragma: nocover
                raise CloudknotConfigurationError(
                    "Unable to login to AWS ECR using the command:\n"
                    "\t{login:s}\nReturned exit code = {code}\n"
                    "STDOUT: {out:s}\nSTDERR: {err:s}\n".format(
                        login=login_cmd.decode(),
                        code=login_result.returncode,
                        out=login_result.stdout.decode(),
                        err=login_result.stderr.decode(),
                    )
                )

            # Use docker low-level APIClient for tagging
            c = docker.from_env().api
            # And the image client for pushing
            cli = docker.from_env().images
            for im in self.images:
                # Log tagging info
                mod_logger.info(
                    "Tagging image {name:s} with tag {tag:s}".format(
                        name=im["name"], tag=im["tag"]
                    )
                )

                # Tag it with the most recently added image_name
                c.tag(
                    image=im["name"] + ":" + im["tag"],
                    repository=self.repo_uri,
                    tag=im["tag"],
                )

                # Log push info
                mod_logger.info(
                    "Pushing image {name:s} with tag {tag:s}".format(
                        name=im["name"], tag=im["tag"]
                    )
                )

                for line in cli.push(
                    repository=self.repo_uri, tag=im["tag"], stream=True
                ):
                    mod_logger.debug(line)

            self._repo_uri = self._repo_uri + ":" + self.images[-1]["tag"]

            section_name = "docker-image " + self.name
            ckconfig.add_resource(section_name, "repo-uri", self.repo_uri)

    def clobber(self):
        """Delete all of the files associated with this instance.

        Always delete the generated requirements.txt and Dockerfile. Only
        delete the script if it was auto-generated. Only delete the parent
        directory if it is empty. Also delete the local docker image.
        """
        if self.clobbered:
            return

        if self._clobber_script:
            os.remove(self.script_path)
            mod_logger.info("Removed {path:s}".format(path=self.script_path))

        os.remove(self.docker_path)
        mod_logger.info("Removed {path:s}".format(path=self.docker_path))
        os.remove(self.req_path)
        mod_logger.info("Removed {path:s}".format(path=self.req_path))

        try:
            os.rmdir(self.build_path)
            mod_logger.info("Removed {path:s}".format(path=self.build_path))
        except OSError:
            # Directory is not empty. There's pre-existing stuff in there
            # that we shouldn't mess with.
            pass

        cli = docker.from_env().images
        # Get local images first (lol stands for list_of_lists)
        local_image_lol = [im.tags for im in cli.list()]
        # Flatten the list of lists
        local_images = [im for sublist in local_image_lol for im in sublist]

        # Use docker image client to remove local images
        for im in self.images:
            if im["name"] + ":" + im["tag"] in local_images:
                # Remove the local docker image, using the image name
                cli.remove(
                    image=im["name"] + ":" + im["tag"], force=True, noprune=False
                )
                # Update local_images to prevent redundant image removal
                local_image_lol = [im.tags for im in cli.list()]
                local_images = [im for sublist in local_image_lol for im in sublist]

        if self.repo_uri:
            # Determine if we're running in moto for CI
            # by retrieving the account ID
            user = aws.clients["iam"].get_user()["User"]
            account_id = user["Arn"].split(":")[4]
            if account_id != "123456789012":
                # Then we're actually doing this thing. Use the Docker CLI
                cli.remove(image=self.repo_uri, force=True, noprune=False)

        # Remove from the config file
        config_file = get_config_file()
        config = configparser.ConfigParser()

        with rlock:
            config.read(config_file)
            config.remove_section("docker-image " + self.name)
            with open(config_file, "w") as f:
                config.write(f)

        self._clobbered = True

        mod_logger.info(
            "Removed local docker images " "{images!s}".format(images=self.images)
        )
