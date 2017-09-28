from __future__ import absolute_import, division, print_function

import ast
import inspect
import logging
import operator
import os
from pipreqs import pipreqs
import six
import tempfile
from collections import namedtuple

from . import aws
from . import config
from .config import CONFIG
from .due import due, Doi

__all__ = ["CloudKnot", "DockerReqs", "Pars", "Jars"]

# Use duecredit (duecredit.org) to provide a citation to relevant work to
# be cited. This does nothing, unless the user has duecredit installed,
# And calls this with duecredit (as in `python -m duecredit script.py`):
due.cite(Doi(""),
         description="",
         tags=[""],
         path='cloudknot')


# noinspection PyPropertyAccess,PyAttributeOutsideInit
class DockerReqs(object):
    def __init__(
            self, func=None, script_path=None, dir_name=None, username=None
    ):
        if not (func or script_path):
            raise ValueError('You must suppy either `func` or `script_path`.')

        if script_path and any([func, dir_name]):
            raise ValueError('You provided `script_path` and other redundant '
                             'arguments, either `func` or `dir_name`. ')

        self._func = func
        if func:
            self._name = func.__name__
        else:
            self._name = None

        self._username = username if username else 'cloudknot-user'

        if script_path:
            # User supplied a pre-existing python script.
            # Check that it is a valid path
            if not os.path.isfile(script_path):
                raise ValueError('If provided, `script_path` must be an '
                                 'existing regular file.')
            self._script_path = os.path.abspath(script_path)

            # Set the parent directory
            self._dir_path = os.path.dirname(self.script_path)
        else:
            # We will create the script, Dockerfile, and requirements.txt
            # in a new directory
            if dir_name:
                self._dir_path = os.path.join(os.getcwd(), dir_name)
                self._script_path = os.path.join(self.dir_path,
                                                 self.name + '.py')

                # Confirm that we will not overwrite an existing Dockerfile
                # or requirements.txt
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
                self._dir_path = tempfile.mkdtemp(prefix=prefix,
                                                  dir=os.getcwd())

                self._script_path = os.path.join(self.dir_path,
                                                 self.name + '.py')

            self.write_script()

        # Create the Dockerfile and requirements.txt in the same directory
        self._docker_path = os.path.join(self.dir_path, 'Dockerfile')
        self._req_path = os.path.join(self.dir_path, 'requirements.txt')

        # Confirm that we won't overwrite an existing Dockerfile or
        # requirements.txt
        if os.path.isfile(self._docker_path):
            raise ValueError(
                'There is a pre-existing Dockerfile in the same directory as '
                'the python script you provided or in the directory name that '
                'you provided. Either specify a new directory, move the '
                'python script `{file:s}` to a new directory, or delete the '
                'existing Dockerfile if it is no longer necessary.'.format(
                    file=self.script_path
                )
            )

        if os.path.isfile(self._req_path):
            raise ValueError(
                'There is a pre-existing requirements.txt in the same '
                'directory as the python script you provided or in the '
                'directory name that you provided. Either specify a new '
                'directory, move the python script `{file:s}` to its own '
                'directory or delete the existing requirements.txt file if it '
                'is no longer needed.'.format(file=self.script_path)
            )

        import_names = [
            i.module[0] if i.module else i.name[0] for i in self.get_imports()
        ]
        self._pip_imports = pipreqs.get_imports_info(import_names)

        if len(import_names) != len(self.pip_imports):
            pip_names = [i['name'] for i in self.pip_imports]
            self._missing_imports = list(set(import_names) - set(pip_names))
            logging.warning(
                'Warning, some imports not found by pipreqs. You will need '
                'to edit the Dockerfile by hand, e.g by installing from '
                'github. You need to install the following packages '
                '{missing:s}'.format(missing=str(self.missing_imports))
            )
        else:
            self._missing_imports = None

        pipreqs.generate_requirements_file(self.req_path, self.pip_imports)
        self.write_dockerfile()

    name = property(operator.attrgetter('_name'))
    func = property(operator.attrgetter('_func'))
    dir_path = property(operator.attrgetter('_dir_path'))
    script_path = property(operator.attrgetter('_script_path'))
    docker_path = property(operator.attrgetter('_docker_path'))
    req_path = property(operator.attrgetter('_req_path'))
    pip_imports = property(operator.attrgetter('_pip_imports'))
    username = property(operator.attrgetter('_username'))
    missing_imports = property(operator.attrgetter('_missing_imports'))

    def write_script(self):
        with open(self.script_path, 'w') as f:
            f.write('from clize import run\n\n\n')
            f.write(inspect.getsource(self.func))
            f.write('\n\n')
            f.write('if __name__ == "__main__":\n')
            f.write('    run({func_name:s})\n'.format(func_name=self.name))

    def get_imports(self):
        Import = namedtuple("Import", ["module", "name", "alias"])

        with open(self.script_path) as fh:
            root = ast.parse(fh.read(), self.script_path)

        for node in ast.walk(root):
            if isinstance(node, ast.Import):
                module = []
            elif isinstance(node, ast.ImportFrom):
                module = node.module.split('.')
            else:
                continue

            for n in node.names:
                yield Import(module, n.name.split('.'), n.asname)

    def write_dockerfile(self):
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
            f.write('RUN pip install --requirements /tmp/requirements.txt\n\n')

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
            f.write('ENTRYPOINT ["python", "{py_script:s}"]'.format(
                py_script=home_dir + '/' + os.path.basename(self.script_path)
            ))


# noinspection PyPropertyAccess,PyAttributeOutsideInit
class CloudKnot(object):
    def __init__(self, func, source_file):
        if not (func or source_file):
            raise ValueError('you must supply either a user-defined function '
                             'or a source file')
        self.function = func
        self.source_file = source_file

    function = property(operator.attrgetter('_function'))

    @function.setter
    def function(self, f):
        if f:
            if not inspect.isfunction(f):
                raise ValueError('if provided, function must be a '
                                 'user-defined function')
            self._function = f
        else:
            self._function = None

    source_file = property(operator.attrgetter('_source_file'))

    @source_file.setter
    def source_file(self, fileobj):
        if fileobj:
            self._source_file = fileobj
        else:
            self._source_file = None


class Pars(object):
    def __init__(self, name='default', batch_service_role_name=None,
                 ecs_instance_role_name=None, spot_fleet_role_name=None,
                 vpc_id=None, vpc_name=None,
                 security_group_id=None, security_group_name=None):
        if not isinstance(name, str):
            raise ValueError('name must be a string')

        self._name = name

        CONFIG.read(config.get_config_file())

        if vpc_name:
            if not isinstance(vpc_name, str):
                raise ValueError('if provided, vpc_name must be a string.')
        else:
            vpc_name = name + '-cloudknot-vpc'

        if security_group_name:
            if not isinstance(security_group_name, str):
                raise ValueError('if provided, security_group_name must be '
                                 'a string.')
        else:
            security_group_name = name + '-cloudknot-security-group'

        # Check for existence of this pars
        self._pars_name = 'pars ' + name
        if self._pars_name in CONFIG.sections():
            # Pars exists, check that user did not provide any resource names
            if any([batch_service_role_name, ecs_instance_role_name,
                    spot_fleet_role_name, vpc_id, security_group_id]):
                raise ValueError('You provided resources for a pars that '
                                 'already exists in configuration file '
                                 '{fn:s}.'.format(fn=config.get_config_file()))

            # Use pars values to instantiate new resources
            try:
                self._batch_service_role = aws.iam.IamRole(
                    name=CONFIG.get(self._pars_name, 'batch-service-role')
                )
            except aws.ResourceDoesNotExistException:
                self._batch_service_role = aws.iam.IamRole(
                    name=CONFIG.get(self._pars_name, 'batch-service-role'),
                    description='This AWS batch service role was '
                                'automatically generated by cloudknot.',
                    service='batch',
                    policies=('AWSBatchServiceRole',),
                    add_instance_profile=False
                )

            try:
                self._ecs_instance_role = aws.iam.IamRole(
                    name=CONFIG.get(self._pars_name, 'ecs-instance-role')
                )
            except aws.ResourceDoesNotExistException:
                self._ecs_instance_role = aws.iam.IamRole(
                    name=CONFIG.get(self._pars_name, 'ecs-instance-role'),
                    description='This AWS ECS instance role was automatically '
                                'generated by cloudknot.',
                    service='ec2',
                    policies=('AmazonEC2ContainerServiceforEC2Role',),
                    add_instance_profile=True
                )

            try:
                self._spot_fleet_role = aws.iam.IamRole(
                    name=CONFIG.get(self._pars_name, 'spot-fleet-role')
                )
            except aws.ResourceDoesNotExistException:
                self._spot_fleet_role = aws.iam.IamRole(
                    name=CONFIG.get(self._pars_name, 'spot-fleet-role'),
                    description='This AWS spot fleet role was automatically '
                                'generated by cloudknot.',
                    service='spotfleet',
                    policies=('AmazonEC2SpotFleetRole',),
                    add_instance_profile=False
                )

            try:
                self._vpc = aws.ec2.Vpc(
                    vpc_id=CONFIG.get(self._pars_name, 'vpc')
                )
            except aws.ResourceDoesNotExistException:
                self._vpc = aws.ec2.Vpc(name=vpc_name)
                CONFIG.set(self._pars_name, 'vpc', self._vpc.vpc_id)

            try:
                self._security_group = aws.ec2.SecurityGroup(
                    security_group_id=CONFIG.get(
                        self._pars_name, 'security-group'
                    )
                )
            except aws.ResourceDoesNotExistException:
                self._security_group = aws.ec2.SecurityGroup(
                    name=security_group_name,
                    vpc=self._vpc
                )
                CONFIG.set(
                    self._pars_name,
                    'security-group', self._security_group.security_group_id
                )

            # Save config to file
            with open(config.get_config_file(), 'w') as f:
                CONFIG.write(f)
        else:
            # Pars doesn't exist, create it
            if batch_service_role_name:
                if not isinstance(batch_service_role_name, str):
                    raise ValueError('if provided, batch_service_role_name '
                                     'must be a string.')
            else:
                batch_service_role_name = (
                    name + '-cloudknot-batch-service-role'
                )

            try:
                self._batch_service_role = aws.iam.IamRole(
                    name=batch_service_role_name,
                    description='This AWS batch service role was '
                                'automatically generated by cloudknot.',
                    service='batch',
                    policies=('AWSBatchServiceRole',),
                    add_instance_profile=False
                )
            except aws.ResourceExistsException as e:
                self._batch_service_role = aws.iam.IamRole(
                    name=e.resource_id
                )

            if ecs_instance_role_name:
                if not isinstance(ecs_instance_role_name, str):
                    raise ValueError('if provided, ecs_instance_role_name '
                                     'must be a string.')
            else:
                ecs_instance_role_name = name + '-cloudknot-ecs-instance-role'

            try:
                self._ecs_instance_role = aws.iam.IamRole(
                    name=ecs_instance_role_name,
                    description='This AWS ECS instance role was automatically '
                                'generated by cloudknot.',
                    service='ec2',
                    policies=('AmazonEC2ContainerServiceforEC2Role',),
                    add_instance_profile=True
                )
            except aws.ResourceExistsException as e:
                self._ecs_instance_role = aws.iam.IamRole(
                    name=e.resource_id
                )

            if spot_fleet_role_name:
                if not isinstance(spot_fleet_role_name, str):
                    raise ValueError('if provided, spot_fleet_role_name must '
                                     'be a string.')
            else:
                spot_fleet_role_name = name + '-cloudknot-spot-fleet-role'

            try:
                self._spot_fleet_role = aws.iam.IamRole(
                    name=spot_fleet_role_name,
                    description='This AWS spot fleet role was automatically '
                                'generated by cloudknot.',
                    service='spotfleet',
                    policies=('AmazonEC2SpotFleetRole',),
                    add_instance_profile=False
                )
            except aws.ResourceExistsException as e:
                self._spot_fleet_role = aws.iam.IamRole(
                    name=e.resource_id
                )

            if vpc_id:
                if not isinstance(vpc_id, str):
                    raise ValueError('if provided, vpc_id must be a string')
                self._vpc = aws.ec2.Vpc(vpc_id=vpc_id)
            else:
                try:
                    self._vpc = aws.ec2.Vpc(name=vpc_name)
                except aws.ResourceExistsException as e:
                    self._vpc = aws.ec2.Vpc(vpc_id=e.resource_id)

            if security_group_id:
                if not isinstance(security_group_id, str):
                    raise ValueError('if provided, security_group_id must '
                                     'be a string')
                self._security_group = aws.ec2.SecurityGroup(
                    security_group_id=security_group_id
                )
            else:
                try:
                    self._security_group = aws.ec2.SecurityGroup(
                        name=security_group_name,
                        vpc=self.vpc
                    )
                except aws.ResourceExistsException as e:
                    self._security_group = aws.ec2.SecurityGroup(
                        security_group_id=e.resource_id
                    )

            # Save the new pars resources in config object
            # Use CONFIG.set() for python 2.7 compatibility
            CONFIG.add_section(self._pars_name)
            CONFIG.set(
                self._pars_name,
                'batch-service-role', self._batch_service_role.name
            )
            CONFIG.set(
                self._pars_name,
                'ecs-instance-role', self._ecs_instance_role.name
            )
            CONFIG.set(
                self._pars_name,
                'spot-fleet-role', self._spot_fleet_role.name
            )
            CONFIG.set(
                self._pars_name,
                'vpc', self._vpc.vpc_id
            )
            CONFIG.set(
                self._pars_name,
                'security-group', self._security_group.security_group_id
            )

            # Save config to file
            with open(config.get_config_file(), 'w') as f:
                CONFIG.write(f)

    name = property(fget=operator.attrgetter('_name'))

    @name.setter
    def name(self, n):
        if not isinstance(n, str):
            raise ValueError('name must be a string')

        # Read current config file
        CONFIG.read(config.get_config_file())

        # Retrieve items and remove old section
        items = CONFIG.items(self._pars_name)
        CONFIG.remove_section(self._pars_name)

        # Save values under new section name
        self._name = n
        self._pars_name = 'pars ' + n
        CONFIG.add_section(self._pars_name)
        for option, value in items:
            CONFIG.set(self._pars_name, option, value)

        # Rewrite config file
        with open(config.get_config_file(), 'w') as f:
            CONFIG.write(f)

    @staticmethod
    def _role_setter(attr):
        def set_role(self, new_role):
            # Verify input
            if not isinstance(new_role, aws.iam.IamRole):
                raise ValueError('new role must be an instance of IamRole')

            old_role = getattr(self, attr)

            logging.warning(
                'You are setting a new role for PARS {name:s}. The old '
                'role {role_name:s} will be clobbered.'.format(
                    name=self.name, role_name=old_role.name
                )
            )

            # Delete the old role
            old_role.clobber()

            # Set the new role attribute
            setattr(self, attr, new_role)

            # Replace the appropriate line in the config file
            CONFIG.read(config.get_config_file())
            field_name = attr.lstrip('_').replace('_', ' ')
            CONFIG.set(self._pars_name, field_name, new_role.name)
            with open(config.get_config_file(), 'w') as f:
                CONFIG.write(f)

        return set_role

    batch_service_role = property(
        fget=operator.attrgetter('_batch_service_role'),
        fset=_role_setter.__func__('_batch_service_role')
    )
    ecs_instance_role = property(
        fget=operator.attrgetter('_ecs_instance_role'),
        fset=_role_setter.__func__('_ecs_instance_role')
    )
    spot_fleet_role = property(
        fget=operator.attrgetter('_spot_fleet_role'),
        fset=_role_setter.__func__('_spot_fleet_role')
    )

    vpc = property(operator.attrgetter('_vpc'))

    @vpc.setter
    def vpc(self, v):
        if not isinstance(v, aws.ec2.Vpc):
            raise ValueError('new vpc must be an instance of Vpc')

        logging.warning(
            'You are setting a new VPC for PARS {name:s}. The old '
            'VPC {vpc_id:s} will be clobbered.'.format(
                name=self.name, vpc_id=self.vpc.vpc_id
            )
        )

        old_vpc = self._vpc
        old_vpc.clobber()
        self._vpc = v

        # Replace the appropriate line in the config file
        CONFIG.read(config.get_config_file())
        CONFIG.set(self._pars_name, 'vpc', v.vpc_id)
        with open(config.get_config_file(), 'w') as f:
            CONFIG.write(f)

    security_group = property(operator.attrgetter('_security_group'))

    @security_group.setter
    def security_group(self, sg):
        if not isinstance(sg, aws.ec2.SecurityGroup):
            raise ValueError('new security group must be an instance of '
                             'SecurityGroup')

        logging.warning(
            'You are setting a new security group for PARS {name:s}. The old '
            'security group {sg_id:s} will be clobbered.'.format(
                name=self.name, sg_id=self.security_group.security_group_id
            )
        )
        old_sg = self._security_group
        old_sg.clobber()
        self._security_group = sg

        # Replace the appropriate line in the config file
        CONFIG.read(config.get_config_file())
        CONFIG.set(self._pars_name, 'security-group', sg.security_group_id)
        with open(config.get_config_file(), 'w') as f:
            CONFIG.write(f)

    def clobber(self):
        # Delete all associated AWS resources
        self._security_group.clobber()
        self._vpc.clobber()
        self._spot_fleet_role.clobber()
        self._ecs_instance_role.clobber()
        self._batch_service_role.clobber()

        # Remove this section from the config file
        CONFIG.read(config.get_config_file())
        CONFIG.remove_section(self._pars_name)
        with open(config.get_config_file(), 'w') as f:
            CONFIG.write(f)


class Jars(object):
    def __init__(self, pars,
                 docker_image_name='cloudknot-docker-image',
                 job_definition_name='cloudknot-job-definition',
                 compute_environment_name='cloudknot-compute-environment',
                 job_queue_name='cloudknot-job-queue', vcpus=1, memory=32000):
        if not isinstance(pars, Pars):
            raise ValueError('infrastructure must be an AWSInfrastructure '
                             'instance.')

        self._pars = pars

        if not isinstance(docker_image_name, str):
            raise ValueError('docker_image_name must be a string.')

        if not isinstance(job_definition_name, str):
            raise ValueError('job_definition_name must be a string.')

        if not isinstance(compute_environment_name, str):
            raise ValueError('compute_environment_name must be a string.')

        if not isinstance(job_queue_name, str):
            raise ValueError('job_queue_name must be a string.')

        try:
            cpus = int(vcpus)
            if cpus < 1:
                raise ValueError('vcpus must be positive')
        except ValueError:
            raise ValueError('vcpus must be an integer')

        try:
            mem = int(memory)
            if mem < 1:
                raise ValueError('memory must be positive')
        except ValueError:
            raise ValueError('memory must be an integer')

        # WIP
        # self._docker_image = aws.ecr.DockerImage(
        #     name=docker_image_name#,
        #     #build_path=,
        #     #dockerfile=,
        #     #requirements=
        # )

        self._job_definition = aws.batch.JobDefinition(
            name=job_definition_name,
            job_role=self._infrastructure.ecs_instance_role,
            docker_image=self._docker_image.uri,
            vcpus=cpus,
            memory=mem
        )

        self._compute_environment = aws.batch.ComputeEnvironment(
            name=compute_environment_name,
            batch_service_role=self._pars.batch_service_role,
            instance_role=self._pars.ecs_instance_role,
            vpc=self._pars.vpc,
            security_group=self._pars.security_group,
            desired_vcpus=cpus
        )

        self._job_queue = aws.batch.JobQueue(
            name=job_queue_name,
            compute_environments=self._compute_environment
        )

    pars = property(operator.attrgetter('_pars'))
    docker_image = property(operator.attrgetter('_docker_image'))
    job_definition = property(operator.attrgetter('_job_definition'))
    job_queue = property(operator.attrgetter('_job_queue'))
    compute_environment = property(operator.attrgetter('_compute_environment'))
