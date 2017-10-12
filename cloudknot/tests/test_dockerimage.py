from __future__ import absolute_import, division, print_function

import cloudknot as ck
import configparser
import docker
import filecmp
import os
import os.path as op
import pytest
import six
import tempfile
import uuid

UNIT_TEST_PREFIX = 'cloudknot-unit-test'
data_path = op.join(ck.__path__[0], 'data')


def get_testing_name():
    u = str(uuid.uuid4()).replace('-', '')[:8]
    name = UNIT_TEST_PREFIX + '-' + u
    return name


def simple_unit_testing_func(name=None):
    """Simple test function with no imports for a small docker image"""
    return 'Hello world!'


def unit_testing_func(name=None, no_capitalize=False):
    """Test function for unit testing of cloudknot.DockerImage

    Import statements of various formats are deliberately scattered
    throughout the function to test the pipreqs components of
    clouknot.DockerImage
    """
    import sys  # noqa: F401
    import boto3.ec2  # noqa: F401
    import AFQ  # noqa: F401
    if name:
        from docker import api  # noqa: F401
        from os.path import join  # noqa: F401

        if not no_capitalize:
            import pytest as pt  # noqa: F401
            import h5py.utils as h5utils  # noqa: F401

            name = name.title()

        return 'Hello {0}!'.format(name)

    from six import binary_type as bt  # noqa: F401
    from dask.base import curry as dbc  # noqa: F401

    return 'Hello world!'


def test_DockerImage():
    config = configparser.ConfigParser()
    config_file = ck.config.get_config_file()
    ecr = ck.aws.clients['ecr']

    try:
        correct_pip_imports = set([
            'clize', 'boto3', 'six', 'dask', 'docker', 'pytest', 'h5py'
        ])

        # First, test a DockerImage instance with `func` input
        # ----------------------------------------------------
        di = ck.DockerImage(func=unit_testing_func)

        assert di.name == unit_testing_func.__name__
        import_names = set([d['name'] for d in di.pip_imports])
        assert import_names == correct_pip_imports
        assert di.missing_imports == ['AFQ']
        assert di.username == 'cloudknot-user'
        assert di.func == unit_testing_func

        py_dir = 'py3' if six.PY3 else 'py2'

        # Compare the created files with the reference files
        correct_dir = op.join(
            data_path, 'docker_reqs_ref_data', py_dir, 'ref1'
        )
        correct_req_path = op.join(correct_dir, 'requirements.txt')
        correct_dockerfile = op.join(correct_dir, 'Dockerfile')

        correct_script_path = op.join(correct_dir, 'unit_testing_func.py')

        with open(correct_req_path) as f:
            correct_reqs = set([s.split('=')[0] for s in f.readlines()])

        with open(di.req_path) as f:
            created_reqs = set([s.split('=')[0] for s in f.readlines()])

        assert created_reqs == correct_reqs
        assert filecmp.cmp(di.docker_path, correct_dockerfile, shallow=False)
        assert filecmp.cmp(di.script_path, correct_script_path, shallow=False)

        # Confirm that the docker image is in the config file
        config = configparser.ConfigParser()
        config.read(config_file)
        assert 'docker-image ' + di.name in config.sections()

        # Next, retrieve another instance with the same name, confirm that it
        # retrieves the same info from the config file
        di2 = ck.DockerImage(name=di.name)
        assert di2.build_path == di.build_path
        assert di2.docker_path == di.docker_path
        assert di2.images == di.images
        assert di2.missing_imports == di.missing_imports
        assert di2.name == di.name
        assert di2.pip_imports == di.pip_imports
        assert di2.repo_uri == di.repo_uri
        assert di2.req_path == di.req_path
        assert di2.script_path == di.script_path
        assert di2.username == di.username

        # Clobber and confirm that it deleted all the created files and dirs
        di2.clobber()
        assert not op.isfile(di.req_path)
        assert not op.isfile(di.docker_path)
        assert not op.isfile(di.script_path)
        assert not op.isdir(di.build_path)

        # Assert that it was removed from the config file
        # If we just re-read the config file, config will keep the union
        # of the in memory values and the file values, updating the
        # intersection of the two with the file values. So we must clear
        # config and then re-read the file
        config = configparser.ConfigParser()
        config.read(config_file)
        assert 'docker-image ' + di.name not in config.sections()

        # Second, test a DockerImage with a func and a dir_name
        # -----------------------------------------------------
        dir_name = tempfile.mkdtemp(dir=os.getcwd())
        di = ck.DockerImage(
            func=unit_testing_func,
            dir_name=dir_name
        )

        assert di.name == unit_testing_func.__name__
        import_names = set([d['name'] for d in di.pip_imports])
        assert import_names == correct_pip_imports
        assert di.missing_imports == ['AFQ']
        assert di.username == 'cloudknot-user'
        assert di.func == unit_testing_func

        with open(di.req_path) as f:
            created_reqs = set([s.split('=')[0] for s in f.readlines()])

        assert created_reqs == correct_reqs
        assert filecmp.cmp(di.docker_path, correct_dockerfile, shallow=False)
        assert filecmp.cmp(di.script_path, correct_script_path, shallow=False)

        # Confirm that the docker image is in the config file
        config = configparser.ConfigParser()
        config.read(config_file)
        assert 'docker-image ' + di.name in config.sections()

        # Clobber and confirm that it deleted all the created files and dirs
        di.clobber()
        assert not op.isfile(di.req_path)
        assert not op.isfile(di.docker_path)
        assert not op.isfile(di.script_path)
        assert not op.isdir(di.build_path)

        # Assert that it was removed from the config file
        # If we just re-read the config file, config will keep the union
        # of the in memory values and the file values, updating the
        # intersection of the two with the file values. So we must clear
        # config and then re-read the file
        config = configparser.ConfigParser()
        config.read(config_file)
        assert 'docker-image ' + di.name not in config.sections()

        # Third, test a DockerImage with script_path and dir_name input
        # -------------------------------------------------------------
        correct_dir = op.join(
            data_path, 'docker_reqs_ref_data', py_dir, 'ref2'
        )
        script_path = op.join(correct_dir, 'test_func_input.py')

        # Put the results in a temp dir with a pre-existing file
        dir_name = tempfile.mkdtemp(dir=os.getcwd())
        _, tmp_file_name = tempfile.mkstemp(dir=dir_name)

        di = ck.DockerImage(
            script_path=script_path,
            dir_name=dir_name,
            username='unit-test-username'
        )

        assert di.name == op.basename(script_path)
        import_names = set([d['name'] for d in di.pip_imports])
        assert import_names == correct_pip_imports
        assert di.missing_imports is None
        assert di.username == 'unit-test-username'
        assert di.func is None
        assert di.build_path == dir_name
        assert di.script_path == script_path

        # Compare the created files with the reference files
        correct_dir = op.join(
            data_path, 'docker_reqs_ref_data', py_dir, 'ref2'
        )
        correct_req_path = op.join(correct_dir, 'requirements.txt')
        correct_dockerfile = op.join(correct_dir, 'Dockerfile')

        with open(correct_req_path) as f:
            correct_reqs = set([s.split('=')[0] for s in f.readlines()])

        with open(di.req_path) as f:
            created_reqs = set([s.split('=')[0] for s in f.readlines()])

        assert created_reqs == correct_reqs
        assert filecmp.cmp(di.docker_path, correct_dockerfile, shallow=False)

        # Confirm that the docker image is in the config file
        config = configparser.ConfigParser()
        config.read(config_file)
        assert 'docker-image ' + di.name in config.sections()

        # Clobber and confirm that it deleted all the created files
        di.clobber()
        assert not op.isfile(di.req_path)
        assert not op.isfile(di.docker_path)

        # But since we had a pre-existing file in the build_path, it should not
        # have deleted the build_path or the input python script
        assert op.isfile(di.script_path)
        assert op.isfile(tmp_file_name)
        assert op.isdir(di.build_path)

        # Now delete them to clean up after ourselves
        os.remove(tmp_file_name)
        os.rmdir(di.build_path)

        # Assert that it was removed from the config file
        # If we just re-read the config file, config will keep the union
        # of the in memory values and the file values, updating the
        # intersection of the two with the file values. So we must clear
        # config and then re-read the file
        config = configparser.ConfigParser()
        config.read(config_file)
        assert 'docker-image ' + di.name not in config.sections()

        # Test for exception handling of incorrect input
        # ----------------------------------------------

        # Assert ValueError on no input
        with pytest.raises(ValueError):
            ck.DockerImage()

        # Assert ValueError on name plus other input
        with pytest.raises(ValueError):
            ck.DockerImage(name=get_testing_name(), func=unit_testing_func)

        # Assert ValueError on non-string name input
        with pytest.raises(ValueError):
            ck.DockerImage(name=42)

        # Assert ValueError on non-existent name input
        with pytest.raises(ck.aws.ResourceDoesNotExistException):
            ck.DockerImage(name=get_testing_name())

        # Assert ValueError on redundant input
        with pytest.raises(ValueError):
            ck.DockerImage(
                func=unit_testing_func,
                script_path=correct_script_path,
                dir_name=os.getcwd()
            )

        # Assert ValueError on invalid script path
        with pytest.raises(ValueError):
            ck.DockerImage(script_path=str(uuid.uuid4()), dir_name=os.getcwd())

        # Assert ValueError on invalid dir name
        with pytest.raises(ValueError):
            ck.DockerImage(
                script_path=correct_script_path,
                dir_name=str(uuid.uuid4())
            )

        correct_dir = op.join(
            data_path, 'docker_reqs_ref_data', py_dir, 'ref1'
        )
        # Assert ValueError to prevent overwriting existing script
        with pytest.raises(ValueError):
            ck.DockerImage(func=unit_testing_func, dir_name=correct_dir)

        # Assert ValueError to prevent overwriting existing Dockerfile
        with pytest.raises(ValueError):
            ck.DockerImage(script_path=correct_script_path)

        # Assert ValueError to prevent overwriting existing requirements.txt
        # First, avoid the existing Dockerfile error by renaming the Dockerfile
        old_dockerfile = op.join(op.dirname(correct_script_path), 'Dockerfile')

        new_dockerfile = op.join(
            op.dirname(correct_script_path), 'tmpdockerfile'
        )
        os.rename(old_dockerfile, new_dockerfile)

        # Assert the ValueError
        with pytest.raises(ValueError):
            ck.DockerImage(script_path=correct_script_path)

        # Clean up our mess by renaming to the old Dockerfile
        os.rename(new_dockerfile, old_dockerfile)

        # Finally, test the build and push methods
        # ----------------------------------------

        # Make one last DockerImage instance with the simple_unit_testing_func
        di = ck.DockerImage(func=simple_unit_testing_func)

        # Create a repo to which to push this image
        response = ecr.create_repository(repositoryName=get_testing_name())
        repo_name = response['repository']['repositoryName']
        repo_uri = response['repository']['repositoryUri']
        repo_registry_id = response['repository']['registryId']

        repo = ck.aws.DockerRepo(name=repo_name)

        # Assert ValueError on push without args
        with pytest.raises(ValueError):
            di.push()

        # Assert ValueError on over-specified input
        with pytest.raises(ValueError):
            di.push(repo="input doesn't matter here", repo_uri=str(repo_uri))

        # Assert ValueError on push before build
        with pytest.raises(ValueError):
            di.push(repo_uri=str(repo_uri))

        # Assert ValueError on incorrect build args
        with pytest.raises(ValueError):
            di.build(tags=[42, -42])

        # Assert ValueError on 'latest' in tags
        with pytest.raises(ValueError):
            di.build(tags=['testing', 'latest'])

        tags = ['testing', ['testing1', 'testing2']]
        image_names = [None, 'testing_image']

        for idx, (tag, n) in enumerate(zip(tags, image_names)):
            di.build(tags=tag, image_name=n)

            n = n if n else 'cloudknot/' + di.name
            if isinstance(tag, str):
                tag = [tag]

            images = [{'name': n, 'tag': t} for t in tag]
            for im in images:
                assert im in di.images

            if idx % 2:
                di.push(repo_uri=str(repo_uri))
            else:
                di.push(repo=repo)

            assert di.repo_uri == repo_uri

        # Assert ValueError on push with invalid repo
        with pytest.raises(ValueError):
            di.push(repo=42)

        # Assert ValueError on push with invalid repo_uri
        with pytest.raises(ValueError):
            di.push(repo_uri=42)

        di.clobber()

        repo.clobber()
    except Exception as e:
        response = ecr.describe_repositories()

        # Get all local images with unit test prefix in any of the repo tags
        c = docker.from_env().api
        unit_test_images = [
            im for im in c.images()
            if any(('unit_testing_func' in tag or 'test_func_input' in tag)
                   for tag in im['RepoTags'])
        ]

        # Remove local images
        for im in unit_test_images:
            for tag in im['RepoTags']:
                c.remove_image(tag, force=True)

        # Get all repos with unit test prefix in the name
        repos = [r for r in response.get('repositories')
                 if ('unit_testing_func' in r['repositoryName']
                     or 'test_func_input' in r['repositoryName'])]

        # Delete the AWS ECR repo
        for r in repos:
            ecr.delete_repository(
                registryId=r['registryId'],
                repositoryName=r['repositoryName'],
                force=True
            )

        # Clean up config file
        config = configparser.ConfigParser()
        config.read(config_file)
        for name in config.sections():
            if name in ['docker-image unit_testing_func',
                        'docker-image test_func_input.py']:
                config.remove_section(name)

        try:
            for option in config.options('docker-repos'):
                if UNIT_TEST_PREFIX in option:
                    config.remove_option('docker-repos', option)
        except configparser.NoSectionError:
            pass

        with open(config_file, 'w') as f:
            config.write(f)

        raise e
