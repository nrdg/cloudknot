from __future__ import absolute_import, division, print_function

import cloudknot as ck
import filecmp
import fileinput
import os
import os.path as op
import pytest
import six
import tempfile
import uuid

data_path = op.join(ck.__path__[0], 'data')


def unit_testing_func(name=None, no_capitalize=False):
    """Test function for unit testing of cloudknot.DockerReqs

    Import statements of various formats are deliberately scattered
    throughout the function to test the pipreqs components of
    clouknot.DockerReqs
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


def test_DockerReqs():
    correct_pip_imports = set([
        'clize', 'sys', 'boto3', 'six', 'dask',
        'docker', 'os', 'pytest', 'h5py'
    ])

    # First, test a DockerReqs instance with `func` input
    reqs = ck.DockerReqs(func=unit_testing_func)

    assert reqs.name == unit_testing_func.__name__
    import_names = set([d['name'] for d in reqs.pip_imports])
    assert import_names == correct_pip_imports
    assert reqs.missing_imports == ['AFQ']
    assert reqs.username == 'cloudknot-user'
    assert reqs.func == unit_testing_func

    # Compare the created files with the reference files
    correct_dir = op.join(data_path, 'docker_reqs_ref_data', 'ref1')
    correct_req_path = op.join(correct_dir, 'requirements.txt')
    correct_dockerfile = op.join(correct_dir, 'Dockerfile')

    # The reference Dockerfile has "FROM python:3" but this will fail for
    # python 2 tests. So edit the reference Dockerfile to make sure.
    with fileinput.FileInput(
            correct_dockerfile, inplace=True, backup='.bak'
    ) as file:
        py_version_str = '3' if six.PY3 else '2'
        for line in file:
            print(line.replace(
                'FROM python:3', 'FROM python:' + py_version_str
            ), end='')

    correct_script_path = op.join(correct_dir, 'unit_testing_func.py')

    assert filecmp.cmp(reqs.req_path, correct_req_path, shallow=False)
    assert filecmp.cmp(reqs.docker_path, correct_dockerfile, shallow=False)
    assert filecmp.cmp(reqs.script_path, correct_script_path, shallow=False)

    # Clobber and confirm that it deleted all the created files and dirs
    reqs.clobber()
    assert not op.isfile(reqs.req_path)
    assert not op.isfile(reqs.docker_path)
    assert not op.isfile(reqs.script_path)
    assert not op.isdir(reqs.dir_path)

    # Second, test a DockerReqs instance with script_path and dir_name input
    correct_dir = op.join(data_path, 'docker_reqs_ref_data', 'ref2')
    script_path = op.join(correct_dir, 'test_func_input.py')

    # Put the results in a temp dir with a pre-existing file
    dir_name = tempfile.mkdtemp(dir=os.getcwd())
    _, tmp_file_name = tempfile.mkstemp(dir=dir_name)

    reqs = ck.DockerReqs(
        script_path=script_path,
        dir_name=dir_name,
        username='unit-test-username'
    )

    assert reqs.name == op.basename(script_path)
    import_names = set([d['name'] for d in reqs.pip_imports])
    assert import_names == correct_pip_imports
    assert reqs.missing_imports is None
    assert reqs.username == 'unit-test-username'
    assert reqs.func is None
    assert reqs.dir_path == dir_name
    assert reqs.script_path == script_path

    # Compare the created files with the reference files
    correct_dir = op.join(data_path, 'docker_reqs_ref_data', 'ref2')
    correct_req_path = op.join(correct_dir, 'requirements.txt')
    correct_dockerfile = op.join(correct_dir, 'Dockerfile')

    # The reference Dockerfile has "FROM python:3" but this will fail for
    # python 2 tests. So edit the reference Dockerfile to make sure.
    with fileinput.FileInput(
            correct_dockerfile, inplace=True, backup='.bak'
    ) as file:
        py_version_str = '3' if six.PY3 else '2'
        for line in file:
            print(line.replace(
                'FROM python:3', 'FROM python:' + py_version_str
            ), end='')

    assert filecmp.cmp(reqs.req_path, correct_req_path, shallow=False)
    assert filecmp.cmp(reqs.docker_path, correct_dockerfile, shallow=False)

    # Clobber and confirm that it deleted all the created files
    reqs.clobber()
    assert not op.isfile(reqs.req_path)
    assert not op.isfile(reqs.docker_path)

    # But since we had a pre-existing file in the dir_path, it should not
    # have deleted the dir_path or the input python script
    assert op.isfile(reqs.script_path)
    assert op.isfile(tmp_file_name)
    assert op.isdir(reqs.dir_path)

    # Now delete them to clean up after ourselves
    os.remove(tmp_file_name)
    os.rmdir(reqs.dir_path)

    # Test for exception handling of incorrect input
    # Assert ValueError on no input
    with pytest.raises(ValueError):
        ck.DockerReqs()

    # Assert ValueError on redundant input
    with pytest.raises(ValueError):
        ck.DockerReqs(
            func=unit_testing_func,
            script_path=correct_script_path,
            dir_name=os.getcwd()
        )

    # Assert ValueError on invalid script path
    with pytest.raises(ValueError):
        ck.DockerReqs(
            script_path=str(uuid.uuid4()),
            dir_name=os.getcwd()
        )

    # Assert ValueError on invalid dir name
    with pytest.raises(ValueError):
        ck.DockerReqs(
            script_path=correct_script_path,
            dir_name=str(uuid.uuid4())
        )

    correct_dir = op.join(data_path, 'docker_reqs_ref_data', 'ref1')
    # Assert ValueError to prevent overwriting existing script
    with pytest.raises(ValueError):
        ck.DockerReqs(
            func=unit_testing_func,
            dir_name=correct_dir
        )

    # Assert ValueError to prevent overwriting existing Dockerfile
    with pytest.raises(ValueError):
        ck.DockerReqs(
            script_path=correct_script_path,
        )

    # Assert ValueError to prevent overwriting existing requirements.txt
    # First, avoid the existing Dockerfile error by renaming the Dockerfile
    old_dockerfile = op.join(op.dirname(correct_script_path), 'Dockerfile')
    new_dockerfile = op.join(op.dirname(correct_script_path), 'tmpdockerfile')
    os.rename(old_dockerfile, new_dockerfile)

    # Assert the ValueError
    with pytest.raises(ValueError):
        ck.DockerReqs(
            script_path=correct_script_path,
        )

    # Clean up our mess by renaming to the old Dockerfile
    os.rename(new_dockerfile, old_dockerfile)


def test_Pars():
    pass
