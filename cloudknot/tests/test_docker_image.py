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
from moto import mock_batch, mock_cloudformation, mock_ec2, mock_ecr
from moto import mock_ecs, mock_iam, mock_s3

bucket_name = "ck-test-bucket-" + str(uuid.uuid4()).replace("-", "")[:6]


def composed(*decs):
    def deco(f):
        for dec in reversed(decs):
            f = dec(f)
        return f

    return deco


@pytest.fixture(scope="module")
def aws_credentials():
    """Mocked AWS Credentials for moto."""
    os.environ["AWS_ACCESS_KEY_ID"] = "testing"
    os.environ["AWS_SECRET_ACCESS_KEY"] = "testing"  # nosec
    os.environ["AWS_SECURITY_TOKEN"] = "testing"  # nosec
    os.environ["AWS_SESSION_TOKEN"] = "testing"  # nosec


mock_all = composed(
    mock_ecr, mock_batch, mock_cloudformation, mock_ec2, mock_ecs, mock_iam, mock_s3
)

UNIT_TEST_PREFIX = "ck-unit-test"
data_path = op.join(ck.__path__[0], "data")


def get_testing_name():
    u = str(uuid.uuid4()).replace("-", "")[:8]
    name = UNIT_TEST_PREFIX + "-" + u
    return name


@pytest.fixture(scope="module")
@mock_all
def bucket_cleanup(aws_credentials):
    config_file = ck.config.get_config_file()
    config = configparser.ConfigParser()

    with ck.config.rlock:
        config.read(config_file)

    option = "s3-bucket"
    if config.has_section("aws") and config.has_option("aws", option):
        old_s3_params = ck.get_s3_params()
    else:
        old_s3_params = None

    new_bucket = bucket_name
    ck.set_s3_params(bucket=new_bucket)

    yield None

    s3_params = ck.get_s3_params()
    bucket_policy = s3_params.policy

    if (old_s3_params is None) or bucket_policy == old_s3_params.policy:
        iam = ck.aws.clients["iam"]
        paginator = iam.get_paginator("list_policies")
        response_iterator = paginator.paginate(Scope="Local", PathPrefix="/cloudknot/")

        # response_iterator is a list of dicts. First convert to list of lists
        # and then flatten to a single list
        response_policies = [response["Policies"] for response in response_iterator]
        policies = [lst for sublist in response_policies for lst in sublist]

        aws_policies = {d["PolicyName"]: d["Arn"] for d in policies}

        arn = aws_policies[bucket_policy]

        paginator = iam.get_paginator("list_policy_versions")
        response_iterator = paginator.paginate(PolicyArn=arn)

        # Get non-default versions
        # response_iterator is a list of dicts. First convert to list of
        # lists. Then flatten to a single list and filter
        response_versions = [response["Versions"] for response in response_iterator]
        versions = [lst for sublist in response_versions for lst in sublist]
        versions = [v for v in versions if not v["IsDefaultVersion"]]

        # Get the oldest versions and delete them
        for v in versions:
            iam.delete_policy_version(PolicyArn=arn, VersionId=v["VersionId"])

        response = iam.list_entities_for_policy(PolicyArn=arn, EntityFilter="Role")

        roles = response.get("PolicyRoles")
        for role in roles:
            iam.detach_role_policy(RoleName=role["RoleName"], PolicyArn=arn)

        try:
            iam.delete_policy(PolicyArn=arn)
        except Exception:
            pass

    if old_s3_params:
        ck.set_s3_params(
            bucket=old_s3_params.bucket,
            policy=old_s3_params.policy,
            sse=old_s3_params.sse,
        )


@pytest.fixture(scope="module")
@mock_all
def cleanup_repos(bucket_cleanup):
    yield None
    ecr = ck.aws.clients["ecr"]
    config_file = ck.config.get_config_file()
    section_suffix = ck.get_profile() + " " + ck.get_region()
    repos_section_name = "docker-repos " + section_suffix

    # Clean up repos from AWS
    # -----------------------
    # Get all repos with unit test prefix in the name
    response = ecr.describe_repositories()
    repos = [
        r
        for r in response.get("repositories")
        if (
            "unit-testing-func" in r["repositoryName"]
            or "test-func-input" in r["repositoryName"]
            or "simple-unit-testing-func" in r["repositoryName"]
            or UNIT_TEST_PREFIX in r["repositoryName"]
        )
    ]

    # Delete the AWS ECR repo
    for r in repos:
        ecr.delete_repository(
            registryId=r["registryId"], repositoryName=r["repositoryName"], force=True
        )

    # Clean up repos from config file
    config = configparser.ConfigParser()
    with ck.config.rlock:
        config.read(config_file)
        for repo_name in config.options(repos_section_name):
            if UNIT_TEST_PREFIX in repo_name:
                config.remove_option(repos_section_name, repo_name)
        with open(config_file, "w") as f:
            config.write(f)


def simple_unit_testing_func(name=None):
    """Simple test function with no imports for a small docker image"""
    return "Hello world!"


def unit_testing_func(name=None, no_capitalize=False):
    """Test function for unit testing of cloudknot.DockerImage

    Import statements of various formats are deliberately scattered
    throughout the function to test the pipreqs components of
    clouknot.DockerImage
    """
    import sys  # noqa: F401
    import boto3.ec2  # noqa: F401

    if name:
        from docker import api  # noqa: F401
        from os.path import join  # noqa: F401

        if not no_capitalize:
            import pytest as pt  # noqa: F401

            name = name.title()

        return "Hello {0}!".format(name)

    from six import binary_type as bt  # noqa: F401
    from dask.base import curry as dbc  # noqa: F401

    return "Hello world!"


@mock_all
def test_DockerImage(cleanup_repos):
    ck.refresh_clients()
    config = configparser.ConfigParser()
    config_file = ck.config.get_config_file()
    ecr = ck.aws.clients["ecr"]

    try:
        correct_pip_imports = {
            "boto3",
            "six",
            "dask",
            "docker",
            "pytest",
            "cloudpickle",
        }

        # First, test a DockerImage instance with `func` input
        # ----------------------------------------------------
        di = ck.DockerImage(
            name=unit_testing_func.__name__.replace("_", "-"), func=unit_testing_func
        )

        assert di.name == unit_testing_func.__name__.replace("_", "-")
        import_names = set([d["name"] for d in di.pip_imports])
        assert import_names == correct_pip_imports
        assert di.missing_imports == []
        assert di.username == "cloudknot-user"
        assert di.func == unit_testing_func

        py_dir = "py3" if six.PY3 else "py2"

        # Compare the created files with the reference files
        correct_dir = op.join(data_path, "docker_reqs_ref_data", py_dir, "ref1")
        correct_req_path = op.join(correct_dir, "requirements.txt")
        correct_dockerfile = op.join(correct_dir, "Dockerfile")

        correct_script_path = op.join(correct_dir, "unit-testing-func.py")

        with open(correct_req_path) as f:
            correct_reqs = set([s.split("=")[0] for s in f.readlines()])

        with open(di.req_path) as f:
            created_reqs = set([s.split("=")[0] for s in f.readlines()])

        assert created_reqs == correct_reqs
        assert filecmp.cmp(di.docker_path, correct_dockerfile, shallow=False)
        assert filecmp.cmp(di.script_path, correct_script_path, shallow=False)

        # Confirm that the docker image is in the config file
        config = configparser.ConfigParser()
        with ck.config.rlock:
            config.read(config_file)

        assert "docker-image " + di.name in config.sections()

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
        with ck.config.rlock:
            config.read(config_file)

        assert "docker-image " + di.name not in config.sections()

        # Second, test a DockerImage with a func and a dir_name
        # -----------------------------------------------------
        dir_name = tempfile.mkdtemp(dir=os.getcwd())
        di = ck.DockerImage(func=unit_testing_func, dir_name=dir_name)

        assert di.name == unit_testing_func.__name__.replace("_", "-")
        import_names = set([d["name"] for d in di.pip_imports])
        assert import_names == correct_pip_imports
        assert di.missing_imports == []
        assert di.username == "cloudknot-user"
        assert di.func == unit_testing_func

        with open(di.req_path) as f:
            created_reqs = set([s.split("=")[0] for s in f.readlines()])

        assert created_reqs == correct_reqs
        assert filecmp.cmp(di.docker_path, correct_dockerfile, shallow=False)
        assert filecmp.cmp(di.script_path, correct_script_path, shallow=False)

        # Confirm that the docker image is in the config file
        config = configparser.ConfigParser()
        with ck.config.rlock:
            config.read(config_file)

        assert "docker-image " + di.name in config.sections()

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
        with ck.config.rlock:
            config.read(config_file)

        assert "docker-image " + di.name not in config.sections()

        # Third, test a DockerImage with script_path and dir_name input
        # -------------------------------------------------------------
        correct_dir = op.join(data_path, "docker_reqs_ref_data", py_dir, "ref2")
        script_path = op.join(correct_dir, "test-func-input.py")

        # Put the results in a temp dir with a pre-existing file
        dir_name = tempfile.mkdtemp(dir=os.getcwd())
        _, tmp_file_name = tempfile.mkstemp(dir=dir_name)

        di = ck.DockerImage(
            script_path=script_path, dir_name=dir_name, username="unit-test-username"
        )

        assert di.name == op.splitext(op.basename(script_path))[0].replace("_", "-")
        import_names = set([d["name"] for d in di.pip_imports])
        assert import_names == correct_pip_imports
        assert di.missing_imports == []
        assert di.username == "unit-test-username"
        assert di.func is None
        assert di.build_path == dir_name
        assert di.script_path == script_path

        # Compare the created files with the reference files
        correct_dir = op.join(data_path, "docker_reqs_ref_data", py_dir, "ref2")
        correct_req_path = op.join(correct_dir, "requirements.txt")
        correct_dockerfile = op.join(correct_dir, "Dockerfile")

        with open(correct_req_path) as f:
            correct_reqs = set([s.split("=")[0] for s in f.readlines()])

        with open(di.req_path) as f:
            created_reqs = set([s.split("=")[0] for s in f.readlines()])

        assert created_reqs == correct_reqs
        assert filecmp.cmp(di.docker_path, correct_dockerfile, shallow=False)

        # Confirm that the docker image is in the config file
        config = configparser.ConfigParser()
        with ck.config.rlock:
            config.read(config_file)

        assert "docker-image " + di.name in config.sections()

        # Assert ck.aws.CloudknotInputError on name plus other input
        with pytest.raises(ck.aws.CloudknotInputError):
            ck.DockerImage(name=di.name, script_path="Foo")

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
        with ck.config.rlock:
            config.read(config_file)

        assert "docker-image " + di.name not in config.sections()

        # Test for exception handling of incorrect input
        # ----------------------------------------------

        # Assert ck.aws.CloudknotInputError on no input
        with pytest.raises(ck.aws.CloudknotInputError):
            ck.DockerImage()

        # Assert ck.aws.CloudknotInputError on non-string name input
        with pytest.raises(ck.aws.CloudknotInputError):
            ck.DockerImage(name=42)

        # Assert ck.aws.CloudknotInputError on redundant input
        with pytest.raises(ck.aws.CloudknotInputError):
            ck.DockerImage(
                func=unit_testing_func,
                script_path=correct_script_path,
                dir_name=os.getcwd(),
            )

        # Assert ck.aws.CloudknotInputError on invalid script path
        with pytest.raises(ck.aws.CloudknotInputError):
            ck.DockerImage(script_path=str(uuid.uuid4()), dir_name=os.getcwd())

        # Assert ck.aws.CloudknotInputError on invalid dir name
        with pytest.raises(ck.aws.CloudknotInputError):
            ck.DockerImage(script_path=correct_script_path, dir_name=str(uuid.uuid4()))

        correct_dir = op.join(data_path, "docker_reqs_ref_data", py_dir, "ref1")
        # Assert CloudknotInputError to prevent overwriting existing script
        with pytest.raises(ck.aws.CloudknotInputError):
            ck.DockerImage(func=unit_testing_func, dir_name=correct_dir)

        # Assert CloudknotInputError to prevent overwriting existing Dockerfile
        with pytest.raises(ck.aws.CloudknotInputError):
            ck.DockerImage(script_path=correct_script_path)

        # Assert CloudknotInputError to prevent overwriting existing
        # requirements.txt
        # First, avoid the existing Dockerfile error by renaming the Dockerfile
        old_dockerfile = op.join(op.dirname(correct_script_path), "Dockerfile")

        new_dockerfile = op.join(op.dirname(correct_script_path), "tmpdockerfile")
        os.rename(old_dockerfile, new_dockerfile)

        # Assert the ck.aws.CloudknotInputError
        with pytest.raises(ck.aws.CloudknotInputError):
            ck.DockerImage(script_path=correct_script_path)

        # Clean up our mess by renaming to the old Dockerfile
        os.rename(new_dockerfile, old_dockerfile)

        # Finally, test the build and push methods
        # ----------------------------------------

        # Make one last DockerImage instance with the simple_unit_testing_func
        di = ck.DockerImage(func=simple_unit_testing_func)

        # Create a repo to which to push this image
        response = ecr.create_repository(repositoryName=get_testing_name())
        repo_name = response["repository"]["repositoryName"]
        repo_uri = response["repository"]["repositoryUri"]

        repo = ck.aws.DockerRepo(name=repo_name)

        # Assert ck.aws.CloudknotInputError on push without args
        with pytest.raises(ck.aws.CloudknotInputError):
            di.push()

        # Assert ck.aws.CloudknotInputError on over-specified input
        with pytest.raises(ck.aws.CloudknotInputError):
            di.push(repo="input doesn't matter here", repo_uri=str(repo_uri))

        # Assert ck.aws.CloudknotInputError on push before build
        with pytest.raises(ck.aws.CloudknotInputError):
            di.push(repo_uri=str(repo_uri))

        # Assert ck.aws.CloudknotInputError on incorrect build args
        with pytest.raises(ck.aws.CloudknotInputError):
            di.build(tags=[42, -42])

        # Assert ck.aws.CloudknotInputError on 'latest' in tags
        with pytest.raises(ck.aws.CloudknotInputError):
            di.build(tags=["testing", "latest"])

        tags = ["testing", ["testing1", "testing2"]]
        image_names = [None, "testing_image"]

        for idx, (tag, n) in enumerate(zip(tags, image_names)):
            di.build(tags=tag, image_name=n)

            n = n if n else "cloudknot/" + di.name
            if isinstance(tag, six.string_types):
                tag = [tag]

            images = [{"name": n, "tag": t} for t in tag]
            for im in images:
                assert im in di.images

            if idx % 2:
                di.push(repo_uri=str(repo_uri))
            else:
                di.push(repo=repo)

            assert repo_uri in di.repo_uri

        # Assert ck.aws.CloudknotInputError on push with invalid repo
        with pytest.raises(ck.aws.CloudknotInputError):
            di.push(repo=42)

        # Assert ck.aws.CloudknotInputError on push with invalid repo_uri
        with pytest.raises(ck.aws.CloudknotInputError):
            di.push(repo_uri=42)

        di.clobber()

        # Assert error on build after clobber
        with pytest.raises(ck.aws.ResourceClobberedException):
            di.build(tags=["testing"])

        # Assert ck.aws.CloudknotInputError on push with invalid repo_uri
        with pytest.raises(ck.aws.ResourceClobberedException):
            di.push(repo=repo)
    except Exception as e:
        # Get all local images with unit test prefix in any of the repo tags
        c = docker.from_env().api
        unit_test_images = [
            im
            for im in c.images()
            if any(
                ("unit-testing-func" in tag or "test-func-input" in tag)
                for tag in im["RepoTags"]
            )
        ]

        # Remove local images
        for im in unit_test_images:
            for tag in im["RepoTags"]:
                c.remove_image(tag, force=True)

        # Clean up config file
        config = configparser.ConfigParser()
        with ck.config.rlock:
            config.read(config_file)

            for name in list(config.sections()):
                if name in [
                    "docker-image unit-testing-func",
                    "docker-image test-func-input",
                ]:
                    config.remove_section(name)

            try:
                section_name = "docker-repos" + ck.aws.get_region()
                for option in config.options(section_name):
                    if UNIT_TEST_PREFIX in option:
                        config.remove_option(section_name, option)
            except configparser.NoSectionError:
                pass

            with open(config_file, "w") as f:
                config.write(f)

        raise e
