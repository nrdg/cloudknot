import cloudknot as ck
import configparser
import filecmp
import os
import os.path as op
import pytest
import shutil
import tempfile

from moto import mock_batch, mock_cloudformation, mock_ec2, mock_ecr
from moto import mock_ecs, mock_iam, mock_s3

data_path = op.join(ck.__path__[0], "data")


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


@pytest.fixture(scope="function")
def tmp_cfg_dir():
    old_cfg_file = os.environ.get("CLOUDKNOT_CONFIG_FILE")
    temp_dir = tempfile.mkdtemp()
    temp_name = os.path.join(temp_dir, "cloudknot")
    os.environ["CLOUDKNOT_CONFIG_FILE"] = temp_name
    yield temp_name
    shutil.rmtree(temp_dir)
    if old_cfg_file is None:
        os.environ.pop("CLOUDKNOT_CONFIG_FILE", None)
    else:
        os.environ["CLOUDKNOT_CONFIG_FILE"] = old_cfg_file


@pytest.fixture(scope="function")
def configured(tmp_cfg_dir):
    tmp_name = tmp_cfg_dir
    ck.config.add_resource("aws", "configured", "True")
    yield tmp_name


def test_get_config_file(tmp_cfg_dir):
    temp_name = tmp_cfg_dir
    temp_cfg_file = ck.config.get_config_file()
    assert os.path.samefile(temp_cfg_file, temp_name)

    with open(temp_name, "r") as fp:
        header_text = fp.read()

    assert header_text == "# cloudknot configuration file"

    os.environ.pop("CLOUDKNOT_CONFIG_FILE", None)
    default_cfg_file = ck.config.get_config_file()
    home = os.path.expanduser("~")
    home_cfg_file = os.path.join(home, ".aws", "cloudknot")
    assert os.path.samefile(default_cfg_file, home_cfg_file)


def test_add_remove_verify(configured):
    temp_name = configured

    ck.config.add_resource("test-section-0", "test-option-0", "test-value")
    ck.config.add_resource("test-section-0", "test-option-1", "test-value")
    ck.config.add_resource("test-section-1", "test-option-0", "test-value")

    ref_cfg = os.path.join(data_path, "config_ref_data", "test_add_resource.cfg")
    assert filecmp.cmp(temp_name, ref_cfg, shallow=False)

    ck.config.remove_resource("test-section-0", "test-option-0")
    ck.config.remove_resource("no-section-error", "test-option-0")
    ref_cfg = os.path.join(data_path, "config_ref_data", "test_remove_resource.cfg")
    assert filecmp.cmp(temp_name, ref_cfg, shallow=False)

    ck.config.verify_sections()
    with open(temp_name, "r") as fp:
        aws_config = fp.read()

    assert aws_config == "[aws]\nconfigured = True\n\n"


@mock_all
def test_is_valid_stack(configured, aws_credentials):
    ck.refresh_clients()

    pars = ck.Pars(name="test-valid-stack")
    assert ck.config.is_valid_stack(stack_id=pars.stack_id)

    ck.aws.clients["cloudformation"].delete_stack(StackName=pars.stack_id)
    assert not ck.config.is_valid_stack(stack_id=pars.stack_id)


@mock_all
def test_prune_stacks(configured, aws_credentials):
    config_name = configured
    ck.refresh_clients()

    pars0 = ck.Pars(name="test-prune-0")
    pars1 = ck.Pars(name="test-prune-1")

    ck.aws.clients["cloudformation"].delete_stack(StackName=pars0.stack_id)
    ck.config.prune_stacks()

    config = configparser.ConfigParser()
    config.read(config_name)
    assert pars0.pars_name not in config.sections()
    assert pars1.pars_name in config.sections()


@mock_all
def test_prune_repos(configured, aws_credentials):
    config_name = configured
    ck.refresh_clients()

    repo0 = ck.aws.DockerRepo(name="test-prune-0")
    repo1 = ck.aws.DockerRepo(name="test-prune-1")
    repo2 = ck.aws.DockerRepo(name="test-prune-2")

    ck.aws.clients["ecr"].delete_repository(repositoryName=repo0.name)
    ck.config.prune_repos()

    config = configparser.ConfigParser()
    config.read(config_name)
    repo_section = config[repo0._section_name]

    assert repo0.name not in repo_section
    assert repo1.name in repo_section
    assert repo2.name in repo_section

    ck.config.add_resource(repo1._section_name, repo1.name, "0123")
    ck.config.prune()

    config = configparser.ConfigParser()
    config.read(config_name)
    repo_section = config[repo0._section_name]

    assert repo1.name not in repo_section
    assert repo2.name in repo_section


def test_prune_batch_jobs():
    pass


def test_prune_images():
    pass
