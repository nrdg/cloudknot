"""Create Pars and Knot classes which represent AWS Cloudformation stack."""
import botocore
import configparser
import ipaddress
import logging
import os
import six

try:
    from collections.abc import Iterable, namedtuple
except ImportError:
    from collections import Iterable, namedtuple
from concurrent.futures import ThreadPoolExecutor

from . import aws
from .config import get_config_file, rlock, is_valid_stack
from . import dockerimage

__all__ = ["Pars", "Knot"]


mod_logger = logging.getLogger(__name__)


def _stack_out(key, outputs):
    o = list(filter(lambda d: d["OutputKey"] == key, outputs))[0]
    return o["OutputValue"]


# noinspection PyPropertyAccess,PyAttributeOutsideInit
class Pars(aws.NamedObject):
    """
    PARS stands for Persistent AWS Resource Set.

    This object collects AWS resources that could, in theory, be created only
    once for each cloudknot user and used for all of their subsequent AWS
    batch jobs. This set consists of IAM roles, a VPC with subnets for each
    availability zone, and a security group.
    """

    def __init__(
        self,
        name=None,
        batch_service_role_name=None,
        ecs_instance_role_name=None,
        spot_fleet_role_name=None,
        policies=(),
        use_default_vpc=True,
        ipv4_cidr=None,
        instance_tenancy=None,
        aws_resource_tags=None,
    ):
        """Initialize a PARS instance.

        Parameters
        ----------
        name : str
            The name of this PARS. If `pars name` exists in the config file,
            Pars will retrieve those PARS resource parameters. Otherwise,
            Pars will create a new PARS with this name.
            Must be less than 46 characters.
            Must satisfy regular expression pattern: [a-zA-Z][-a-zA-Z0-9]*
            Default: '${AWS-username}-default'

        batch_service_role_name : str
            Name of this PARS' batch service IAM role. If the role already
            exists, Pars will adopt it. Otherwise, it will create it.
            Default: name + '-cloudknot-batch-service-role'

        ecs_instance_role_name : str
            Name of this PARS' ECS instance IAM role. If the role already
            exists, Pars will adopt it. Otherwise, it will create it.
            Default: name + '-cloudknot-ecs-instance-role'

        spot_fleet_role_name : str
            Name of this PARS' spot fleet IAM role. If the role already
            exists, Pars will adopt it. Otherwise, it will create it.
            Default: name + '-cloudknot-spot-fleet-role'

        policies : tuple of strings
            tuple of names of AWS policy ARNs to attach to each role
            Default: ()

        use_default_vpc : bool
            if True, create or retrieve the default VPC
            if False, use other input args to create a non-default VPC

        ipv4_cidr : string
            IPv4 CIDR block to be used for creation of a new VPC

        instance_tenancy : string
            Instance tenancy for this VPC, one of ['default', 'dedicated']
            Default: 'default'

        aws_resource_tags : dict or list of dicts
            Additional AWS resource tags to apply to this repository
        """
        # Validate name input
        if name is not None and not isinstance(name, six.string_types):
            raise aws.CloudknotInputError(
                "PARS name must be a string. You passed a " "{t!s}".format(t=type(name))
            )

        if name is None:
            name = aws.get_user() + "-default"

        if len(name) > 45:
            raise aws.CloudknotInputError("Pars name must be less than 46 characters.")

        super(Pars, self).__init__(name=name)

        # Validate aws_resource_tags input before creating any resources
        self._tags = aws.get_tags(name=name, additional_tags=aws_resource_tags)

        # Check for existence of this pars in the config file
        config = configparser.ConfigParser()
        with rlock:
            config.read(get_config_file())

        self._pars_name = "pars " + self.name
        if self._pars_name in config.sections():
            self._region = config.get(self._pars_name, "region")
            self._profile = config.get(self._pars_name, "profile")
            self.check_profile_and_region()

            mod_logger.info("Found PARS {name:s} in config".format(name=name))

            self._stack_id = config.get(self._pars_name, "stack-id")

            if not is_valid_stack(self._stack_id):
                # Remove this section from the config file
                with rlock:
                    config.read(get_config_file())
                    config.remove_section(self._pars_name)
                    with open(get_config_file(), "w") as f:
                        config.write(f)
                raise aws.ResourceDoesNotExistException(
                    "Cloudknot found this PARS in its config file, but "
                    "the PARS stack that you requested does not exist on "
                    "AWS. Cloudknot has deleted this PARS from the config "
                    "file, so you may be able to create a new one simply "
                    "by re-running your previous command.",
                    self._stack_id,
                )

            response = aws.clients["cloudformation"].describe_stacks(
                StackName=self._stack_id
            )
            outs = response.get("Stacks")[0]["Outputs"]

            self._batch_service_role = _stack_out("BatchServiceRole", outs)
            self._ecs_instance_role = _stack_out("EcsInstanceRole", outs)
            self._spot_fleet_role = _stack_out("SpotFleetRole", outs)
            self._ecs_instance_profile = _stack_out("InstanceProfile", outs)
            self._vpc = _stack_out("VpcId", outs)
            self._subnets = _stack_out("SubnetIds", outs).split(",")
            self._security_group = _stack_out("SecurityGroupId", outs)

            vpc_response = aws.clients["ec2"].describe_vpcs(VpcIds=[self._vpc])["Vpcs"][
                0
            ]
            stack_instance_tenancy = vpc_response["InstanceTenancy"]
            stack_ipv4_cidr = vpc_response["CidrBlock"]
            ecs_response = aws.clients["iam"].list_attached_role_policies(
                RoleName=self._ecs_instance_role.split("/")[-1]
            )
            stack_policies = set(
                [d["PolicyName"] for d in ecs_response["AttachedPolicies"]]
            )

            # Pars exists, check that user did not provide any conflicting
            # resource names. This dict has values that are tuples, the first
            # value of which is the provided input parameter in __init__
            # and the second of which is the resource name in the AWS stack
            input_params = {
                "batch_service_role_name": (
                    batch_service_role_name,
                    self._batch_service_role,
                ),
                "ecs_instance_role_name": (
                    ecs_instance_role_name,
                    self._ecs_instance_role,
                ),
                "spot_fleet_role_name": (spot_fleet_role_name, self._spot_fleet_role),
                "ipv4_cidr": (ipv4_cidr, stack_ipv4_cidr),
                "instance_tenancy": (instance_tenancy, stack_instance_tenancy),
            }

            conflicting_params = {
                k: v for k, v in input_params.items() if v[0] and v[1] != v[0]
            }

            # Inspect policies separately since we only require policies
            # the input to be a subset of the stack-defined policies
            if not set(policies) <= stack_policies:
                conflicting_params["policies"] = (set(policies), stack_policies)

            if conflicting_params:
                raise aws.CloudknotInputError(
                    "You provided resources for a PARS that already exists in "
                    "config file {fn:s} but the ".format(fn=get_config_file())
                    + "AWS resources in that PARS stack conflict with some of "
                    "your input parameters. The conflicting parameters you "
                    "provided were {l}".format(l=list(conflicting_params.keys()))
                )

            conf_bsr = config.get(self._pars_name, "batch-service-role")
            conf_sfr = config.get(self._pars_name, "spot-fleet-role")
            conf_ecsr = config.get(self._pars_name, "ecs-instance-role")
            conf_ecsp = config.get(self._pars_name, "ecs-instance-profile")
            conf_vpc = config.get(self._pars_name, "vpc")
            conf_subnets = config.get(self._pars_name, "subnets")
            conf_sg = config.get(self._pars_name, "security-group")

            if not all(
                [
                    self._batch_service_role == conf_bsr,
                    self._ecs_instance_role == conf_ecsr,
                    self._ecs_instance_profile == conf_ecsp,
                    self._spot_fleet_role == conf_sfr,
                    self._vpc == conf_vpc,
                    ",".join(self._subnets) == conf_subnets,
                    self._security_group == conf_sg,
                ]
            ):
                raise aws.CloudknotConfigurationError(
                    "The resources in the CloudFormation stack do not match "
                    "the resources in the cloudknot configuration file. "
                    "Please try a different name."
                )
        else:
            # Pars doesn't exist, use input to create resources
            def validated_name(role_name, fallback_suffix):
                # Validate role name input
                if role_name:
                    if not isinstance(role_name, six.string_types):
                        raise aws.CloudknotInputError(
                            "if provided, role names must be strings."
                        )
                else:
                    role_name = name + "-" + fallback_suffix

                return role_name

            batch_service_role_name = validated_name(
                batch_service_role_name, "batch-service-role"
            )
            ecs_instance_role_name = validated_name(
                ecs_instance_role_name, "ecs-instance-role"
            )
            spot_fleet_role_name = validated_name(
                spot_fleet_role_name, "spot-fleet-role"
            )

            # Check the user supplied policies. Remove redundant entries
            if isinstance(policies, six.string_types):
                input_policies = {policies}
            else:
                try:
                    if all(isinstance(x, six.string_types) for x in policies):
                        input_policies = set(list(policies))
                    else:
                        raise aws.CloudknotInputError(
                            "policies must be a string or a " "sequence of strings."
                        )
                except TypeError:
                    raise aws.CloudknotInputError(
                        "policies must be a string " "or a sequence of strings"
                    )

            # Validate policies against the available policies
            policy_arns = []
            policy_names = []
            for policy in input_policies:
                try:
                    aws.clients["iam"].get_policy(PolicyArn=policy)
                    policy_arns.append(policy)
                except (
                    aws.clients["iam"].exceptions.InvalidInputException,
                    aws.clients["iam"].exceptions.NoSuchEntityException,
                    botocore.exceptions.ParamValidationError,
                ):
                    policy_names.append(policy)

            if policy_names:
                # Get all AWS policies
                paginator = aws.clients["iam"].get_paginator("list_policies")
                response_iterator = paginator.paginate()

                # response_iterator is a list of dicts. First convert to list of lists
                # and the flatten to a single list
                response_policies = [
                    response["Policies"] for response in response_iterator
                ]
                policies_list = [
                    lst for sublist in response_policies for lst in sublist
                ]

                aws_policies = {d["PolicyName"]: d["Arn"] for d in policies_list}

                # If input policies are not subset of aws_policies, throw error
                if not (set(policy_names) < set(aws_policies.keys())):
                    bad_policies = set(policy_names) - set(aws_policies.keys())
                    raise aws.CloudknotInputError(
                        "Could not find the policies {bad_policies!s} on "
                        "AWS.".format(bad_policies=bad_policies)
                    )

                policy_arns += [aws_policies[policy] for policy in policy_names]

            s3_params = aws.get_s3_params()
            policy_list = [s3_params.policy_arn] + [policy for policy in policy_arns]
            policies = ",".join(policy_list)

            if use_default_vpc:
                if any([ipv4_cidr, instance_tenancy]):
                    raise aws.CloudknotInputError(
                        "if using the default VPC, you cannot specify "
                        "`ipv4_cidr` or `instance_tenancy`."
                    )

                # Retrieve the default VPC ID
                try:
                    response = aws.clients["ec2"].create_default_vpc()
                    vpc_id = response.get("Vpc").get("VpcId")
                except aws.clients["ec2"].exceptions.ClientError as e:
                    error_code = e.response.get("Error").get("Code")
                    if error_code == "DefaultVpcAlreadyExists":
                        # Then use first default VPC
                        response = aws.clients["ec2"].describe_vpcs(
                            Filters=[{"Name": "isDefault", "Values": ["true"]}]
                        )
                        vpc_id = response.get("Vpcs")[0].get("VpcId")
                    elif error_code == "UnauthorizedOperation":
                        raise aws.CannotCreateResourceException(
                            "Cannot create a default VPC because this is an "
                            "unauthorized operation. You may not have the "
                            "proper permissions to create a default VPC."
                        )
                    elif error_code == "OperationNotPermitted":
                        raise aws.CannotCreateResourceException(
                            "Cannot create a default VPC because this is an "
                            "unauthorized operation. You might have resources "
                            "in EC2-Classic in the current region."
                        )
                    else:  # pragma: nocover
                        raise e
                except NotImplementedError as e:
                    moto_msg = (
                        "The create_default_vpc action has not " "been implemented"
                    )
                    if moto_msg in e.args:
                        # This exception is here for compatibility with
                        # moto testing since the create_default_vpc
                        # action has not been implemented in moto.
                        # Pretend that the default vpc already exists
                        response = aws.clients["ec2"].describe_vpcs(
                            Filters=[{"Name": "isDefault", "Values": ["true"]}]
                        )
                        vpc_id = response.get("Vpcs")[0].get("VpcId")
                    else:
                        raise e

                # Retrieve the subnets for the default VPC
                paginator = aws.clients["ec2"].get_paginator("describe_subnets")
                response_iterator = paginator.paginate(
                    Filters=[{"Name": "vpc-id", "Values": [vpc_id]}]
                )

                # response_iterator is a list of dicts. First convert to list
                # of lists and then flatten to a single list
                response_subnets = [
                    response["Subnets"] for response in response_iterator
                ]
                subnets_list = [lst for sublist in response_subnets for lst in sublist]
                subnet_ids = [d["SubnetId"] for d in subnets_list]
                subnet_zones = [d["AvailabilityZone"] for d in subnets_list]

                response = aws.clients["ec2"].describe_availability_zones()
                zones = [
                    d["ZoneName"]
                    for d in response.get("AvailabilityZones")
                    if d["State"] == "available"
                ]

                # If this region doesn't have a subnet in each availability
                # zone, then create the required subnets and repopulate
                # the subnet list
                if set(subnet_zones) < set(zones):
                    for z in set(zones) - set(subnet_zones):
                        aws.clients["ec2"].create_default_subnet(AvailabilityZone=z)

                    response_iterator = paginator.paginate(
                        Filters=[{"Name": "vpc-id", "Values": [vpc_id]}]
                    )

                    # response_iterator is a list of dicts. First convert to
                    # list of lists and then flatten to a single list
                    response_subnets = [
                        response["Subnets"] for response in response_iterator
                    ]
                    subnets_list = [
                        lst for sublist in response_subnets for lst in sublist
                    ]
                    subnet_ids = [d["SubnetId"] for d in subnets_list]

                template_path = os.path.abspath(
                    os.path.join(
                        os.path.dirname(__file__),
                        "templates",
                        "pars-with-default-vpc.template",
                    )
                )

                with open(template_path, "r") as fp:
                    template_body = fp.read()

                response = aws.clients["cloudformation"].create_stack(
                    StackName=self.name + "-pars",
                    TemplateBody=template_body,
                    Parameters=[
                        {
                            "ParameterKey": "BatchServiceRoleName",
                            "ParameterValue": batch_service_role_name,
                        },
                        {
                            "ParameterKey": "EcsInstanceRoleName",
                            "ParameterValue": ecs_instance_role_name,
                        },
                        {
                            "ParameterKey": "SpotFleetRoleName",
                            "ParameterValue": spot_fleet_role_name,
                        },
                        {"ParameterKey": "IamPolicies", "ParameterValue": policies},
                        {"ParameterKey": "VpcId", "ParameterValue": vpc_id},
                        {
                            "ParameterKey": "Subnets",
                            "ParameterValue": ",".join(subnet_ids),
                        },
                    ],
                    Capabilities=["CAPABILITY_NAMED_IAM"],
                    Tags=self.tags,
                )

                self._stack_id = response["StackId"]

                waiter = aws.clients["cloudformation"].get_waiter(
                    "stack_create_complete"
                )
                waiter.wait(StackName=self._stack_id, WaiterConfig={"Delay": 10})

                response = aws.clients["cloudformation"].describe_stacks(
                    StackName=self._stack_id
                )

                outs = response.get("Stacks")[0]["Outputs"]

                self._batch_service_role = _stack_out("BatchServiceRole", outs)
                self._ecs_instance_role = _stack_out("EcsInstanceRole", outs)
                self._spot_fleet_role = _stack_out("SpotFleetRole", outs)
                self._ecs_instance_profile = _stack_out("InstanceProfile", outs)
                self._vpc = _stack_out("VpcId", outs)
                self._subnets = _stack_out("SubnetIds", outs).split(",")
                self._security_group = _stack_out("SecurityGroupId", outs)
            else:
                # Check that ipv4 is a valid network range or set default value
                if ipv4_cidr:
                    try:
                        ipv4_cidr = str(ipaddress.IPv4Network(six.text_type(ipv4_cidr)))
                    except (ipaddress.AddressValueError, ValueError):
                        raise aws.CloudknotInputError(
                            "If provided, ipv4_cidr must be a valid IPv4 "
                            "network range."
                        )
                else:
                    ipv4_cidr = str(ipaddress.IPv4Network("172.31.0.0/16"))

                # Validate instance_tenancy input
                if instance_tenancy:
                    if instance_tenancy in ("default", "dedicated"):
                        instance_tenancy = instance_tenancy
                    else:
                        raise aws.CloudknotInputError(
                            "If provided, instance tenancy must be "
                            'one of ("default", "dedicated").'
                        )
                else:
                    instance_tenancy = "default"

                # Get subnet CIDR blocks
                # Get an IPv4Network instance representing the VPC CIDR block
                cidr = ipaddress.IPv4Network(six.text_type(ipv4_cidr))

                # Get list of subnet CIDR blocks
                subnet_ipv4_cidrs = list(cidr.subnets(new_prefix=20))

                if len(subnet_ipv4_cidrs) < 2:  # pragma: nocover
                    raise aws.CloudknotInputError(
                        "If provided, ipv4_cidr must be large enough to "
                        "accomodate two subnets. If you don't know what this "
                        "means, try the default value or specify "
                        "`use_default_vpc=True`."
                    )

                subnet_ipv4_cidrs = subnet_ipv4_cidrs[:2]

                template_path = os.path.abspath(
                    os.path.join(
                        os.path.dirname(__file__),
                        "templates",
                        "pars-with-new-vpc.template",
                    )
                )

                with open(template_path, "r") as fp:
                    template_body = fp.read()

                response = aws.clients["cloudformation"].create_stack(
                    StackName=self.name + "-pars",
                    TemplateBody=template_body,
                    Parameters=[
                        {
                            "ParameterKey": "BatchServiceRoleName",
                            "ParameterValue": batch_service_role_name,
                        },
                        {
                            "ParameterKey": "EcsInstanceRoleName",
                            "ParameterValue": ecs_instance_role_name,
                        },
                        {
                            "ParameterKey": "SpotFleetRoleName",
                            "ParameterValue": spot_fleet_role_name,
                        },
                        {"ParameterKey": "IamPolicies", "ParameterValue": policies},
                        {"ParameterKey": "VpcCidr", "ParameterValue": ipv4_cidr},
                        {
                            "ParameterKey": "VpcInstanceTenancy",
                            "ParameterValue": instance_tenancy,
                        },
                        {
                            "ParameterKey": "Subnet1Cidr",
                            "ParameterValue": str(subnet_ipv4_cidrs[0]),
                        },
                        {
                            "ParameterKey": "Subnet2Cidr",
                            "ParameterValue": str(subnet_ipv4_cidrs[1]),
                        },
                    ],
                    Capabilities=["CAPABILITY_NAMED_IAM"],
                    Tags=self.tags,
                )

                self._stack_id = response["StackId"]

                waiter = aws.clients["cloudformation"].get_waiter(
                    "stack_create_complete"
                )
                waiter.wait(StackName=self._stack_id, WaiterConfig={"Delay": 10})

                response = aws.clients["cloudformation"].describe_stacks(
                    StackName=self._stack_id
                )

                outs = response.get("Stacks")[0]["Outputs"]

                self._batch_service_role = _stack_out("BatchServiceRole", outs)
                self._ecs_instance_role = _stack_out("EcsInstanceRole", outs)
                self._spot_fleet_role = _stack_out("SpotFleetRole", outs)
                self._ecs_instance_profile = _stack_out("InstanceProfile", outs)
                self._vpc = _stack_out("VpcId", outs)
                self._subnets = _stack_out("SubnetIds", outs).split(",")
                self._security_group = _stack_out("SecurityGroupId", outs)

            # Save the new pars resources in config object
            # Use config.set() for python 2.7 compatibility
            with rlock:
                config.read(get_config_file())
                config.add_section(self._pars_name)
                config.set(self._pars_name, "stack-id", self._stack_id)
                config.set(self._pars_name, "region", self.region)
                config.set(self._pars_name, "profile", self.profile)
                config.set(
                    self._pars_name, "batch-service-role", self._batch_service_role
                )
                config.set(
                    self._pars_name, "ecs-instance-role", self._ecs_instance_role
                )
                config.set(self._pars_name, "spot-fleet-role", self._spot_fleet_role)
                config.set(
                    self._pars_name, "ecs-instance-profile", self._ecs_instance_profile
                )
                config.set(self._pars_name, "vpc", self._vpc)
                config.set(self._pars_name, "subnets", ",".join(self._subnets))
                config.set(self._pars_name, "security-group", self._security_group)

                # Save config to file
                with open(get_config_file(), "w") as f:
                    config.write(f)

    @property
    def pars_name(self):
        """Return section name for this PARS in the cloudknot config file."""
        return self._pars_name

    @property
    def tags(self):
        """Return AWS resource tags for this stack and all of its constituent resources."""
        return self._tags

    @property
    def stack_id(self):
        """Return Cloudformation Stack ID for this PARS."""
        return self._stack_id

    @property
    def batch_service_role(self):
        """Return IAM batch service role associated with this PARS."""
        return self._batch_service_role

    @property
    def ecs_instance_role(self):
        """Return IAM ECS instance role associated with this PARS."""
        return self._ecs_instance_role

    @property
    def ecs_instance_profile(self):
        """Return IAM ECS instance profile associated with this PARS."""
        return self._ecs_instance_profile

    @property
    def spot_fleet_role(self):
        """Return IAM spot fleet role associated with this PARS."""
        return self._spot_fleet_role

    @property
    def vpc(self):
        """Return VPC ID attached to this PARS."""
        return self._vpc

    @property
    def subnets(self):
        """Return VPC subnets for this PARS."""
        return self._subnets

    @property
    def security_group(self):
        """Return security group ID attached to this PARS."""
        return self._security_group

    def clobber(self):
        """Delete associated AWS resources and remove section from config."""
        if self.clobbered:
            return

        self.check_profile_and_region()

        aws.clients["cloudformation"].delete_stack(StackName=self._stack_id)

        # Remove this section from the config file
        config = configparser.ConfigParser()

        with rlock:
            config.read(get_config_file())
            config.remove_section(self._pars_name)
            with open(get_config_file(), "w") as f:
                config.write(f)

        # Set the clobbered parameter to True,
        # preventing subsequent method calls
        self._clobbered = True

        mod_logger.info("Clobbered PARS {name:s}".format(name=self.name))


# noinspection PyPropertyAccess,PyAttributeOutsideInit
class Knot(aws.NamedObject):
    """
    A collection of resources and methods to submit jobs to AWS Batch.

    This object collects AWS resources that should be created once for each
    type of batch run. The resource set consists of a PARS; a docker image
    made from an input function or python script; a remote docker repo to
    house said image; and an AWS batch job definition, compute environment,
    and job queue. It also contains methods to submit batch jobs for a range
    of arguments.
    """

    def __init__(
        self,
        name=None,
        pars=None,
        pars_policies=(),
        docker_image=None,
        base_image=None,
        func=None,
        image_script_path=None,
        image_work_dir=None,
        image_github_installs=(),
        username=None,
        repo_name=None,
        image_tags=None,
        job_definition_name=None,
        job_def_vcpus=None,
        memory=None,
        retries=None,
        compute_environment_name=None,
        instance_types=None,
        min_vcpus=None,
        max_vcpus=None,
        desired_vcpus=None,
        volume_size=None,
        image_id=None,
        ec2_key_pair=None,
        bid_percentage=None,
        job_queue_name=None,
        priority=None,
        aws_resource_tags=None,
    ):
        """
        Initialize a Knot instance.

        Parameters
        ----------
        name : str, optional
            The name for this knot. Must be less than 46 characters.
            Must satisfy regular expression pattern: [a-zA-Z][-a-zA-Z0-9]*
            Default='${AWS-username}-default'

        pars : Pars, optional
            The PARS on which to base this knot's AWS resources
            Default: instance returned by Pars()

        pars_policies : tuple of strings
            tuple of names of AWS policies to attach to each role
            Default: ()

        docker_image : DockerImage, optional
            The pre-existing DockerImage instance to adopt. i.e.,
            you may construct your own Docker Image using
            ```
            d = cloudknot.DockerImage(*args)
            ```
            and then supply that docker image as a keyword arg using
            ```
            knot = cloudknot.Knot(..., docker_image=d)
            ```

        base_image : string
            Docker base image on which to base this Dockerfile.
            You may not specify both docker_image and base_image.
            Default: None will use the python base image for the
            current version of python

        func : function
            Python function to be dockerized

        image_script_path : str
            Path to file with python script to be dockerized

        image_work_dir : string
            Directory to store Dockerfile, requirements.txt, and python
            script with CLI
            Default: parent directory of script if `script_path` is provided
            else DockerImage creates a new directory, accessible by the
            `docker_image.build_path` property.

        image_github_installs : string or sequence of strings
            Github addresses for packages to install from github rather than
            PyPI (e.g. git://github.com/nrdg/cloudknot.git or
            git://github.com/nrdg/cloudknot.git@newfeaturebranch)
            Default: ()

        username : string
            default username created in Dockerfile and in batch job definition
            Default: 'cloudknot-user'

        repo_name : str, optional
            Name of the AWS ECR repository to store the created Docker image
            Default: return value of cloudknot.get_ecr_repo()

        image_tags : str or sequence of str
            Tags to be applied to this Docker image

        job_definition_name : str, optional
            Name for this knot's AWS Batch job definition
            Default: name + '-cloudknot-job-definition'

        job_def_vcpus : int, optional
            number of virtual cpus to be used to this knot's job definition
            Default: 1

        memory : int, optional
            memory (MiB) to be used for this knot's job definition
            Default: 8000

        retries : int, optional
            number of times a job can be moved to 'RUNNABLE' status.
            May be between 1 and 10
            Default: 1

        compute_environment_name : str
            Name for this knot's AWS Batch compute environment
            Default: name + '-cloudknot-compute-environment'

        instance_types : string or sequence of strings, optional
            Compute environment instance types
            Default: ('optimal',)

        min_vcpus : int, optional
            minimum number of virtual cpus for instances launched in this
            compute environment
            Default: 0

        max_vcpus : int, optional
            maximum number of virtual cpus for instances launched in this
            compute environment
            Default: 256

        desired_vcpus : int, optional
            desired number of virtual cpus for instances launched in this
            compute environment
            Default: 8

        volume_size : int, optional
            the size (in GiB) of the Amazon EBS volumes used for
            instances launched by AWS Batch. If not provided, cloudknot
            will use the default Amazon ECS-optimized AMI version based
            on Amazon Linux 1, which has an 8-GiB root volume and an
            additional 22-GiB volume used for the Docker image. If
            provided, cloudknot will use the ECS-optimized AMI based on
            Amazon Linux 2 and increase the attached volume size to the
            value of `volume_size`. If this parameter is provided, you
            may not specify the `image_id`.

        image_id : string or None, optional
            optional AMI id used for instances launched in this compute
            environment
            Default: None

        ec2_key_pair : string or None, optional
            optional EC2 key pair used for instances launched in this compute
            environment
            Default: None

        bid_percentage : int, optional
            Compute environment bid percentage if using spot instances
            Default: None, which means that on-demand instances are provisioned.

        job_queue_name : str, optional
            Name for this knot's AWS Batch job queue
            Default: name + '-cloudknot-job-queue'

        priority : int, optional
            Default priority for jobs in this knot's job queue
            Default: 1

        aws_resource_tags : dict or list of dicts
            Additional AWS resource tags to apply to this repository
        """
        # Validate name input
        if name is not None and not isinstance(name, six.string_types):
            raise aws.CloudknotInputError(
                "Knot name must be a string. You passed a " "{t!s}".format(t=type(name))
            )

        if name is None:
            name = aws.get_user() + "-default"

        if len(name) > 45:
            raise aws.CloudknotInputError("Knot name must be less than 46 characters.")

        super(Knot, self).__init__(name=name)
        self._knot_name = "knot " + name

        # Validate aws_resource_tags input before creating any resources
        self._tags = aws.get_tags(name=name, additional_tags=aws_resource_tags)

        image_tags = image_tags if image_tags else [name]

        # Check for existence of this knot in the config file
        config = configparser.ConfigParser()

        with rlock:
            config.read(get_config_file())

        if self._knot_name in config.sections():
            if any(
                [
                    pars,
                    pars_policies,
                    docker_image,
                    base_image,
                    func,
                    image_script_path,
                    image_work_dir,
                    username,
                    repo_name,
                    job_definition_name,
                    job_def_vcpus,
                    memory,
                    retries,
                    compute_environment_name,
                    instance_types,
                    min_vcpus,
                    max_vcpus,
                    desired_vcpus,
                    volume_size,
                    image_id,
                    ec2_key_pair,
                    bid_percentage,
                    job_queue_name,
                    priority,
                ]
            ):
                mod_logger.warning(
                    "You specified configuration arguments for a knot that "
                    "already exists. Cloudknot has returned the pre-existing "
                    "knot, ignoring all of your other input parameters, which "
                    "may or may not be the same. You should proceed with "
                    "caution and confirm that this knot's parameters are as "
                    "expected. If you want to be extra-safe, choose a "
                    "different name or clobber this pre-existing knot and "
                    "instantiate a new one with your input arguments."
                )

            mod_logger.info("Found knot {name:s} in config".format(name=name))

            self._region = config.get(self._knot_name, "region")
            self._profile = config.get(self._knot_name, "profile")
            self.check_profile_and_region()

            pars_name = config.get(self._knot_name, "pars")
            self._pars = Pars(name=pars_name)
            mod_logger.info(
                "Knot {name:s} adopted PARS "
                "{p:s}".format(name=self.name, p=self.pars.name)
            )

            image_name = config.get(self._knot_name, "docker-image")
            self._docker_image = dockerimage.DockerImage(name=image_name)
            mod_logger.info(
                "Knot {name:s} adopted docker image {dr:s}"
                "".format(name=self.name, dr=image_name)
            )

            if not self.docker_image.images:
                self.docker_image.build(tags=image_tags)
                mod_logger.info(
                    "knot {name:s} built docker image {i!s}"
                    "".format(name=self.name, i=self.docker_image.images)
                )

            if self.docker_image.repo_uri is None:
                repo_name = config.get(self._knot_name, "docker-repo")
                self._docker_repo = aws.DockerRepo(name=repo_name)
                mod_logger.info(
                    "Knot {name:s} adopted docker repository "
                    "{dr:s}".format(name=self.name, dr=repo_name)
                )

                self.docker_image.push(repo=self.docker_repo)
                mod_logger.info(
                    "Knot {name:s} pushed docker image {dr:s}"
                    "".format(name=self.name, dr=self.docker_image.name)
                )
            else:
                self._docker_repo = None

            self._stack_id = config.get(self._knot_name, "stack-id")

            if not is_valid_stack(self._stack_id):
                # Remove this section from the config file
                with rlock:
                    config.read(get_config_file())
                    config.remove_section(self._knot_name)
                    with open(get_config_file(), "w") as f:
                        config.write(f)
                raise aws.ResourceDoesNotExistException(
                    "The Knot cloudformation stack that you requested "
                    "does not exist. Cloudknot has deleted this Knot from "
                    "the config file, so you may be able to create a new "
                    "one simply by re-running your previous command.",
                    self._stack_id,
                )

            response = aws.clients["cloudformation"].describe_stacks(
                StackName=self._stack_id
            )
            outs = response.get("Stacks")[0]["Outputs"]

            job_def_arn = _stack_out("JobDefinition", outs)
            response = aws.clients["batch"].describe_job_definitions(
                jobDefinitions=[job_def_arn]
            )
            job_def = response.get("jobDefinitions")[0]
            job_def_name = job_def["jobDefinitionName"]
            job_def_env = job_def["containerProperties"]["environment"]
            bucket_env = [
                env for env in job_def_env if env["name"] == "CLOUDKNOT_JOBS_S3_BUCKET"
            ]
            output_bucket = bucket_env[0]["value"] if bucket_env else None
            job_def_retries = job_def["retryStrategy"]["attempts"]

            JobDef = namedtuple("JobDef", ["name", "arn", "output_bucket", "retries"])
            self._job_definition = JobDef(
                name=job_def_name,
                arn=job_def_arn,
                output_bucket=output_bucket,
                retries=job_def_retries,
            )

            self._compute_environment = _stack_out("ComputeEnvironment", outs)
            self._job_queue = _stack_out("JobQueue", outs)

            conf_jd = config.get(self._knot_name, "job-definition")
            conf_ce = config.get(self._knot_name, "compute-environment")
            conf_jq = config.get(self._knot_name, "job-queue")

            if not all(
                [
                    self._job_definition.arn == conf_jd,
                    self._compute_environment == conf_ce,
                    self._job_queue == conf_jq,
                ]
            ):
                raise aws.CloudknotConfigurationError(
                    "The resources in the CloudFormation stack do not match "
                    "the resources in the cloudknot configuration file. "
                    "Please try a different name."
                )

            self._job_ids = config.get(self._knot_name, "job_ids").split()
            self._jobs = [aws.BatchJob(job_id=jid) for jid in self.job_ids]
        else:
            if pars and not isinstance(pars, Pars):
                raise aws.CloudknotInputError(
                    "if provided, pars must be a " "Pars instance."
                )

            if docker_image and any(
                [
                    func,
                    image_script_path,
                    image_work_dir,
                    base_image,
                    image_github_installs,
                ]
            ):
                raise aws.CloudknotInputError(
                    "you gave redundant, possibly conflicting input: "
                    "`docker_image` and one of [`func`, `base_image`, "
                    "`image_script_path`, `image_work_dir`, "
                    "`image_github_installs`]"
                )

            if docker_image and not isinstance(docker_image, dockerimage.DockerImage):
                raise aws.CloudknotInputError(
                    "docker_image must be a cloudknot DockerImage instance."
                )

            # Validate names for job def, job queue, and compute environment
            job_definition_name = (
                job_definition_name
                if job_definition_name
                else name + "-cloudknot-job-definition"
            )
            compute_environment_name = (
                compute_environment_name
                if compute_environment_name
                else name + "-cloudknot-compute-environment"
            )
            job_queue_name = (
                job_queue_name if job_queue_name else name + "-cloudknot-job-queue"
            )

            # Validate job_def_vcpus input
            if job_def_vcpus:
                cpus = int(job_def_vcpus)
                if cpus < 1:
                    raise aws.CloudknotInputError("vcpus must be positive")
                else:
                    job_def_vcpus = cpus
            else:
                job_def_vcpus = 1

            # Set default memory
            try:
                memory = int(memory) if memory is not None else 8000
                if memory < 1:
                    raise aws.CloudknotInputError("memory must be positive")
            except ValueError:
                raise aws.CloudknotInputError("memory must be an integer")

            # Validate retries input
            try:
                retries = int(retries) if retries is not None else 1
                if retries < 1:
                    raise aws.CloudknotInputError("retries must be > 0")
                elif retries > 10:
                    raise aws.CloudknotInputError("retries must be < 10")
            except ValueError:
                raise aws.CloudknotInputError("retries must be an integer")

            # Validate priority
            try:
                priority = int(priority) if priority is not None else 1
                if priority < 1:
                    raise aws.CloudknotInputError("priority must be positive")
            except ValueError:
                raise aws.CloudknotInputError("priority must be an integer")

            # Set resource type, default to 'EC2' unless bid_percentage
            # is provided
            if bid_percentage is not None:
                resource_type = "SPOT"
            else:
                resource_type = "EC2"

            min_vcpus = int(min_vcpus) if min_vcpus else 0
            if min_vcpus < 0:
                raise aws.CloudknotInputError("min_vcpus must be non-negative")

            if min_vcpus > 0:
                mod_logger.warning(
                    "min_vcpus is greater than zero. This means that your "
                    "compute environment will maintain some EC2 vCPUs, "
                    "regardless of job demand, potentially resulting in "
                    "unnecessary AWS charges. We strongly recommend using "
                    "a compute environment with min_vcpus set to zero."
                )

            # Validate desired_vcpus input, default to 8
            desired_vcpus = int(desired_vcpus) if desired_vcpus is not None else 8
            if desired_vcpus < 0:
                raise aws.CloudknotInputError("desired_vcpus must be " "non-negative")

            # Validate max_vcpus, default to 256
            max_vcpus = int(max_vcpus) if max_vcpus is not None else 256
            if max_vcpus < 0:
                raise aws.CloudknotInputError("max_vcpus must be non-negative")

            if volume_size is not None and image_id is not None:
                raise aws.CloudknotInputError(
                    "If you provide volume_size, you cannot specify the image_id"
                )

            if volume_size is not None:
                if not isinstance(volume_size, int):
                    raise aws.CloudknotInputError("volume_size must be an integer.")
                if not volume_size > 0:
                    raise aws.CloudknotInputError(
                        "volume_size must be greater than zero."
                    )

            # Default instance type is 'optimal'
            instance_types = instance_types if instance_types else ["optimal"]
            if isinstance(instance_types, six.string_types):
                instance_types = [instance_types]
            elif all(isinstance(x, six.string_types) for x in instance_types):
                instance_types = list(instance_types)
            else:
                raise aws.CloudknotInputError(
                    "instance_types must be a string or a " "sequence of strings."
                )

            # Validate instance types
            valid_instance_types = {
                "optimal",
                # Current generation general purpose
                "t2",
                "m4",
                "m5",
                "m5d",
                "t2.nano",
                "t2.micro",
                "t2.small",
                "t2.medium",
                "t2.large",
                "t2.xlarge",
                "t2.2xlarge",
                "m4.large",
                "m4.xlarge",
                "m4.2xlarge",
                "m4.4xlarge",
                "m4.10xlarge",
                "m4.16xlarge",
                "m5.large",
                "m5.xlarge",
                "m5.2xlarge",
                "m5.4xlarge",
                "m5.12xlarge",
                "m5.24xlarge",
                "m5d.large",
                "m5d.xlarge",
                "m5d.2xlarge",
                "m5d.4xlarge",
                "m5d.12xlarge",
                "m5d.24xlarge",
                # Current generation compute optimized
                "c4",
                "c5",
                "c5d",
                "c4.large",
                "c4.xlarge",
                "c4.2xlarge",
                "c4.4xlarge",
                "c4.8xlarge",
                "c5.large",
                "c5.xlarge",
                "c5.2xlarge",
                "c5.4xlarge",
                "c5.9xlarge",
                "c5.18xlarge",
                "c5d.xlarge",
                "c5d.2xlarge",
                "c5d.4xlarge",
                "c5d.9xlarge",
                "c5d.18xlarge",
                # Current generation memory optimized
                "r4",
                "x1",
                "x1e",
                "r4.large",
                "r4.xlarge",
                "r4.2xlarge",
                "r4.4xlarge",
                "r4.8xlarge",
                "r4.16xlarge",
                "x1.16xlarge",
                "x1.32xlarge",
                "x1e.xlarge",
                "x1e.2xlarge",
                "x1e.4xlarge",
                "x1e.8xlarge",
                "x1e.16xlarge",
                "x1e.32xlarge",
                # Current generation storage optimized
                "d2",
                "h1",
                "i3",
                "d2.xlarge",
                "d2.2xlarge",
                "d2.4xlarge",
                "d2.8xlarge",
                "h1.2xlarge",
                "h1.4xlarge",
                "h1.8xlarge",
                "h1.16xlarge",
                "i3.large",
                "i3.xlarge",
                "i3.2xlarge",
                "i3.4xlarge",
                "i3.8xlarge",
                "i3.16xlarge",
                "i3.metal",
                # Current generation accelerated computing
                "f1",
                "g3",
                "p2",
                "p3",
                "f1.2xlarge",
                "f1.16xlarge",
                "g3.4xlarge",
                "g3.8xlarge",
                "g3.16xlarge",
                "p2.xlarge",
                "p2.8xlarge",
                "p2.16xlarge",
                "p3.2xlarge",
                "p3.8xlarge",
                "p3.16xlarge",
                # Previous generation general purpose
                "m1",
                "m3",
                "m1.small",
                "m1.medium",
                "m1.large",
                "m1.xlarge",
                "m3.medium",
                "m3.large",
                "m3.xlarge",
                "m3.2xlarge",
                # Previous generation compute optimized
                "c1",
                "cc2",
                "c3",
                "c1.medium",
                "c1.xlarge",
                "cc2.8xlarge",
                "c3.large",
                "c3.xlarge",
                "c3.2xlarge",
                "c3.4xlarge",
                "c3.8xlarge",
                # Previous generation memory optimized
                "m2",
                "cr1",
                "r3",
                "m2.xlarge",
                "m2.2xlarge",
                "m2.4xlarge",
                "cr1.8xlarge",
                "r3.large",
                "r3.xlarge",
                "r3.2xlarge",
                "r3.4xlarge",
                "r3.8xlarge",
                # Previous generation storage optimized
                "hs1",
                "i2",
                "hs1.8xlarge",
                "i2.xlarge",
                "i2.2xlarge",
                "i2.4xlarge",
                "i2.8xlarge",
                # Previous generation GPU optimized
                "g2",
                "g2.2xlarge",
                "g2.8xlarge",
                # Previous generation micro
                "t1.micro",
            }

            if not set(instance_types) < valid_instance_types:
                raise aws.CloudknotInputError(
                    "instance_types must be a subset of {types!s}".format(
                        types=valid_instance_types
                    )
                )

            if bid_percentage is not None:
                bid_percentage = int(bid_percentage)
                if bid_percentage < 0:
                    bid_percentage = 0
                elif bid_percentage > 100:
                    bid_percentage = 100

            # Validate image_id input
            if image_id is not None:
                if not isinstance(image_id, six.string_types):
                    raise aws.CloudknotInputError(
                        "if provided, image_id must " "be a string"
                    )

            # Validate ec2_key_pair input
            if ec2_key_pair is not None:
                if not isinstance(ec2_key_pair, six.string_types):
                    raise aws.CloudknotInputError(
                        "if provided, ec2_key_pair must be a string"
                    )

            def set_pars(knot_name, input_pars, pars_policies_):
                # Validate and set the PARS
                if input_pars:
                    pars_ = input_pars

                    mod_logger.info(
                        "knot {name:s} adopted PARS {p:s}".format(
                            name=knot_name, p=pars_.name
                        )
                    )
                    pars_cleanup_ = False
                else:
                    try:
                        pars_ = Pars(name=knot_name, policies=pars_policies_)
                    except aws.CannotCreateResourceException:
                        pars_ = Pars(
                            name=knot_name,
                            policies=pars_policies_,
                            use_default_vpc=False,
                        )

                    mod_logger.info(
                        "knot {name:s} created PARS {p:s}".format(
                            name=knot_name, p=pars_.name
                        )
                    )
                    pars_cleanup_ = True

                return pars_, pars_cleanup_

            def set_dockerimage(
                knot_name,
                input_docker_image,
                func_,
                script_path,
                work_dir,
                base_image_,
                github_installs,
                username_,
                tags,
                repo_name_,
            ):
                if input_docker_image:
                    di = input_docker_image

                    mod_logger.info(
                        "Knot {name:s} adopted docker image {i:s}"
                        "".format(name=knot_name, i=docker_image.name)
                    )
                else:
                    # Create and build the docker image
                    di = dockerimage.DockerImage(
                        func=func_,
                        script_path=script_path,
                        dir_name=work_dir,
                        base_image=base_image_,
                        github_installs=github_installs,
                        username=username_,
                    )

                if not di.images:
                    di.build(tags=tags)
                    mod_logger.info(
                        "knot {name:s} built docker image {i!s}"
                        "".format(name=knot_name, i=di.images)
                    )

                if di.repo_uri is None:
                    # Create the remote repo
                    repo_name_ = repo_name_ if repo_name_ else aws.get_ecr_repo()

                    # Later in __init__, we may abort this init because of
                    # inconsistent job def, compute env, or job queue
                    # parameters. If we do that, we don't want to leave a
                    # bunch of newly created resources around so keep track of
                    # whether this repo was created or adopted.
                    if config.has_option("docker-repos", repo_name_):
                        # Pre-existing repo, no cleanup necessary
                        repo_cleanup_ = False
                    elif repo_name_ == aws.get_ecr_repo():
                        repo_cleanup_ = False
                    else:
                        # Freshly created repo, cleanup necessary
                        repo_cleanup_ = True

                    dr = aws.DockerRepo(name=repo_name_)

                    mod_logger.info(
                        "knot {name:s} created/adopted docker repo "
                        "{r:s}".format(name=knot_name, r=dr.name)
                    )

                    # Push to remote repo
                    di.push(repo=dr)

                    mod_logger.info(
                        "knot {name:s} pushed it's docker image to the repo "
                        "{r:s}".format(name=knot_name, r=dr.name)
                    )
                else:
                    repo_cleanup_ = False
                    dr = None

                return di, dr, repo_cleanup_

            # Set default username
            username = str(username) if username else "cloudknot-user"

            executor = ThreadPoolExecutor(3)
            futures = {
                "pars": executor.submit(
                    set_pars,
                    knot_name=self.name,
                    input_pars=pars,
                    pars_policies_=pars_policies,
                ),
                "docker-image": executor.submit(
                    set_dockerimage,
                    knot_name=self.name,
                    input_docker_image=docker_image,
                    func_=func,
                    script_path=image_script_path,
                    work_dir=image_work_dir,
                    base_image_=base_image,
                    github_installs=image_github_installs,
                    username_=username,
                    tags=image_tags,
                    repo_name_=repo_name,
                ),
            }

            self._pars, pars_cleanup = futures["pars"].result()

            self._docker_image, self._docker_repo, repo_cleanup = futures[
                "docker-image"
            ].result()

            executor.shutdown()

            repo_uri = self.docker_image.repo_uri
            output_bucket = aws.get_s3_params().bucket

            response = aws.clients["cloudformation"].describe_stacks(
                StackName=self.pars.stack_id
            )
            pars_stack_name = response.get("Stacks")[0]["StackName"]

            params = [
                {"ParameterKey": "ParsStackName", "ParameterValue": pars_stack_name},
                {"ParameterKey": "DockerImage", "ParameterValue": repo_uri},
                {"ParameterKey": "JdName", "ParameterValue": job_definition_name},
                {"ParameterKey": "JdvCpus", "ParameterValue": str(job_def_vcpus)},
                {"ParameterKey": "JdMemory", "ParameterValue": str(memory)},
                {"ParameterKey": "JdUser", "ParameterValue": username},
                {"ParameterKey": "JdOutputBucket", "ParameterValue": output_bucket},
                {"ParameterKey": "JdRetries", "ParameterValue": str(retries)},
                {"ParameterKey": "JqName", "ParameterValue": job_queue_name},
                {"ParameterKey": "JqPriority", "ParameterValue": str(priority)},
                {"ParameterKey": "CeName", "ParameterValue": compute_environment_name},
                {"ParameterKey": "CeResourceType", "ParameterValue": resource_type},
                {"ParameterKey": "CeMinvCpus", "ParameterValue": str(min_vcpus)},
                {"ParameterKey": "CeTagNameValue", "ParameterValue": self.name},
                {"ParameterKey": "CeTagOwnerValue", "ParameterValue": aws.get_user()},
                {
                    "ParameterKey": "CeTagEnvironmentValue",
                    "ParameterValue": "cloudknot",
                },
                {
                    "ParameterKey": "CeDesiredvCpus",
                    "ParameterValue": str(desired_vcpus),
                },
                {"ParameterKey": "CeMaxvCpus", "ParameterValue": str(max_vcpus)},
                {
                    "ParameterKey": "CeInstanceTypes",
                    "ParameterValue": ",".join(instance_types),
                },
            ]

            if resource_type == "SPOT":
                params.append(
                    {
                        "ParameterKey": "CeBidPercentage",
                        "ParameterValue": str(bid_percentage),
                    }
                )

            if image_id is not None:
                params.append({"ParameterKey": "CeAmiId", "ParameterValue": image_id})

            if ec2_key_pair is not None:
                params.append(
                    {"ParameterKey": "CeEc2KeyPair", "ParameterValue": ec2_key_pair}
                )

            if volume_size is not None:
                params.append(
                    {"ParameterKey": "LtVolumeSize", "ParameterValue": str(volume_size)}
                )
                params.append(
                    {
                        "ParameterKey": "LtName",
                        "ParameterValue": name + "-cloudknot-launch-template",
                    }
                )

                # Set the image id to use the ECS-optimized Amazon Linux
                # 2 image

                # First, determine if we're running in moto for CI
                # by retrieving the account ID
                user = aws.clients["iam"].get_user()["User"]
                account_id = user["Arn"].split(":")[4]
                if account_id == "123456789012":
                    response = aws.clients["ec2"].describe_images()
                else:
                    response = aws.clients["ec2"].describe_images(Owners=["amazon"])

                ecs_optimized_images = sorted(
                    [
                        image
                        for image in response["Images"]
                        if image.get("Description") is not None
                        and "amazon linux ami 2" in image["Description"].lower()
                        and "x86_64 ecs hvm gp2" in image["Description"].lower()
                        and "gpu" not in image["Name"].lower()
                        and len(image["BlockDeviceMappings"]) == 1
                    ],
                    key=lambda image: image["CreationDate"],
                    reverse=True,
                )
                image_id = ecs_optimized_images[0]["ImageId"]

                params.append({"ParameterKey": "CeAmiId", "ParameterValue": image_id})

                template_path = os.path.abspath(
                    os.path.join(
                        os.path.dirname(__file__),
                        "templates",
                        "batch-environment-increase-ebs-volume.template",
                    )
                )
            else:
                template_path = os.path.abspath(
                    os.path.join(
                        os.path.dirname(__file__),
                        "templates",
                        "batch-environment.template",
                    )
                )

            with open(template_path, "r") as fp:
                template_body = fp.read()

            response = aws.clients["cloudformation"].create_stack(
                StackName=self.name + "-knot",
                TemplateBody=template_body,
                Parameters=params,
                Capabilities=["CAPABILITY_NAMED_IAM"],
                Tags=self.tags,
            )

            self._stack_id = response["StackId"]
            waiter = aws.clients["cloudformation"].get_waiter("stack_create_complete")
            waiter.wait(StackName=self._stack_id, WaiterConfig={"Delay": 10})

            response = aws.clients["cloudformation"].describe_stacks(
                StackName=self._stack_id
            )

            outs = response.get("Stacks")[0]["Outputs"]

            job_def_arn = _stack_out("JobDefinition", outs)
            response = aws.clients["batch"].describe_job_definitions(
                jobDefinitions=[job_def_arn]
            )
            job_def = response.get("jobDefinitions")[0]
            job_def_name = job_def["jobDefinitionName"]
            job_def_env = job_def["containerProperties"]["environment"]
            bucket_env = [
                e for e in job_def_env if e["name"] == "CLOUDKNOT_JOBS_S3_BUCKET"
            ]
            if bucket_env:
                job_def_output_bucket = bucket_env[0]["value"]
            else:
                job_def_output_bucket = None
            job_def_retries = job_def["retryStrategy"]["attempts"]

            if not all(
                [job_def_output_bucket == output_bucket, job_def_retries == retries]
            ):
                raise aws.CloudknotConfigurationError(
                    "The job definition parameters in the AWS CloudFormation "
                    "stack do not match the input parameters."
                )

            JobDef = namedtuple("JobDef", ["name", "arn", "output_bucket", "retries"])
            self._job_definition = JobDef(
                name=job_def_name,
                arn=job_def_arn,
                output_bucket=output_bucket,
                retries=retries,
            )

            self._compute_environment = _stack_out("ComputeEnvironment", outs)
            self._job_queue = _stack_out("JobQueue", outs)

            self._jobs = []
            self._job_ids = []

            # Save the new Knot resources in config object
            # Use config.set() for python 2.7 compatibility
            config = configparser.ConfigParser()

            with rlock:
                config.read(get_config_file())
                config.add_section(self._knot_name)
                config.set(self._knot_name, "region", self.region)
                config.set(self._knot_name, "profile", self.profile)
                config.set(self._knot_name, "stack-id", self.stack_id)
                config.set(self._knot_name, "pars", self.pars.name)
                config.set(self._knot_name, "docker-image", self.docker_image.name)
                config.set(
                    self._knot_name,
                    "docker-repo",
                    self.docker_repo.name if self.docker_repo else "None",
                )
                config.set(self._knot_name, "job-definition", self.job_definition.arn)
                config.set(
                    self._knot_name, "compute-environment", self.compute_environment
                )
                config.set(self._knot_name, "job-queue", self.job_queue)
                config.set(self._knot_name, "job_ids", "")

                # Save config to file
                with open(get_config_file(), "w") as f:
                    config.write(f)

    # Declare read-only properties
    @property
    def knot_name(self):
        """Return section name for this knot in the cloudknot config file."""
        return self._knot_name

    @property
    def tags(self):
        """Return AWS resource tags for this stack and all of its constituent resources."""
        return self._tags

    @property
    def stack_id(self):
        """Return Cloudformation Stack ID for this knot."""
        return self._stack_id

    @property
    def pars(self):
        """Return Pars instance attached to this knot."""
        return self._pars

    @property
    def docker_image(self):
        """Return DockerImage instance attached to this knot."""
        return self._docker_image

    @property
    def docker_repo(self):
        """Return DockerRepo instance attached to this knot."""
        return self._docker_repo

    @property
    def job_definition(self):
        """Return namedtuple describing the job definition attached to this knot.

        The fields are 'name', 'arn', 'output_bucket', and 'retries'
        """
        return self._job_definition

    @property
    def job_queue(self):
        """Return job queue ARN for this knot."""
        return self._job_queue

    @property
    def compute_environment(self):
        """Return compute environment ARN for this knot."""
        return self._compute_environment

    @property
    def jobs(self):
        """List BatchJob instances that this knot has launched."""
        return self._jobs

    @property
    def job_ids(self):
        """List batch job IDs that this knot has launched."""
        return self._job_ids

    def map(
        self, iterdata, env_vars=None, max_threads=64, starmap=False, job_type=None
    ):
        """Submit batch jobs for a range of commands and environment vars.

        Each item of `iterdata` is assumed to be a single input for the
        python function in this knot's docker image. If your function takes
        multiple arguments, pre-zip the arguments into a tuple, so that
        iterdata is an iterable of tuples, and set `starmap=True`.

        map returns a list of futures, which can return their result when
        the jobs are complete.

        Parameters
        ----------
        iterdata :
            An iteratable of input data

        env_vars : sequence of dicts
            Additional environment variables for the Batch environment
            Each dict must have only 'name' and 'value' keys. The same
            environment variables are applied for each item in `iterdata`.
            Default: None

        max_threads : int
            Maximum number of threads used to invoke.
            Default: 64

        starmap : bool
            If True, assume argument parameters are already grouped in
            tuples from a single iterable. This behavior is similar to
            `itertools.starmap()`. If False, assume argument parameters
            have not been "pre-zipped". Then the behavior is similar to
            python's built-in `map()` method.

        job_type : string, 'array' or 'independent'
            Type of batch job to submit. If 'array', then an array job is
            submitted (see
            https://docs.aws.amazon.com/batch/latest/userguide/array_jobs.html)
            with one child job for each input element and map returns one
            future for the entire results list. If job_type is 'independent'
            then one independent batch job is submitted for each input
            element and map returns a list of futures for each element of the
            results. If the length of ``iterdata`` is one and job_type is
            specified, it must be "independent."
            Default: 'array'

        Returns
        -------
        map : future or list of futures
            If `job_type` is 'array', a future for the list of results.
            If `job_type` is 'independent', list of futures for each job
        """
        if job_type is None:
            if len(iterdata) == 1:
                job_type = "independent"
            else:
                job_type = "array"

        if job_type not in ["array", "independent"]:
            raise ValueError("`job_type` must be 'array' or 'independent'.")

        if self.clobbered:
            raise aws.ResourceClobberedException(
                "This Knot has already been clobbered.", self.name
            )

        self.check_profile_and_region()

        if not isinstance(iterdata, Iterable):
            raise TypeError("iterdata must be an iterable.")

        # env_vars should be a sequence of sequences of dicts
        if env_vars and not all(isinstance(s, dict) for s in env_vars):
            raise aws.CloudknotInputError("env_vars must be a sequence of " "dicts")

        # and each dict should have only 'name' and 'value' keys
        if env_vars and not all(set(d.keys()) == {"name", "value"} for d in env_vars):
            raise aws.CloudknotInputError(
                "each dict in env_vars must have " 'keys "name" and "value"'
            )

        these_jobs = []

        if job_type == "independent":
            for input_ in iterdata:
                job = aws.BatchJob(
                    input_=input_,
                    starmap=starmap,
                    name="{n:s}-{i:d}".format(n=self.name, i=len(self.job_ids)),
                    job_queue=self.job_queue,
                    job_definition=self.job_definition,
                    environment_variables=env_vars,
                    array_job=False,
                )

                these_jobs.append(job)
                self._jobs.append(job)
                self._job_ids.append(job.job_id)
        else:
            job = aws.BatchJob(
                input_=iterdata,
                starmap=starmap,
                name="{n:s}-{i:d}".format(n=self.name, i=len(self.job_ids)),
                job_queue=self.job_queue,
                job_definition=self.job_definition,
                environment_variables=env_vars,
                array_job=True,
            )

            these_jobs.append(job)
            self._jobs.append(job)
            self._job_ids.append(job.job_id)

        if not these_jobs:
            return []

        config = configparser.ConfigParser()

        with rlock:
            config.read(get_config_file())
            config.set(self._knot_name, "job_ids", " ".join(self.job_ids))
            # Save config to file
            with open(get_config_file(), "w") as f:
                config.write(f)

        # Increase the max_pool_connections in the boto3 clients to prevent
        # https://github.com/boto/botocore/issues/766
        aws.refresh_clients(max_pool=max_threads)

        executor = ThreadPoolExecutor(max(min(len(these_jobs), max_threads), 2))

        futures = [executor.submit(lambda j: j.result(), jb) for jb in these_jobs]

        # Shutdown the executor but do not wait to return the futures
        executor.shutdown(wait=False)

        if job_type == "independent":
            return futures
        else:
            return futures[0]

    def view_jobs(self):
        """Print the job_id, name, and status of all jobs in self.jobs."""
        if self.clobbered:
            raise aws.ResourceClobberedException(
                "This Knot has already been clobbered.", self.name
            )

        self.check_profile_and_region()

        order = {
            "SUBMITTED": 0,
            "PENDING": 1,
            "RUNNABLE": 2,
            "STARTING": 3,
            "RUNNING": 4,
            "FAILED": 5,
            "SUCCEEDED": 6,
        }

        response = aws.clients["batch"].describe_jobs(jobs=self.job_ids)
        sorted_jobs = sorted(response.get("jobs"), key=lambda j: order[j["status"]])

        fmt = "{jobId:12s}        {jobName:20s}        {status:9s}"
        header = fmt.format(jobId="Job ID", jobName="Name", status="Status")
        print(header)
        print("-" * len(header))

        for job in sorted_jobs:
            print(fmt.format(**job))

    def clobber(self, clobber_pars=False, clobber_repo=False, clobber_image=False):
        """Delete associated AWS resources and remove section from config.

        Parameters
        ----------
        clobber_pars : boolean
            If true, clobber the associated Pars instance
            Default: False

        clobber_repo : boolean
            If true, clobber the associated DockerRepo instance
            Default: False

        clobber_image : boolean
            If true, clobber the associated DockerImage instance
            Default: False
        """
        if self.clobbered:
            return

        self.check_profile_and_region()

        # Delete all associated AWS resources
        with ThreadPoolExecutor(32) as e:
            # Iterate over copy of self.jobs since we are
            # removing from the list while iterating
            for job in list(self.jobs):
                e.submit(job.clobber)
                self._jobs.remove(job)

        aws.clients["cloudformation"].delete_stack(StackName=self._stack_id)

        if clobber_repo:
            dr = self.docker_repo
            if dr and dr.name != aws.get_ecr_repo():
                # if the docker repo instance exists and it is not the
                # default cloudknot ECR repo, then clobber it
                self.docker_repo.clobber()
            else:
                # Either the repo instance is unavailable or this is in
                # the default cloudknot ECR repo.
                uri = self.docker_image.repo_uri
                repo_name = uri.split("amazonaws.com/")[-1].split(":")[0]
                if repo_name == aws.get_ecr_repo():
                    # This is in the default ECR repo. So just delete the
                    # image from the remote repo, leaving other images
                    # untouched.
                    registry_id = uri.split(".")[0]
                    tag = uri.split(":")[-1]

                    aws.clients["ecr"].batch_delete_image(
                        registryId=registry_id,
                        repositoryName=repo_name,
                        imageIds=[{"imageTag": tag}],
                    )
                else:
                    # This is not the default repo, feel free to clobber
                    repo = aws.DockerRepo(name=repo_name)
                    repo.clobber()

        if clobber_image:
            self.docker_image.clobber()

        if clobber_pars:
            waiter = aws.clients["cloudformation"].get_waiter("stack_delete_complete")
            waiter.wait(StackName=self.stack_id, WaiterConfig={"Delay": 10})
            self.pars.clobber()

        # Remove this section from the config file
        config = configparser.ConfigParser()

        with rlock:
            config.read(get_config_file())
            config.remove_section(self._knot_name)
            with open(get_config_file(), "w") as f:
                config.write(f)

        # Set the clobbered parameter to True,
        # preventing subsequent method calls
        self._clobbered = True

        mod_logger.info("Clobbered Knot {name:s}".format(name=self.name))
