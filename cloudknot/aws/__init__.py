"""The aws submodule contains classes representing AWS resources

This module contains classes representing AWS resources:
    - IamRole : AWS IAM role
    - Vpc : Amazon virtual private cloud
    - SecurityGroup : AWS security group
    - DockerRepo : AWS ECR repository
    - JobDefinition : AWS Batch job definition
    - ComputeEnvironment : AWS Batch compute environment
    - JobQueue : AWS Batch job queue
    - BatchJob : AWS Batch job

For each class, you may specify an identifier for an existing AWS resource
or specify parameters to create a new resource on AWS. Higher level resources
(e.g. ComputeEnvironment) take subordinate resources (e.g. IamRole) as input.
"""
from __future__ import absolute_import, division, print_function

from .base_classes import *  # noqa: F401,F403
from .batch import *  # noqa: F401,F403
from .ec2 import *  # noqa: F401,F403
from .ecr import *  # noqa: F401,F403
from .iam import *  # noqa: F401,F403
