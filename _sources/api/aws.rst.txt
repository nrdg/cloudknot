aws Module
==========

.. automodule:: cloudknot.aws

Classes
-------

.. autosummary::
   :template: autosummary/class.rst
   :toctree: _autosummary

   cloudknot.aws.DockerRepo
   cloudknot.aws.BatchJob

Functions
---------

.. autosummary::
   :template: autosummary/function.rst
   :toctree: _autosummary

   cloudknot.aws.get_region
   cloudknot.aws.set_region
   cloudknot.aws.get_profile
   cloudknot.aws.set_profile
   cloudknot.aws.list_profiles
   cloudknot.aws.refresh_clients
   cloudknot.aws.get_s3_params
   cloudknot.aws.set_s3_params

Clients
-------

.. autoattribute:: cloudknot.aws.clients

   Module-level dictionary of boto3 clients for IAM, EC2, Batch, ECR, and ECS.

   Storing the boto3 clients in a module-level dictionary allows us to change
   the region and profile and have those changes reflected globally.

   Advanced users: if you want to use cloudknot and boto3 at the same time,
   you should use these clients to ensure that you have the right profile
   and region.

Exceptions
----------

.. autosummary::
   :template: autosummary/class.rst
   :toctree: _autosummary

   cloudknot.aws.ResourceDoesNotExistException
   cloudknot.aws.ResourceClobberedException
   cloudknot.aws.ResourceExistsException
   cloudknot.aws.CannotDeleteResourceException
   cloudknot.aws.CannotCreateResourceException
   cloudknot.aws.RegionException
