.. _faq-label:

Frequently Asked Questions
==========================

.. container:: toggle

   .. container:: header

      How much is this thing going to cost?

   .. container:: content

      Cloudknot is free (both *gratis* and *libre*).
      EC2 and Spot instances launched from AWS Batch are `billed on a per-second basis
      <https://aws.amazon.com/blogs/aws/new-per-second-billing-for-ec2-instances-and-ebs-volumes/>`_.
      So feel free to submit jobs that complete in less than an hour. You can
      minimize your cost by using the cheapest appropriate instance type (see `EC2 pricing
      <https://aws.amazon.com/ec2/pricing/on-demand/>`_). You can specify the instance type
      by using `Knot`'s `instance_type` input argument. If you don't specify an instance
      type, the default is `optimal`, meaning that AWS Batch will select the most appropriate
      instance type. You can help Batch select the cheapest viable instance by specifying
      the lowest required memory to `Knot`'s `memory` input argument.

      Another way to lower your expenses is to use spot instances by specifying `Knot`'s
      `bid_percentage=bid`, where `bid` is an integer between 0 and 100. Then you can choose the cheapest region
      (see :ref:`region-shopping-label`).

.. container:: toggle

   .. container:: header

      My Batch jobs finished but my `future.result()` returns an error or exception. What gives?

   .. container:: content

      First off, sorry about the error. Please submit a `bug report
      <https://github.com/nrdg/cloudknot/issues>`_ so that we can try to prevent this
      error from happening again. But fear not, if the job succeeded, your results are
      probably still there. In addition to the results futures returned by `Knot.map()`,
      you can also access the `result()` method of each job in `Knot.jobs`.

      .. code-block:: python

         # Some code up here that did awesome cloudknot stuff

         >>> results_futures = knot.map(input_args)
         >>> r0 = results_futures[0]
         >>> r0.result()
         An error occured

         # Have no fear, results are still here
         >>> j0 = knot.jobs[0]
         >>> j0.result()
         An amazing result

      See :ref:`eg-label` for more details.

.. container:: toggle

   .. container:: header

      I'm having trouble installing or configuring cloudknot on an Amazon EC2 instance. Help!

   .. container:: content

      Do your error messages look similar to the ones reported in
      `this issue <https://github.com/nrdg/cloudknot/issues/131>`_?
      If so, you need to install Docker such that you can run Docker
      commands without sudo. See :ref:`install-label` for
      installation instructions on an EC2 instance.

.. container:: toggle

   .. container:: header

      I found a bug in my function and need to fix it and try it again on
      AWS Batch. What should I do?

   .. container:: content

      Debugging application the run on AWS Batch can be frustrating because you are managing both local and remote resources. AWS tries to ease this burden using containers and cloudknot tries to ease it further by abstracting away some of the AWS resource provisioning. But still, you will likely find bugs and have to rerun your code. You have two options here.

      #. Simply declare a new `ck.Knot()` instance with a different name
         from the previous instance. For example:

         .. code-block:: python

            >>> import cloudknot as ck

            >>> def my_awesome_func(args):
            ...     # Your amazing code goes here
            ...     return "Typo"
            ...

            >>> knot = ck.Knot(name="attempt0", func=my_awesome_func)

            >>> results_futures = knot.map(input_args)

            # Oops, I just realized there's a typo in `my_awesome_func`

            # Optionally clobber this knot to clean up resources on AWS
            >>> knot.clobber()

            # Fix the error in my function
            >>> def my_awesome_func(args):
            ...     # Your amazing code goes here
            ...     return "Correct result"
            ...

            # Instantiate a new knot. Note the different name
            >>> knot = ck.Knot(name="attempt1", func=my_awesome_func)

            # Try again with the same arguments
            >>> results_futures = knot.map(input_args)

      #. The first option works well for functions with simple dependencies.
         However, many scientific workflows have a high dependency burden.
         For example, in neuroimaging, it is not uncommon to have Docker base
         images that are 20 GB in size. Creating a branch new knot for these
         cases would force cloudknot to upload a brand new 20 GB Docker image
         to AWS ECR every time amend our function. This greatly increases the
         time devoted to development cycles. But don't despair. There is a
         way to capitalize upon Docker's layers to minimize upload time
         when you edit your functions. To do so, we need to introduce a few
         more cloudknot objects:

         .. code-block:: python

            >>> import cloudknot as ck

            >>> def my_awesome_func(args):
            ...     # Your amazing code goes here
            ...     return "Typo"
            ...

            # Create a DockerImage instance
            # base_image and github_installs are optional arguments just as
            # they are for ck.Knot
            # Note that we specify overwrite=True so that we can quickly
            # overwrite the cloudknot generated script, rather than writing
            # an entirely new one
            >>> image = ck.DockerImage(
            ...     name="my-awesome-function",
            ...     func=my_awesome_func,
            ...     base_image="some-large-base-image:tag",
            ...     github_installs="some-github-repo"
            ... )
            ...

            # Build the Docker image locally
            >>> image.build(tags=["a-really-helpful-tag"])

            # Create a DockerRepo instance to which to push this new local image
            >>> repo = ck.aws.DockerRepo(name=ck.get_ecr_repo())

            # Push the local image to the AWS ECR repo
            # For the first run, this might take a while if your Docker
            # base image is large
            >>> image.push(repo=repo)

            # Now instantiate a Knot, supplying the DockerImage we just created
            >>> knot = ck.Knot(name="attempt0", docker_image=image)

            >>> results_futures = knot.map(input_args)

            # Oops, I just realized there's a typo in `my_awesome_func`

            # Optionally clobber this knot to clean up resources on AWS
            >>> knot.clobber()

            # Fix the error in my function
            >>> def my_awesome_func(args):
            ...     # Your amazing code goes here
            ...     return "Correct result"
            ...

            # Rebuild and push the DockerImage, using all of the same commands
            # we used before. But this time, they should execute much faster.
            >>> image = ck.DockerImage(
            ...     name="my-awesome-function",
            ...     func=my_awesome_func,
            ...     base_image="some-large-base-image:tag",
            ...     github_installs="some-github-repo"
            ... )
            ...

            >>> image.build(tags=["a-really-helpful-tag"])

            >>> image.push(repo=repo)

            # Instantiate a new knot. Note the different name
            >>> knot = ck.Knot(name="attempt1", docker_image=image)

            # Try again with the same arguments
            >>> results_futures = knot.map(input_args)

.. container:: toggle

   .. container:: header

      I'm running on a Windows machine and I am getting the following error::

         docker.errors.DockerException: Install pypiwin32 package to enable npipe:// support,


   .. container:: content

      Turns out that's a bug in the installation of the pywin32 package.
      To complete the installation, you'll need to run the following command::

         python <path-to-python-env>\Scripts\pywin32_postinstall.py -install

      For example::

         python c:\users\my_user_name\anaconda3\envs\ck\Scripts\pywin32_postinstall.py -install
