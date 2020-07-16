Frequently Asked Questions
==========================

.. container:: toggle

   .. container:: header

      How much is this thing going to cost?

   .. container:: content

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
      <https://github.com/richford/cloudknot/issues>`_ so that we can try to prevent this
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
      `this issue <https://github.com/richford/cloudknot/issues/131>`_?
      If so, you need to install Docker such that you can run Docker
      commands without sudo. See :ref:`install-label` for
      installation instructions on an EC2 instance.
