.. _doc-label:

Documentation
=============

.. _knot-label:

Knot
----

The primary object in cloudknot is the `Knot`. It represents a collection of
AWS Batch resources and has methods for interacting with AWS Batch components.
For more detail, you can familiarize yourself with the `components of AWS Batch
<http://docs.aws.amazon.com/batch/latest/userguide/what-is-batch.html>`_.
`Knot` instantiation creates the required AWS resources. You can build a `Knot`
on top of a customized `Pars` (see below) or just use the default `Pars`
(default behavior). You can submit and view jobs using the `map` and `view_jobs`
methods. In particular, `map` returns a list of futures for each submitted job's
results. You can also inspect the :class:`cloudknot.aws.BatchJob` instance for
each job by accessing the knot's `jobs` parameter. To see `Knot` in action,
see :ref:`eg-label`.

.. container:: toggle

   .. container:: header

      cloudknot.Knot

   .. container:: content

      .. autoclass:: cloudknot.Knot


.. _pars-label:

Pars
----

While `Knot` creates job-specific resources, `Pars` creates persistent
resources that can be used for different types of AWS Batch workflows.
PARS stands for Persistent AWS Resource Set. You can use one `Pars` for
all of your cloudknot jobs. Or you may need to create `Pars` with different
permission sets for different types of jobs. See :ref:`eg-label` for
more details.

.. container:: toggle

   .. container:: header

      cloudknot.Pars

   .. container:: content

      .. autoclass:: cloudknot.Pars


.. _docker-image-label:

DockerImage
-----------

`DockerImage` is basically `Knot` without any of the AWS resources or
submit capabilities. It will take your existing code, create a command
line interface, and Dockerize it for later upload to AWS. If your function
has simple dependencies, then `Knot` will do all of this for you. If
you need more customization, then you may need to use `DockerImage` first.
See :ref:`eg-label` for more details.

.. container:: toggle

   .. container:: header

      cloudknot.DockerImage

   .. container:: content

      .. autoclass:: cloudknot.DockerImage


.. _clobber-label:

Clobbering and AWS resource persistence
---------------------------------------

Each cloudknot object has a `clobber` method that will delete all associated
AWS resources and remove references to those resources from the cloudknot
config file. If you do not clobber an instance, you can retrieve it in a later
cloudknot session by using its name in the initialization arguments. This
will reduce the overhead of AWS resource creation (especially if it means
avoiding pushing another Docker image for :ref:`Knots <knot-label>` or
:ref:`DockerImages <docker-image-label>`). However, if you know you are done
with a resource on AWS, it is good practice to clobber the associated cloudknot
object to reduce clutter and avoid name collisions.

API
---

For details on the rest of the cloudknot API, please see the following
module pages.

.. toctree::
   :maxdepth: 2

   api/aws
   api/config
