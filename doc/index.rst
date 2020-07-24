Welcome to cloudknot
====================

"Knot" is a collective noun for a group of snakes. `Cloudknot` is a python
library designed to run your existing python code on
`AWS Batch <https://aws.amazon.com/batch>`_.

Usage
-----

.. code-block:: python

   import cloudknot as ck

   def random_mv_prod(b):
      """Here is a function I want to run on AWS Batch"""
      # Always import dependencies within the function
      import numpy as np

      x = np.random.normal(0, b, 1024)
      A = np.random.normal(0, b, (1024, 1024))

      return np.dot(A, x)

   # Create a `Knot`, the primary object in cloudknot (read the docs)
   knot = ck.Knot(name='random-mv-prod', func=random_mv_prod)

   # Submit the jobs
   import numpy as np
   result_futures = knot.map(np.linspace(0.1, 100, 20))

Motivation
----------

In the quest to minimize time-to-first-result, many computational scientists are
turning to cloud-based distributed computing with commercial vendors like
Amazon to run their computational workloads. Yet cloud computing remains
inaccessible to many researchers. A number of python scientific libraries have
sought to close this gap by allowing users to interact seamlessly with AWS
resources from within their python environment. For example, see
`cottoncandy <https://doi.org/10.5281/zenodo.1034342>`_ for interacting with
numpy array data on `Amazon S3 <https://aws.amazon.com/s3/>`_. Or see `pywren
<http://pywren.io/>`_, which enables users to run their existing python code
on `AWS Lambda <https://aws.amazon.com/lambda/>`_, providing convenient
distributed execution for jobs that fall within the AWS Lambda limits (maximum
300 seconds of execution time, 1.5 GB of RAM, 512 MB of local storage, and no
root access). For jobs that require more, we introduce cloudknot to execute
existing python code on AWS Batch.

Cloudknot takes as input a python function, Dockerizes it for use in an Amazon
ECS instance, and creates all the necessary AWS Batch constituent resources to
submit jobs. You can then use cloudknot to submit and view jobs for a range
of inputs.

Installation and getting started
--------------------------------

To install cloudknot and take your first few slithers,
visit :ref:`getting-started-label`

Documentation and API
---------------------

Most cloudknot users will only need to interact with the Knot and Pars classes
(perhaps the DockerImage class). For details on those objects and links to the
lower-level API, see :ref:`doc-label`.

Bugs and issues
---------------

If you are having issues, please let us know by `opening up a new issue
<https://github.com/nrdg/cloudknot/issues>`_.
You will probably want to tag your issue with the "bug" or "question" label.

Contribute
----------

We invite you to contribute to cloudknot. Take a look at the `source code
<https://github.com/nrdg/cloudknot>`_. Or tackle one of the `open issues
<https://github.com/nrdg/cloudknot/issues>`_. Issues labeled "help wanted"
or "good first issue" are particularly appropriate for beginners.

AWS Batch vs AWS Lambda
-----------------------

`AWS Lambda`_ is a service that runs your code
in response to certain events (e.g. file uploads). It starts executing very
quickly after the triggering event but it has `some limitations
<https://docs.aws.amazon.com/lambda/latest/dg/limits.html>`_ (e.g. on the
amount of memory or the size of your deployment package). If your existing
code falls within the AWS Lambda limitations, you should probably be using
AWS Lambda instead of AWS Batch. In that case, check out the excellent
`pywren <http://pywren.io/>`_. If your code exceeds the AWS Lambda limitations,
then welcome to cloudknot.

License
-------

The project is licensed under the `MIT license
<https://github.com/nrdg/cloudknot/blob/master/LICENSE>`_.

Citing cloudknot
----------------

If you use cloudknot in a scientific publication, we would appreciate
citations to the following paper:

`Cloudknot: A Python library to run your existing code on AWS Batch
<http://conference.scipy.org/proceedings/scipy2018/adam_richie-halford.html>`_
Richie-Halford and Rokem, Proceedings of the 17th python in science
conference, pp. 8-14, 2018.

Bibtex entry::

   @InProceedings{ adam_richie-halford-proc-scipy-2018,
     author    = { {A}dam {R}ichie-{H}alford and {A}riel {R}okem },
     title     = { {C}loudknot: {A} {P}ython {L}ibrary to {R}un your {E}xisting {C}ode on {A}{W}{S} {B}atch },
     booktitle = { {P}roceedings of the 17th {P}ython in {S}cience {C}onference },
     pages     = { 8 - 14 },
     year      = { 2018 },
     editor    = { {F}atih {A}kici and {D}avid {L}ippa and {D}illon {N}iederhut and {M} {P}acer },
     doi       = { 10.25080/Majora-4af1f417-001 }
   }

Acknowledgements
----------------

Cloudknot development is supported through a grant from the `Gordon and Betty
Moore Foundation <https://www.moore.org/>`_ and from the `Alfred P. Sloan
Foundation <https://sloan.org/>`_ to the `University of Washington eScience
Institute <http://escience.washington.edu/>`_, as well as NIH Collaborative
Research in Computational Neuroscience grant R01EB027585-01 through the National
Institute of Biomedical Imaging and Bioengineering to Eleftherios Garyfallidis
(Indiana University) and Ariel Rokem (University of Washington).

.. toctree::
   :hidden:

   getting started <getting_started>
   documentation <documentation>
   faq <faq>
   examples <https://github.com/nrdg/cloudknot/tree/master/examples>
   code <https://github.com/nrdg/cloudknot>
   bugs <https://github.com/nrdg/cloudknot/issues>
