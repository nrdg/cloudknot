Welcome to cloudknot
====================

A knot is a collective noun for a group of snakes. `Cloudknot` is a python
library designed to run your existing python code on
`AWS Batch <https://aws.amazon.com/batch>`_.

Features
--------

- Be awesome
- Make batch submission easier

Installation and getting started
--------------------------------

To install cloudknot and take your first few slithers,
visit :ref:`getting-started-label`

Documentation and API
---------------------

Most cloudknot users will only need to interact with the Knot and Pars classes
(perhaps the DockerImage class). For details on those objects, see
:ref:`doc-label`. For even more detail, see the :ref:`api-label` page.

Bugs and issues
---------------

If you are having issues, please let us know by `opening up a new issue
<https://github.com/richford/cloudknot/issues>`_.
You will probably want to tag your issue with the "bug" or "question" label.

Contribute
----------

We invite you to contribute to cloudknot. Take a look at the `source code
<https://github.com/richford/cloudknot>`_. Or tackle one of the `open issues
<https://github.com/richford/cloudknot/issues>`_. Issues labeled "help wanted"
or "good first issue" are particularly appropriate for beginners.

AWS Batch vs AWS Lambda
-----------------------

`AWS Lambda <https://aws.amazon.com/lambda>`_ is a service that runs your code
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

The project is licensed under the MIT license.

.. toctree::
   :hidden:

   getting_started
   documentation
   api
