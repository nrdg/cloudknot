# Cloudknot Examples

This is a collection of cloudknot examples in jupyter notebooks.
You will need to have jupyter notebook installed to run these examples:

    $ pip install notebook

Then launch the jupyter notebook with:

    $ jupyter notebook

and select an example.

The examples in this directory are:

- `write_to_s3_bucket.ipynb`: demonstrates how to use cloudknot to submit
  AWS batch jobs that write a simple text file to an S3 bucket.
- `using_docker_image.ipynb`: demonstrates how to use the `DockerImage`
  class to dockerize an arbitrary python function
- `using_knot.ipynb`: demonstrates how to use the `Knot` class to dockerize
  an arbitrary python function and create all of the necessary AWS resources
  to start submitting batch jobs.
