# Cloudknot Examples

This is a collection of cloudknot examples in jupyter notebooks.
You will need to have jupyter notebook installed to run these examples:

    $ pip install notebook

Then launch the jupyter notebook with:

    $ jupyter notebook

and select an example.

The examples in this directory are:

-   `00_random_matrix_vector_multiply.ipynb`: demonstrates how to use cloudknot
    to multiply a bunch of random matrices and vectors.

-   `01_a_bunch_of_hellos.ipynb`: demonstrates how to use cloudknot to write 
    "hello" a bunch of times.

-   `02_process_mri_data.ipynb`: a non-trivial example demonstrating how to use
    cloudknot to process MRI data using pyAFQ.

-   `03_write_to_s3_bucket.ipynb`: demonstrates how to use cloudknot to submit
    AWS batch jobs that write a simple text file to an S3 bucket.

-   `04_using_docker_image.ipynb`: demonstrates how to use the `DockerImage`
    class to dockerize an arbitrary python function when `Knot`'s automatic
    Dockerization won't do.
