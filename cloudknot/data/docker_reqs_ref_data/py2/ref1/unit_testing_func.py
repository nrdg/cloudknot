from clize import run


def unit_testing_func(name=None, no_capitalize=False):
    """Test function for unit testing of cloudknot.DockerImage

    Import statements of various formats are deliberately scattered
    throughout the function to test the pipreqs components of
    clouknot.DockerImage
    """
    import sys  # noqa: F401
    import boto3.ec2  # noqa: F401
    import AFQ  # noqa: F401
    if name:
        from docker import api  # noqa: F401
        from os.path import join  # noqa: F401

        if not no_capitalize:
            import pytest as pt  # noqa: F401
            import h5py.utils as h5utils  # noqa: F401

            name = name.title()

        return 'Hello {0}!'.format(name)

    from six import binary_type as bt  # noqa: F401
    from dask.base import curry as dbc  # noqa: F401

    return 'Hello world!'


if __name__ == "__main__":
    run(unit_testing_func)
