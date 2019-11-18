import boto3
import cloudpickle
import os
import pickle
from argparse import ArgumentParser
from functools import wraps


def pickle_to_s3(server_side_encryption=None, array_job=True):
    def real_decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            s3 = boto3.client("s3")
            bucket = os.environ.get("CLOUDKNOT_JOBS_S3_BUCKET")

            if array_job:
                array_index = os.environ.get("AWS_BATCH_JOB_ARRAY_INDEX")
            else:
                array_index = '0'

            jobid = os.environ.get("AWS_BATCH_JOB_ID")

            if array_job:
                jobid = jobid.split(':')[0]

            key = '/'.join([
                'cloudknot.jobs',
                os.environ.get("CLOUDKNOT_S3_JOBDEF_KEY"),
                jobid,
                array_index,
                '{0:03d}'.format(int(os.environ.get("AWS_BATCH_JOB_ATTEMPT"))),
                'output.pickle'
            ])

            result = f(*args, **kwargs)

            # Only pickle output and write to S3 if it is not None
            if result is not None:
                pickled_result = cloudpickle.dumps(result)
                if server_side_encryption is None:
                    s3.put_object(Bucket=bucket, Body=pickled_result, Key=key)
                else:
                    s3.put_object(Bucket=bucket, Body=pickled_result, Key=key,
                                  ServerSideEncryption=server_side_encryption)

        return wrapper
    return real_decorator


def unit_testing_func(name=None, no_capitalize=False):
    """Test function for unit testing of cloudknot.DockerImage

    Import statements of various formats are deliberately scattered
    throughout the function to test the pipreqs components of
    clouknot.DockerImage
    """
    import sys  # noqa: F401
    import boto3.ec2  # noqa: F401

    if name:
        from docker import api  # noqa: F401
        from os.path import join  # noqa: F401

        if not no_capitalize:
            import pytest as pt  # noqa: F401

            name = name.title()

        return "Hello {0}!".format(name)

    from six import binary_type as bt  # noqa: F401
    from dask.base import curry as dbc  # noqa: F401

    return "Hello world!"


if __name__ == "__main__":
    description = ('Download input from an S3 bucket and provide that input '
                   'to our function. On return put output in an S3 bucket.')

    parser = ArgumentParser(description=description)

    parser.add_argument(
        'bucket', metavar='bucket', type=str,
        help='The S3 bucket for pulling input and pushing output.'
    )

    parser.add_argument(
        '--starmap', action='store_true',
        help='Assume input has already been grouped into a single tuple.'
    )

    parser.add_argument(
        '--arrayjob', action='store_true',
        help='If True, this is an array job and it should reference the '
             'AWS_BATCH_JOB_ARRAY_INDEX environment variable.'
    )

    parser.add_argument(
        '--sse', dest='sse', action='store',
        choices=['AES256', 'aws:kms'], default=None,
        help='Server side encryption algorithm used when storing objects '
             'in S3.'
    )

    args = parser.parse_args()

    s3 = boto3.client('s3')
    bucket = args.bucket

    jobid = os.environ.get("AWS_BATCH_JOB_ID")

    if args.arrayjob:
        jobid = jobid.split(':')[0]

    key = '/'.join([
        'cloudknot.jobs',
        os.environ.get("CLOUDKNOT_S3_JOBDEF_KEY"),
        jobid,
        'input.pickle'
    ])

    response = s3.get_object(Bucket=bucket, Key=key)
    input_ = pickle.loads(response.get('Body').read())

    if args.arrayjob:
        array_index = int(os.environ.get("AWS_BATCH_JOB_ARRAY_INDEX"))
        input_ = input_[array_index]

    if args.starmap:
        pickle_to_s3(args.sse, args.arrayjob)(unit_testing_func)(*input_)
    else:
        pickle_to_s3(args.sse, args.arrayjob)(unit_testing_func)(input_)
