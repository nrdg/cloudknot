from __future__ import absolute_import, division, print_function

from os.path import join as pjoin

# Format expected by setup.py and doc/source/conf.py: string of form "X.Y.Z"
_version_major = 0
_version_minor = 2
_version_micro = 1  # use '' for first of series, number for 1 and above
# _version_extra = 'dev'
_version_extra = ''  # Uncomment this for full releases

# Construct full version string from these.
_ver = [_version_major, _version_minor]
if _version_micro:
    _ver.append(_version_micro)
if _version_extra:
    _ver.append(_version_extra)

__version__ = '.'.join(map(str, _ver))

CLASSIFIERS = ["Development Status :: 3 - Alpha",
               "Environment :: Console",
               "Intended Audience :: Science/Research",
               "License :: OSI Approved :: MIT License",
               "Operating System :: OS Independent",
               "Programming Language :: Python",
               "Topic :: Scientific/Engineering"]

# Description should be a one-liner:
description = ("cloudknot: a python library designed to run "
               "your existing python code on AWS Batch")
# Long description will go up on the pypi page
long_description = """
Cloudknot
========
Cloudknot is a python library designed to run your existing python code on
AWS Batch

Cloudknot takes as input a python function, Dockerizes it for use in an Amazon
ECS instance, and creates all the necessary AWS Batch constituent resources to
submit jobs. You can then use cloudknot to submit and view jobs for a range of
inputs.

To get started using cloudknot, please see the documentation_.

.. _documentation: https://richford.github.io/cloudknot/

License
=======
``cloudknot`` is licensed under the terms of the MIT license. See the file
"LICENSE" for information on the history of this software, terms & conditions
for usage, and a DISCLAIMER OF ALL WARRANTIES.

All trademarks referenced herein are property of their respective holders.

Copyright (c) 2017, Adam Richie-Halford, Ariel Rokem, University of Washington
"""

NAME = "cloudknot"
MAINTAINER = "Adam Richie-Halford"
MAINTAINER_EMAIL = "richiehalford@gmail.com"
DESCRIPTION = description
LONG_DESCRIPTION = long_description
URL = "http://github.com/richford/cloudknot"
DOWNLOAD_URL = ""
LICENSE = "MIT"
AUTHOR = "Adam Richie-Halford"
AUTHOR_EMAIL = "richiehalford@gmail.com"
PLATFORMS = "OS Independent"
MAJOR = _version_major
MINOR = _version_minor
MICRO = _version_micro
VERSION = __version__
PACKAGE_DATA = {'cloudknot': [pjoin('data', '*'), pjoin('templates', '*')]}
REQUIRES = ["awscli", "boto3", "cloudpickle", "docker", "pipreqs",
            "six", "tenacity", 'configparser;python_version<"3.0"']
EXTRAS_REQUIRE = {':python_version < "3.0"': ["configparser"]}
ENTRY_POINTS = {'console_scripts': ['cloudknot=cloudknot.cli:main']}
