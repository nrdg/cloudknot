---
title: 'Cloudknot: run your existing python code on AWS batch'
tags:
  - AWS
  - python
  - batch
authors:
 - name: Adam C Richie-Halford
   orcid: 0000-0001-9276-9084
   affiliation: 1
 - name: Ariel Rokem
   orcid: 0000-0003-0679-1985
   affiliation: 2
affiliations:
 - name: University of Washington, Department of Physics
   index: 1
 - name: University of Washington, eScience Institute
   index: 2
date: 14 November 2017
bibliography: paper.bib
---

# Summary

In the quest to minimize time-to-first-result, many computational scientists are
turning to cloud-based distributed computing with commercial vendors like
Amazon to run their computational workloads. Yet cloud computing remains
inaccessible to many researchers. A number of python scientific libraries have
sought to close this gap by allowing users to interact seamlessly with AWS
resources from within their python environment. For example, see
cottoncandy [@cottoncandy] for interacting with numpy array data on Amazon
S3 [@S3]. Or see pywren [@pywren], which enables users to run their existing
python code on AWS Lambda [@AWSLambda], providing convenient distributed
execution for jobs that fall within the AWS Lambda limits (maximum 300 seconds
of execution time, 1.5 GB of RAM, 512 MB of local storage, and no root access).
For jobs that require more, we introduce cloudknot [@cloudknot] to execute
existing python code on AWS Batch [@AWSBatch].

Cloudknot takes as input a python function, Dockerizes it for use in an Amazon
ECS instance, and creates all the necessary AWS Batch constituent resources to
submit jobs. Users can then use cloudknot to submit and view jobs for a range
of inputs. For more details and usage examples, please see the cloudknot
documentation [@cloudknotdocs] and examples [@cloudknotexamples].

# Acknowledgements

Cloudknot development is supported through a grant from the
[Gordon and Betty Moore Foundation](https://www.moore.org/) and from the
[Alfred P. Sloan Foundation](https://sloan.org) to the
[University of Washington eScience Institute](http://escience.washington.edu/)


# References
