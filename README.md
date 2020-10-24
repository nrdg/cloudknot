[![Build Status](https://github.com/nrdg/cloudknot/workflows/build/badge.svg)](https://github.com/nrdg/cloudknot/workflows/build/badge.svg)
[![Coverage Status](https://coveralls.io/repos/github/nrdg/cloudknot/badge.svg?branch=master)](https://coveralls.io/github/nrdg/cloudknot?branch=master)
[![Codacy Badge](https://app.codacy.com/project/badge/Grade/4a5d0c767bfd4f0eae820c24df1ce2a8)](https://www.codacy.com/gh/nrdg/cloudknot?utm_source=github.com&utm_medium=referral&utm_content=nrdg/cloudknot&utm_campaign=Badge_Grade)
[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/python/black)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![DOI](https://zenodo.org/badge/102051437.svg)](https://zenodo.org/badge/latestdoi/102051437)

# cloudknot

A knot is a collective noun for a group of snakes. Cloudknot is a python
library designed to run your existing python code on
[AWS Batch](https://aws.amazon.com/batch).

Cloudknot takes as input a python function, Dockerizes it for use in an
Amazon ECS instance, and creates all the necessary AWS Batch constituent
resources to submit jobs. You can then use cloudknot to submit and view jobs
for a range of inputs.

To get started using cloudknot, please see the [cloudknot documentation](https://nrdg.github.io/cloudknot/)

This is the cloudknot development site. You can view the source code, file new
issues, and contribute to cloudknot's development. If you are just getting
started, you should look at the
[cloudknot documentation](https://nrdg.github.io/cloudknot/).

## Contributing

We love contributions! Cloudknot is open source, built on open source,
and we'd love to have you hang out in our community.

We have developed some [guidelines](CONTRIBUTING.md) for contributing to
cloudknot.

**Imposter syndrome disclaimer**: We want your help. No, really.

There may be a little voice inside your head that is telling you that
you're not ready to be an open source contributor; that your skills
aren't nearly good enough to contribute. What could you possibly offer a
project like this one?

We assure you - the little voice in your head is wrong. If you can
write code at all, you can contribute code to open source. Contributing
to open source projects is a fantastic way to advance one's coding
skills. Writing perfect code isn't the measure of a good developer (that
would disqualify all of us!); it's trying to create something, making
mistakes, and learning from those mistakes. That's how we all improve,
and we are happy to help others learn.

Being an open source contributor doesn't just mean writing code, either.
You can help out by writing documentation, tests, or even giving
feedback about the project (and yes - that includes giving feedback
about the contribution process). Some of these contributions may be the
most valuable to the project as a whole, because you're coming to the
project with fresh eyes, so you can see the errors and assumptions that
seasoned contributors have glossed over.

## Citing cloudknot

If you use cloudknot in a scientific publication, please see our [citation
instructions](https://nrdg/github.io/cloudknot/index.html#citing-cloudknot).

## Credits

Cloudknot development is supported through a grant from the [Gordon
and Betty Moore Foundation](https://www.moore.org/) and from the
[Alfred P. Sloan Foundation](https://sloan.org/) to the [University of
Washington eScience Institute](http://escience.washington.edu/), as
well as NIH Collaborative Research in Computational Neuroscience grant
R01EB027585-01 through the National Institute of Biomedical Imaging and
Bioengineering to Eleftherios Garyfallidis (Indiana University) and
Ariel Rokem (University of Washington).

This package was created with
[shablona](https://github.com/uwescience/shablona).

The imposter syndrome disclaimer was originally written by
[Adrienne Lowe](https://github.com/adriennefriend) for a [PyCon
talk](https://www.youtube.com/watch?v=6Uj746j9Heo), and was
adapted based on its use in the README file for the [MetPy
project](https://github.com/Unidata/MetPy).
