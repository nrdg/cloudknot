# Contributing

Contributions are welcome, and they are greatly appreciated! Every little bit
helps, and credit will always be given.

## Installing a development version of cloudknot

You can install a development version of cloudknot by cloning in the repository
and then typing

```bash
pip install -e .[dev]
```

Activate the pre-commit formatting hook by typing

```bash
pre-commit install
```

Before committing your work, you can check for formatting issues or errors by typing

```bash
make lint
make test
```

## Types of Contributions

You can contribute in many ways:

### Report Bugs

Report bugs at <https://github.com/nrdg/cloudknot/issues>.

If you are reporting a bug, please include:

-   Your operating system name and version.
-   Any details about your local setup that might be helpful in troubleshooting.
-   Detailed steps to reproduce the bug.

### Work on "good first issues"

Look through the GitHub issues for anything labelled "good first issue." These
are issues that we think would be especially appropriate for those new to
open-source software contribution.

### Fix Bugs

Look through the GitHub issues for bugs. Anything tagged with "bug" and "help
wanted" is open to whoever wants to implement it.

### Implement Features

Look through the GitHub issues for features. Anything tagged with "enhancement"
and "help wanted" is open to whoever wants to implement it.

### Write Documentation

Cloudknot could always use more documentation, whether as part of the
official afq-insight docs, in docstrings, or even on the web in blog posts,
articles, and such.

### Submit Feedback

The best way to send feedback is to file an issue at
<https://github.com/nrdg/cloudknot/issues>.

If you are proposing a feature:

-   Explain in detail how it would work.

-   Keep the scope as narrow as possible, to make it easier to implement.

-   Remember that this is a volunteer-driven project, and that contributions
    are welcome :)

## Maintainers

Cloudknot pushes a development version to
[Test-PyPI](https://test.pypi.org/) on every pull request merged into
the master branch. To release a new version of cloudknot, use the `publish_release.sh` script from the root directory, i.e.:
```bash
.maintenance/publish_release.sh <version_number>
```
For releases, use the following format for <version_number>:
"v<major>.<minor>.<micro>".
When executed, this will ask you if you want to customize the
`CHANGES.rst` document or the release notes. After that, cloudknot's
GitHub actions will take care of publishing the new release on PyPI and
creating a release on GitHub.
