import os
import string
from setuptools import setup, find_packages
from setuptools_scm import get_version

PACKAGES = find_packages()

# Get release info, which is all stored in cloudknot/_meta.py
ver_file = os.path.join("cloudknot", "_meta.py")
with open(ver_file) as f:
    exec(f.read())


def local_version(version):
    """
    Patch in a version that can be uploaded to test PyPI
    """
    scm_version = get_version()
    if "dev" in scm_version:
        gh_in_int = []
        for char in version.node:
            if char.isdigit():
                gh_in_int.append(str(char))
            else:
                gh_in_int.append(str(string.ascii_letters.find(char)))
        return "".join(gh_in_int)
    else:
        return ""


opts = dict(
    name=NAME,
    maintainer=MAINTAINER,
    maintainer_email=MAINTAINER_EMAIL,
    description=DESCRIPTION,
    long_description=LONG_DESCRIPTION,
    url=URL,
    download_url=DOWNLOAD_URL,
    license=LICENSE,
    classifiers=CLASSIFIERS,
    author=AUTHOR,
    author_email=AUTHOR_EMAIL,
    platforms=PLATFORMS,
    packages=PACKAGES,
    package_data=PACKAGE_DATA,
    install_requires=REQUIRES,
    extras_require=EXTRAS_REQUIRE,
    entry_points=ENTRY_POINTS,
    use_scm_version={
        "root": ".",
        "relative_to": __file__,
        "write_to": "cloudknot/version.py",
        "local_scheme": local_version,
    },
    setup_requires=["setuptools_scm"],
)


if __name__ == "__main__":
    setup(**opts)
