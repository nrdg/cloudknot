"""
cloudknot

Usage:
  cloudknot configure
  cloudknot -h | --help
  cloudknot --version
Options:
  -h --help                         Show this screen.
  --version                         Show version.
Examples:
  cloudknot configure
Help:
  For help using this tool, please see the Github repository:
  https://github.com/richford/cloudknot
"""

from inspect import getmembers, isclass
from docopt import docopt

from . import __version__ as VERSION


def main():
    """Main CLI entrypoint"""
    import cloudknot.commands
    options = docopt(__doc__, version=VERSION)

    # Here we try to dynamically match the command the user is trying to run
    # with a pre-defined command class we've already created
    for (k, v) in options.items():
        if hasattr(cloudknot.commands, k) and v:
            module = getattr(cloudknot.commands, k)
            cloudknot.commands = getmembers(module, isclass)
            command = [command[1] for command in cloudknot.commands
                       if command[0] != 'Base'][0]
            command = command(options)
            command.run()
