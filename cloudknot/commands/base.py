"""The base command for the cloudknot CLI."""


class Base(object):
    """A base command."""
    def __init__(self, options, *args, **kwargs):
        self.options = options
        self.args = args
        self.kwargs = kwargs

    def run(self):
        raise NotImplementedError(
            'This is a base class. You must implement the run() '
            'method yourself for child classes.'
        )
