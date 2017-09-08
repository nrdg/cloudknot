from __future__ import absolute_import, division, print_function

import inspect
import operator

from .aws_utils import *
from .due import due, Doi

__all__ = ["CloudKnot"]


# Use duecredit (duecredit.org) to provide a citation to relevant work to
# be cited. This does nothing, unless the user has duecredit installed,
# And calls this with duecredit (as in `python -m duecredit script.py`):
due.cite(Doi(""),
         description="",
         tags=[""],
         path='cloudknot')


# noinspection PyPropertyAccess,PyAttributeOutsideInit
class CloudKnot(object):
    def __init__(self, func, source_file):
        if not (func or source_file):
            raise Exception('you must supply either a user-defined function '
                            'or a source file')
        self.function = function
        self.source_file = source_file

    function = property(operator.attrgetter('_function'))

    @function.setter
    def function(self, f):
        if f:
            if not inspect.isfunction(f):
                raise Exception('if provided, function must be a user-defined '
                                'function')
            self._function = f
        else:
            self._function = None

    source_file = property(operator.attrgetter('_source_file'))

    @source_file.setter
    def source_file(self, fileobj):
        if fileobj:
            self._source_file = fileobj
        else:
            self._source_file = None
