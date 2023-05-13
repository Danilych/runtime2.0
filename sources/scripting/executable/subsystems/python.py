
import re
from __builtin__ import compile as python_compile
from logs import server_log
from memory import PYTHON_EXTENSION, BYTECODE_EXTENSION
from ...wrappers import environment
from ..constants import BYTECODE
from ..bytecode import Bytecode
from ..exceptions import SourceSyntaxError


REMOVE_ENCODING_REGEX = re.compile(r"^[ \t\v]*#.*?coding[:=][ \t]*([-_.a-zA-Z0-9]+).*$", re.MULTILINE)
ENCODING_ERROR_MESSAGE = "encoding declaration in Unicode string"


class Unavailable(object):

    def __getattribute__(self, name):
        raise Exception("self is not available")

    def __str__(self):
        return "self is not available"

    def __unicode__(self):
        return u"self is not available"

    def __repr__(self):
        return "self is not available"


class PythonBytecode(Bytecode):

    __slots__ = ()

    _unavailable = Unavailable()

    source_extension = PYTHON_EXTENSION
    extensions = {BYTECODE: BYTECODE_EXTENSION}

    @classmethod
    def compile(cls, executable, signature=None):
        try:
            bytecode = python_compile(executable.source_code, signature or executable.signature, "exec")
        except SyntaxError as error:
            if error.msg == ENCODING_ERROR_MESSAGE:
                server_log.warning("Unsuitable encoding declaration into %s, line %s" % (executable, error.lineno))
                source_code = REMOVE_ENCODING_REGEX.sub("", executable.source_code)
                bytecode = python_compile(source_code, signature or executable.signature, "exec")
            else:
                raise SourceSyntaxError(error.msg.capitalize(), lineno=error.lineno)
        return cls(executable, bytecode)

    def execute(self, context, namespace, arguments):
        if arguments:
            namespace["self"] = self._unavailable
            namespace.update(arguments)
        elif context:
            namespace["self"] = context
        namespace.update(environment)
        exec(self._bytecode, namespace)
