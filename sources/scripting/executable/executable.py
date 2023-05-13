
import sys

import settings
import managers
import file_access

from logs import log
from utils.properties import aroproperty
from utils.tracing import show_exception_trace
from engine.exceptions import RenderTermination

from ..manager import ScriptTimeoutError
from .constants import SOURCE_CODE, LISTING
from .subsystems import select
from .bytecode import ErrorBytecode
from .exceptions import SourceSyntaxError, CompilationError, RequirePrecompileError


class Executable(object):

    class SubsystemLazyProperty(object):

        def __get__(self, instance, owner=None):
            with instance.lock:
                instance.subsystem = value = select(instance.scripting_language)
                return value

    class SourceCodeProperty(object):

        __slots__ = "_handler"

        def __init__(self, handler=None):
            self._handler = handler

        def __get__(self, instance, owner=None):
            with instance.lock:
                try:
                    return instance._source_code
                except AttributeError:
                    location = instance.locate(SOURCE_CODE)
                    if location:
                        value = managers.file_manager.read(file_access.FILE, None,
                            location + instance.subsystem.source_extension, encoding="utf8", default=u"")
                    else:
                        value = u""
                    instance._source_code = value
                    return value

        def __set__(self, instance, value):
            value = unicode(value)
            with instance.lock:
                instance._source_code = value
                location = instance.locate(SOURCE_CODE)
                if location:
                    managers.file_manager.write(file_access.FILE, None,
                        location + instance.subsystem.source_extension, value, encoding="utf8")
                instance.cleanup()
                if self._handler:
                    self._handler(instance, value)

        def __delete__(self, instance):
            with instance.lock:
                instance._source_code = u""
                location = instance.locate(SOURCE_CODE)
                if location:
                    managers.file_manager.delete(file_access.FILE, None,
                        location + instance.subsystem.source_extension)

    class BytecodeLazyProperty(object):

        def __get__(self, instance, owner=None):
            with instance.lock:
                instance.bytecode = value = \
                    (instance.subsystem.restore(instance) if settings.STORE_BYTECODE else None) or instance._compile()
                return value

    scripting_language = aroproperty()
    package = aroproperty()
    signature = aroproperty()

    subsystem = SubsystemLazyProperty()
    source_code = SourceCodeProperty()
    bytecode = BytecodeLazyProperty()

    def locate(self, entity):
        return None

    def cleanup(self, remove=False):
        with self.lock:
            if remove:
                del self.source_code
            self.subsystem.cleanup(self)
            self.__dict__.pop("bytecode", None)

    def _compile(self):
        while 1:
            try:
                extension = self.subsystem.extensions.get(LISTING)
                if extension:
                    if settings.STORE_BYTECODE:
                        location = self.locate(LISTING)
                        if location:
                            signature = location + extension
                        else:
                            signature = None
                    else:
                        signature = None
                else:
                    location = self.locate(SOURCE_CODE)
                    if location:
                        signature = location + self.subsystem.source_extension
                    else:
                        signature = None

                return self.subsystem.compile(self, signature)
            except RequirePrecompileError as error:
                executable = error.executable
                if executable is self:
                    log.write("Require %s" % self)
                    raise
                else:
                    log.write("Precompile %s" % executable)
                    try:
                        executable.compile()
                    except Exception:
                        show_exception_trace(caption="Unable to precompile %s" % executable, locals=True)
                        return ErrorBytecode(self, cause=sys.exc_info())
            except CompilationError as error:
                log.error("Unable to compile %s\n%sDue to error in %s" %
                    (self, settings.LOGGING_INDENT, error.source))
                return ErrorBytecode(self, cause=sys.exc_info())
            except SourceSyntaxError as error:
                log.error("Unable to compile %s\n%sDue to syntax error%s: %s"
                    % (self, settings.LOGGING_INDENT,
                        (" on line %d" % error.lineno if error.lineno else ""), error))
                return ErrorBytecode(self, cause=sys.exc_info())
            except Exception as error:
                show_exception_trace(caption="Unable to compile %s" % self, locals=True)
                return ErrorBytecode(self, cause=sys.exc_info())

    def compile(self, force=False):
        if force:
            self.__dict__.pop("bytecode", None)
        bytecode = self.bytecode
        return bytecode

    def execute(self, context=None, namespace=None, arguments=None):
        if namespace is None:
            namespace = {}

        package = self.package
        if package:
            __import__(package)
            namespace["__package__"] = package

        normally = False
        managers.script_manager.watch()
        try:
            self.bytecode.execute(context, namespace, arguments)
            normally = True  # complete before exception was raised
            managers.script_manager.ignore()  # and cancel exception
        except ScriptTimeoutError:
            if not normally:
                message = "Terminate %s due to timeout" % self
                log.warning(message)
                raise Exception(message)
        except (RenderTermination, CompilationError, RequirePrecompileError):
            raise
        except Exception:
            show_exception_trace(caption="Unhandled exception in %s" % self, locals=True)
            raise
        finally:
            managers.script_manager.leave()
