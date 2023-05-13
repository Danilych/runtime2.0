
from itertools import chain
from inspect import iscode, isroutine, ismodule
from threading import Lock


import managers
import version
import vscript

from uuid import uuid4
from vscript.engine import vcompile, vexecute, vevaluate
from mailing.message import Message, MailAttachment as Attachment
from mailing.pop import VDOM_Pop3_client


class VDOM_vscript_libraries(object):

    def __init__(self, owner):
        self._owner = owner

    def register(self, name, source, data=None, environment=None, context=None):
        if context is None:
            raise Exception("Require context")

        if isroutine(source):

            def initializer(context, name, namespace):
                code = source(context, name)
                if isinstance(code, tuple):
                    code, data = code
                self._owner.execute(code, data, namespace=namespace, environment=environment)

        else:
            if iscode(source):
                code = source
            else:
                code, data = self._owner.compile(source, environment=environment)

            def initializer(context, name, namespace):
                self._owner.execute(code, data, namespace=namespace, environment=environment)

        managers.import_manager.register(context, name, initializer)

    def unregister(self, name=None, context=None):
        if context is None:
            raise Exception("Require context")
        managers.import_manager.unregister(context, name)

    def exists(self, name=None, context=None):
        if context is None:
            return False
        else:
            return managers.import_manager.lookup(context, name) is not None


class VDOM_vscript(object):

    def __init__(self):
        self._libraries = VDOM_vscript_libraries(self)

    libraries = property(lambda self: self._libraries)

    error = property(lambda self: vscript.errors.generic)

    variant = property(lambda self: vscript.variant)
    integer = property(lambda self: vscript.integer)
    string = property(lambda self: vscript.string)
    generic = property(lambda self: vscript.generic)

    vfunction = property(lambda self: vscript.vfunction)
    vsub = property(lambda self: vscript.vsub)
    vproperty = property(lambda self: vscript.vproperty)
    vcollection = property(lambda self: vscript.vcollection)

    def compile(self, source=None, let=None, set=None, use=None,
            anyway=False, context=None, environment=None, **keywords):
        if environment is None:
            environment = {"v_%s" % name: value for name, value in keywords.iteritems()}
        package = None if context is None else ":".join((managers.engine.application.id, context))
        return vcompile(source, let, set, package=package, environment=environment, use=use, anyway=anyway)

    def execute(self, source_or_code, data=None, use=None,
            anyway=False, context=None, environment=None, namespace=None, **keywords):
        if environment is None:
            environment = {"v_%s" % name: value for name, value in keywords.iteritems()}
        if iscode(source_or_code):
            code = source_or_code
        else:
            code, data = self.compile(source_or_code, use=use,
                anyway=anyway, context=context, environment=environment, **keywords)
        vexecute(code, data, use=use, environment=environment, namespace=namespace)

    def evaluate(self, let=None, set=None, use=None,
            anyway=False, context=None, environment=None, namespace=None, result=None, **keywords):
        if environment is None:
            environment = {"v_%s" % name: value for name, value in keywords.iteritems()}
        if iscode(let or set):
            code = let or set
        else:
            code, data = self.compile(let=let, set=set, use=use,
                anyway=anyway, context=context, environment=environment, **keywords)
        return vevaluate(code, data, use=use, environment=environment, namespace=namespace, result=result)


class VDOM_javascript_libraries_module_exports(object):

    def __init__(self):
        self.__dict__["_namespace"] = {}

    def __getattr__(self, name):
        return self._namespace[name]

    def __setattr__(self, name, value):
        self._namespace[name] = value


class VDOM_javascript_libraries_module(object):

    def __init__(self):
        self.__dict__["_exports"] = VDOM_javascript_libraries_module_exports()

    exports = property(lambda self: self._exports)


class VDOM_javascript_libraries(object):

    def __init__(self, owner):
        self._owner = owner
        self._mapping = {}

    def register(self, name, source_or_namespace, environment=None, context=None):
        if context is None:
            raise Exception("Require context")

        def normalize(namespace):
            if ismodule(namespace):
                return {name: value for name, value in namespace.__dict__.iteritems()
                    if not name.startswith("_")}
            else:
                return namespace

        if isinstance(source_or_namespace, basestring):
            code = self._owner.compile(source_or_namespace, context=context, environment=environment)
            module = VDOM_javascript_libraries_module()
            self._owner.execute(code, context=context, environment=environment, module=module)
            namespace = module.exports._namespace

            def initializer(context, name):
                return namespace

        elif isroutine(source_or_namespace):

            def initializer(context, name):
                return normalize(source_or_namespace(context, name))

        else:

            def initializer(context, name):
                return normalize(source_or_namespace)

        try:
            submapping = self._mapping[context]
        except KeyError:
            submapping = self._mapping.setdefault(context, {})

        submapping[name] = initializer

    def unregister(self, name=None, context=None):
        if context is None:
            raise Exception("Require context")

        if name is None:
            try:
                del self._mapping[context]
            except KeyError:
                pass
        else:
            try:
                del self._mapping[context][name]
            except KeyError:
                pass

    def exists(self, name=None, context=None):
        if context is None:
            return False
        else:
            try:
                return self._mapping[context][name]
            except KeyError:
                return False

    def lookup(self, name, context=None):
        if context is None:
            return None
        else:
            try:
                initializer = self._mapping[context][name]
            except KeyError:
                return None
            else:
                return initializer(context, name)


class VDOM_javascript(object):

    SIGNATURE = "<javascript>"
    EMPTY = None

    def __init__(self):
        import js2py
        self.EMPTY = compile(js2py.translators.DEFAULT_HEADER, "<javascript:header>", "exec")
        self._lock = Lock()
        self._libraries = VDOM_javascript_libraries(self)
        js2py.disable_pyimport()

    libraries = property(lambda self: self._libraries)

    def compile(self, source, context=None, environment=None, **keywords):
        if context is None:
            header = ""
        else:
            header = "__package__=\"%s\"\n" % ":".join((managers.engine.application.id, context))

        with self._lock:
            source_in_python = js2py.translate_js(source, header)

        return compile(source_in_python, self.SIGNATURE, "exec")

    def execute(self, source_or_code, context=None, environment=None, **keywords):
        if iscode(source_or_code):
            code = source_or_code
        else:
            with self._lock:
                code = self._compile(source_or_code, environment=environment, **keywords)

        namespace = {}
        exec(self.EMPTY, namespace)

        def require(name):
            library = self._libraries.lookup(name.to_python(), context=context)
            if library is None:
                raise js2py.PyJsException(message="Unable to import \"%s\" library" % name.to_python())
            return library

        var = namespace["var"].to_python()
        setattr(var, "require", require)

        for name, value in chain((environment or {}).iteritems(), keywords.iteritems()):
            if hasattr(var, name):
                raise Exception("Unable to redefine: \"%s\"" % name)
            setattr(var, name, value)

        # NOTE: lock here?
        #       there are possible problems in:
        #       - ArrayPrototype.join
        #       - TypedArrayPrototype.join
        #       - PyJs.own??? - used in all objects
        exec(code, namespace)

    def evaluate(self, source_or_code, context=None, environment=None, **keywords):
        # TODO: implement later on demand...
        raise NotImplementedError


class VDOM_mailer(object):

    def send(self, *args, **kw):
        return managers.email_manager.send(*args, **kw)

    def check(self, _id):
        return managers.email_manager.check(_id)

    def check_connection(self):
        return managers.email_manager.check_connection()

    def cancel(self, _id):
        return managers.email_manager.cancel(_id)

    def status(self):
        return managers.email_manager.status()

    def clear_queue(self):
        managers.email_manager.clear_queue()

    def get_queue(self):
        return managers.email_manager.get_queue()

    def pop3_connect(self, server, port=110, secure=False):
        return VDOM_Pop3_client(server, port, secure)

    Message = Message
    Attachment = Attachment
    smtp_server = property(lambda self: managers.email_manager.smtp_server)
    smtp_port = property(lambda self: managers.email_manager.smtp_port)
    smtp_user = property(lambda self: managers.email_manager.smtp_user)
    smtp_pass = property(lambda self: managers.email_manager.smtp_pass)
    smtp_sender = property(lambda self: managers.email_manager.smtp_sender)
    use_ssl = property(lambda self: managers.email_manager.use_ssl)


class VDOM_server(object):

    def __init__(self):
        self._vscript = VDOM_vscript()
        self._javascript = None
        
        self._mailer = VDOM_mailer()

    def _get_version(self):
        # return version.VDOM_server_version
        return version.SERVER_VERSION

    def _get_guid(self):
        # return utils.uuid.uuid4()
        return uuid4()

    def _load_javascript(self):
        if self._javascript is None:
            self._javascript = VDOM_javascript()
        return self._javascript
    
    version = property(_get_version)
    # mailer=property(lambda self: managers.email_manager)
    mailer = property(lambda self: self._mailer)
    guid = property(_get_guid)
    vscript = property(lambda self: self._vscript)
    javascript = property(_load_javascript)
