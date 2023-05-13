
import managers
from utils.file_argument import File_argument


class VDOM_arguments(object):

    def __getitem__(self, name):
        value = managers.request_manager.current.arguments().arguments()[name]
        good = (isinstance(value, list) and len(value) > 0)
        # in case of File_argumet value is not list, will raise TypeError
        if not good:
            raise TypeError
        return self.__try_decode(value[0])

    def get(self, name, default=None, castto=None):
        value = managers.request_manager.current.arguments().arguments().get(name, None)

        good = ((isinstance(value, list) and len(value) > 0) or isinstance(value, File_argument))
        if not good:
            return default

        if castto is list:
            return [self.__try_decode(item) for item in value]
        elif castto is Attachment:
            if isinstance(value, File_argument):
                return Attachment(value)
            else:
                return default
        else:
            if isinstance(value, File_argument):
                return default
            item = self.__try_decode(value[0])
            return castto(item) if castto and item else item

    def __try_decode(self, item):
        if isinstance(item, str):
            return unicode(item.decode("utf-8", "ignore"))
        else:
            return item

    def keys(self):
        return managers.request_manager.current.arguments().arguments().keys()

    def __iter__(self):
        return iter(managers.request_manager.current.arguments().arguments())  # iter is only keys


class VDOM_headers(object):

    def __getitem__(self, name):
        return managers.request_manager.current.headers().headers()[name.lower()]

    def get(self, name, default=None):
        return managers.request_manager.current.headers().headers().get(name.lower(), default)

    def keys(self):
        return managers.request_manager.current.headers().headers().keys()

    def __contains__(self, name):
        return name.lower() in managers.request_manager.current.headers_out().headers()

    def __iter__(self):
        return iter(managers.request_manager.current.headers_out().headers())


class VDOM_client_information(object):

    def _get_host(self):
        return managers.request_manager.current.environment().environment()["REMOTE_ADDR"]

    def _get_address(self):
        return managers.request_manager.current.environment().environment()["REMOTE_ADDR"]

    def _get_port(self):
        return int(managers.request_manager.current.environment().environment()["REMOTE_PORT"])

    host = property(_get_host)
    address = property(_get_address)
    port = property(_get_port)


class VDOM_server_information(object):

    def _get_host(self):
        return managers.request_manager.current.environment().environment()["HTTP_HOST"]

    def _get_address(self):
        return managers.request_manager.current.environment().environment()["SERVER_ADDR"]

    def _get_port(self):
        return int(managers.request_manager.current.environment().environment()["SERVER_PORT"])

    host = property(_get_host)
    address = property(_get_address)
    port = property(_get_port)


class VDOM_protocol_information(object):

    def _get_name(self):
        return managers.request_manager.current.environment().environment()["SERVER_PROTOCOL"].split("/")[0]

    def _get_version(self):
        return managers.request_manager.current.environment().environment()["SERVER_PROTOCOL"].split("/")[1]

    name = property(_get_name)
    version = property(_get_version)


class VDOM_shared_variables(object):

    def __getitem__(self, name):
        return managers.request_manager.current.shared_variables.get(name)

    def keys(self):
        return managers.request_manager.current.shared_variables.keys()


class VDOM_request(object):

    def __init__(self):
        self._arguments = VDOM_arguments()
        self._headers = VDOM_headers()
        self._client = VDOM_client_information()
        self._server = VDOM_server_information()
        self._protocol = VDOM_protocol_information()
        self._shared_vars = VDOM_shared_variables()

    def _get_environment(self):
        return managers.request_manager.current.environment().environment()

    def _get_cookies(self):
        return managers.request_manager.current.cookies()

    def _get_container(self):  # TODO: change stub to real container object
        class container_stub(object):
            def __init__(self):
                self.id = managers.request_manager.current.container_id
        return container_stub()

    def _get_render_type(self):
        return managers.request_manager.current.render_type

    def _get_dyn_libraries(self):
        return managers.request_manager.current.dyn_libraries

    def uploaded_file(self, guid):
        u_file = managers.session_manager.current.files.pop(guid, None)
        return Attachment(u_file) if u_file else None

    def clear_files(self):
        files = managers.session_manager.current.files
        for x in files:
            files[x].remove()
        managers.session_manager.current.files = {}

    arguments = property(lambda self: self._arguments)
    container = property(_get_container)
    environment = property(_get_environment)
    headers = property(lambda self: self._headers)
    cookies = property(_get_cookies)
    client = property(lambda self: self._client)
    server = property(lambda self: self._server)
    protocol = property(lambda self: self._protocol)
    shared_variables = property(lambda self: self._shared_vars)
    render_type = property(_get_render_type)
    dyn_libraries = property(_get_dyn_libraries)
