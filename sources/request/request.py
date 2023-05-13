"""request module represents the request got by the VDOM server"""

import sys
from cStringIO import StringIO
from StringIO import StringIO as uStringIO
import cgi
from cgi import FieldStorage

from environment import VDOM_environment
from headers import VDOM_headers
from arguments import VDOM_request_arguments
from Cookie import BaseCookie
#from memory.interface import MemoryInterface
import managers
from utils.file_argument import File_argument
import tempfile
from utils.properties import weak


class MFSt(FieldStorage):
    def make_file(self, binary=None):
        return tempfile.NamedTemporaryFile("w+b", prefix="vdomupload", dir=VDOM_CONFIG["TEMP-DIRECTORY"], delete=False)


@weak("_handler")
class VDOM_request(object):
    """VDOM server request object"""

    #------------------------------------------------------------
    def __init__(self, arguments):
        """ Constructor, create headers, cookies, request and environment """

        headers = arguments["headers"]
        handler = arguments["handler"]

        #debug("Incoming headers---")
        #for h in headers:
        #	debug(h + ": " + headers[h])
        #debug('-'*40)

        self.__headers = VDOM_headers(headers)
        self.__headers_out = VDOM_headers({})

        self.__cookies = BaseCookie(headers.get("cookie"))
        self.__response_cookies = BaseCookie()
        self.__environment = VDOM_environment(headers, handler)
        self.files = {}
        args = {}
        env = self.__environment.environment()
        #parse request data depenging on the request method
        if arguments["method"] == "post":
            try:
                if env["HTTP_CONTENT-TYPE"] == r'application/json':
                    import json
                    try:
                        request_body_size = int(env.get('HTTP_CONTENT-LENGTH', 0))
                    except ValueError:
                        request_body_size = 0

                    request_body = handler.rfile.read(request_body_size)
                    params = json.loads(request_body)
                    args = {key: params[key] for key in params}

                elif env["REQUEST_URI"] != VDOM_CONFIG["SOAP-POST-URL"]:  # TODO: check situation with SOAP and SOAP-POST-URL
                    storage = MFSt(handler.rfile, headers, "", env, True)
                    for key in storage.keys():
                        #Access to file name after uploading
                        filename = getattr(storage[key], "filename", "")
                        if filename and storage[key].file:
                            args[key] = File_argument(storage[key].file, filename)
                            self.files[key] = args[key]
                        else:
                            args[key] = storage.getlist(key)
                        if filename:
                            args[key+"_filename"] = [filename]
                else:
                    self.postdata = handler.rfile.read(int(self.__headers.header("Content-length")))
            except Exception as e:
                debug("Error while reading socket: %s"%e)

        try:
        #    print("ENV = " + str(env))
            args1 = cgi.parse_qs(env["QUERY_STRING"], True)
            print("ARGS1 = " + str(args1))
            for key in args1.keys():
                args[key] = args1[key]
        except Exception as e:
            debug("Error while Query String reading: %s"%e)

        self.fault_type_http_code = 500
        if "user-agent" in self.__headers.headers():
            if "adobeair" in self.__headers.headers()["user-agent"].lower():
                self.fault_type_http_code = 200

        # session
        sid = ""
        if "sid" in args:
            #debug("Got session from arguments "+str(args["sid"]))
            sid = args["sid"][0]
        elif "sid" in self.__cookies:
            #debug("Got session from cookies "+cookies["sid"].value)
            sid = self.__cookies["sid"].value
        if sid == "":
            
            sid = managers.session_manager.create_session()
            #debug("Created session " + sid)
        else:
            x = managers.session_manager[sid]
            if x is None:
                
                #debug("Session " + sid + " expired")
                sid = managers.session_manager.create_session()
        #debug("Session ID "+str(sid))
        self.__cookies["sid"] = sid
    #    print("SESSION SID = " + str(sid))

        #if sid not in args.get('sid', []):
        self.__response_cookies["sid"] = sid
        args["sid"] = sid
        self.__session = managers.session_manager[sid]
        self.__arguments = VDOM_request_arguments(args)
        self.__server = handler.server
        self._handler = handler
        self.app_vhname = env["HTTP_HOST"].lower()
        vh = handler.server.virtual_hosting()
        self.__app_id = vh.get_site(self.app_vhname)
        if not self.__app_id:
            self.__app_id = vh.get_def_site()
        self.__stdout = StringIO()
        self.action_result = uStringIO()
        self.wholeAnswer = None
        self.application_id = self.__app_id

        self.sid = sid
        self.method = arguments["method"]
        self.vdom = None  # MemoryInterface(self) #CHECK: Not used??

        self.args = self.__arguments
        self.__app = None
        if self.__app_id:
            self.__session.context["application_id"] = self.__app_id
            try:
                self.__app = managers.memory.applications[self.__app_id]
            except:
                sys.excepthook(*sys.exc_info())

        # special flags
        self.redirect_to = None
        self.wfile = handler.wfile
        self.__nocache = False
        self.nokeepalive = False
        self.__binary = False
        self.fh = None
        self.shared_variables = {}
        self.render_type = "html"
        self.dyn_libraries = {}
        self.container_id = None

        self.last_state = self.__session.states[0]
        self.next_state = None

    def collect_files(self):
        """Replacement for destructor needed for temp files cleanup"""
        for file_attach in self.files.itervalues():
            if file_attach.autoremove:
                file_attach.remove()

    def add_client_action(self, obj_id, data):
        self.action_result.write(data)

    def binary(self, b=None):
        if b is not None:
            self.__binary = b
        return self.__binary

    def set_nocache(self):
        if not self.__nocache:
            self._handler.send_response(200)
            self._handler.send_headers()
            self._handler.end_headers()  # TODO!
            self.wfile.write(self.output())
            #self.wfile.write('\n')
        self.__nocache = True
        self.nokeepalive = True

    def send_htmlcode(self, code=200):
        if not self.__nocache:
            self._handler.send_response(code)
            self._handler.send_headers()
            self._handler.end_headers()
            self.wfile.write(self.output())
        self.__nocache = True
        self.nokeepalive = True

    def set_application_id(self, application_id):
        self.__app_id = application_id
        self.application_id = application_id
        # try: self.__app = managers.xml_manager.get_application(self.__app_id)
        try:
            self.__app = managers.memory.applications[self.__app_id]
        except:
            sys.excepthook(*sys.exc_info())

    def write(self, string=None):
        """save output"""
        if string:
            if self.__nocache:
                self.wfile.write(string)
                #self.wfile.write('\n')
            else:
                self.__stdout.write(string)
                self.__stdout.write('\n')

    def write_handler(self, handler):
        """writing into stream from file handler"""
        self.fh = handler

    def content_length(self):
        """get output length"""
        return self.__stdout.tell()

    def output(self):
        """get output"""
        value = self.__stdout.getvalue()
        del self.__stdout
        self.__stdout = StringIO()
        return value

    def server(self, server=None):
        """ server object """
        return self.__server

    def session(self):
        """session object"""
        return self.__session

    def set_session_id(self, sid):
        old_sid = self.__session.id()
        self.__cookies["sid"] = sid
        self.args.arguments()["sid"] = sid
        self.__session = managers.session_manager[sid]
        managers.session_manager.remove_session(old_sid)

    def headers(self, headers=None):
        """ Server headers. """
        return self.__headers

    def headers_out(self, headers=None):
        """ Server headers. """
        return self.__headers_out

    def environment(self, environment=None):
        """ Server environment """
        return self.__environment

    def arguments(self, args=None):
        """ request arguments """
        return self.__arguments

    def cookies(self):
        """ Server cookies """
        return self.__cookies

    def response_cookies(self):
        """ Server response cookies """
        return self.__response_cookies

    def application(self):
        """get application object"""
        return self.__app

    def handler(self):
        return self._handler

    def app_id(self):
        """get application identifier"""
        return self.__app_id

    def redirect(self, to):
        """specify redirection to some url"""
        self.redirect_to = to

    def add_header(self, name, value):
        """add header"""
        headers = self.__headers_out.headers()
        headers[name] = value
        print("NEW HEADER = " + str(headers))

    def send_file(self, filename, length, handler, content_type=None, cache_control=True):
        print("SEND FILE")
        f_content_type = content_type if content_type else "application/octet-stream"
        print("NEW CONTENT TYPE = " + str(f_content_type))
        self.add_header("Content-type", f_content_type)
        if content_type:
            self.add_header("Content-Disposition", "inline; filename=\"%s\""%filename)
        else:
            self.add_header("Content-Disposition", "attachment; filename=\"%s\""%filename)

        if cache_control is None:
            pass
        elif cache_control is True:
            self.add_header("Cache-Control", "max-age=86400")
        elif cache_control is False:
            self.add_header("Cache-Control", "no-cache, no-store, must-revalidate")
        elif isinstance(cache_control, int):
            self.add_header("Cache-Control", "max-age=%s"%cache_control)

        self.add_header("Content-Length", str(length))
        self.set_nocache()
        self.write_handler(handler)
