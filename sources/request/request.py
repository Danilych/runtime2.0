"""request module represents the request got by the VDOM server"""

import sys
import os
from cStringIO import StringIO
from StringIO import StringIO as uStringIO
import cgi
from cgi import FieldStorage, parse_header

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

    def __init__(self, fp=None, headers=None, outerboundary="",
                 environ=os.environ, keep_blank_values=0, strict_parsing=0,
                 max_num_fields=None):
        """Constructor.  Read multipart/* until last part.

        Arguments, all optional:

        fp              : file pointer; default: sys.stdin
            (not used when the request method is GET)

        headers         : header dictionary-like object; default:
            taken from environ as per CGI spec

        outerboundary   : terminating multipart boundary
            (for internal use only)

        environ         : environment dictionary; default: os.environ

        keep_blank_values: flag indicating whether blank values in
            percent-encoded forms should be treated as blank strings.
            A true value indicates that blanks should be retained as
            blank strings.  The default false value indicates that
            blank values are to be ignored and treated as if they were
            not included.

        strict_parsing: flag indicating what to do with parsing errors.
            If false (the default), errors are silently ignored.
            If true, errors raise a ValueError exception.

        max_num_fields: int. If set, then __init__ throws a ValueError
            if there are more than n fields read by parse_qsl().

        """
        method = 'GET'
        self.keep_blank_values = keep_blank_values
        self.strict_parsing = strict_parsing
        self.max_num_fields = max_num_fields
        if 'REQUEST_METHOD' in environ:
            method = environ['REQUEST_METHOD'].upper()
        if 'HTTP_REQUEST_METHOD' in environ:
            method = environ['HTTP_REQUEST_METHOD'].upper()   
        self.qs_on_post = None
        if method == 'GET' or method == 'HEAD':
            if 'HTTP_QUERY_STRING' in environ:
                qs = environ['HTTP_QUERY_STRING']
            elif sys.argv[1:]:
                qs = sys.argv[1]
            else:
                qs = ""
            fp = StringIO(qs)
            if headers is None:
                headers = {'content-type':
                           "application/x-www-form-urlencoded"}
        if headers is None:
            headers = {}
            if method == 'POST':
                # Set default content-type for POST to what's traditional
                headers['content-type'] = "application/x-www-form-urlencoded"
            if 'HTTP_CONTENT_TYPE' in environ:
                headers['content-type'] = environ['HTTP_CONTENT_TYPE']
            if 'HTTP_QUERY_STRING' in environ:
                self.qs_on_post = environ['HTTP_QUERY_STRING']
            if 'HTTP_CONTENT_LENGTH' in environ:
                headers['content-length'] = environ['HTTP_CONTENT_LENGTH']
        self.fp = fp or sys.stdin
        self.headers = headers
        self.outerboundary = outerboundary

        # Process content-disposition header
        cdisp, pdict = "", {}
        if 'content-disposition' in self.headers:
            cdisp, pdict = parse_header(self.headers['content-disposition'])
        self.disposition = cdisp
        self.disposition_options = pdict
        self.name = None
        if 'name' in pdict:
            self.name = pdict['name']
        self.filename = None
        if 'filename' in pdict:
            self.filename = pdict['filename']

        # Process content-type header
        #
        # Honor any existing content-type header.  But if there is no
        # content-type header, use some sensible defaults.  Assume
        # outerboundary is "" at the outer level, but something non-false
        # inside a multi-part.  The default for an inner part is text/plain,
        # but for an outer part it should be urlencoded.  This should catch
        # bogus clients which erroneously forget to include a content-type
        # header.
        #
        # See below for what we do if there does exist a content-type header,
        # but it happens to be something we don't understand.
        if 'content-type' in self.headers:
            ctype, pdict = parse_header(self.headers['content-type'])
        elif self.outerboundary or method != 'POST':
            ctype, pdict = "text/plain", {}
        else:
            ctype, pdict = 'application/x-www-form-urlencoded', {}
        self.type = ctype
        self.type_options = pdict
        self.innerboundary = ""
        if 'boundary' in pdict:
            self.innerboundary = pdict['boundary']
        clen = -1
        if 'content-length' in self.headers:
            try:
                clen = int(self.headers['content-length'])
            except ValueError:
                pass
            if 0 and clen > 0:
                raise ValueError, 'Maximum content length exceeded'
        self.length = clen

        self.list = self.file = None
        self.done = 0
       # print("CTYPE = " + str(ctype))
        if ctype == 'application/x-www-form-urlencoded':
            self.read_urlencoded()
        elif ctype[:10] == 'multipart/':
            self.read_multi(environ, keep_blank_values, strict_parsing)
        else:
            self.read_single()

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
#        self.__headers = VDOM_headers(headers)
        self.__headers = headers
        self.__headers_out = VDOM_headers({})
     #   print(str(headers))
      #  self.__cookies = BaseCookie(headers["HTTP_COOKIE"])

        self.__cookies = BaseCookie(headers.get("cookie"))
        if "HTTP_COOKIE" in headers:
            self.__cookies = BaseCookie(headers.get("HTTP_COOKIE"))
        
        #if "HTTP_COOKIE" in headers:
        #    self.__cookies = BaseCookie(headers["HTTP_COOKIE"])
        #else:
        #    self.__cookies = []
        self.__response_cookies = BaseCookie()
        self.__environment = VDOM_environment(headers, handler)
        self.files = {}
        args = {}
        env = self.__environment.environment()
#        print("+_+_+_+_+_+_+_+_")
#        print(str(self.__headers.headers()))
#        print("+_+_+_+_+_+_+_+_")
#        print(str(self.__headers.header('CONTENT_LENGTH', push=False))) 
#        print("+_+_+_+_+_+_+_+_")
        #parse request data depenging on the request method
        if arguments["method"] == "post":
            try:
                if env["HTTP_CONTENT_TYPE"] == r'application/json':
                    import json
                    try:
                        request_body_size = int(env.get('HTTP_CONTENT_LENGTH', 0))
                    except ValueError:
                        request_body_size = 0

                    request_body = self.__headers['wsgi.input'].read(request_body_size)
                    params = json.loads(request_body)
                    args = {key: params[key] for key in params}

                elif env["REQUEST_URI"] != VDOM_CONFIG["SOAP-POST-URL"]:  # TODO: check situation with SOAP and SOAP-POST-URL
                    storage = MFSt(self.__headers['wsgi.input'], None, "", env, True)
               #     print(storage)
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
 #                   print(str(headers['CONTENT_LENGTH']))
                    self.postdata = self.__headers['wsgi.input'].read(int(self.__headers["CONTENT_LENGTH"]))
            except Exception as e:
                debug("Error while reading socket: %s"%e)

        try:
    #        print("ENV = " + str(env))
            args1 = cgi.parse_qs(env["HTTP_QUERY_STRING"], True)
            print("ARGS1 = " + str(args1))
            for key in args1.keys():
                args[key] = args1[key]
        except Exception as e:
            debug("Error while Query String reading: %s"%e)

        self.fault_type_http_code = 500
        if "HTTP_USER_AGENT" in self.__headers:
            if "adobeair" in self.__headers["HTTP_USER_AGENT"].lower():
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

        #if sid not in args.get('sid', []):
        self.__response_cookies["sid"] = sid
        args["sid"] = sid
        self.__session = managers.session_manager[sid]
        self.__arguments = VDOM_request_arguments(args)
#        self.__server = handler.server
        self._handler = handler
        self.app_vhname = env["HTTP_HOST"].lower()
        vh = arguments["vhosting"]
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
        print("SET NO CACHE")
        if not self.__nocache:
            print("!!!!!")

      #     self.response['code'] = str(code)
     #      self.response['response_body'].append(("Conenction", "close"))
      #     self.wfile["response"].append("Error " + str(code) + " " + message)

      #      self._handler.send_response(200)
            print("1")
            self._handler.response['code'] = str(200)
            print("2")
            self._handler.response['response_body'] = []
            print("3")
            for hh in self.headers_out().headers():
                print("4")
                self._handler.response['response_body'].append((str(hh), str(self.headers_out().headers()[hh])))
#            print("Headers = " + str(self.__request.headers_out().headers()))
#            print("My headers = " + str(self.response['response_body']))

            print("5")
            print("6")
           # cookie = self._handler.remove_prefix(self.response_cookies().output(), "Set-Cookie: ") 
            print("7")
           # self._handler.response['response_body'].append(("Set-Cookie", str("%s\r" % cookie)))
            print("8")
            self.wfile["response"]
            self._handler.wfile["response"] = str(self.output())

            print("SET REDIRECT FALSE")
            self._handler.redirect_rewrite = True
            print("HANDLER = " + str(self._handler))

         #   self._handler.send_headers()
         #   self._handler.end_headers()  # TODO!
         #   self.wfile.write(self.output())
            #self.wfile.write('\n')
        print("@@@@@@")
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

#    def server(self, server=None):
        """ server object """
#       return self.__server

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
