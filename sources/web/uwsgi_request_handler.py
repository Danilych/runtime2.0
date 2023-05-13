"""server request handler module"""
import sys, os, posixpath, urllib, shutil, mimetypes, thread, re, socket, threading, time, SOAPpy, traceback, select, cgi
import io
import uwsgi
if sys.platform.startswith("freebsd"):
    import vdomlib

import BaseHTTPServer
from cStringIO import StringIO
import xml.sax.saxutils
#import webdav_server
#from wsgidav.wsgidav_app import WsgiDAVApp
from wsgiref.util import guess_scheme

import managers
import settings

from time import time

from request.request import VDOM_request
from storage.storage import VDOM_config
from version import *
#import soap.SOAPBuilder
from soap.wsdl import methods as soap_methods
from utils.exception import VDOM_exception
from utils.pages import compose_page, compose_trace
from version import SERVER_NAME, SERVER_VERSION
#from server import VDOM_WSGI_Vhosting
#from server.uwsgi_vhosting import VDOM_WSGI_Vhosting

# A class to describe how header messages are handled
class HeaderHandler:
    # Initially fail out if there are any problems.
    def __init__(self, header, attrs):
        for i in header.__dict__.keys():
            if i[0] == "_":
                continue

            d = getattr(header, i)

            try:
                fault = int(attrs[id(d)][(NS.ENV, 'mustUnderstand')])
            except:
                fault = 0

            if fault:
                raise faultType, ("%s:MustUnderstand" % NS.ENV_T,
                                  "Required Header Misunderstood",
                                  "%s" % i)

# for the soap handler
_contexts = dict()
#class VDOM_http_request_handler(SimpleHTTPServer.SimpleHTTPRequestHandler):
class VDOM_uwsgi_request_handler(object):
    """VDOM wsgi request handler"""

    """server version string"""
    server_version = SERVER_NAME

    responses = {
        100: ('Continue', 'Request received, please continue'),
        101: ('Switching Protocols',
              'Switching to new protocol; obey Upgrade header'),

        200: ('OK', 'Request fulfilled, document follows'),
        201: ('Created', 'Document created, URL follows'),
        202: ('Accepted',
              'Request accepted, processing continues off-line'),
        203: ('Non-Authoritative Information', 'Request fulfilled from cache'),
        204: ('No Content', 'Request fulfilled, nothing follows'),
        205: ('Reset Content', 'Clear input form for further input.'),
        206: ('Partial Content', 'Partial content follows.'),

        300: ('Multiple Choices',
              'Object has several resources -- see URI list'),
        301: ('Moved Permanently', 'Object moved permanently -- see URI list'),
        302: ('Found', 'Object moved temporarily -- see URI list'),
        303: ('See Other', 'Object moved -- see Method and URL list'),
        304: ('Not Modified',
              'Document has not changed since given time'),
        305: ('Use Proxy',
              'You must use proxy specified in Location to access this '
              'resource.'),
        307: ('Temporary Redirect',
              'Object moved temporarily -- see URI list'),

        400: ('Bad Request',
              'Bad request syntax or unsupported method'),
        401: ('Unauthorized',
              'No permission -- see authorization schemes'),
        402: ('Payment Required',
              'No payment -- see charging schemes'),
        403: ('Forbidden',
              'Request forbidden -- authorization will not help'),
        404: ('Not Found', 'Nothing matches the given URI'),
        405: ('Method Not Allowed',
              'Specified method is invalid for this resource.'),
        406: ('Not Acceptable', 'URI not available in preferred format.'),
        407: ('Proxy Authentication Required', 'You must authenticate with '
              'this proxy before proceeding.'),
        408: ('Request Timeout', 'Request timed out; try again later.'),
        409: ('Conflict', 'Request conflict.'),
        410: ('Gone',
              'URI no longer exists and has been permanently removed.'),
        411: ('Length Required', 'Client must specify Content-Length.'),
        412: ('Precondition Failed', 'Precondition in headers is false.'),
        413: ('Request Entity Too Large', 'Entity is too large.'),
        414: ('Request-URI Too Long', 'URI is too long.'),
        415: ('Unsupported Media Type', 'Entity body in unsupported format.'),
        416: ('Requested Range Not Satisfiable',
              'Cannot satisfy request range.'),
        417: ('Expectation Failed',
              'Expect condition could not be satisfied.'),

        500: ('Internal Server Error', 'Server got itself in trouble'),
        501: ('Not Implemented',
              'Server does not support this operation'),
        502: ('Bad Gateway', 'Invalid responses from another server/proxy.'),
        503: ('Service Unavailable',
              'The server cannot process the request due to a high load'),
        504: ('Gateway Timeout',
              'The gateway server did not receive a timely response'),
        505: ('HTTP Version Not Supported', 'Cannot fulfill request.'),
        }

    def __init__(self, request, client_address, args=None):
        """constructor"""
        self.__reject = args["reject"]
        self.__deny = args["deny"]
        self.__card = args["card"]
        self.__limit = args["limit"]
        self.__connections = args["connections"]
        self.request = request
        self.client_address = client_address
        self.wfile = {'response': []}
        self.response = {'code': '', 'response_body': []}

    def remove_prefix(self, text, prefix):
        if text.startswith(prefix):
            return text[len(prefix):]
        return text

    def start_response(self, status, response_headers, exc_info=None):
        if exc_info:
            try:
                raise exc_info[0], exc_info[1], exc_info[2]
                # do stuff w/exc_info here
            finally:
                exc_info = None    # Avoid circular ref.
        status_code = int(status.split(' ')[0])
        status_message = status[status.find(' ')+1:]
        
        self.response['code'] = '200'
        self.wfile["response"].append(status_message)
 
        for header in response_headers:
            if header[0] != 'Date':
                self.response[header[0]] =  header[1]

        cookies = self.__request.cookies()
        if "sid" in cookies:
            cookies["sid"]["path"] = "/"
            self.wfile["response"].append(status_message)

        #print response_headers
        #_str = '\n'.join( traceback.format_stack() )
        #print _str
        #cgi.escape( str )		
        return self.wfile.append

    def get_environ(self):
        env = self.__request.environment().environment().copy()
        #env = {}
        env['wsgi.input']        = self.rfile
        env['wsgi.errors']       = sys.stderr
        env['wsgi.version']      = (1, 0)
        env['wsgi.run_once']     = False
        env['wsgi.url_scheme']   = guess_scheme(env)
        env['wsgi.multithread']  = True
        env['wsgi.multiprocess'] = True
        env['SERVER_PROTOCOL'] = self.request_version
        env['REQUEST_METHOD'] = self.command
        if '?' in self.path:
            path,query = self.path.split('?',1)
        else:
            path,query = self.path,''

        env['PATH_INFO'] = urllib.unquote(path)
        env['QUERY_STRING'] = query

        host = self.address_string()
        if host != self.client_address[0]:
            env['REMOTE_HOST'] = host
        env['REMOTE_ADDR'] = self.client_address[0]

        if self.headers.typeheader is None:
            env['CONTENT_TYPE'] = self.headers.type
        else:
            env['CONTENT_TYPE'] = self.headers.typeheader

        length = self.headers.getheader('content-length')
        if length:
            env['CONTENT_LENGTH'] = length
        script_name = env.get('SCRIPT_NAME')
        if script_name:
            env['SCRIPT_NAME'] = script_name.rstrip("/")

        for h in self.headers.headers:
            k,v = h.split(':',1)
            k=k.replace('-','_').upper(); v=v.strip()
            if k in env:
                continue                    # skip content length, type,etc.
            if 'HTTP_'+k in env:
                if 'HTTP_'+k not in self.__request.environment().environment():
                    env['HTTP_'+k] += ','+v     # comma-separate multiple headers
            else:
                env['HTTP_'+k] = v
        return env

    def handle_uwsgi_request(self, environ, start_response):
        print(" ============ NEW REQUEST ============")
            
        self.command = environ['REQUEST_METHOD']
        mname = 'do_' + self.command
        self.headers = environ
        self.path = environ["PATH_INFO"]
        host = environ["HTTP_HOST"]

        self.response = {'code': '', 'response_body': []}
    
        app_id = (managers.module_manager.getVHosting().virtual_hosting().get_site(host.lower()) if host else None) or managers.module_manager.getVHosting().virtual_hosting().get_def_site()
        if not app_id:
            app_id = managers.memory.applications.default.id if managers.memory.applications.default else None
        self.wsgidav_app = None
        if app_id:
            try:
                #if app_id not in managers.memory.applications:
                appl = managers.memory.applications[app_id]
                self.wsgidav_app = getattr(appl, 'wsgidav_app', None)
            except KeyError as e:
                debug(e)			
            else:
            #realm = environ["PATH_INFO"].strip("/").split("/").pop(0)
            #objects_list = appl.search_objects_by_name(realm)
            #for o in objects_list:
                #if managers.webdav_manager.get_webdav_share_path(appl.id, o.id) != None:
                    #self.wsgidav_app = appl.wsgidav_app
                    #mname = 'do_WebDAV'
                    #break
                realm = self.path.strip("/").split("/").pop(0)
                if managers.webdav_manager.check_webdav_share_path(appl.id, realm):
                    mname = 'do_WebDAV'

        if self.command not in ("GET", "POST"):
            mname = 'do_WebDAV'

        if mname == 'do_WebDAV' and self.wsgidav_app is None:
            managers.webdav_manager.load_webdav(app_id)
            self.wsgidav_app = appl.wsgidav_app

        if not hasattr(self, mname):
            self.send_error(501, "Unsupported method (%r)" % self.command)
            start_response(self.response['code'], self.response['response_body'])
            return self.wfile["response"]
        
        method = getattr(self, mname)
        method()

     #   nlength = 0
      #  tempfile = []
      #  for line in self.wfile["response"]:
      #      tempfile.append(line)
       #     print("()")
       #     print(str(len(line)) + "===" + str(line))
       #     print("()")
       #     nlength += len(line)
       # print("-----" + str(nlength))
       # print("Response content length = " + str(self.response["response_body"]))
       # if nlength == 8789:
       #     nlength = 0
       #     self.wfile["response"] = []
        #    for i in range(0, max(1, len(tempfile))):
        #        self.wfile["response"].append(tempfile[i])
         #       nlength += len(tempfile[i])
         #   print("actual length = " + str(nlength))
           # self.response = {'code': '200', 'response_body': [('Content-Length', str(nlength)), ('Content-type', 'text/plain')]}


        
        start_response(self.response['code'], self.response['response_body'])
        return self.wfile["response"] #actually send the response if not already done.


    def do_WebDAV(self):

        if self.__reject:
            self.send_error(503, self.responses[503][0])
            return None		
        self.create_request(self.command.lower())
        environ = self.get_environ()
        application = self.wsgidav_app
        if not application:
            self.send_error(404, self.responses[404][0])
            return
        elif environ["REQUEST_METHOD"] == "OPTIONS" and environ["PATH_INFO"] in ("/", "*"):
            import wsgidav.util as util
            self.response['code'] = '200'
            self.response['response_body'].append(('Content-type', 'text/xml'))
            self.response['response_body'].append(('Content-Length', '0'))
            self.response['response_body'].append(('DAV', '1,2'))
            self.response['response_body'].append(('Server', 'DAV/2'))
            self.response['response_body'].append(('Date', util.getRfc1123Time()))	
            return

        if environ["REQUEST_METHOD"] == "PROPFIND" and environ["PATH_INFO"] in ("/", "*"):
            providers = self.wsgidav_app.providerMap.keys()
            if providers:
                environ["PATH_INFO"] = providers[0]  # Need some testing if this approach will work
            else:
                self.send_error(404, self.responses[404][0])
                return
        #print "<<<%s %s"%(environ["REQUEST_METHOD"], environ["PATH_INFO"])
        application(environ, self.start_response)
 #       for v in application(environ, self.start_response):
 #           self.wfile["response"].append(v)


    def do_GET(self):
        print("DO GET")
        """serve a GET request"""
        # create request object
        #debug("DO GET %s"%self)
        self.create_request("get")
        f = self.on_request("get")
        if f:
            sys.setcheckinterval(0)
            for line in f:
                self.wfile["response"].append(line)
            sys.setcheckinterval(100)
            f.close()

    def do_HEAD(self):
        """serve a HEAD request"""
        # create request object
        self.create_request("get")
        f = self.on_request("get")
        if f:
            f.close()

    def do_POST(self):
        print("DO POST")
   #     print("===== Post triggered! =====")
        """serve a POST request"""
        # create request object
        #debug("DO POST %s"%self)
        self.create_request("post")
        # if POST to SOAP-POST-URL call do_SOAP
        if self.__request.environment().environment()["REQUEST_URI"] == VDOM_CONFIG["SOAP-POST-URL"]:
            if self.__card:
                self.do_SOAP()
            return
 #       print("===== Post triggered (on request) ! =====")
        
        f = self.on_request("post")
        if f:
            sys.setcheckinterval(0)
            for line in f:
                self.wfile["response"].append(line)
            sys.setcheckinterval(100)
            f.close()

    def create_request(self, method):
        """initialize request, <method> is either 'post' or 'get'"""
        #debug("CREATE REQUEST %s"%self)
        #import gc
        #debug("\nGarbage: "+str(len(gc.garbage))+"\n")
        #debug("Creating request object")
        args = {}
        args["headers"] = self.headers
        args["handler"] = self
        args["vhosting"] = managers.module_manager.getVHosting().virtual_hosting()
        args["method"] = method
#        print("==========================")
        self.__request = VDOM_request(args)
        self.__request.number_of_connections = self.__connections
        #debug("Creating request object complete")
        # put request to the manager
        managers.request_manager.current = self.__request

 #       if "127.0.0.1" != self.client_address[0]:
 #           debug("Session is " + self.__request.sid)

    def on_request(self, method):
        """request handling code the method <method>"""
        #debug("ON REQUEST %s"%self)
        #check if we should send 503 or 403 errors
        if self.__reject:
            self.send_error(503, self.responses[503][0])
            return None
        if self.__deny:
            self.send_error(403, self.responses[403][0])
            return None
        if not self.__card:
            data = _("Please insert your card")
            self.response['code'] = '200'
            self.response['response_body'].append(('Content-type', 'text/xml'))
            self.response['response_body'].append(('Content-Length', str(len(data))))
            return StringIO(data)
        if not self.__limit:
            data = _("License exceeded")
            self.response['code'] = '200'
            self.response['response_body'].append(('Content-type', 'text/xml'))
            self.response['response_body'].append(('Content-Length', str(len(data))))
            return StringIO(data)
        # check if requested for wsdl file - then return it
        if self.__request.environment().environment()["REQUEST_URI"] == VDOM_CONFIG["WSDL-FILE-URL"]:
            wsdl = managers.module_manager.getSOAPModule().get_wsdl()
            self.response['code'] = '200'
            self.response['response_body'].append(('Content-type', 'text/xml'))
            self.response['response_body'].append(('Content-Length', str(len(wsdl))))
            return StringIO(wsdl)
        if self.__request.environment().environment()["REQUEST_URI"] == "/crossdomain.xml":
            data = """<?xml version="1.0"?>
<cross-domain-policy>
     <allow-access-from domain="*"/>
</cross-domain-policy>"""
            self.response['code'] = '200'
            self.response['response_body'].append(('Content-type', 'text/xml'))
            self.response['response_body'].append(('Content-Length', str(len(data))))
            return StringIO(data)
        # management

        if self.__request.environment().environment()["REQUEST_URI"] == VDOM_CONFIG["MANAGEMENT-URL"]:
            self.redirect("/index.py")
            return
        # process requested URI, call module manager
        try:
            (code, ret) = managers.module_manager.process_request(self.__request) ############
          #  print("CODE = " + str(code))
           # print("ret = " + str(ret))
            self.__request.collect_files()
        except Exception as e:
      #      print("Brrrrrrrrrrrrrrr")
            requestline = "<br>"
            if hasattr(self, "requestline"):
                requestline = "<br>" + self.requestline + "<br>" + '-' * 80
            if not hasattr(self, "request_version"):
                self.request_version = "HTTP/1.1"
            fe = "".join(["<br><br>", '-' * 80, requestline, "<br>Exception happened during processing of request:",
                          traceback.format_exc(), '-' * 40])
            self.__request.collect_files()
            self.send_error(500, excinfo=fe)
            debug(e)
            return None

        # check redirect
        if self.__request.redirect_to:
            self.redirect(self.__request.redirect_to)
            return
        elif code == 25:    #Send files via X-Sendfile with uwsgi server
            self.response['code'] = '200 OK'
            self.response['response_body'].append(('X-Sendfile', ret))
            self.wfile['response'] = []
            return None
        elif ret:
            self.response['code'] = '200'
            ret_len = None

            if isinstance(ret, (file, io.IOBase)):
                ret.seek(0,2)
                ret_len = str(ret.tell())
                ret.seek(0)
            else:
                ret_len = str(len(ret))

            self.__request.add_header("Content-Length", ret_len)
            if self.__request.nokeepalive:
                self.__request.add_header("Connection", "Close")
            else:
                self.__request.add_header("Connection", "Keep-Alive")
            for hh in self.__request.headers_out().headers():
                
#                print("test header = " + str(hh) + " : " + str(self.__request.headers_out().headers()[hh]))
                self.response['response_body'].append((str(hh), str(self.__request.headers_out().headers()[hh])))
#            print("Headers = " + str(self.__request.headers_out().headers()))
#            print("My headers = " + str(self.response['response_body']))

            self.wfile['response'] = []
            
            cookie = self.remove_prefix(self.__request.response_cookies().output(), "Set-Cookie: ") 
            self.response['response_body'].append(("Set-Cookie", str("%s\r" % cookie)))
            

            #print(str(self.__request.headers().headers()))
            # cookies
            #if len(self.__request.cookies())>0:
            #	for key in self.__request.cookies():
            #		self.__request.add_header("Set-cookie",self.__request.cookies()[key].output())
                #self.__request.add_header("Set-cookie",self.__request.cookies().output())
            #if len(self.__request.cookies().cookies()) > 0:
                #self.__request.add_header("Set-cookie", self.__request.cookies().get_string())

#            response['response_body'] = self.__request.headers_out().headers().items()
            
#            self.send_headers()
#            self.end_headers()
            if isinstance(ret, (file, io.IOBase)):
                if sys.platform.startswith("freebsd"):
#                    vdomlib.sendres(self.wfile.fileno(), ret.fileno(), int(ret_len))
                    ret.close()
                    return None
                else:
                    return ret
            else:
                return StringIO(ret)
        elif "" == ret:
            self.response['code'] = '204 OK'
    #        print("cookie to response = " + str(self.__request.response_cookies().output()))
            cookie = self.remove_prefix(self.__request.response_cookies().output(), "Set-Cookie: ") 
            self.response['response_body'].append(("Set-Cookie", str("%s\r" % cookie)))
            return None
        elif code:
            self.send_error(code, self.responses[code][0])
            return None
        else:
            self.send_error(404, self.responses[404][0])
            return None
        
    

    def redirect(self, to):
        self.response['code'] = '302'
        self.response['response_body'] = [('Location', str(to))]

  #      print("cookie to response = " + str(self.__request.response_cookies().output()))
        cookie = self.remove_prefix(self.__request.response_cookies().output(), "Set-Cookie: ") 
        self.response['response_body'].append(("Set-Cookie", str("%s\r" % cookie)))

    def address_string(self):
        """Return the client address formatted for logging"""
        host, port = self.client_address[:2]
        return host 

    def do_SOAP(self):
        global _contexts
        status = 500

        VDOM_debug = 0
        dumpSOAPIn = 0
        dumpSOAPOut = 0
        dumpHeadersIn = 0
        dumpHeadersOut = 0

        cf = VDOM_config()
        #No more alot of debug while soap
        #if "1" == cf.get_opt("DEBUG"):       
        #	VDOM_debug = 1
        #	dumpSOAPIn = 1
        #	dumpSOAPOut = 1
        #	dumpHeadersIn = 1
        #	dumpHeadersOut = 1

        try:
            if dumpHeadersIn:
                s = 'Incoming HTTP headers'
                SOAPpy.debugHeader(s)
                debug(self.raw_requestline.strip())
                debug("\n".join(map (lambda x: x.strip(), self.headers)))
                SOAPpy.debugFooter(s)
            data = self.__request.postdata
            if dumpSOAPIn:
                s = 'Incoming SOAP'
                SOAPpy.debugHeader(s)
                debug(data)
                SOAPpy.debugFooter(s)

            (r, header, body, attrs) = SOAPpy.parseSOAPRPC(data, header = 1, body = 1, attrs = 1)

            method = r._name
            args = r._aslist()
            kw = r._asdict()

            # TODO:
            # check if there are list items in args or kw
            # and leave only the first element

            if SOAPpy.Config.simplify_objects:
                args = SOAPpy.simplify(args)
                kw = SOAPpy.simplify(kw)

            # Handle mixed named and unnamed arguments by assuming
            # that all arguments with names of the form "v[0-9]+"
            # are unnamed and should be passed in numeric order,
            # other arguments are named and should be passed using
            # this name.

            # This is a non-standard exension to the SOAP protocol,
            # but is supported by Apache AXIS.

            # It is enabled by default.  To disable, set
            # Config.specialArgs to False.

            if SOAPpy.Config.specialArgs: 

                ordered_args = {}
                named_args   = {}

                for (k,v) in  kw.items():

                    if k[0]=="v":
                        try:
                            i = int(k[1:])
                            ordered_args[i] = v
                        except ValueError:
                            named_args[str(k)] = v

                    else:
                        named_args[str(k)] = v

            # We have to decide namespace precedence
            # I'm happy with the following scenario
            # if r._ns is specified use it, if not check for
            # a path, if it's specified convert it and use it as the
            # namespace. If both are specified, use r._ns.

            ns = r._ns

            if len(self.path) > 1 and not ns:
                ns = self.path.replace("/", ":")
                if ns[0] == ":": 
                    ns = ns[1:]

            # authorization method
            a = None

            keylist = ordered_args.keys()
            keylist.sort()

            # create list in proper order w/o names
            tmp = map( lambda x: ordered_args[x], keylist)
            ordered_args = tmp

#			print '<-> Argument Matching Yielded:'
#			print '<-> Ordered Arguments:' + str(ordered_args)
#			print '<-> Named Arguments  :' + str(named_args)

            arg_names = soap_methods[method]
            if "sid" in arg_names:
                _i = arg_names.index("sid")
                if _i < len(ordered_args):
                    managers.request_manager.current.set_session_id(ordered_args[_i])
                elif "sid" in named_args:
                    managers.request_manager.current.set_session_id(named_args["sid"])
            if "appid" in arg_names:
                _i = arg_names.index("appid")
                if _i < len(ordered_args):
                    managers.request_manager.current.set_application_id(ordered_args[_i])
                elif "appid" in named_args:
                    managers.request_manager.current.set_application_id(named_args["appid"])

            resp = ""

            # For fault messages
            if ns:
                nsmethod = "%s:%s" % (ns, method)
            else:
                nsmethod = method

            try:
                # First look for registered functions
                if ns in managers.module_manager.getSOAPModule().funcmap and method in managers.module_manager.getSOAPModule().funcmap[ns]:
                    f = managers.module_manager.getSOAPModule().funcmap[ns][method]

                    # look for the authorization method
                    if managers.module_manager.getSOAPModule().config.authMethod != None:
                        authmethod = self.server.config.authMethod
                        if ns in self.server.funcmap and authmethod in self.server.funcmap[ns]:
                            a = self.server.funcmap[ns][authmethod]
                else:
                    # Now look at registered objects
                    # Check for nested attributes. This works even if
                    # there are none, because the split will return
                    # [method]
                    f = managers.module_manager.getSOAPModule().objmap[ns]

                    # Look for the authorization method
                    if managers.module_manager.getSOAPModule().config.authMethod != None:
                        authmethod = managers.module_manager.getSOAPModule().config.authMethod
                        if hasattr(f, authmethod):
                            a = getattr(f, authmethod)

                    # then continue looking for the method
                    l = method.split(".")
                    for i in l:
                        f = getattr(f, i)
            except:
                info = sys.exc_info()
                try:
                    resp = SOAPpy.buildSOAP(SOAPpy.faultType("%s:Client" % SOAPpy.NS.ENV_T, "Method Not Found",
                                                             "%s : %s %s %s" % (nsmethod,
                                                                                info[0],
                                                                                info[1],
                                                                                info[2])),
                                            encoding = managers.module_manager.getSOAPModule().encoding,
                                            config = managers.module_manager.getSOAPModule().config)
                finally:
                    del info
                status = self.__request.fault_type_http_code
            else:
                try:
                    if header:
                        x = HeaderHandler(header, attrs)

                    fr = 1

                    # call context book keeping
                    # We're stuffing the method into the soapaction if there
                    # isn't one, someday, we'll set that on the client
                    # and it won't be necessary here
                    # for now we're doing both

                    if "SOAPAction".lower() not in self.headers.keys() or self.headers["SOAPAction"] == "\"\"":
                        self.headers["SOAPAction"] = method

                    thread_id = thread.get_ident()
                    _contexts[thread_id] = SOAPpy.SOAPContext(header, body,
                                                              attrs, data,
                                                              socket.fromfd(uwsgi.connection_fd(), socket.AF_INET, socket.SOCK_STREAM),
                                                              self.headers,
                                                              self.headers["SOAPAction"])

                    # Do an authorization check
                    if a != None:
                        if not a(None, **{"_SOAPContext" :
                                          _contexts[thread_id] }):
                            raise SOAPpy.faultType("%s:Server" % SOAPpy.NS.ENV_T,
                                                   "Authorization failed.",
                                                   "%s" % nsmethod)

                    # If it's wrapped, some special action may be needed
                    if isinstance(f, SOAPpy.MethodSig):
                        c = None

                        if f.context:  # retrieve context object
                            c = _contexts[thread_id]

## log
                        if c:
                            info = c.connection.getpeername()
                            debug("Web service request from %s:%s - %s" % (info[0], info[1], c.soapaction))
#######

                        if SOAPpy.Config.specialArgs:
                            if c:
                                named_args["_SOAPContext"] = c
                            fr = f(*ordered_args, **named_args)
                        elif f.keywords:
                            # This is lame, but have to de-unicode
                            # keywords

                            strkw = {}

                            for (k, v) in kw.items():
                                strkw[str(k)] = v
                            if c:
                                strkw["_SOAPContext"] = c
                            fr = f(None, **strkw)
                        elif c:
                            fr = f(*args, **{'_SOAPContext':c})
                        else:
                            fr = f(*args, **{})

                    else:
                        if SOAPpy.Config.specialArgs:
                            fr = f(*ordered_args, **named_args)
                        else:
                            fr = f(*args, **{})


                    if type(fr) == type(self) and \
                       isinstance(fr, SOAPpy.voidType):
                        resp = SOAPpy.buildSOAP(kw = {'%sResponse xmlns="http://services.vdom.net/VDOMServices"' % method: fr},
                                                encoding = managers.module_manager.getSOAPModule().encoding,
                                                config = managers.module_manager.getSOAPModule().config)
                    else:
                        resp = SOAPpy.buildSOAP(kw =
                                                {'Result': fr},
                                                encoding = managers.module_manager.getSOAPModule().encoding,
                                                config = managers.module_manager.getSOAPModule().config,
                                                method = method + "Response",
                                                namespace = ('', "http://services.vdom.net/VDOMServices"))

                    # Clean up _contexts
                    if thread_id in _contexts:
                        del _contexts[thread_id]

                except Exception as e:
                    import traceback
                    info = sys.exc_info()

                    try:
                        if managers.module_manager.getSOAPModule().config.dumpFaultInfo and not isinstance(e, SOAPpy.faultType):
                            s = 'Method %s exception' % nsmethod
                            SOAPpy.debugHeader(s)
                            traceback.print_exception(info[0], info[1],
                                                      info[2])
                            SOAPpy.debugFooter(s)

                        if isinstance(e, SOAPpy.faultType):
                            f = e
                        else:
                            f = SOAPpy.faultType("%s:Server" % SOAPpy.NS.ENV_T,
                                                 "Method Failed",
                                                 "%s" % nsmethod)

                        if managers.module_manager.getSOAPModule().config.returnFaultInfo:
                            f._setDetail("".join(traceback.format_exception(
                                info[0], info[1], info[2])))
                        elif not hasattr(f, 'detail'):
                            f._setDetail("%s %s" % (info[0], info[1]))
                    finally:
                        del info


                    #method failed - return soap fault (no method tag needed)
                    resp = SOAPpy.buildSOAP(f, encoding = managers.module_manager.getSOAPModule().encoding,
                                            config = managers.module_manager.getSOAPModule().config, namespace = "http://services.vdom.net/VDOMServices")
                    status = self.__request.fault_type_http_code
                else:
                    status = 200
        except SOAPpy.faultType as e:
            import traceback
            info = sys.exc_info()
            try:
                if managers.module_manager.getSOAPModule().config.dumpFaultInfo and not isinstance(e, SOAPpy.faultType):
                    s = 'Method %s exception' % nsmethod
                    SOAPpy.debugHeader(s)
                    traceback.print_exception(info[0], info[1],
                                                info[2])
                    SOAPpy.debugFooter(s)

                if isinstance(e, SOAPpy.faultType):
                    f = e
                else:
                    f = SOAPpy.faultType("%s:Server" % SOAPpy.NS.ENV_T,
                                            "Method Failed",
                                            "%s" % nsmethod)

                if managers.module_manager.getSOAPModule().config.returnFaultInfo:
                    f._setDetail("".join(traceback.format_exception(
                        info[0], info[1], info[2])))
                elif not hasattr(f, 'detail'):
                    f._setDetail("%s %s" % (info[0], info[1]))
            finally:
                del info

            # method failed - return soap fault (no method tag needed)
            resp = SOAPpy.buildSOAP(f, encoding=managers.module_manager.getSOAPModule().encoding,
                                    config=managers.module_manager.getSOAPModule().config, namespace="http://services.vdom.net/VDOMServices")
            status = self.__request.fault_type_http_code
        except Exception as e:
            # internal error, report as HTTP server error

            if managers.module_manager.getSOAPModule().config.dumpFaultInfo:
                s = 'Internal exception %s' % e
                import traceback
                SOAPpy.debugHeader(s)
                info = sys.exc_info()
                try:
                    traceback.print_exception(info[0], info[1], info[2])
                finally:
                    del info

                SOAPpy.debugFooter(s)


            self.send_response(self.__request.fault_type_http_code)
            self.end_headers()

            if dumpHeadersOut and \
               self.request_version != 'HTTP/0.9':
                s = 'Outgoing HTTP headers'
                SOAPpy.debugHeader(s)
                if status in self.responses:
                    s = ' ' + self.responses[status][0]
                else:
                    s = ''
                debug("%s %d%s" % (self.protocol_version, self.__request.fault_type_http_code, s))
                debug("Server: %s" % self.version_string())
                debug("Date: %s" % self.__last_date_time_string)
                SOAPpy.debugFooter(s)
        else:
            # got a valid SOAP response
            self.response['code'] = str(status)

            t = 'text/xml';
            if managers.module_manager.getSOAPModule().encoding != None:
                t += '; charset="%s"' % managers.module_manager.getSOAPModule().encoding

            self.response['response_body'].append(('Content-type', str(t)))
            self.response['response_body'].append(('Content-length', str(len(resp))))

            if dumpHeadersOut and \
               self.request_version != 'HTTP/0.9':
                s = 'Outgoing HTTP headers'
                SOAPpy.debugHeader(s)
                if status in self.responses:
                    s = ' ' + self.responses[status][0]
                else:
                    s = ''
 #               debug("%s %d%s" % (self.protocol_version, status, s))
                debug("Server: %s" % self.version_string())
                debug("Date: %s" % self.__last_date_time_string)
                debug("Content-type: %s" % t)
                debug("Content-length: %d" % len(resp))
                SOAPpy.debugFooter(s)

            if dumpSOAPOut:
                try:
                    s = 'Outgoing SOAP'
                    SOAPpy.debugHeader(s)
                    debug(resp)

                    SOAPpy.debugFooter(s)
                except: pass

            #resp = xml.sax.saxutils.unescape(resp)
            self.wfile["response"].append(str(resp))

            # We should be able to shut down both a regular and an SSL
            # connection, but under Python 2.1, calling shutdown on an
            # SSL connections drops the output, so this work-around.
            # This should be investigated more someday.

            if managers.module_manager.getSOAPModule().config.SSLserver and \
               isinstance(self.connection, SSL.Connection):
                self.connection.set_shutdown(SSL.SSL_SENT_SHUTDOWN |
                                             SSL.SSL_RECEIVED_SHUTDOWN)
            else:
                #self.connection.shutdown(1)
                pass

    def date_time_string(self):
        self.__last_date_time_string = BaseHTTPServer.BaseHTTPRequestHandler.date_time_string(self)
        return self.__last_date_time_string
    
    def send_error(self, code, message=None, excinfo=None):
        """ send error """
        try:
            short, explanation=self.responses[code]
        except KeyError:
            short, explanation='???', '???'
        if message is None:
            message=short

        self.response['code'] = str(code)
        self.response['response_body'].append(("Conenction", "close"))
        self.wfile["response"].append("Error " + str(code) + " " + message)

        if code < 200 or code in (204, 205, 304):
            content = None
        else:
            content = compose_page(
                explanation, title="Error", heading="Error %d: %s" % (code, message),
                extra=compose_trace if settings.SHOW_PAGE_DEBUG else None)
            self.response['response_body'].append(('Content-Type', "text/html"))

        if self.command != "HEAD" and content:
            self.wfile["response"].append(str(content))

    def version_string(self):
        """Return the server software version string."""
        return "VDOM v2 server " + VDOM_server_version + ' ' + self.sys_version
