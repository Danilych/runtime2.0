from utils.threads import SmartServer
from watcher import Watcher
from web import VDOM_web_server_thread
from wsgiref.simple_server import make_server
from web.wsgi_request_handler import VDOM_wsgi_request_handler
from web.vhosting import VDOM_vhosting

class WsgiServer(SmartServer):

    def prepare(self):

        self._watcher = Watcher()
        self._watcher.start()

        self._web_server = VDOM_web_wsgiserver_thread()
        self._web_server.start()
        def entry_point(environ, start_response):
            request_handler = VDOM_wsgi_request_handler(None, ("0.0.0.0","80"), 
                                                        self,{"reject":0, "deny":0, "card":True, "limit":True, "connections":1024})
            request_handler.handle_wsgi_request(environ,start_response)
            return request_handler.wfile        
            
        httpd = make_server(VDOM_CONFIG["SERVER-ADDRESS"], VDOM_CONFIG["SERVER-PORT"], entry_point)
        httpd.serve_forever()

    def virtual_hosting(self):
        if not hasattr(self, "_vhosting"):
            self._vhosting = VDOM_vhosting()
        return self._vhosting

VDOM_wsgi_server = WsgiServer








