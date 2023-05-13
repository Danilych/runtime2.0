
from logs import log
from utils.threads import SmartThread
from http_server import VDOM_http_server
from http_request_handler import VDOM_http_request_handler


class WebServer(SmartThread):

    def __init__(self):
        SmartThread.__init__(self, name="Web Server")
        self.__server = None

    def main(self):
        log.write("Start %s\n" % self.name)
        server_address = (VDOM_CONFIG["SERVER-ADDRESS"], VDOM_CONFIG["SERVER-PORT"])
        self.__server = VDOM_http_server(server_address, VDOM_http_request_handler)
        msg = "%s listening on port %s" % (VDOM_http_request_handler.server_version, VDOM_CONFIG["SERVER-PORT"])
        log.write(msg, "Web server thread")
        self.__server.daemon_threads = True
        self.__server.serve_forever()

    def stop(self):
        super(VDOM_web_server_thread, self).stop()
        log.write("Stop %s\n" % self.name)
        if self.__server:
            self.__server.shutdown()



VDOM_web_wsgiserver_thread = WebServer
