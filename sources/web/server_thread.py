
from threading import current_thread, enumerate as enumerate_threads
from time import sleep

import settings

from logs import log
from utils.threads import SmartThread
from .http_server import VDOM_http_server
from .http_request_handler import THREAD_ATTRIBUTE_NAME, VDOM_http_request_handler


class WebServer(SmartThread):

    def __init__(self):
        SmartThread.__init__(self, name="Web Server")
        self.__server = None

    http_server = property(lambda self: self.__server)

    def main(self):
        log.write("Start %s\n" % self.name)
        print("----------------")
        server_address = (VDOM_CONFIG["SERVER-ADDRESS"], VDOM_CONFIG["SERVER-PORT"])
        self.__server = VDOM_http_server(server_address, VDOM_http_request_handler)
        msg = "%s listening on port %s" % (VDOM_http_request_handler.server_version, VDOM_CONFIG["SERVER-PORT"])
        log.write(msg, "Web server thread")
        # self.__server.daemon_threads = True
        self.__server.serve_forever()

    def suspend(self):
        self.__server.unavailable = True

        allowable = {current_thread()}
        while 1:
            threads = {thread for thread in enumerate_threads()
                if getattr(thread, THREAD_ATTRIBUTE_NAME, None) is not None}
            if not threads or threads == allowable:
                break
            sleep(settings.QUANTUM)

    def resume(self):
        self.__server.unavailable = False

    def stop(self):
        super(VDOM_web_server_thread, self).stop()
        log.write("Stop %s\n" % self.name)
        if self.__server:
            self.__server.shutdown()
        for thread in enumerate_threads():
            request = getattr(thread, THREAD_ATTRIBUTE_NAME, None)
            if request is not None:
                print thread, thread.name, request


VDOM_web_server_thread = WebServer
