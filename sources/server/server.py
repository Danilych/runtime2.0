
from utils.threads import SmartServer
from utils.profiling import profiler
from watcher import Watcher
from web import WebServer
from utils.properties import roproperty



class Server(SmartServer):

    watcher = roproperty("_watcher")
    web_server = roproperty("_web_server")

    def prepare(self):
        self._watcher = Watcher()
        self._watcher.start()

        self._web_server = WebServer()
        self._web_server.start()

    def work(self):
        profiler.autosave()


VDOM_server = Server