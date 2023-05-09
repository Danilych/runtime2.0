
import socket
import select
from utils.threads import SmartDaemon
import settings
from logs import log
from ..loggers import Logger
from .session import LogServerSession


LISTEN_BACKLOG = 3


class LogServer(SmartDaemon):

    name = "Log Server"

    def __init__(self, address=settings.LOGGING_ADDRESS, port=settings.LOGGING_PORT):
        super(LogServer, self).__init__(name=LogServer.name, latter=True, dependencies=Logger.name)
        self._address = address
        self._port = port
        self._socket = None

    def prepare(self):
        log.write("Start " + self.name)

    def cleanup(self):
        log.write("Stop " + self.name)
        self._socket = None

    def main(self):
        while self.running:
            if self._socket is None:
                self._socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                try:
                    self._socket.bind(('', self._port))
                except:
                    log.error("Log server is already running or incorrect address or port")
                    self.stop()
                    return
                self._socket.listen(LISTEN_BACKLOG)
                log.write("Listen on %s:%d" % (self._address, self._port))
            reading, writing, erratic = select.select((self._socket,), (), (), self.quantum)
            if reading:
                try:
                    session_socket, address = self._socket.accept()
                    log.write("Start session with %s" % session_socket.getpeername()[0])
                    LogServerSession(session_socket).start()
                except socket.error:
                    continue


VDOM_log_server = LogServer
