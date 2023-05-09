
import weakref
import socket
from collections import deque
from threading import Lock
from time import sleep

import settings
from logs import log

from .. import actions
from ..packer import create_packer
from ..stream import LogSocketStream
from ..logger import BaseLogger


COUNTDOWN = 3.0
RECONNECT_TIMEOUT = 5


class Logger(BaseLogger):

    name = "Logger"

    def __init__(self):

        def condition():
            with self._lock:
                return not self._queue

        super(Logger, self).__init__(condition=condition, countdown=COUNTDOWN)

        self._address = settings.LOGGING_ADDRESS
        self._port = settings.LOGGING_PORT

        self._lock = Lock()
        self._queue = deque()

        self._index = 0
        self._available = deque()
        self._mapping = {}
        self._counters = {}

        self._actual = {}
        self._stream = None

    def ascribe(self, sublog):
        # prepare packer and perform assume
        name, packer = sublog.name, sublog.packer
        with self._lock:
            try:
                luid = self._mapping[name]
                self._counters[luid] += 1
            except KeyError:
                try:
                    luid = self._available.popleft()
                except IndexError:
                    luid = self._index
                    self._index += 1
                self._mapping[name] = luid
                self._counters[luid] = 1
                self._queue.append((actions.ASSUME, luid, name))

        def enqueue(*values):
            with self._lock:
                self._queue.append((actions.WRITE, luid, packer, values))

        def cleanup(nothing):
            proxy  # prevent to unlink proxy
            with self._lock:
                self._counters[luid] -= 1
                if self._counters[luid] == 0:
                    self._queue.append((actions.REVOKE, luid))
                    del self._counters[luid]
                    self._available.appendleft(luid)
                    del self._mapping[name]

        # return enqueue
        proxy = weakref.proxy(enqueue, cleanup)
        return enqueue

    def cleanup(self):
        super(Logger, self).cleanup()
        self.work()
        self._stream = None

    _assume_request = create_packer("BBS")
    _revoke_request = create_packer("BB")
    _write_request = create_packer("BBL")

    def work(self):
        # obtain entry(ies)
        with self._lock:
            try:
                entry = self._queue.popleft()
            except IndexError:
                return

            # consume as much write actions as possible
            if entry[0] == actions.WRITE:
                entries, luid = [entry], entry[1]
                while self._queue:
                    next_entry = self._queue[0]
                    if next_entry[0] != actions.WRITE or next_entry[1] != luid:
                        break
                    entries.append(self._queue.popleft())

        # def restore():
        #     with self._lock:
        #         if entry[0] in (actions.ASSUME, actions.REVOKE):
        #             self._queue.appendleft(entry)
        #         else:
        #             for entry in reversed(entries):
        #                 self._queue.appendleft(entry)

        # send entry(ies)
        try:
            if self._stream is None:

                # (re)connect to the server
                while 1:
                    log.write("Connect to %s:%d" % (self._address, self._port))
                    stream_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    stream_socket.settimeout(RECONNECT_TIMEOUT) # self.quantum
                    try:
                        stream_socket.connect((self._address, self._port))
                        print("connection successful")
                        break
                    except socket.timeout:
                        if not self.running:
                            return
                    except socket.error as error:
                        log.error(error.strerror or str(error))
                        sleep(RECONNECT_TIMEOUT)

                # create stream
                self._stream = LogSocketStream(self, stream_socket)
                with self._lock:
                    for luid, name in self._actual.iteritems():
                        self._queue.appendleft((actions.ASSUME, luid, name))

            # send entry(ies) to the server
            try:
                if entry[0] == actions.ASSUME:
                    self._assume_request.pack_into(self._stream, actions.ASSUME, entry[1], entry[2])
                    with self._lock:
                        self._actual[entry[1]] = entry[2]
                elif entry[0] == actions.REVOKE:
                    self._revoke_request.pack_into(self._stream, actions.REVOKE, entry[1])
                    with self._lock:
                        del self._actual[entry[1]]
                else:
                    self._write_request.pack_into(self._stream, actions.WRITE, entry[1], len(entries))
                    for index, entry in enumerate(entries):
                        entry[2].pack_into(self._stream, *entry[3])
                return 0
            except socket.error as error:
                log.error(error.strerror or error.message)
                self._stream = None
        except:
            with self._lock:
                if entry[0] == actions.WRITE:
                    self._queue.extendleft(entries)
                else:
                    self._queue.appendleft(entry)
            raise
