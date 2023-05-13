"""Session Manager module"""

import thread, time, copy

from session import VDOM_session
from utils.semaphore import VDOM_semaphore
from utils.exception import VDOM_exception
import managers
from daemon import VDOM_session_cleaner
from utils.id import vdomid
import settings

class VDOM_session_manager(dict):
	"""Session Manager class"""

	def __init__(self):
		"""constructor"""
		dict.__init__(self)
		self.__timeout = VDOM_CONFIG["SESSION-LIFETIME"]
		self.__sem = VDOM_semaphore()#1,True)
		#start clean thread
		self.__daemon=VDOM_session_cleaner(self)
		self.__daemon.start()

	def check_sessions(self):
		"""clean timed-out sessions"""
		keys_copy = copy.deepcopy(self.keys())
		for sid in keys_copy: self[sid]

	def work(self):
		"""clean thread function"""
		self.check_sessions()
		return min(120, self.__timeout)

	def create_session(self):
		print("CREATE SESSION (MANAGER)")
		"""create session & return it`s id"""
		s = VDOM_session(self.get_unique_sid())
		self.__sem.lock()
		try:
			dict.__setitem__(self, s.id(), s)
		finally:
			self.__sem.unlock()
		return s.id()

	def remove_session(self, session_id):
		self.__delitem__(session_id)

	def session_exists(self, session_id):
		print("SESSION EXISTS (MANAGER)")
		return self.__contains__(session_id)

	def get_session(self, session_id):
		print("GET SESSION (MANAGER)")
		return self.__getitem__(session_id)

	def __setitem__(self, key, value):
		# not allowed
		raise AttributeError()

	def __getitem__(self, key):
		print("GET SESSION ITEM (MANAGER)")
		self.__sem.lock()
		try:
			if dict.__contains__(self, key):
				s = dict.__getitem__(self, key)
				if s.is_expired(self.__timeout):
					# execute session onfinish action and cleanup dynamic objects
					try:
						if settings.SERVER and "application_id" in s.context and s.context["application_id"]:
							application = managers.memory.applications[s.context["application_id"]]
							action = application.actions.get("sessiononfinish")
							if action and action.source_code:
								managers.engine.execute(action)
					finally:
						s.context = {}
						s.clean_files()
						dict.__delitem__(self, key)
				else:
					return s
			return None
		finally:
			self.__sem.unlock()

	def __delitem__(self, key):
		self.__sem.lock()
		try:
			if dict.__contains__(self, key):
				s = dict.__getitem__(self, key)
				s.context = {}
				dict.__delitem__(self, key)
		finally:
			self.__sem.unlock()

	def __contains__(self, key):
		return dict.__contains__(self, key)

	def __get_current(self):
		self.__sem.lock()
		try:
			return managers.request_manager.current.session()
		finally:
			self.__sem.unlock()

	def __set_current(self, sess):
		self.__sem.lock()
		try:
			managers.request_manager.current.set_session_id(sess.id)
		finally:
			self.__sem.unlock()

	current = property(__get_current, __set_current)

	def get_unique_sid(self):
		print("GET UNIQUE SID (MANAGER)")
		sid = vdomid()
		while dict.__contains__(self, sid):

			sid = vdomid()
			debug("Sid generation colision")
		return sid