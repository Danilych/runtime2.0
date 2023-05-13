"""session module"""

import sys, string, time, os, shutil
from copy import copy

from utils.exception import *
import managers


class VDOM_session(dict):
	"""session class"""

	def __init__(self, sid):
		print("SESSION INIT = " + str(sid))
		"""session constructor"""
		dict.__init__(self)

		self.__id = sid or managers.session_manager.get_unique_sid()
		print("SESSION ID = " + str(self.__id))
		self.context={}
		self.on_start_executed = False
		self.__user = ""
		self.update()
		self.files = {}
		self.states = [{"#": 0}]

	def id(self):
		"""access id property"""
		return self.__id

	def update(self):
		"""update last access time"""
		self.__last_access = time.time()

	def is_expired(self, tout):
		"""check if session is expired"""
		if self.__last_access < time.time() - tout:
			return True
		return False

	def value(self, key, value=None):
		"""access session values"""
		if value is not None:
			self[key] = value
			return value
		elif key in self:
			return self[key]
		else:
			return None

	def remove(self, key):
		"""remove data"""
		self.__delitem__(key)

	def get_key_list(self):
		"""get list of keys"""
		return self.keys()

	def __setitem__(self, key, value):
		print("SET ITEM SESSION = " + str(key) + " == " + str(value))
		self.update()
		if not isinstance(key, basestring):
			raise TypeError()
		dict.__setitem__(self, key, value)

	def __getitem__(self, key):
		print("GET ITEM SESSION = " + str(key))
		self.update()
		if not isinstance(key, basestring):
			raise TypeError()
		if dict.__contains__(self, key):
			return dict.__getitem__(self, key)
		return None

	def __delitem__(self, key):
		self.update()
		if dict.__contains__(self, key):
			dict.__delitem__(self, key)

	def __contains__(self, key):
		self.update()
		if not isinstance(key, basestring):
			raise TypeError()
		return dict.__contains__(self, key)

	def get(self, key, default=None):
		print("GET (2) ITEM SESSION = " + str(key) + " === " + str(dict.get(self, key, default)))
		self.update()
		if not isinstance(key, basestring):
			raise TypeError()
		return dict.get(self, key, default)
	
	def set_user(self, login, password, md5 = False):
		print("SET USER")
		if md5:
			if managers.user_manager.match_user_md5(login, password):
				self.__user = login
				return
		else:
			if managers.user_manager.match_user(login, password):
				self.__user = login
				return
		raise VDOM_exception_sec("Authentication failed")

	def __get_user(self):
		print("GET USER = " + str(self.__user))
		return self.__user

	user = property(__get_user)

	def clean_files(self):
		for uploaded_file in self.files.itervalues():
			uploaded_file.remove()