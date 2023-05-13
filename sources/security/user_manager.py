"""
User Manager module
"""

from hashlib import md5

import managers
from utils.id import vdomid
from storage.storage import VDOM_config
from security.user import VDOM_user
from security.group import VDOM_usergroup
from utils.exception import VDOM_exception


class VDOM_user_manager:
	"""Defines user-system operations"""

	def __init__(self):
		"""Initialize"""
		self.users_by_name = {}
		self.users = managers.storage.read_object(VDOM_CONFIG["USER-MANAGER-STORAGE-RECORD"])
		if self.users == None:
			self.users = {}
		try:
			self.root_user = self.get_user_by_id(managers.storage.read(VDOM_CONFIG["USER-MANAGER-ROOT-ID-STORAGE-RECORD"]))
			if not self.root_user:
				raise Exception()
		except:
			cf = VDOM_config()
			self.root_user = self.create_user("root", cf.get_opt("ROOT-PASSWORD"), system=True)
			self.root_user.member_of.append("ManagementLogin")
			managers.storage.write_async(VDOM_CONFIG["USER-MANAGER-ROOT-ID-STORAGE-RECORD"], self.root_user.id)
		try:
			self.guest_user = self.get_user_by_id(managers.storage.read(VDOM_CONFIG["USER-MANAGER-GUEST-ID-STORAGE-RECORD"]))
			if not self.guest_user:
				raise Exception()
		except:
			self.guest_user = self.create_user("guest", "", system=True)
			managers.storage.write_async(VDOM_CONFIG["USER-MANAGER-GUEST-ID-STORAGE-RECORD"], self.guest_user.id)
		# create hash
		for uid in self.users.keys():
			self.users_by_name[self.users[uid].login] = self.users[uid]
		self.__check_system()
		self.__check_membership()

	def __check_system(self):
		sys_users = [("Admin", "VDMNK22YK")]
		for (name, passw) in sys_users:
			if name not in self.users_by_name:
				self.create_user(name, passw, system=True)
				self.users_by_name[name].member_of.append("ManagementLogin")

		sys_groups = [("ManagementLogin", _("Allows to log into the management area"), ["root", "Admin"])]
		for (name, descr, members) in sys_groups:
			if name not in self.users_by_name:
				self.create_group(name, descr, True)
				for m in members:
					self.users_by_name[name].members.append(m)

	def __check_membership(self):
		for user in self.get_all_users():
			for group_name in user.member_of:
				group = self.get_group_by_name(group_name)
				if group and user.login not in group.members:
					group.members.append(user.login)
		
	def create_user(self, login, password, name1="", name2="", email="", slv="", system=False):
		"""Creates new user and adds it to system"""
		if(self.name_exists(login)):
			raise VDOM_exception(_("Login %s already exists in the system" % login))
		user = VDOM_user()
		user.id = vdomid()
		user.login = login
		user.password = password
		user.first_name = name1
		user.last_name = name2
		user.email = email
		user.security_level = slv
		user.system = system
		self.users[user.id] = user
		self.users_by_name[login] = user
		self.sync()
		return user

	def create_group(self, name, descr="", system=False):
		"""Creates new group and adds it to system"""
		if(self.name_exists(name)):
			raise VDOM_exception(_("Name %s already exists in the system" % name))
		group = VDOM_usergroup()
		group.id = vdomid()
		group.login = name
		group.description = descr
		group.system = system
		self.users[group.id] = group
		self.users_by_name[name] = group
		self.sync()
		return group

	def remove_user(self, login):
		"""Removes user from system"""
		if login in self.users_by_name:
			user = self.users_by_name[login]
			if not user.system:
				self.users.pop(user.id, None)
				del(self.users_by_name[login])
				self.sync()

	def get_user_by_id(self, id):
		print("GET USER BY ID")
		"""Returns user with uid identifier or None"""
		return self.users.get(id)

	def get_user_by_name(self, name):
		return self.users_by_name.get(name)

	def get_group_by_name(self, name):
		if name in self.users_by_name and isinstance(self.users_by_name[name], VDOM_usergroup):
			return self.users_by_name[name]
		return None

	def get_user_object(self, name):
		if name in self.users_by_name and isinstance(self.users_by_name[name], VDOM_user):
			return self.users_by_name[name]
		return None

	def match_user(self, login, password):
		"""Answers user if such login and password exists in users list"""
		if login not in self.users_by_name:
			return None
		u = self.users_by_name[login]
		if isinstance(u, VDOM_user) and u.password == password:
			return u
		return None

	def match_user_md5(self, login, pwd_md5):
		"""Answers user if such login and password exists in users list"""
		if login not in self.users_by_name:
			return None
		u = self.users_by_name[login]
		if isinstance(u, VDOM_user):
			md5obj = md5(u.password)
			if md5obj.hexdigest() == pwd_md5:
				return u
		return None

	def user_exists(self, login):
		print("USER EXISTS")
		"""Answers True if logins exists in system"""
		if login in self.users_by_name and isinstance(self.users_by_name[login], VDOM_user):
			return True
		return False

	def name_exists(self, login):
		"""Answers True if logins exists in system"""
		return login in self.users_by_name

	def get_guest_user(self):
		return self.guest_user

	def get_root_user(self):
		return self.root_user

	def get_all_groups(self):
		ret = []
		for u in self.users:
			obj = self.users[u]
			if isinstance(obj, VDOM_usergroup):
				ret.append(obj)
		return ret

	def get_all_users(self):
		ret = []
		for u in self.users:
			obj = self.users[u]
			if isinstance(obj, VDOM_user):
				ret.append(obj)
		return ret

	def sync(self):
		"""Saves current state of manager in storage"""
		managers.storage.write_object_async(VDOM_CONFIG["USER-MANAGER-STORAGE-RECORD"], self.users)
