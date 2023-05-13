import json
import managers
import wsgidav.util as util
from webdav_request import VDOM_webdav_request
from wsgidav.dav_error import DAVError, HTTP_FORBIDDEN
from webdav_cache import lru_cache
from wsgidav.http_authenticator import HTTPAuthenticator
from wsgidav.middleware import BaseMiddleware
class VDOM_DigestHandler(BaseMiddleware):
	def __init__(self, application, domaincontroller):
		self._domaincontroller = domaincontroller
		self._application = application	
	def __call__(self, environ, start_response):
		if environ["http_authenticator.username"]:
			self._domaincontroller.authDomainUser(environ["http_authenticator.realm"], environ["http_authenticator.username"],"",environ)
		return self._application(environ, start_response)	
	
class VDOM_HTTPAuthenticator(HTTPAuthenticator):
	def computeDigestResponse(self, username, realm, password, method, uri, nonce, cnonce, qop, nc):
		md5hA1 = self._domaincontroller.getDigest(realm, username)
		A2 = method + ":" + uri
		if qop:
			digestresp = self.md5kd( md5hA1, nonce + ":" + nc + ":" + cnonce + ":" + qop + ":" + self.md5h(A2))
		else:
			digestresp = self.md5kd( md5hA1, nonce + ":" + self.md5h(A2))
			
		if not isinstance (self._application,VDOM_DigestHandler):
			self._application = VDOM_DigestHandler(self._application,self._domaincontroller)
		return digestresp
		

def authAppUser(app_id, obj_id, user, password):
	try:
		xml_data = """{"user": "%s","password": "%s"}""" % (user, password)
		return managers.dispatcher.dispatch_action(app_id, obj_id, "authentication", "",xml_data)
	except Exception as e:
		debug("DAV auth error: %s"%e)
		return False

def authGetDigest(app_id, obj_id, user):
	try:
		xml_data = json.dumps({"user":user})
		return managers.dispatcher.dispatch_action(app_id, obj_id, "getDigest", "",xml_data)
	except Exception as e:
		debug("DAV auth error: %s"%e)
		return ""


class VDOM_domain_controller(object):
	
	def __init__(self, appid):
		
		try:
			self._application = managers.memory.applications.get(appid) 
		except:
			self._application = None
			
	def getDomainRealm(self, inputRelativeURL, environ):
		davProvider = environ["wsgidav.provider"]
		if not davProvider:
			if environ["wsgidav.verbose"] >= 2:
				print >>sys.stdout, "getDomainRealm(%s): '%s'" %(inputURL, None)
			return None
		obj_name = davProvider.sharePath.strip("/")
		if obj_name == "":
			return ""
		obj = self._application.objects.get(obj_name)
			
		return obj.id

	def requireAuthentication(self, realmname, environ):
		session = managers.request_manager.current.session()
		return "current_user" not in session and "dav_user" not in session

	def isRealmUser(self, realmname, username, environ):
		return True

	def getRealmUserPassword(self, realmname, username, environ):
		return ""

	def authDomainUser(self, realmname, username, password, environ):
		#request = VDOM_webdav_request(environ)
		#managers.request_manager.current = request
		obj_id = realmname
		session = managers.request_manager.current.session()
		if "dav_user" in session and session["dav_user"] == (self._application.id, obj_id,username, password):
			return True
		else:
			ret = authAppUser(self._application.id, obj_id,username, password)
			if ret:
				session["dav_user"] = (self._application.id, obj_id,username, password)
				return True
			else:
				return False
		#raise DAVError(HTTP_FORBIDDEN)
	
	def getDigest(self, realmname, username):
		obj_id = realmname
		if obj_id == '/':
			obj_id = managers.webdav_manager.list_webdav(self._application.id)[0]
			
		session = managers.request_manager.current.session()
		if not session.get("dav_digest"):
			session["dav_digest"] = authGetDigest(self._application.id, obj_id,username)
		return session.get("dav_digest","")

#	def _get_app(self, host):
#
#		vh = managers.virtual_hosts
#		app_id = vh.get_site(host.lower())
#		if not app_id:
#			app_id = vh.get_def_site()
#		return managers.xml_manager.get_application(app_id)

#	def _get_object_id(self, path, app):
#		pathInfoParts = path.strip("/").split("/")
#		name = pathInfoParts[0]
#		if not app:
#			return None
#		try:        
#			obj = app.get_objects_by_name()[name.lower()]
#			r  = util.toUnicode(obj.id) if obj else None
#		except:
#			r = ""
#		return r