
import os, socket

from version import SERVER_NAME, SERVER_VERSION

class VDOM_environment:
	"""environment variables"""

	def __init__(self, headers, handler):
		""" Constructor """
		self.__environment = {}
		for k in headers.keys():
#			if 'HTTP_' not in k:
				self.__environment[k] = str(headers[k])

		self.__environment["DOCUMENT_ROOT"] = str(os.getcwd())
		self.__environment["GATEWAY_INTERFACE"] = str("CGI/1.1")

	#	request_uri = str(handler.path)
	#	request_uri = request_uri.split('//')[-1]
	#	rrr = request_uri.split('/', 1)
	#	if len(rrr) > 1: request_uri = rrr[1]
	#	else: request_uri = rrr[0]
	#	self.__environment["REQUEST_URI"] = '/' + request_uri

		self.__environment["REMOTE_PORT"] = str(handler.client_address[1])
		self.__environment["SERVER_ADDR"] = str(socket.gethostbyname(socket.gethostname())) # str(handler.server.server_address[0])

		hh = ""
		if "HTTP_HOST" not in self.__environment:
			hh = self.__environment["SERVER_ADDR"]
		else: hh = self.__environment["HTTP_HOST"]
		hh = hh.split(":")[0]
		self.__environment["HTTP_HOST"] = hh
		self.__environment["SERVER_NAME"] = SERVER_NAME
		self.__environment["SERVER_VERSION"] = SERVER_VERSION
		self.__environment["SERVER_SOFTWARE"] = "Python 2.5"
		request_list = str(handler.path).split("?", 1)
		if request_list[0].find("..") != -1:
			self.__environment["SCRIPT_NAME"] = "/"
		else:
			self.__environment["SCRIPT_NAME"] = request_list[0]
	#try: self.__environment["QUERY_STRING"] = request_list[1]
	#	except: self.__environment["QUERY_STRING"] = ""

	def environment(self):
		"""access environment property"""
		return self.__environment
