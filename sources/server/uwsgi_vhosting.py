from utils.singleton2 import SingletonTwo
from web.vhosting import VDOM_vhosting

class wsgiVhosting(SingletonTwo):
    def virtual_hosting(self):
        if not hasattr(self, "_vhosting"):
            self._vhosting = VDOM_vhosting()
        return self._vhosting
    
VDOM_WSGI_Vhosting = wsgiVhosting