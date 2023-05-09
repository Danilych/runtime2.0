from web.uwsgi_request_handler import VDOM_uwsgi_request_handler


def myapplication(env, start_response):
    request_handler = VDOM_uwsgi_request_handler(None, ("0.0.0.0", "80"),{"reject":0, "deny":0, "card":True, "limit":True, "connections":1024})
    return request_handler.handle_wsgi_request(env, start_response)

   # start_response('200 OK', [('Content-Type', 'text/html')])
   # return [b"Hello World"]
    #return request_handler.wfile  








