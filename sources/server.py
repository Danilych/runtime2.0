#!/usr/bin/python
# encoding: utf8

import startup.server  # noqa
import settings
import managers

from logs import VDOM_log_manager
from startup import ImportManager
from storage import VDOM_storage
from file_access import VDOM_file_manager  # VDOM_share
from request import VDOM_request_manager
from resource import VDOM_resource_manager, VDOM_resource_editor
from database import VDOM_database_manager
from security import VDOM_user_manager, VDOM_acl_manager
from scripting import VDOM_compiler, VDOM_dispatcher, ScriptManager
from memory import VDOM_memory
from engine import VDOM_engine

from server import myapplication
#from server import VDOM_wsgi_server
# from mailing import VDOM_email_manager
from session import VDOM_session_manager
from module import VDOM_module_manager
from soap import VDOM_soap_server
from webdav_server import VDOM_webdav_manager

managers.register("log_manager", VDOM_log_manager)
managers.register("import_manager", ImportManager)
managers.register("file_manager", VDOM_file_manager, lazy=True)
managers.register("storage", VDOM_storage, lazy=True)
# managers.register("file_share", VDOM_share, lazy=True)
managers.register("resource_manager", VDOM_resource_manager, lazy=True)
managers.register("database_manager", VDOM_database_manager, lazy=True)
managers.register("user_manager", VDOM_user_manager, lazy=True)
managers.register("acl_manager", VDOM_acl_manager, lazy=True)
managers.register("dispatcher", VDOM_dispatcher, lazy=True)
managers.register("compiler", VDOM_compiler, lazy=True)
managers.register("script_manager", ScriptManager, lazy=True)
managers.register("memory", VDOM_memory, lazy=not settings.MANUAL_GARBAGE_COLLECTING)
managers.register("engine", VDOM_engine, lazy=True)

managers.register("session_manager", VDOM_session_manager, lazy=True)
managers.register("request_manager", VDOM_request_manager, lazy=True)
managers.register("resource_editor", VDOM_resource_editor, lazy=True)
# managers.register("scheduler_manager", VDOM_scheduler_manager, lazy=True)
# managers.register("email_manager", VDOM_email_manager, lazy=True)
managers.register("module_manager", VDOM_module_manager)
managers.register("soap_server", VDOM_soap_server)
managers.register("webdav_manager", VDOM_webdav_manager)
#managers.register("server", VDOM_server)

#on_prepare = (lambda: managers.memory.applications.default) if settings.PRELOAD_DEFAULT_APPLICATION else None #none
#managers.server.start(on_prepare)
print("=======================")
application = myapplication

