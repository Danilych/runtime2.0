"""VDOM web services"""
import SOAPpy
# import traceback

# import utils.encode
from utils.exception import *
import managers

from importlib import import_module
show_exception_trace = import_module("utils.tracing").show_exception_trace


def format_error(msg):
    """prepare error xml message"""
    return "<Error><![CDATA[%s]]></Error>" % str(msg)


def proxy1(args):
    try:
        return args[0](*args[1:]) or ""
    except SOAPpy.faultType:
        show_exception_trace(label="SOAP Proxy", locals=True)
        raise
    except VDOM_exception, v:
        show_exception_trace(label="SOAP Proxy1", locals=True)
        # traceback.print_exc(file=debugfile)
        return format_error(str(v))
    except Exception, e:
        show_exception_trace(label="SOAP Proxy1", locals=True)
        # traceback.print_exc(file=debugfile)
        return format_error(str(e))


def proxy(args):
    try:
        return (args[0](*args[1:]) or "") + ("\n<Key>%s</Key>" % args[2])
    except SOAPpy.faultType:
        show_exception_trace(label="SOAP Proxy", locals=True)
        raise
    except VDOM_exception, v:
        show_exception_trace(label="SOAP Proxy", locals=True)
        # traceback.print_exc(file=debugfile)
        return format_error(str(v))
    except Exception, e:
        show_exception_trace(label="SOAP Proxy", locals=True)
        # traceback.print_exc(file=debugfile)
        return format_error(str(e))


# open session with the server

def open_session(name, pwd_md5, _SOAPContext):
    return proxy1([managers.soap_server.open_session, name, pwd_md5])


# close session

def close_session(sid, _SOAPContext):
    return proxy1([managers.soap_server.close_session, sid])


# create new application

def create_application(sid, skey, attr, _SOAPContext):
    return proxy([managers.soap_server.create_application, sid, skey, attr])


# set application info attributes

def set_application_info(sid, skey, appid, attr, _SOAPContext):
    return proxy([managers.soap_server.set_application_info, sid, skey, appid, attr])


# get application info attributes

def get_application_info(sid, skey, appid, _SOAPContext):
    return proxy([managers.soap_server.get_application_info, sid, skey, appid])


# get the list of all applications

def list_applications(sid, skey, _SOAPContext):
    return proxy([managers.soap_server.list_applications, sid, skey])


# get the list of all types

def list_types(sid, skey, _SOAPContext):
    return proxy([managers.soap_server.list_types, sid, skey])


# get type description

def get_type(sid, skey, typeid, _SOAPContext):
    return proxy([managers.soap_server.get_type, sid, skey, typeid])


# add/update type

def set_type(sid, skey, typexml, _SOAPContext):
    return proxy([managers.soap_server.set_type, sid, skey, typexml])


# get all types description

def get_all_types(sid, skey, _SOAPContext):
    return proxy([managers.soap_server.get_all_types, sid, skey])


# get resource

def get_resource(sid, skey, ownerid, resid, _SOAPContext):
    return proxy([managers.soap_server.get_resource, sid, skey, ownerid, resid])


# list resources

def list_resources(sid, skey, ownerid, _SOAPContext):
    return proxy([managers.soap_server.list_resources, sid, skey, ownerid])


# create object in the application

def create_object(sid, skey, appid, parentid, typeid, name, attr, _SOAPContext):
    return proxy([managers.soap_server.create_object, sid, skey, appid, parentid, typeid, name, attr])


# create objects in the application

def create_objects(sid, skey, appid, parentid, objects, _SOAPContext):
    return proxy([managers.soap_server.create_objects, sid, skey, appid, parentid, objects])


# copy object in the application

def copy_object(sid, skey, appid, parentid, objid, tgt_appid, _SOAPContext):
    return proxy([managers.soap_server.copy_object, sid, skey, appid, parentid, objid, tgt_appid])


def move_object(sid, skey, appid, parentid, objid, _SOAPContext):
    return proxy([managers.soap_server.move_object, sid, skey, appid, parentid, objid])


# update object in the application

def update_object(sid, skey, appid, objid, data, _SOAPContext):
    return proxy([managers.soap_server.update_object, sid, skey, appid, objid, data])


# render object to xml presentation

def render_wysiwyg(sid, skey, appid, objid, parentid, dynamic, _SOAPContext):
    return proxy([managers.soap_server.render_wysiwyg, sid, skey, appid, objid, parentid, int(dynamic)])


# get application top-level objects

def get_top_objects(sid, skey, appid, _SOAPContext):
    return proxy([managers.soap_server.get_top_objects, sid, skey, appid])


# lightweight get application top-level objects

def get_top_object_list(sid, skey, appid, _SOAPContext):
    return proxy([managers.soap_server.get_top_object_list, sid, skey, appid])


# get all objects

def get_all_object_list(sid, skey, appid, _SOAPContext):
    return proxy([managers.soap_server.get_all_object_list, sid, skey, appid])


# get object's child objects

def get_child_objects(sid, skey, appid, objid, _SOAPContext):
    return proxy([managers.soap_server.get_child_objects, sid, skey, appid, objid])


# get all object's child objects

def get_child_objects_tree(sid, skey, appid, objid, _SOAPContext):
    return proxy([managers.soap_server.get_child_objects_tree, sid, skey, appid, objid])


# get one object description

def get_one_object(sid, skey, appid, objid, _SOAPContext):
    return proxy([managers.soap_server.get_one_object, sid, skey, appid, objid])


# get application language data

def get_application_language_data(sid, skey, appid, _SOAPContext):
    return proxy([managers.soap_server.get_application_language_data, sid, skey, appid])


# get application structure

def get_application_structure(sid, skey, appid, _SOAPContext):
    return proxy([managers.soap_server.get_application_structure, sid, skey, appid])


# set application structure

def set_application_structure(sid, skey, appid, struct, _SOAPContext):
    return proxy([managers.soap_server.set_application_structure, sid, skey, appid, struct])


# set object attribute value

def set_attribute(sid, skey, appid, objid, attr, value, _SOAPContext):
    return proxy([managers.soap_server.set_attribute, sid, skey, appid, objid, attr, value])


# set value of several object's attributes

def set_attributes(sid, skey, appid, objid, attr, _SOAPContext):
    return proxy([managers.soap_server.set_attributes, sid, skey, appid, objid, attr])


# set object name

def set_name(sid, skey, appid, objid, name, _SOAPContext):
    return proxy([managers.soap_server.set_name, sid, skey, appid, objid, name])


# set application resource

def set_resource(sid, skey, appid, restype, resname, resdata, _SOAPContext):
    return proxy([managers.soap_server.set_resource, sid, skey, appid, restype, resname, resdata])


# update application resource

def update_resource(sid, skey, appid, resid, resdata, _SOAPContext):
    return proxy([managers.soap_server.update_resource, sid, skey, appid, resid, resdata])


# delete application resource

def delete_resource(sid, skey, appid, resid, _SOAPContext):
    return proxy([managers.soap_server.delete_resource, sid, skey, appid, resid])


# delete object

def delete_object(sid, skey, appid, objid, _SOAPContext):
    return proxy([managers.soap_server.delete_object, sid, skey, appid, objid])


# get object xml script presentation

def get_object_script_presentation(sid, skey, appid, objid, _SOAPContext):
    return proxy([managers.soap_server.get_object_script_presentation, sid, skey, appid, objid])


# submit object xml script presentation

def submit_object_script_presentation(sid, skey, appid, objid, pres, _SOAPContext):
    return proxy([managers.soap_server.submit_object_script_presentation, sid, skey, appid, objid, pres])


# modify resource

def modify_resource(sid, skey, appid, objid, resid, attrname, operation, attr, _SOAPContext):
    return proxy([managers.soap_server.modify_resource, sid, skey, appid, objid, resid, attrname, operation, attr])


# execute sql

def execute_sql(sid, skey, appid, dbid, sql, script, _SOAPContext):
    return proxy([managers.soap_server.execute_sql, sid, skey, appid, dbid, sql, script])


# get application events

def get_application_events(sid, skey, appid, objid, _SOAPContext):
    return proxy([managers.soap_server.get_application_events, sid, skey, appid, objid])


# set application events

def set_application_events(sid, skey, appid, objid, events, _SOAPContext):
    return proxy([managers.soap_server.set_application_events, sid, skey, appid, objid, events])


# execute object method

def remote_method_call(sid, skey, appid, objid, func_name, xml_param, session_id, _SOAPContext):
    return proxy([managers.soap_server.remote_method_call, sid, skey, appid, objid, func_name, xml_param, session_id])


def remote_call(sid, skey, appid, objid, func_name, xml_param, xml_data, _SOAPContext):
    return proxy([managers.soap_server.remote_call, sid, skey, appid, objid, func_name, xml_param, xml_data])


def install_application(sid, skey, vhname, appxml, _SOAPContext):
    return proxy([managers.soap_server.install_application, sid, skey, vhname, appxml])


def uninstall_application(sid, skey, appid, _SOAPContext):
    return proxy([managers.soap_server.uninstall_application, sid, skey, appid])


def export_application(sid, skey, appid, _SOAPContext):
    return proxy([managers.soap_server.export_application, sid, skey, appid])


def update_application(sid, skey, appxml, _SOAPContext):
    return proxy([managers.soap_server.update_application, sid, skey, appxml])


def check_application_exists(sid, skey, appid, _SOAPContext):
    return proxy([managers.soap_server.check_application_exists, sid, skey, appid])


def backup_application(sid, skey, appid, driverid, _SOAPContext):
    return proxy([managers.soap_server.backup_application, sid, skey, appid, driverid])


def get_task_status(sid, skey, taskid, _SOAPContext):
    return proxy([managers.soap_server.get_task_status, sid, skey, taskid])


def restore_application(sid, skey, appid, driverid, revision, _SOAPContext):
    return proxy([managers.soap_server.restore_application, sid, skey, appid, driverid, revision])


def list_backup_drivers(sid, skey, _SOAPContext):
    return proxy([managers.soap_server.list_backup_drivers, sid, skey])


def set_vcard_license(sid, skey, serial, reboot, _SOAPContext):
    return proxy([managers.soap_server.set_vcard_license, sid, skey, serial, reboot])


def create_guid(sid, skey, _SOAPContext):
    print("CREATE GUID")
    return proxy([managers.soap_server.create_guid, sid, skey])


def get_thumbnail(sid, skey, appid, resid, width, height, _SOAPContext):
    return proxy([managers.soap_server.get_thumbnail, sid, skey, appid, resid, width, height])


def search(sid, skey, appid, pattern, _SOAPContext):
    return proxy([managers.soap_server.search, sid, skey, appid, pattern])


def keep_alive(sid, skey, _SOAPContext):
    return proxy([managers.soap_server.keep_alive, sid, skey])


# set server actions

def set_server_actions(sid, skey, appid, objid, actions, _SOAPContext):
    return proxy([managers.soap_server.set_server_actions, sid, skey, appid, objid, actions])


def get_events_structure(sid, skey, appid, objid, _SOAPContext):
    return proxy([managers.soap_server.get_events_structure, sid, skey, appid, objid])


def set_events_structure(sid, skey, appid, objid, events, _SOAPContext):
    return proxy([managers.soap_server.set_events_structure, sid, skey, appid, objid, events])


def create_server_action(sid, skey, appid, objid, actionname, actionvalue, _SOAPContext):
    return proxy([managers.soap_server.create_server_action, sid, skey, appid, objid, actionname, actionvalue])


def delete_server_action(sid, skey, appid, objid, actionid, _SOAPContext):
    return proxy([managers.soap_server.delete_server_action, sid, skey, appid, objid, actionid])


def rename_server_action(sid, skey, appid, objid, actionid, new_actionname, _SOAPContext):
    return proxy([managers.soap_server.rename_server_action, sid, skey, appid, objid, actionid, new_actionname])


def get_server_action(sid, skey, appid, objid, actionid, _SOAPContext):
    return proxy([managers.soap_server.get_server_action, sid, skey, appid, objid, actionid])


def set_server_action(sid, skey, appid, objid, actionid, actionvalue, _SOAPContext):
    return proxy([managers.soap_server.set_server_action, sid, skey, appid, objid, actionid, actionvalue])


def get_server_actions_list(sid, skey, appid, objid, _SOAPContext):
    return proxy([managers.soap_server.get_server_actions_list, sid, skey, appid, objid])

# NOTE: already defined above
# def set_application_events(sid, skey, appid, objid, events, _SOAPContext):
#     return proxy([managers.soap_server.set_application_events, sid, skey, appid, objid, events])


# get server actions

def get_server_actions(sid, skey, appid, objid, _SOAPContext):
    return proxy([managers.soap_server.get_server_actions, sid, skey, appid, objid])


def set_library(sid, skey, appid, name, data, _SOAPContext):
    return proxy([managers.soap_server.set_lib, sid, skey, appid, name, data])


def remove_library(sid, skey, appid, name, _SOAPContext):
    return proxy([managers.soap_server.del_lib, sid, skey, appid, name])


def get_library(sid, skey, appid, name, _SOAPContext):
    return proxy([managers.soap_server.get_lib, sid, skey, appid, name])


def get_libraries(sid, skey, appid, _SOAPContext):
    return proxy([managers.soap_server.get_libs, sid, skey, appid])


def server_information(sid, skey, _SOAPContext):
    return proxy([managers.soap_server.server_information, sid, skey])


def set_application_vhost(sid, skey, appid, hostname, _SOAPContext):
    return proxy([managers.soap_server.set_application_vhost, sid, skey, appid, hostname])


def delete_application_vhost(sid, skey, hostname, _SOAPContext):
    return proxy([managers.soap_server.delete_application_vhost, sid, skey, hostname])
