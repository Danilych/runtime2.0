"""wsdl utilities"""

header = """<?xml version="1.0"?>
<definitions 
	targetNamespace="http://services.vdom.net/VDOMServices" 
	xmlns="http://schemas.xmlsoap.org/wsdl/" 
	xmlns:http="http://schemas.xmlsoap.org/wsdl/http/" 
	xmlns:mime="http://schemas.xmlsoap.org/wsdl/mime/" 
	xmlns:s="http://www.w3.org/2001/XMLSchema" 
	xmlns:s0="http://services.vdom.net/VDOMServices" 
	xmlns:soap="http://schemas.xmlsoap.org/wsdl/soap/" 
	xmlns:soapenc="http://schemas.xmlsoap.org/soap/encoding/" 
	xmlns:tm="http://microsoft.com/wsdl/mime/textMatching/">
"""

methods = {
	"open_session"	: ["name", "pwd_md5"],
	"close_session"	: ["sid"],
	"create_application" : ["sid", "skey", "attr"],
	"set_application_info" : ["sid", "skey", "appid", "attr"],
	"get_application_info" : ["sid", "skey", "appid"],
	"list_applications" : ["sid", "skey"],
	"list_types" : ["sid", "skey"],
	"get_type" : ["sid", "skey", "typeid"],
        "set_type" : ["sid", "skey", "typexml"],
	"get_all_types" : ["sid", "skey"],
	"get_resource" : ["sid", "skey", "ownerid", "resid"],
	"create_object" : ["sid", "skey", "appid", "parentid", "typeid", "name", "attr"],
	"create_objects" : ["sid", "skey", "appid", "parentid", "objects"],
	"copy_object" : ["sid", "skey", "appid", "parentid", "objid", "tgt_appid"],
	"move_object" : ["sid", "skey", "appid", "parentid", "objid"],
	"update_object" : ["sid", "skey", "appid", "objid", "data"],
	"render_wysiwyg" : ["sid", "skey", "appid", "objid", "parentid", "dynamic"],
	"get_object_script_presentation" : ["sid", "skey", "appid", "objid"],
	"submit_object_script_presentation" : ["sid", "skey", "appid", "objid", "pres"],
	"get_top_objects" : ["sid", "skey", "appid"],
        "get_top_object_list" : ["sid", "skey", "appid"],
        "get_all_object_list" : ["sid", "skey", "appid"],
	"get_child_objects" : ["sid", "skey", "appid", "objid"],
	"get_child_objects_tree" : ["sid", "skey", "appid", "objid"],
	"get_one_object" : ["sid", "skey", "appid", "objid"],
	"get_application_language_data" : ["sid", "skey", "appid"],
	"get_application_structure" : ["sid", "skey", "appid"],
	"set_application_structure" : ["sid", "skey", "appid", "struct"],
	"set_attribute" : ["sid", "skey", "appid", "objid", "attr", "value"],
	"set_attributes" : ["sid", "skey", "appid", "objid", "attr"],
	"set_resource" : ["sid", "skey", "appid", "restype", "resname", "resdata"],
	"update_resource" : ["sid", "skey", "appid", "resid", "resdata"],
	"delete_resource" : ["sid", "skey", "appid", "resid"],
	"set_name" : ["sid", "skey", "appid", "objid", "name"],
	"set_library" : ["sid", "skey", "appid", "name", "data"],
	"remove_library" : ["sid", "skey", "appid", "name"],
	"get_libraries" : ["sid", "skey", "appid"],
	"get_library" : ["sid", "skey", "appid", "name"],
	"delete_object" : ["sid", "skey", "appid", "objid"],
	"list_resources" : ["sid", "skey", "ownerid"],
	"modify_resource" : ["sid", "skey", "appid", "objid", "resid", "attrname", "operation", "attr"],
	"execute_sql" : ["sid", "skey", "appid", "dbid", "sql", "script"],
	"get_application_events" : ["sid", "skey", "appid", "objid"],
	"set_application_events" : ["sid", "skey", "appid", "objid", "events"],
	"set_server_actions" : ["sid", "skey", "appid", "objid", "actions"],
	"get_events_structure" : ["sid", "skey", "appid", "objid"],
	"set_events_structure" : ["sid", "skey", "appid", "objid", "events"],
	"get_server_actions" : ["sid", "skey", "appid", "objid"],
	"create_server_action" : ["sid", "skey", "appid", "objid", "actionname", "actionvalue"],
	"delete_server_action" : ["sid", "skey", "appid", "objid", "actionid"],
	"rename_server_action" : ["sid", "skey", "appid", "objid", "actionid", "new_actionname"],
	"get_server_action" : ["sid", "skey", "appid", "objid", "actionid"],
	"set_server_action" : ["sid", "skey", "appid", "objid", "actionid", "actionvalue"],
	"get_server_actions_list" : ["sid", "skey", "appid", "objid"],

	"remote_method_call" : ["sid", "skey", "appid", "objid", "func_name", "xml_param", "session_id"],
	"remote_call" : ["sid", "skey", "appid", "objid", "func_name", "xml_param", "xml_data"],
	"install_application" : ["sid", "skey", "vhname", "appxml"],
	"uninstall_application" : ["sid", "skey", "appid"],
	"export_application" : ["sid", "skey", "appid"],
	"update_application" : ["sid", "skey", "appxml"],
	"check_application_exists" : ["sid", "skey", "appid"],
	"backup_application" : ["sid", "skey", "appid", "driverid"],
        "get_task_status"  : ["sid", "skey", "taskid"],
	"restore_application" : ["sid", "skey", "appid", "driverid", "revision"],
	"list_backup_drivers" : ["sid", "skey"],
	"set_vcard_license" : ["sid", "skey","serial","reboot"],        

	"create_guid" : ["sid", "skey"],
	"get_thumbnail" : ["sid", "skey", "appid", "resid", "width", "height"],
	"search" : ["sid", "skey", "appid", "pattern"],
	"keep_alive" : ["sid", "skey"],
	"server_information" : ["sid", "skey"],
        "set_application_vhost" : ["sid", "skey", "appid", "hostname"],
        "delete_application_vhost" : ["sid", "skey", "hostname"]        
}

def gen_wsdl():
	"""generate VDOM wsdl file"""
	result = header

	
	# types section
	result += """	<types>\n"""
	result += """	<s:schema elementFormDefault="qualified" targetNamespace="http://services.vdom.net/VDOMServices">\n"""

	for m in methods.keys():
		result += """		<s:element name="%s">
			<s:complexType>
				<s:sequence>\n""" % m
		for p in methods[m]:
			result += """					<s:element maxOccurs="1" minOccurs="1" name="%s" type="s:string"/>\n""" % p
		result += """				</s:sequence>
			</s:complexType>
		</s:element>\n"""
		result += """		<s:element name="%sResponse">
			<s:complexType>
				<s:sequence>
					<s:element maxOccurs="1" minOccurs="1" name="Result" type="s:string"/>
				</s:sequence>
			</s:complexType>
		</s:element>\n""" % m

	result += """	</s:schema>\n"""
	result += """	</types>\n"""


	# message block
	for m in methods.keys():
		result += """	<message name="%sRequest">
		<part element="s0:%s" name="parameters"/>
	</message>
	<message name="%sResponse">
		<part element="s0:%sResponse" name="parameters"/>
	</message>\n""" % (m, m, m, m)


	# port block
	result += """	<portType name="vdomService">\n"""

	for m in methods.keys():
		result += """		<operation name="%s">
			<input message="s0:%sRequest"/>
			<output message="s0:%sResponse"/>
		</operation>\n""" % (m, m, m)

	result += """	</portType>\n"""


	# binding
	result += """	<binding name="vdomService" type="s0:vdomService">
		<soap:binding style="document" transport="http://schemas.xmlsoap.org/soap/http"/>\n"""

	for m in methods.keys():
		result += """		<operation name="%s">
			<soap:operation soapAction="http://services.vdom.net/VDOMServices/%s" style="document"/>
			<input>
				<soap:body use="literal" namespace="http://services.vdom.net/VDOMServices"/>
			</input>
			<output>
				<soap:body use="literal" namespace="http://services.vdom.net/VDOMServices"/>
			</output>
		</operation>\n""" % (m, m)

	result += """	</binding>\n"""


	# service
	result += """	<service name="vdom">
		<port name="vdomService" binding="s0:vdomService">
			<soap:address location="/SOAP"/>
		</port>
	</service>\n"""


	# done
	result += """</definitions>\n"""

	print("trying to open file = " + str(VDOM_CONFIG["WSDL-FILE-LOCATION"]))
	ff = open(VDOM_CONFIG["WSDL-FILE-LOCATION"], "wb")
	print("trying to open file (success) = " + str(VDOM_CONFIG["WSDL-FILE-LOCATION"]))
	ff.write(result)
	ff.close()
