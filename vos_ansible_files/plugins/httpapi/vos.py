"""
COPYRIGHT 2019 Keysight Technologies.

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights to
use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies
of the Software, and to permit persons to whom the Software is furnished to do
so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.


Keysight Visibility Operating System (VOS) implementation of Ansible httpapi
plugin providing a connection to remote NPB devices over the HTTPS-based Web API.
"""

from __future__ import (absolute_import, division, print_function)

__metaclass__ = type

ANSIBLE_METADATA = {
    'metadata_version': '1.1',
    'supported_by': 'community',
    'status': ['preview']
}

from ansible.errors import AnsibleConnectionFailure
from ansible import __version__ as ansible_version
from ansible.plugins.httpapi import HttpApiBase
from requests_toolbelt import MultipartEncoder
from requests import Session
from json import loads, dumps
import base64
import os
import time
import sys
import re
import itertools
import xml.etree.ElementTree as et

SOFTWARE_VERSION = 'software_version'
NO_VERSION_HEADER = 'no_version_header'
INSTALL_SOFTWARE = 'install_software'
X_AUTH_TOKEN = "X-Auth-Token"
BASE_HEADERS = {'Accept-Encoding': 'identity',
                'Content-Type': 'application/json',
                'Connection': 'keep-alive',
                'User-Agent': 'VOS Ansible/%s' % ansible_version,
                'Flags': 'substitute_props+cli'}

MULTIPART_FILES = {
    '7300': '.+73xx-62xx[-]\d{6}[-]\d{8}[-]\d{6}\.zip$',
    'VISION_X': '.+73xx-62xx[-]\d{6}[-]\d{8}[-]\d{6}\.zip$',
    'VISION_ONE': '.+73xx-62xx[-]\d{6}[-]\d{8}[-]\d{6}\.zip$',
    'TRADE_VISION': '.+73xx-62xx[-]\d{6}[-]\d{8}[-]\d{6}\.zip$',
    'VISION_5812': '.+VisionEdge[-]\d{6}[-]\d{8}[-]\d{6}\.zip$',
    'VISION_7712': '.+VisionEdge[-]\d{6}[-]\d{8}[-]\d{6}\.zip$',
    'VISION_E100': '.+VisionEdge[-]\d{6}[-]\d{8}[-]\d{6}\.zip$',
    'VISION_E40': '.+VisionEdge[-]\d{6}[-]\d{8}[-]\d{6}\.zip$',
    'VISION_E10S': '.+VisionEdge[-]\d{6}[-]\d{8}[-]\d{6}\.zip$'
}


class HttpApi(HttpApiBase):
    @staticmethod
    def get_namespace(element):
        """
        Description: Static method that returns the namespace of an input node.
        :param element: input node
        :return: namespace value
        """
        m = re.match('\{.*\}', element.tag)
        return m.group(0) if m else ''

    @staticmethod
    def check_qualifier(node):
        """
        Description: Static method that checks whether a node has a qualifier
        subnode.

        :param node: input XML node
        :return: no_qualifier or the actual name of the qualifier
        """
        qualifier = node.find(".//qualifier")
        if qualifier is not None:
            return qualifier.get('name')

        return 'no_qualifier'

    @staticmethod
    def get_opt_node_subtype(node):
        """
        Description: Static method that checks the type of children nodes for
        an input 'opt_type' node.

        :param node: the input opt_type node
        :return: the children nodes type or None
        """
        for each in node.findall(".//*"):
            if each.tag == 'option' or each.tag == 'typed_option':
                if each.tag == 'option' and each.get('ref') is not None:
                    return 'complex_option'
                return each.tag
        return None

    def __init__(self, connection):
        super(HttpApi, self).__init__(connection)
        self.session = Session()
        self.host_details = dict()
        self.repository = dict()

    def define_type(self, xml, a_name, a_ref, a_type, c_qualifier):
        """
        Description: Utility method that translates the Web API specific XML
        representation of a resource into a python dictionary.

        :param xml: Web API XML representation of a NPB resource
        :param a_name: XML node 'name' attribute
        :param a_ref: XML node 'ref' attribute
        :param a_type: XML node 'type' attribute
        :param c_qualifier: XML node 'qualifier' tag
        :return: python representation of the input XML
        """
        expression = ".//*[@id='%s']" % a_ref
        try:
            node = xml.find(expression)
            if a_name is None:
                a_name = node.get('name')
        except SyntaxError:
            node = None
        if node is None:
            expression = ".//*[@name='%s'][@type='%s']" % (a_name, a_type)
            try:
                node = xml.find(expression)
            except SyntaxError:
                node = None
        if node is None:
            output = dict(a_name=dict(type='str'))
            return output

        node_type = node.get('type')
        try:
            node_ref = node.get('ref')[1:]
        except TypeError:
            node_ref = None
        output = dict()

        if node_type is not None and node_ref is None:  # simple node
            if node_type == 'string':
                output[a_name] = dict(type='str')
            elif node_type == 'boolean':
                output[a_name] = dict(type='bool')
            elif node_type == 'integer' or node_type == 'short' or \
                    node_type == 'long':
                output[a_name] = dict(type='int')
            else:
                output[a_name] = dict(type=node_type)
        else:  # complex node
            json_type = node.get('jsonType')

            if json_type is not None:
                if c_qualifier == 'array' or c_qualifier == 'single_or_array':

                    output[a_name] = dict(type='list')
                else:
                    if json_type == 'number':
                        output[a_name] = dict(type='int')
                    else:
                        output[a_name] = dict(type='str')
            else:
                if node_ref is not None and 'id_c_l_i' in node_ref:
                    # particular case reuqired only for certain cases where 
                    # internal_ids are replaced with strings for convenience
                    if c_qualifier == 'no_qualifier' or \
                            c_qualifier == 'single_or_range':
                        output[a_name] = dict(type='str')
                    if c_qualifier == 'array' or \
                            c_qualifier == 'single_or_array':
                        output[a_name] = dict(type='list')
                    # end of param type processing
                if node.tag == 'obj_type':
                    if c_qualifier == 'no_qualifier' or \
                            c_qualifier == 'single_or_range':
                        output[a_name] = dict(type='dict', options=None)
                    if c_qualifier == 'array' or \
                            c_qualifier == 'single_or_array':
                        output[a_name] = dict(type='list', options=None)

                    if len(node.findall(".//param")):
                        output[a_name]['options'] = dict()

                    for child in node.findall(".//param"):
                        name_value = child.get('name')
                        try:
                            ref_value = child.get('ref')[1:]
                        except TypeError:
                            ref_value = None
                        type_value = child.get('type')
                        output[a_name]['options'].update(
                            self.define_type(xml, name_value, ref_value,
                                             type_value,
                                             HttpApi.check_qualifier(child)))
                    # end of obj type processing
                if node.tag == 'opt_type':
                    subtype = HttpApi.get_opt_node_subtype(node)

                    if subtype is not None and subtype == 'complex_option':
                        if c_qualifier == 'array' or \
                                c_qualifier == 'single_or_array':
                            output[a_name] = dict(type='list', choises=list())
                        else:
                            output[a_name] = dict(type='dict', choises=list())
                        for child in node.findall('.//option'):
                            name_value = child.get('name')
                            try:
                                ref_value = child.get('ref')[1:]
                            except TypeError:
                                ref_value = None
                            type_value = child.get('type')
                            output[a_name]['choises'].append(
                                self.define_type(xml, name_value, ref_value,
                                                 type_value,
                                                 HttpApi.check_qualifier(child)))
                    elif subtype is not None and subtype == 'option':
                        output[a_name] = dict(type='str', choises=list())
                        for child in node.findall('.//option'):
                            output[a_name]['choises'].append(child.get('name'))
                    elif subtype is not None and \
                            subtype == 'typed_option':
                        for child in node.findall('.//typed_option'):
                            name_value = child.get('name')
                            try:
                                ref_value = child.get('ref')[1:]
                            except TypeError:
                                ref_value = None
                            type_value = child.get('type')

                            output.update(
                                self.define_type(xml, name_value, ref_value,
                                                 type_value,
                                                 HttpApi.check_qualifier(child)))
                    # end of opt type processing
                if node.tag == 'mixed_type':
                    output[a_name] = dict(type='dict', options=dict())
                    for child in node.findall('.//*'):
                        name_value = child.get('name')
                        try:
                            ref_value = child.get('ref')[1:]
                        except TypeError:
                            ref_value = None
                        type_value = child.get('type')

                        if child.tag == 'option':
                            if HttpApi.check_qualifier(child) == 'no_qualifier':
                                output[a_name]['options'].update(
                                    self.define_type(xml, name_value,
                                                     ref_value, type_value,
                                                     HttpApi.check_qualifier(
                                                         child)))
                            else:
                                output[a_name]['options'].update(
                                    self.define_type(xml, name_value,
                                                     ref_value, type_value,
                                                     HttpApi.check_qualifier(
                                                         child)))
                        elif child.tag == 'param':
                            if HttpApi.check_qualifier(child) == 'array':
                                output[a_name]['options'][name_value] = dict(
                                    type='list')
                            else:
                                output[a_name]['options'].update(
                                    self.define_type(xml, name_value,
                                                     ref_value, type_value,
                                                     HttpApi.check_qualifier(
                                                         child)))
                    # end of mixed type processing
                if node.tag == 'map_type':
                    output[a_name] = dict(type='str', options=dict())

                    for child in node.findall('.//*'):
                        for grandchild in child.findall(".//*"):
                            if child.tag == 'param':
                                name_value = child.get('name')
                                try:
                                    ref_value = child.get('ref')[1:]
                                except TypeError:
                                    ref_value = None
                                type_value = child.get('type')

                                output[a_name]['options'].update(
                                    self.define_type(xml, name_value,
                                                     ref_value, type_value,
                                                     HttpApi.check_qualifier(
                                                         child)))
                    # end of map type processing
        return output

    def get_python_representation_of_object(self, resource_url, resource_name):
        """
        Description: Method that dynamically retrieves the python dictionary
        associated to a NPB platform, version and resource.

        :param resource_name: the resource type whose python representation we
         want to get
        :param resource_url: the path associated in WebAPI to resource_name
        :return: the python dictionary
        """
        if self.connection._connected is False:
            self.connection._connect()

        key = self.connection._url + "_" + resource_url
        if key not in self.repository:
            url = self.connection._url + '/docs/' + resource_url
            headers = self.get_headers()

            result = self.execute_request(url=url, data={},
                                          method='OPTIONS', headers=headers)

            grammar = et.fromstring(result.text)

            w_name = ".//*[@name='%s_writable_properties']/param" % resource_name
            c_name = ".//*[@name='%s_create_properties']/param" % resource_name

            writable = grammar.findall(w_name)
            creatable = grammar.findall(c_name)

            visited = list()
            py_dict = dict()

            if resource_name == 'packetstack_resources':
                py_dict = self.get_python_representation_of_method(False, resource_url)

            for each in itertools.chain(writable, creatable):
                a_name = each.get('name')

                if a_name is not None and a_name not in visited:
                    visited.append(a_name)

                    try:
                        a_ref = each.get('ref')[1:]
                    except TypeError:
                        a_ref = None
                    a_type = each.get('type')
                    py_dict.update(
                        self.define_type(grammar, a_name, a_ref, a_type,
                                         HttpApi.check_qualifier(each)))

            self.repository[key] = py_dict

        return self.repository[key]

    def get_python_representation_of_method(self, query_for_actions=True, resource_url='actions'):
        """
        Description: Method that dynamically retrieves the python dictionary
        associated to a NPB platform and version for the actions resource or
        for particular operations associated with regular NPB resources.

        :return: the python dictionary for the actions resource
        """
        if self.connection._connected is False:
            self.connection._connect()

        key = self.connection._url + "_" + resource_url
        if key not in self.repository:
            url = self.connection._url + '/docs/' + resource_url

            headers = self.get_headers()
            result = self.execute_request(url=url, data={},
                                          method='OPTIONS', headers=headers)

            grammar = et.fromstring(result.text)

            if query_for_actions:
                name = ".//*[@http_method='POST']"
            else:
                name = ".//*[@http_method='PUT']"
            methods = grammar.findall(name)

            visited = list()
            py_dict = dict()

            for each_method in methods:
                if each_method.get('name') == 'Update':
                    continue

                request = each_method.findall("request")[0]

                if request is not None:
                    representation = \
                        request.findall("representation")[0]

                    if representation is not None:
                        for each in representation.findall(
                                "param"):
                            try:
                                node_style = each.get('style')
                            except TypeError:
                                node_style = None
                            if node_style is not None:
                                node_name = each.get('fixed')

                                if query_for_actions:
                                    node_name += "_payload"

                                if node_name is not None and node_name not in visited:
                                    visited.append(node_name)
                            else:
                                if not query_for_actions:
                                    node_name = each.get('name')
                                    if node_name is not None and node_name not in visited:
                                        visited.append(node_name)

                                try:
                                    node_ref = each.get('ref')[1:]
                                except TypeError:
                                    node_ref = None
                                node_type = each.get('type')

                                if node_type == 'file':
                                    continue

                                py_dict.update(
                                    self.define_type(grammar,
                                                     node_name,
                                                     node_ref, node_type,
                                                     HttpApi.check_qualifier(each)))

            self.repository[key] = py_dict

        return self.repository[key]

    def execute_request(self, url, data, method, headers):
        """
        Description: Method invoked from send_request, send_binary and
        send_multipart to call requests using the requests.Session object.

        :param url: HTTP request url
        :param data: HTTP request body
        :param method: HTTP request method
        :param headers: HTTP request headers
        :return: HTTP response object
        """
        if method == 'GET':
            response = self.session.get(url, data=data, headers=headers, verify=False)
        elif method == 'POST':
            response = self.session.post(url, data=data, headers=headers, verify=False)
        elif method == 'PUT':
            response = self.session.put(url, data=data, headers=headers, verify=False)
        elif method == 'DELETE':
            response = self.session.delete(url, data=data, headers=headers, verify=False)
        elif method == 'OPTIONS':
            response = self.session.options(url, data=data, headers=headers, verify=False)

        return response

    def check_nto_is_up(self, up_status_retries, up_line_cards_retries):
        """
        Description: Method that verifies a NPB box has recovered after a
        build installation, a Web API port change, a clear system action, an
        import action or other similar scenarios. This usually freezes the
        Ansible execution as such operations last long and the playbook result
        won't be displayed until either NPB recovers or the default timeout
        expires.

        :param up_status_retries: number of times the function will try to
         reconnect to the NPB
        :param up_line_cards_retries: number of times the function will try to
         reconnect to the line cards of complex NPB architectures like 7300
         or VISION_X
        """
        time.sleep(30)
        for sec in range(up_status_retries):
            if sec == up_status_retries - 1:
                raise Exception(
                    "ERROR: NTO {} is down for {} seconds..".format(
                        self.connection._url, up_status_retries))
            try:
                url = '/system?properties=type'
                method = 'GET'

                r = self.send_request(url, {}, method)
                r = self.check_error_codes(r, url, {}, method)
 
                time.sleep(5)
                break
            except Exception as e:
                sys.stdout.flush()
                time.sleep(1)
                continue

        boards_url = {"url_1": {"boards": "line_boards",
                                "board_status": "line_board_status"},
                      "url_2": {"boards": "boards", "board_status": "state"}}

        for url in boards_url.keys():
            for attempt in range(up_line_cards_retries):
                if attempt == up_line_cards_retries - 1:
                    raise Exception(
                        "ERROR: One of the NTO line cards is down for %s "
                        "seconds.." % up_line_cards_retries * 10)
                try:
                    response = self.send_request("/" +
                                    boards_url[url]["boards"], {}, 'GET')
                    if response['status_code'] == 404:
                        break
                    if response['status_code'] != 200:
                        time.sleep(10)
                        continue
                except Exception as e:
                    time.sleep(10)
                    continue

                line_boards_list = response['content']
                for line_board in line_boards_list:
                    if line_board[boards_url[url]['board_status']] in [
                            'PRESENT', 'NOT_PRESENT', 'READY']:
                        flag = "break"
                        continue
                    elif line_board[boards_url[url]['board_status']] in [
                            'INITIALIZING', 'INITIALIZING_1',
                            'INITIALIZING_2', 'UPGRADING']:
                        flag = "continue"
                        break
                    elif line_board[boards_url[url]['board_status']] in [
                            'FAULTY', 'INSUFFICIENT_POWER', 'UNSUPPORTED_HW',
                            'FORCE_POWER_OFF', 'CONFIG_MISMATCH']:
                        raise Exception(
                            "ERROR: One of the NTO line cards is FAULTY..")
                if flag == "continue":
                    time.sleep(5)
                    continue
                elif flag == "break":
                    time.sleep(5)
                    break

    def check_error_codes(self, response, url, data, method):
        """
        Description: Method that checks the correctness of the Web API
        response. This method addresses the following scenarios:
        - when the user is logged out as a result of a correct execution of a
          particular Web API request and a new authentication is needed
        - the authentication token expired during the HTTP request processing

        :param response: HTTP request object
        :param url: HTTP request url
        :param data: HTTP request body
        :param method: HTTP request method
        :return: response object or exception
        """
        # expired token
        if response['status_code'] == 401:
            self.connection.login(self.connection.get_option('remote_user'),
                                  self.connection.get_option('password'))

            headers = self.connection.get_headers()

            response = self.connection.execute_request(url=url, data=data, method=method,
                                                       headers=headers)
        # changes that involve system restart
        if response['status_code'] == 202:
            if 'web_api_config' in data:
                port = data['web_api_config']['port']
                new = self.connection._url.rsplit(':', 1)[0] + ':' + str(port)

                self.connection._url = new
            self.check_nto_is_up(600, 1200)

        return response

    def send_request(self, path, data, method, headers=None):
        """
        Description: General purpose method responsible for sending HTTP
        requests that have the body structured in JSON format.

        :param path: HTTP request url
        :param data: HTTP request body
        :param method: HTTP request method
        :param headers: HTTP request headers
        :return: HTTP response body
        """
        data = dumps(data) if type(data) == dict else data
        headers = self.get_headers() if headers is None else headers
        url = self.connection._url + path
        response = self.execute_request(url=url, data=data, method=method,
                                        headers=headers)

        try:
            content = loads(response.text)
        except Exception:
            content = response.text

        return {'status_code': response.status_code, 'content': content}

    def send_binary(self, path, data):
        """
        Description: Generic method responsible for sending binary requests.
        The implementation differs from the general purpose send_request
        method, as Ansible design of the httpapi plugin allows only a JSON
        format request/response body, while in Web API there are several
        scenarios where binary requests are required.

        :param path: HTTP request url
        :param data: HTTP request body
        :return: HTTP response body
        """
        headers = self.get_headers()

        if data and 'file_name' in data:
            file_name = data['file_name']
        else:
            tokens = path.split('/')
            file_name = tokens[len(tokens) - 1]

        serial_number = self.host_details[self.connection._url].split('|')[2]

        if os.path.isdir(file_name):
            if path.endswith('/'):
                path = path[:-1]
            tokens = path.split('/')
            if not file_name.endswith('/'):
                file_name = file_name + '/' + tokens[
                    len(tokens) - 1] + '_' + serial_number
            else:
                file_name = file_name + tokens[
                    len(tokens) - 1] + '_' + serial_number
        elif file_name.endswith(".ata") or file_name.endswith(".zip") or \
                file_name.endswith(".bin"):
            file_name = file_name[:-4] + "_" + serial_number + file_name[-4:]
        else:
            file_name = file_name + "_" + serial_number

        url = self.connection._url + path
        data = dumps(data) if type(data) == dict else data

        response = self.session.post(url=url,
                                     data=data,
                                     headers=headers,
                                     stream=True)

        if response.status_code == 200:
            f = open(file_name, 'wb')
            for chunk in response.iter_content(chunk_size=1024):
                if chunk:
                    f.write(chunk)
            f.close()

        return {'status_code': response.status_code, 'content': ''}

    def send_multipart(self, path, data, method):
        """
        Description: Generic method responsible for sending multipart requests.
        The implementation differs from the general purpose send_request
        method, as Ansible design of the httpapi plugin allows only a JSON
        format request/response body, while in Web API multipart requests
        return a byte response.

        :param path: HTTP request url
        :param data: HTTP request body
        :param method: HTTP request method
        :return: HTTP response body
        """
        headers = self.get_headers()

        file_path = data['file_path']

        platform = self.host_details[self.connection._url].split('|')[1]
        serial_number = self.host_details[self.connection._url].split('|')[2]

        found = False
        if os.path.isdir(file_path):
            for root, dirs, files in os.walk(file_path):
                for file in files:
                    if found:
                        break

                    if (INSTALL_SOFTWARE in path and re.match(
                            MULTIPART_FILES[platform], file)) or \
                            serial_number in file:
                        found = True
                        if not file_path.endswith('/'):
                            file_path += ('/' + file)
                        else:
                            file_path += file

        multipart = MultipartEncoder(fields={
            'field0': (os.path.basename(file_path), open(file_path, 'rb'),
                       'application/octet-stream')})

        if 'payload' in data:
            multipart.fields['field1'] = (
                "json", data['payload'], 'application/json')

        headers['Content-Type'] = multipart.content_type
        if 'Flags' in headers:
            del headers['Flags']

        url = self.connection._url + path
        response = self.execute_request(url=url,
                                        data=multipart,
                                        method=method,
                                        headers=headers)

        return {'status_code': response.status_code, 'content': response.text}

    def login(self, username, password):
        """
        Description: Method that returns an authentication token from the
        provided username and password granting the authenticity of the user.

        :param username: Web API valid user login_id
        :param password: associated password of the provided user
        """
        if username and password:
            self.session.headers.pop('Authentication', None)

            headers = {
                'Authorization': 'Basic %s' % base64.b64encode(bytearray(username + ":" + password, 'ascii'))
                                                    .decode('ascii'),
                'Accept-Encoding': 'identity',
                'Content-Type': 'application/json',
                'Connection': 'keep-alive',
                'User-Agent': 'VOS Ansible/%s' % ansible_version,
                'Flags': 'substitute_props+cli'}

            response = self.execute_request(url=self.connection._url + '/api/auth',
                                            data={},
                                            method='GET',
                                            headers=headers)

            self.session.headers.update({'Authentication': '%s' % response.headers[X_AUTH_TOKEN]})
        else:
            raise AnsibleConnectionFailure('Username and password are required for login')

    def update_auth(self, response, response_data):
        return None

    def set_become(self, become_context):
        return None

    def logout(self):
        """
        Description: Web API request that closes the current session and
        invalidates any token associated with the current session.
        """

        self.execute_request(url=self.connection._url + '/api/auth/logout',
                             data={},
                             method='POST',
                             headers={'Content-type': 'application/json'})
        self.session.headers.pop('Authentication', None)

    def get_host_details(self):
        """
        Description: Method designed to access the current NPB host and get
        details about the installed platform, the software version of the
        platform and some hardware information.
        """
        host = self.connection._url
        if host not in self.host_details:
            url = '/system?properties=type,hardware_info'

            response = self.send_request(path=url, data={}, method='GET',
                                         headers=BASE_HEADERS)

            if response['status_code'] == 200:
                response_data = dumps(response['content'])

            response_data = response_data.replace('true', 'True')
            response_data = response_data.replace('false', 'False')
            response_data = response_data.replace('null', '"null"')

            response_data = loads(response_data)

            if SOFTWARE_VERSION in self.connection._options:
                self.host_details[host] = \
                    self.connection.get_option(SOFTWARE_VERSION) + "|" + \
                    response_data['type'] + "|" + \
                    response_data['hardware_info']['system_id']
            else:
                self.host_details[host] = \
                    NO_VERSION_HEADER + "|" + \
                    response_data['type'] + "|" + \
                    response_data['hardware_info']['system_id']

    def set_software_version(self, version):
        """
        Description: Method designed to set the software version value within
        connection's options.
        """
        self.connection.set_option(SOFTWARE_VERSION, version)

    def get_headers(self):
        """
        Description: Method designed to retrieve the HTTP request headers.
        """
        if self.connection._url not in self.host_details:
            self.get_host_details()

        headers = {key: value for key, value in BASE_HEADERS.items()}

        # consider the case of intermediary versions (e.g. 5.2.0.2)
        version_number = self.host_details[self.connection._url].split("|")[0]
        if version_number != NO_VERSION_HEADER:
            version_tokens = version_number.split('.')
            if len(version_tokens) > 3:
                version_number = version_tokens[0] + '.' + version_tokens[
                    1] + '.' + version_tokens[2]

            headers['Version'] = version_number

        return headers
