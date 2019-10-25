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


NVOS implementation of Ansible httpapi plugin providing a connection to remote
NPB devices over the HTTPS-based Web API.
"""

from __future__ import (absolute_import, division, print_function)

__metaclass__ = type

ANSIBLE_METADATA = {
    'metadata_version': '1.1',
    'supported_by': 'community',
    'status': ['preview']
}

from ansible.module_utils._text import to_native
from ansible.errors import AnsibleError
from ansible.plugins.httpapi import HttpApiBase
from requests_toolbelt import MultipartEncoder
from requests import Session, ConnectionError
from json import loads, dumps
import subprocess
import base64
import os
import time
import sys
import re
import itertools
import xml.etree.ElementTree as et


class HttpApi(HttpApiBase):
    _session_obj = None
    _host_facts = {}
    _auth_tokens = {}
    _repository = {}

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
    def check_qualifier(node, ns):
        """
        Description: Static method that checks whether a node has a qualifier
        subnode.

        :param node: input XML node
        :param ns: namespace of the input node
        :return: no_qualifier or the actual name of the qualifier
        """
        qualifier = node.find(".//%squalifier" % ns)
        if qualifier is not None:
            return qualifier.get('name')

        return 'no_qualifier'

    @staticmethod
    def get_opt_node_subtype(node, ns):
        """
        Description: Static method that checks the type of children nodes for
        an input 'opt_type' node.

        :param node: the input opt_type node
        :param ns: the namespace of node
        :return: the children nodes type or None
        """
        for each in node.findall(".//*"):
            if each.tag == ns + 'option' or each.tag == ns + 'typed_option':
                if each.tag == ns + 'option' and each.get('ref') is not None:
                    return 'complex_option'
                return each.tag
        return None

    @staticmethod
    def get_attribute_value(node, attribute):
        """
        Description: Static method that returns the value of an input attribute
        for an input XML node.

        :param node: input XML node
        :param attribute: attribute of the input node
        :return: the value of the attribute or None
        """
        try:
            if attribute == 'REF':
                return node.attributes[attribute][1:]
            return node.attributes[attribute]
        except:
            return None

    def __init__(self, *args, **kwargs):
        super(HttpApi, self).__init__(*args, **kwargs)

    @property
    def _session(self):
        """
        Description: Property that points to the Session object.
        """
        if HttpApi._session_obj is None:
            HttpApi._session_obj = Session()

        return HttpApi._session_obj

    def define_type(self, xml, a_name, a_ref, a_type, c_qualifier, ns):
        """
        Description: Utility method that translates the Web API specific XML
        representation of a resource into a python dictionary.

        :param xml: Web API XML representation of a NPB resource
        :param a_name: XML node 'name' attribute
        :param a_ref: XML node 'ref' attribute
        :param a_type: XML node 'type' attribute
        :param c_qualifier: XML node 'qualifier' tag
        :param ns: XML node namespace
        :return: python representation of the input XML
        """
        expression = ".//*[@id='%s']" % a_ref
        try:
            node = xml.find(expression)
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
                if node.tag == ns + 'obj_type':
                    if c_qualifier == 'no_qualifier' or \
                            c_qualifier == 'single_or_range':
                        output[a_name] = dict(type='dict', options=None)
                    if c_qualifier == 'array' or \
                            c_qualifier == 'single_or_array':
                        output[a_name] = dict(type='list', options=None)

                    if len(node.findall(".//%sparam" % ns)):
                        output[a_name]['options'] = dict()

                    for child in node.findall(".//%sparam" % ns):
                        name_value = child.get('name')
                        try:
                            ref_value = child.get('ref')[1:]
                        except TypeError:
                            ref_value = None
                        type_value = child.get('type')
                        output[a_name]['options'].update(
                            self.define_type(xml, name_value, ref_value,
                                             type_value,
                                             HttpApi.check_qualifier(child,
                                                                     ns),
                                             ns))
                    # end of obj type processing
                if node.tag == ns + 'opt_type':
                    subtype = HttpApi.get_opt_node_subtype(node, ns)

                    if subtype is not None and subtype == 'complex_option':
                        if c_qualifier == 'array':
                            output[a_name] = dict(type='list', choises=list())
                        else:
                            output[a_name] = dict(type='dict', choises=list())
                        for child in node.findall('.//%soption' % ns):
                            name_value = child.get('name')
                            try:
                                ref_value = child.get('ref')[1:]
                            except TypeError:
                                ref_value = None
                            type_value = child.get('type')
                            output[a_name]['choises'].append(
                                self.define_type(xml, name_value, ref_value,
                                                 type_value,
                                                 HttpApi.check_qualifier(child,
                                                                         ns),
                                                 ns))
                    elif subtype is not None and subtype == ns + 'option':
                        output[a_name] = dict(type='str', choises=list())
                        for child in node.findall('.//%soption' % ns):
                            output[a_name]['choises'].append(child.get('name'))
                    elif subtype is not None and \
                            subtype == ns + 'typed_option':
                        for child in node.findall('.//%styped_option' % ns):
                            name_value = child.get('name')
                            try:
                                ref_value = child.get('ref')[1:]
                            except TypeError:
                                ref_value = None
                            type_value = child.get('type')

                            output.update(
                                self.define_type(xml, name_value, ref_value,
                                                 type_value,
                                                 HttpApi.check_qualifier(child,
                                                                         ns),
                                                 ns))
                    # end of opt type processing
                if node.tag == ns + 'mixed_type':
                    output[a_name] = dict(type='dict', options=dict())
                    for child in node.findall('.//*'):
                        name_value = child.get('name')
                        try:
                            ref_value = child.get('ref')[1:]
                        except TypeError:
                            ref_value = None
                        type_value = child.get('type')

                        if child.tag == ns + 'option':
                            if HttpApi.check_qualifier(child,
                                                       ns) == 'no_qualifier':
                                output[a_name]['options'].update(
                                    self.define_type(xml, name_value,
                                                     ref_value, type_value,
                                                     HttpApi.check_qualifier(
                                                         child, ns), ns))
                            else:
                                output[a_name]['options'].update(
                                    self.define_type(xml, name_value,
                                                     ref_value, type_value,
                                                     HttpApi.check_qualifier(
                                                         child, ns), ns))
                        elif child.tag == ns + 'param':
                            if HttpApi.check_qualifier(child, ns) == 'array':
                                output[a_name]['options'][name_value] = dict(
                                    type='list')
                            else:
                                output[a_name]['options'].update(
                                    self.define_type(xml, name_value,
                                                     ref_value, type_value,
                                                     HttpApi.check_qualifier(
                                                         child, ns), ns))
                    # end of mixed type processing
                if node.tag == ns + 'map_type':
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
                                                         child, ns), ns))
                    # end of map type processing
        return output

    def get_py_dictionary(self, resource_value):
        """
        Description: Method that dynamically retrieves the python dictionary
        associated to a NPB platform, version and resource.

        :param resource_value: the resource type whose python representation we
         want to get
        :return: the python dictionary
        """

        key = self.connection._url + "_" + resource_value

        if key not in HttpApi._repository:
            url = '/docs/' + resource_value
            facts = self.get_facts()

            # consider the case of intermediary versions (e.g. 5.2.0.2)
            version_number = facts.split('|')[0]
            version_tokens = version_number.split('.')
            if len(version_tokens) > 3:
                version_number = version_tokens[0] + '.' + version_tokens[1] \
                                 + '.' + version_tokens[2]

            result = self.send_request(path=url, data={}, method='OPTIONS',
                                       headers={
                                           'Content-type': 'application/json',
                                           'Version': version_number})

            grammar = et.fromstring(result)

            node = grammar.find(".")
            name_space = HttpApi.get_namespace(node)

            w_name = ".//*[@name='%s_writable_properties']/%sparam" % (
                resource_value, name_space)
            c_name = ".//*[@name='%s_create_properties']/%sparam" % (
                resource_value, name_space)

            writable = grammar.findall(w_name)
            creatable = grammar.findall(c_name)

            visited = list()
            py_dict = dict()

            for each in itertools.chain(writable, creatable):
                a_name = each.get('name')

                if a_name not in visited:
                    visited.append(a_name)

                    try:
                        a_ref = each.get('ref')[1:]
                    except TypeError:
                        a_ref = None
                    a_type = each.get('type')

                    py_dict.update(
                        self.define_type(grammar, a_name, a_ref, a_type,
                                         HttpApi.check_qualifier(each,
                                                                 name_space),
                                         name_space))

            HttpApi._repository[key] = py_dict

        return str(HttpApi._repository[key])

    def get_actions_py_dictionary(self):
        """
        Description: Method that dynamically retrieves the python dictionary
        associated to a NPB platform and version for the actions resource.

        :return: the python dictionary for the actions resource
        """
        key = self.connection._url + "_actions"
        if key not in HttpApi._repository:
            url = '/docs/actions'
            facts = self.get_facts()

            # consider the case of intermediary versions (e.g. 5.2.0.2)
            version_number = facts.split('|')[0]
            version_tokens = version_number.split('.')
            if len(version_tokens) > 3:
                version_number = version_tokens[0] + '.' + version_tokens[1] \
                                 + '.' + version_tokens[2]

            result = self.send_request(path=url, data={}, method='OPTIONS',
                                       headers={
                                           'Content-type': 'application/json',
                                           'Version': version_number})

            grammar = et.fromstring(result)

            node = grammar.find(".")
            name_space = HttpApi.get_namespace(node)

            name = ".//*[@http_method='POST']"
            methods = grammar.findall(name)

            visited = list()
            py_dict = dict()

            for each_method in methods:
                request = each_method.findall("%srequest" % name_space)[0]

                if request is not None:
                    representation = \
                        request.findall("%srepresentation" % name_space)[0]

                    if representation is not None:
                        for each in representation.findall(
                                "%sparam" % name_space):

                            try:
                                node_style = each.get('style')
                            except TypeError:
                                node_style = None

                            if node_style is not None:
                                node_name = each.get('fixed')
                                if node_name + "_payload" not in visited:
                                    visited.append(node_name + "_payload")
                                continue
                            else:
                                try:
                                    node_ref = each.get('ref')[1:]
                                except TypeError:
                                    node_ref = None
                                node_type = each.get('type')

                                if node_type == 'file':
                                    continue

                                py_dict.update(
                                    self.define_type(grammar,
                                                     node_name + "_payload",
                                                     node_ref, node_type,
                                                     HttpApi.check_qualifier(
                                                         each,
                                                         name_space),
                                                     name_space))

            HttpApi._repository[key] = py_dict

        return str(HttpApi._repository[key])

    def get_host_vars(self):
        """
        Description: Method that reads the inventory file and stores the user
        defined Ansible variables.

        :return: a reference to the stored Ansible variables or exception
        """
        # check if ansible-playbook has been run with -i argument
        pid = sys.argv[1]

        cmd = "ps -Flww -p " + pid
        cmd_output = subprocess.check_output(cmd, stderr=subprocess.STDOUT,
                                             shell=True)

        tokens = cmd_output.decode().split("-i")
        if len(tokens) > 1:
            inventory_file_name = tokens[1].strip().split(" ")[0]

            # get the path where ansible-playbook has been called
            cmd = "pwdx " + pid
            cmd_output = subprocess.check_output(cmd,
                                                 stderr=subprocess.STDOUT,
                                                 shell=True)
            decoded_cmd_output = cmd_output.decode()
            decoded_cmd_output = decoded_cmd_output.replace("\n", "")
            if inventory_file_name.startswith("/"):
                inventory_path = inventory_file_name
            else:
                inventory_path = decoded_cmd_output.split(pid + ":")[
                                    1].strip() + "/" + inventory_file_name

            cmd = "ansible-inventory --list -i " + inventory_path
            output = subprocess.check_output(cmd,
                                             stderr=subprocess.STDOUT,
                                             shell=True)
        else:
            cmd = "ansible-inventory --list"
            output = subprocess.check_output(cmd,
                                             stderr=subprocess.STDOUT,
                                             shell=True)

        # hack for scenario when ANSIBLE_DEBUG is activated
        if type(output) is str:
            tokens = output.split("done with get_vars()")
        else:
            tokens = output.decode().split("done with get_vars()")
        if len(tokens) > 1:
            output = tokens[1].strip()
        else:
            output = tokens[0].strip()

        inventory_json = loads(output)
        host_variables = inventory_json['_meta']['hostvars']

        return host_variables[self.connection._url.split(':')[1][2:]]

    def get_facts(self):
        """
        Description: Method designed to access the current NPB host and get
        details about the installed platform, the software version of the
        platform and some hardware information.

        :return: facts about the current NPB host
        """
        if self.connection._url not in HttpApi._host_facts:
            url = '/system?properties=type,software_version,hardware_info'
            headers = {'Content-Type': 'application/json'}

            resp_text = self.send_request(path=url, data={}, method='GET',
                                          headers=headers)
            if type(resp_text) is not str:
                resp_text = resp_text.decode('utf-8')

            resp_text = resp_text.replace('true', 'True')
            resp_text = resp_text.replace('false', 'False')
            resp_text = resp_text.replace('null', '"null"')

            response = eval(resp_text)

            host_vars = self.get_host_vars()

            if 'nvos_version' in host_vars:
                HttpApi._host_facts[self.connection._url] = \
                    host_vars['nvos_version'] + "|" + response['type'] + "|" \
                    + response['hardware_info']['system_id']
            else:
                HttpApi._host_facts[self.connection._url] = \
                    response['software_version'].split('-')[0] + "|" + \
                    response['type'] + "|" + \
                    response['hardware_info']['system_id']

        return HttpApi._host_facts[self.connection._url]

    def get_option(self, option):
        """
        Description: Method that tries to get the value of a particular
        inventory option, passed as a parameter.

        :param option: the name of the option we want to query
        :return: option value or exception
        """
        if not self._options or option not in self._options:
            try:
                hosts_variables = self.get_host_vars()
                option_value = hosts_variables[option]
            except AnsibleError as e:
                raise KeyError(to_native(e))
            self._options[option] = option_value

        return self._options.get(option)

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
        try:
            username = self.get_option('ansible_httpapi_remote_user')
        except KeyError as e:
            username = self.get_option('ansible_user')

        try:
            password = self.get_option('ansible_httpapi_password')
        except KeyError as e:
            password = self.get_option('ansible_password')

        headers = {
            'Authorization': 'Basic ' + base64.b64encode(
                bytearray(username + ":" + password, 'ascii')).decode(
                'ascii'),
            'Content-type': 'application/json'}

        for sec in range(up_status_retries):
            if sec == up_status_retries - 1:
                raise Exception(
                    "ERROR: NTO {} is down for {} seconds..".format(
                        self.connection._url, up_status_retries))
            try:
                self._session.get(
                    self.connection._url + '/system?properties=type',
                    headers=headers, verify=False)
                time.sleep(5)
                break
            except ConnectionError as e:
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
                    response = self._session.get(
                        self.connection._url + "/" + boards_url[url]["boards"],
                        headers=headers, verify=False)
                    if response.status_code == 404:
                        break
                    if response.status_code != 200:
                        time.sleep(10)
                        continue
                except ConnectionError:
                    time.sleep(10)
                    continue

                line_boards_list = loads(response.text)
                for line_board in line_boards_list:
                    if line_board[boards_url[url]['board_status']] in [
                            'PRESENT', 'NOT_PRESENT', 'READY']:
                        flag = "while_break"
                        continue
                    elif line_board[boards_url[url]['board_status']] in [
                            'INITIALIZING', 'INITIALIZING_1',
                            'INITIALIZING_2', 'UPGRADING']:
                        flag = "while_continue"
                        break
                    elif line_board[boards_url[url]['board_status']] in [
                            'FAULTY', 'INSUFFICIENT_POWER', 'UNSUPPORTED_HW',
                            'FORCE_POWER_OFF', 'CONFIG_MISMATCH']:
                        raise Exception(
                            "ERROR: One of the NTO line cards is FAULTY..")
                if flag == "while_continue":
                    time.sleep(5)
                    continue
                elif flag == "while_break":
                    time.sleep(5)
                    break

    def execute_request(self, url, data, method, headers):
        """
        Description: Method invoked from send_request, send_binary_request and
        send_multipart to call requests using the requests.Session object.

        :param url: HTTP request url
        :param data: HTTP request body
        :param method: HTTP request method
        :param headers: HTTP request headers
        :return: HTTP response object
        """
        if method == 'GET':
            response = self._session.get(url, data=data, headers=headers)
        elif method == 'POST':
            response = self._session.post(url, data=data, headers=headers)
        elif method == 'PUT':
            response = self._session.put(url, data=data, headers=headers)
        elif method == 'DELETE':
            response = self._session.delete(url, data=data, headers=headers)
        elif method == 'OPTIONS':
            response = self._session.options(url, data=data, headers=headers)

        return response

    def check_error_codes(self, response, url, data, method, headers):
        """
        Description: Method that checks the correctness of the Web API
        response. This method addresses the following scenarios:
        - when the user is logged out as a result of a correct execution of a
          particular Web API request and a new authentication is needed
        - the authentication token expired during the HTTP request processing
        - something went wrong during the execution and a different status
          code from 200 is returned

        :param response: HTTP request object
        :param url: HTTP request url
        :param data: HTTP request body
        :param method: HTTP request method
        :param headers: HTTP request headers
        :return: response object or exception
        """
        # token expired in the middle of the session
        if response is not None and response.status_code == 401:
            try:
                self.login(self.get_option('ansible_httpapi_remote_user'),
                           self.get_option('ansible_httpapi_password'))
            except KeyError as e:
                self.login(self.get_option('ansible_user'),
                           self.get_option('ansible_password'))
            headers['Authentication'] = HttpApi._auth_tokens[
                self.connection._url]

            return self.execute_request(url=url, data=data, method=method,
                                        headers=headers)
        if response is not None and response.status_code == 202:
            if 'web_api_config' in data:
                port = loads(data)['web_api_config']['port']

                new_key = self.connection._url.rsplit(':', 1)[0] + ':' + str(
                    port)

                HttpApi._auth_tokens[new_key] = HttpApi._auth_tokens.pop(
                    self.connection._url)
                self.connection._url = new_key

            self.check_nto_is_up(600, 1200)
        if response is not None and response.status_code != 200:
            resp = {'code': response.status_code,
                    'msg': response.text.split('Debug info')[0]}

            raise Exception(resp)

        return response

    def send_request(self, path, data, method, headers):
        """
        Description: General purpose method responsible for sending HTTP
        requests that have the body structured in JSON format.

        :param path: HTTP request url
        :param data: HTTP request body
        :param method: HTTP request method
        :param headers: HTTP request headers
        :return: HTTP response body
        """
        if type(data) == dict:
            data = dumps(data)

        headers['Authentication'] = HttpApi._auth_tokens[self.connection._url]
        url = self.connection._url + path

        response = self.execute_request(url=url, data=data, method=method,
                                        headers=headers)

        try:
            response = self.check_error_codes(response, url, data, method,
                                              headers)
        except Exception as e:
            return str(e)

        return response.content

    def send_binary_request(self, path, data, method):
        """
        Description: Generic method responsible for sending binary requests.
        The implementation differs from the general purpose send_request
        method, as Ansible design of the httpapi plugin allows only a JSON
        format request/response body, while in Web API there are several
        scenarios where binary requests are required.

        :param path: HTTP request url
        :param data: HTTP request body
        :param method: HTTP request method
        :return: HTTP response body
        """

        # consider the case of intermediary versions (e.g. 5.2.0.2)
        version_number = self.connection.get_facts().split('|')[0]
        version_tokens = version_number.split('.')
        if len(version_tokens) > 3:
            version_number = version_tokens[0] + '.' + version_tokens[1] \
                             + '.' + version_tokens[2]

        headers = {'Version': version_number,
                   'Content-Type': 'application/json',
                   'Authentication': HttpApi._auth_tokens[
                       self.connection._url]}

        if data and 'file_name' in data:
            file_name = data['file_name']
        else:
            tokens = path.split('/')
            file_name = tokens[len(tokens) - 1]
        serial_number = HttpApi._host_facts[self.connection._url].split('|')[2]

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

        if method == 'POST':
            response = self._session.post(self.connection._url + path,
                                          data=str(data), headers=headers,
                                          stream=True)

        try:
            response = self.check_error_codes(response,
                                              self.connection._url + path,
                                              str(data), method, headers)
        except Exception as e:
            return str(e)

        if response is not None and response.status_code == 200:
            f = open(file_name, 'wb')
            for chunk in response.iter_content(chunk_size=1024):
                if chunk:
                    f.write(chunk)
            f.close()
            return {'code': response.status_code}
        else:
            return {'code': response.status_code,
                    'msg': response.text.split('Debug info')[0]}

    def send_multipart(self, path, data, method, headers):
        """
        Description: Generic method responsible for sending multipart requests.
        The implementation differs from the general purpose send_request
        method, as Ansible design of the httpapi plugin allows only a JSON
        format request/response body, while in Web API multipart requests
        return a byte response.

        :param path: HTTP request url
        :param data: HTTP request body
        :param method: HTTP request method
        :param headers: HTTP request headers
        :return: HTTP response body
        """
        file_path = data['file_path']

        platform = HttpApi._host_facts[self.connection._url].split('|')[1]
        serial_number = HttpApi._host_facts[self.connection._url].split('|')[2]

        match_strings = {
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

        found = False
        if os.path.isdir(file_path):
            for root, dirs, files in os.walk(file_path):
                for file in files:
                    if found:
                        break

                    if ('install_software' in path and re.match(
                            match_strings[platform], file)) or \
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
        headers['Authentication'] = HttpApi._auth_tokens[self.connection._url]

        url = self.connection._url + path

        response = self.execute_request(url=url, data=multipart, method=method,
                                        headers=headers)

        try:
            response = self.check_error_codes(response, url, data, method,
                                              headers)
        except Exception as e:
            return str(e)

        return response.text

    def login(self, username, password):
        """
        Description: Method that returns an authentication token from the
        provided username and password granting the authenticity of the user.

        :param username: Web API valid user login_id
        :param password: associated password of the provided user
        """
        if not username:
            try:
                username = self.get_option('ansible_httpapi_remote_user')
            except KeyError as e:
                username = self.get_option('ansible_user')
        if not password:
            try:
                password = self.get_option('ansible_httpapi_password')
            except KeyError as e:
                password = self.get_option('ansible_password')

        timeout = self.get_option('ansible_connect_timeout')
        headers = {
            'Authorization': 'Basic ' + base64.b64encode(
                bytearray(username + ":" + password, 'ascii')).decode(
                'ascii'),
            'Content-type': 'application/json'}

        url = self.connection._url + '/api/auth'
        response = self._session.get(url, headers=headers, verify=False,
                                     timeout=timeout)

        auth_header = response.headers['X-Auth-Token']
        HttpApi._auth_tokens[self.connection._url] = auth_header

    def update_auth(self, response, response_data):
        """
        Description: Method that updates an expired authentication token.

        :param response: HTTP response object
        :param response_data: HTTP body
        :return: new authentication header with an updated token or None
        """
        auth_header = response.info().get('X-Auth-Token')
        if auth_header:
            return {'Authentication': auth_header}
        return None

    def logout(self):
        """
        Description: Web API request that closes the current session and
        invalidates any token associated with the current session.
        """
        self.send_request('/api/auth/logout', {}, 'POST',
                          {'Content-type': 'application/json'})
