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


NVOS module_utils class responsible for processing YAML playbooks and
constructing Web API HTTP requests. An intermediate layer between the NVOS
Ansible modules and the custom NVOS httpapi plugin.
"""

ANSIBLE_METADATA = {
    'metadata_version': '1.1',
    'supported_by': 'community',
    'status': ['preview']
}

from json import loads
from ansible.module_utils.connection import Connection
from platform import system
from urllib3 import disable_warnings
from urllib3.exceptions import InsecureRequestWarning

# Disable unverified HTTPS requests (certificate verification is strongly
# advised).
if system() in ['Linux', 'Windows']:
    disable_warnings(InsecureRequestWarning)


class HttpApi:
    _connection_obj = None

    def __init__(self, module):
        self._module = module
        self._files = None

    @property
    def _connection(self):
        """
        Description: property that points to the Connection object
        """
        if not HttpApi._connection_obj:
            HttpApi._connection_obj = Connection(self._module._socket_path)

        return HttpApi._connection_obj

    def get_all_items(self, resource_url):
        """
        Description: Method that retrieves all objects of a particular type in
        NPB.

        :param resource_url: type of objects we want to query for
        :return: a list of object names
        """

        response = self.handle(url=resource_url, method='GET', data={})
        if isinstance(response, str):
            response = loads(response)

        json_response = loads(response['msg'])

        output = []
        for each in json_response:
            output.append(each['name'])

        return output

    def get_comma_list_items(self, object_list):
        """
        Description: Method that retrieves all objects of a particular type in
        NPB from a comma separated list.

        :param object_list: actual list expressed like "[P10, P20, P30]"
        :return: a list of names
        """
        tokens = str(object_list).split(',')
        stripped_tokens = [item.strip() for item in tokens]

        return stripped_tokens

    def get_range(self, resource_url, object_range):
        """
        Description: Method that retrieves all objects of a particular type in
        NPB within a range.

        :param resource_url: type of objects we want to query for
        :param object_range: actual range expressed like "[P01:P10]"
        :return: a list of object names
        """
        lower_bound = str(object_range).split(':')[0]
        upper_bound = str(object_range).split(':')[1]

        output = self.get_all_items(resource_url)

        return sorted(
            item for item in output if lower_bound <= item <= upper_bound)

    def get_id_of_name(self, resource_url, name):
        """
        Description: Method that retrieves the numeric ID of an object in NPB
        using either the name or the default_name property.

        :param resource_url: type of the object
        :param name: actual name of the object for which we want the ID
        :return: the integer ID or None
        """

        try:
            response = self.handle(url=resource_url + "/" + name, method='GET',
                                   data=dict())
        except Exception as e:
            return None

        if response:
            try:
                if isinstance(response, str):
                    response = loads(response)

                json_response = loads(response['msg'])
                return json_response['id']
            except (ValueError, KeyError):
                return None

        return None

    def get_target(self, property_name, resource_url):
        """
        Description: Method that retrieves the NPB objects affected by a
        particular Web API call and stores them inside self._module.resource_id
        variable.

        :param property_name: identifier used to refer of the object (either
         name or the synthetic key)
        :param resource_url: type of the object
        """

        target = str(self._module.params[property_name])
        if property_name != 'name':
            self._module.params.pop(property_name)

        if target is None:
            raise Exception(
                'Name or default name property has not been provided.')
        elif target == 'ALL':
            self._module.resource_id = self.get_all_items(resource_url)
        elif target.startswith("[") and target.endswith("]"):
            if ',' in target:
                self._module.resource_id = self.get_comma_list_items(
                    target[1:-1])
            else:
                self._module.resource_id = self.get_range(resource_url,
                                                          target[1:-1])
        else:
            self._module.resource_id = target

    def is_subdict(self, pattern, real):
        """
        This method determines if a dictionary is contained within another
        dictionary. Each key/value pair in "pattern" must appear in "real"
        although "real" may have many additional keys/values.

        :param pattern: the dictionary being searched for
        :param real: the reference dictionary being searched
        :return: True if the dictionary is contained and False otherwise
        """
        if real is None:
            return False

        if isinstance(real, str):
            real = eval(real)
        if isinstance(pattern, str):
            pattern = eval(pattern)

        for pattern_key, pattern_value in pattern.items():
            if isinstance(pattern_value, dict):
                if pattern_key not in real:
                    return False
                found = self.is_subdict(pattern_value, real[pattern_key])
            elif isinstance(pattern_value, list):
                if pattern_key not in real:
                    return False
                found = self.is_same_list(pattern_value, real[pattern_key])
            else:
                try:
                    if pattern_key in real and pattern_value == real[pattern_key]:
                        found = True
                    else:
                        found = False
                except Exception:
                    found = False

            if found is False:
                return False

        return True

    def is_same_list(self, pattern, real):
        """
        This method determines if two lists are identical.

        :param pattern: the list being searched for
        :param real: the reference list being searched
        :return: True if the lists are identical and False otherwise
        """
        if real is None:
            return False

        if len(real) != len(pattern):
            return False

        for list_pattern in pattern:
            found = False
            for list_real in real:
                if isinstance(list_pattern, dict):
                    found = self.is_subdict(list_pattern, list_real)
                elif isinstance(list_pattern, list):
                    found = self.is_same_list(list_pattern, list_real)
                else:
                    if list_pattern == list_real:
                        found = True

                if found is True:
                    break

            if found is False:
                return False

        return True

    def will_payload_imply_changes(self, url, data, method):
        """
        Description: Method that checks if a particular Web API call will
        change the state of the current NPB box.

        :param url: the HTTP url of the request
        :param data: the HTTP body of the request
        :param method: the HTTP method of the request
        :return: true or false
        """
        if method == 'POST' or method == 'DELETE' or method == 'GET' or len(
                data.keys()) == 0:
            return True

        url += '?properties='
        for key, value in data.items():
            url += key + ","

        resp_text = self.handle(url, 'GET', {}, True)

        if isinstance(resp_text, str):
            resp_text = eval(resp_text)

        resp_text = str(resp_text['msg'])

        resp_text = resp_text.replace('true', 'True')
        resp_text = resp_text.replace('false', 'False')
        resp_text = resp_text.replace('null', '"null"')

        resp_dict = eval(resp_text)
        return not self.is_subdict(data, resp_dict)

    def handle(self, url, method, data, add_substitution_flag=None):
        """
        Description: Generic method that executes HTTP requests on remote
        devices for all supported NPB resources.

        :param url: the HTTP url of the request
        :param method: the HTTP method of the request
        :param data: the HTTP body of the request
        :param add_substitution_flag: if set to true, a custom Web API header
         will be included to facilitate the translation between integer IDs
         and string NAMEs
        :return: the HTTP response of the request containing the status code
         and the actual returned message
        """
        # consider the case of intermediary versions (e.g. 5.2.0.2)
        version_number = self._connection.get_facts().split('|')[0]
        version_tokens = version_number.split('.')
        if len(version_tokens) > 3:
            version_number = version_tokens[0] + '.' + version_tokens[1]\
                             + '.' + version_tokens[2]

        headers = {'Version': version_number}

        if add_substitution_flag:
            headers['Flags'] = 'substitute_props+cli'

        try:
            if self._files:
                content = self._connection.send_multipart(path=url, data=data,
                                                          method=method,
                                                          headers=headers)

                content_dict = eval(content)
                if 'code' in content_dict and 'msg' in content_dict:
                    response = {'code': content_dict['code'],
                                'msg': content_dict['msg']}
                else:
                    response = {'code': 200, 'msg': content}
            else:
                headers['Content-Type'] = 'application/json'

                if self.will_payload_imply_changes(url, data, method):
                    content = self._connection.send_request(path=url,
                                                            data=data,
                                                            method=method,
                                                            headers=headers)
                    if len(str(content).strip()) > 0:
                        if 'code' in content and 'msg' in content:
                            response = eval(content)
                        else:
                            response = {'code': 200, 'msg': str(content)}
                    else:
                        response = {'code': 200, 'msg': "SUCCESSFULLY CHANGED"}
                else:
                    response = {'code': 200, 'msg': "NOT CHANGED"}
        except Exception as e:
            return str(e)

        return response

    def handle_actions(self, add_substitution_flag=None):
        """
        Description: Method for constructing Web API actions requests that are
        further handled by the generic handler.

        :param add_substitution_flag: if set to true, a custom Web API header
         will be included to facilitate the translation between integer IDs
         and string NAMEs
        :return: the response from the generic handler
        """
        action_name = self._module.params['action_name']
        url = '/actions/' + action_name

        if 'file_path' in self._module.params:
            self._files = True
        else:
            if action_name + '_payload' in self._module.params:
                self._module.params = self._module.params[
                    action_name + '_payload']
            else:
                self._module.params = {}

        if action_name == 'export' or action_name == 'save_logs' or \
                action_name == 'export_offline_license_request_file':
            content = self._connection.send_binary_request(path=url,
                                                           data=
                                                           self._module.params,
                                                           method='POST')

            if type(content) is str:
                content = eval(content)

            if 'code' in content and 'msg' in content:
                response = {'code': content['code'],
                            'msg': content['msg']}
            else:
                if action_name == 'export':
                    response = {'code': 200,
                                'msg': '.ata export successfully.'}

                if action_name == 'save_logs' or \
                        action_name == 'export_offline_license_request_file':
                    response = {'code': 200, 'msg': 'File saved successfully.'}
        else:
            response = self.handle(url=url, method='POST',
                                   data=self._module.params,
                                   add_substitution_flag=add_substitution_flag)

        return response

    def handle_system(self):
        """
        Description: Method for constructing Web API system requests that are
        further handled by the generic handler.

        :return: the response from the generic handler
        """
        url = '/system'

        # let Web API throw error
        if 'delete' in self._module.params:
            method = 'DELETE'
            self._module.params.pop('delete')
        else:
            method = 'PUT'

        response = [
            self.handle(url=url, method=method, data=self._module.params,
                        add_substitution_flag=True)]

        return response

    def handle_ports(self):
        """
        Description: Method for constructing Web API ports requests that are
        further handled by the generic handler.

        :return: the response from the generic handler
        """
        url = '/ports/'

        # let Web API throw error
        if 'delete' in self._module.params:
            method = 'DELETE'
            self._module.params.pop('delete')
        else:
            method = 'PUT'

        response = []
        if self._module.resource_id:
            if not isinstance(self._module.resource_id, list):
                self._module.resource_id = [self._module.resource_id]
            for each in self._module.resource_id:
                response.append(
                    self.handle(url=url + each, method=method,
                                data=self._module.params,
                                add_substitution_flag=True))
        else:
            response.append(
                self.handle(url=url, method=method, data=self._module.params,
                            add_substitution_flag=True))

        return response

    def handle_port_groups(self):
        """
        Description: Method for constructing Web API port groups requests that
        are further handled by the generic handler.

        :return: the response from the generic handler
        """
        response = []

        if 'delete' in self._module.params:
            method = 'DELETE'
            self._module.params.pop('delete')
        else:
            method = None

        if self._module.resource_id:
            if not isinstance(self._module.resource_id, list):
                self._module.resource_id = [self._module.resource_id]

            for each in self._module.resource_id:
                exists = self.get_id_of_name('/port_groups', name=each)

                url = '/port_groups/' + each

                if method is None and exists:
                    method = 'PUT'
                elif method is None:
                    method = 'POST'
                    url = '/port_groups'

                response.append(
                    self.handle(url=url, method=method,
                                data=self._module.params,
                                add_substitution_flag=True))
        else:
            if method is None:
                method = 'POST'
            response.append(
                self.handle(url='/port_groups/', method=method,
                            data=self._module.params,
                            add_substitution_flag=True))

        return response

    def handle_filters(self):
        """
        Description: Method for constructing Web API filters requests that are
        further handled by the generic handler.

        :return: the response from the generic handler
        """
        response = []

        if 'delete' in self._module.params:
            method = 'DELETE'
            self._module.params.pop('delete')
        else:
            method = None

        if self._module.resource_id:
            if not isinstance(self._module.resource_id, list):
                self._module.resource_id = [self._module.resource_id]

            for each in self._module.resource_id:
                exists = self.get_id_of_name('/filters', name=each)

                url = '/filters/' + each

                if method is None and exists:
                    method = 'PUT'
                elif method is None:
                    method = 'POST'
                    url = '/filters'

                response.append(
                    self.handle(url=url, method=method,
                                data=self._module.params,
                                add_substitution_flag=True))
        else:
            if method is None:
                method = 'POST'
            response.append(
                self.handle(url='/filters/', method=method,
                            data=self._module.params,
                            add_substitution_flag=True))

        return response
