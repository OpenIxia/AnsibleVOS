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


Keysight Visibility Operating System (VOS) module_utils class responsible for 
processing YAML playbooks and constructing Web API HTTP requests. An intermediate
layer between the VOS Ansible modules and the custom VOS httpapi plugin.
"""

ANSIBLE_METADATA = {
    'metadata_version': '1.1',
    'supported_by': 'community',
    'status': ['preview']
}

from json import dumps
import re

SOFTWARE_VERSION = 'software_version'
EXPORT_ACTION = 'export'
SAVE_LOGS_ACTION = 'save_logs'
EXPORT_OFFLINE_LICENSE = 'export_offline_license_request_file'
BINARY_ACTIONS = [EXPORT_ACTION, SAVE_LOGS_ACTION, EXPORT_OFFLINE_LICENSE]
BINARY = 'binary'
MULTIPART = 'multipart'
REGULAR = 'regular'
REGEX = '^[0-9]+$'
RAFM_URL = '/recirculated_afm_resources/'
ENABLE = '/enable'
DISABLE = '/disable'
ATIP_URL = '/atip_resources/'
RESOURCE_ATTACHMENT_RESULTS = {'resource_not_set': 0, 'resource_set_same_config': 1, 'resource_set_different_config': 2}


class ResourceConfigurator:
    def __init__(self, connection, module):
        self.connection = connection
        self.module = module
        self.resource_ids = []

        if SOFTWARE_VERSION in module.params:
            self.connection.set_software_version(module.params[SOFTWARE_VERSION])

    def get_all_items(self, resource_url):
        """
        Description: Method that retrieves all objects of a particular type in
        NPB.

        :param resource_url: type of objects we want to query for
        :return: a list of object names
        """

        response = self.connection.send_request(path=resource_url, data={},
                                                method='GET')

        json_response = response['content']

        output = []
        for each in json_response:
            output.append(each['name'])

        return output

    def get_range(self, resource_url, object_range):
        """
        Description: Method that retrieves all objects of a particular type in
        NPB within a range.

        :param resource_url: type of objects we want to query for
        :param object_range: actual range expressed like "[P01: P10]"
        :return: a list of object names
        """
        if "'" in object_range:
            object_range = object_range.replace("'", "")
        if '"' in object_range:
            object_range = object_range.replace('"', '')
        if "{" in object_range or "}" in object_range:
            object_range = object_range.replace("{", "")
            object_range = object_range.replace("}", "")

        lower_bound = object_range.split(':')[0].strip()
        upper_bound = object_range.split(':')[1].strip()

        output = self.get_all_items(resource_url)

        return sorted(
            item for item in output if lower_bound <= item <= upper_bound)

    def does_object_exist(self, resource_url, name):
        """
        Description: Method that checks whether an object exists
        in NPB using either the name or the default_name property.

        :param resource_url: type of the object
        :param name: actual name of the object for which we want the ID
        :return: true if the object exists
        """
        response = self.connection.send_request(path=resource_url + "/" + name,
                                                data=dict(), method='GET')
        if response['status_code'] == 200:
            return True
        return False

    def get_target(self, property_name, resource_url):
        """
        Description: Method that retrieves the NPB objects affected by a
        particular Web API call and stores them inside self.resource_ids
        variable.

        :param property_name: identifier used to refer of the object (either
         name or the synthetic key)
        :param resource_url: type of the object
        """

        target = self.module.params[property_name]
        if property_name != 'name':
            self.module.params.pop(property_name)

        if target is None:
            raise Exception(
                'Name or default name property has not been provided.')
        elif target == 'ALL':
            self.resource_ids = self.get_all_items(resource_url)
        elif target.startswith("[") and target.endswith("]"):
            if ',' in target:
                self.resource_ids = get_comma_list_items(target[1:-1])
            else:
                self.resource_ids = self.get_range(resource_url,
                                                   target[1:-1])
        else:
            self.resource_ids = [target]

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

    def clear_payload(self, input_dict):
        """
        Description: Removes from the input dictionary the keys with None values,
        as they do not produce changes and either override existing values or
        trigger Web API errors.

        :param input_dict: dictionary to be processed
        """
        copy = {k: v for k, v in input_dict.items()}
        for key, value in copy.items():
            if key == SOFTWARE_VERSION:
                input_dict.pop(SOFTWARE_VERSION)
            elif value is None:
                input_dict.pop(key)
            elif isinstance(value, dict):
                self.clear_payload(value)

    def unicode_to_numeric_list_conversion(self, input_list):
        """
        Description: Converts positive integer values
        represented as unicode strings from a list into
        corresponding integers
        :param input_list: list to be processed
        """
        copy = list(input_list)
        for index in range(len(copy)):
            item = copy[index]
            if isinstance(item, dict):
                self.unicode_to_numeric_dict_conversion(item)
            elif isinstance(item, list):
                self.unicode_to_numeric_list_conversion(item)
            elif isinstance(item, bool) or isinstance(item, int) \
                    or isinstance(item, float):
                continue
            elif re.search(REGEX, item):
                input_list[index] = int(item)

        return input_list

    def unicode_to_numeric_dict_conversion(self, input_dict):
        """
        Description: Converts positive integer values
        represented as unicode strings from a dict into
        corresponding integers
        :param input_dict: dictionary to be processed
        """
        copy = {k: v for k, v in input_dict.items()}
        for key, value in copy.items():
            if isinstance(value, dict):
                self.unicode_to_numeric_dict_conversion(value)
            elif isinstance(value, list):
                self.unicode_to_numeric_list_conversion(value)
            elif isinstance(value, bool) or isinstance(value, int) \
                    or isinstance(value, float):
                continue
            elif re.search(REGEX, value):
                input_dict[key] = int(value)

        return input_dict

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

        response = self.connection.send_request(url, {}, 'GET')

        if response['status_code'] == 200:
            resp_text = dumps(response['content'])

            resp_text = resp_text.replace('true', 'True')
            resp_text = resp_text.replace('false', 'False')
            resp_text = resp_text.replace('null', '"null"')

            resp_dict = eval(resp_text)
            resp_dict = self.unicode_to_numeric_dict_conversion(resp_dict)

            return not self.is_subdict(data, resp_dict)

        return True

    def is_resource_attached(self, url, data):
        """
        Description: Method that checks if a resource is attached and compares
        the values in the request body with existing values on the resource.

        :param url: the HTTP url of the request
        :param data: the HTTP body of the request
        :return: one of the RESOURCE_ATTACHMENT_RESULTS values
        """
        url_res = url[:url.rfind('/')]
        resp_res = self.connection.send_request(url_res, {}, 'GET')

        if resp_res['status_code'] == 200:
            lane_config_list = resp_res['content']['lane_config_list']
            if lane_config_list:
                for lane_config in lane_config_list:
                    kind = lane_config['attachment_type'].lower()

                    url_attachment = '/' + kind + 's/' + lane_config['attachment_id']
                    resp_attachment = self.connection.send_request(url_attachment, {}, 'GET')

                    if resp_attachment['status_code'] == 200:
                        if resp_attachment['content']['id'] == data['object_id'] or \
                            resp_attachment['content']['name'] == data['object_id'] or \
                                resp_attachment['content']['default_name'] == data['object_id']:

                            if 'allocated_bandwidth' in data and \
                                    lane_config['allocated_bandwidth'] == data["allocated_bandwidth"]:
                                return RESOURCE_ATTACHMENT_RESULTS['resource_set_same_config']

                            return RESOURCE_ATTACHMENT_RESULTS['resource_set_different_config']

        return RESOURCE_ATTACHMENT_RESULTS['resource_not_set']

    def configure(self, url, method, data, request_type=REGULAR):
        """
        Description: Generic method that delegates HTTP requests on remote
        devices for all supported NPB resources.

        :param url: the HTTP url of the request
        :param method: the HTTP method of the request
        :param data: the HTTP body of the request
        :param request_type: flag for MULTIPART, BINARY or REGULAR requests

        :return: the HTTP response of the request containing the status code
         and the actual returned message
        """

        if request_type == MULTIPART:
            response = self.connection.send_multipart(path=url, data=data,
                                                      method=method)
        elif request_type == BINARY:
            response = self.connection.send_binary(path=url, data=data)
        else:
            if RAFM_URL in url and (ENABLE in url or DISABLE in url):
                result = self.is_resource_attached(url, data)
                if DISABLE in url:
                    if result == RESOURCE_ATTACHMENT_RESULTS['resource_not_set']:
                        return {'status_code': 200, 'content': 'NOT CHANGED'}
                    else:
                        return self.connection.send_request(path=url, data=data, method=method)
                else:
                    if result == RESOURCE_ATTACHMENT_RESULTS['resource_set_same_config']:
                        return {'status_code': 200, 'content': 'NOT CHANGED'}
                    elif result == RESOURCE_ATTACHMENT_RESULTS['resource_set_different_config']:
                        return {'status_code': 409, 'content': "FAILED - Cannot change "
                                                               "PacketStack properties while the resource is attached."}
                    else:
                        response = self.connection.send_request(path=url, data=data, method=method)
            else:
                skipped = True
                if not self.will_payload_imply_changes(url, data, method):
                    skipped = False

                response = self.connection.send_request(path=url, data=data, method=method)

                if skipped:
                    return {'status_code': 200, 'content': 'NOT CHANGED'}

        response = self.connection.check_error_codes(response, url, data,
                                                     method)

        if response['status_code'] != 200 and response['status_code'] != 202:
            try:
                if isinstance(response['content'], str):
                    content = ' - ' + response['content'].split('Debug info')[0]
                else:
                    content = ' - ' + str(response['content']).replace("u'", "'")
            except:
                content = ''
            response['content'] = 'FAILED' + content
        else:
            try:
                content = str(response['content']).replace("u'", "'")
                content = ' - ' + content if content else ''
            except:
                content = ''

            response['content'] = 'SUCCESSFULLY CHANGED' + content

        return response

    def configure_resources(self):
        """
        Description: Method for constructing Web API resources requests that are
        further handled by the generic method.

        :return: the response from the generic method
        """
        resource_type = self.module.params['type']

        if resource_type == 'packetstack':
            url = RAFM_URL
        elif resource_type == 'appstack':
            url = ATIP_URL
        if 'payload' in self.module.params:
            payload = self.module.params['payload']
        else:
            payload = dict()

        response = []
        if self.resource_ids:
            for each in self.resource_ids:
                url += each
                if 'operation' in self.module.params:
                    url += '/' + self.module.params['operation']
                response.append(
                    self.configure(url=url, method='PUT', data=payload))

        return response

    def configure_actions(self):
        """
        Description: Method for constructing Web API actions requests that are
        further handled by the generic method.

        :return: the response from the generic method
        """
        action_name = self.module.params['action_name']
        url = '/actions/' + action_name

        if 'file_path' in self.module.params:
            request_type = MULTIPART
        else:
            request_type = BINARY if action_name in BINARY_ACTIONS else REGULAR

            if action_name + '_payload' in self.module.params:
                self.module.params = self.module.params[action_name + '_payload']
            else:
                self.module.params = {}

        action_response = self.configure(url=url, method='POST',
                                         data=self.module.params, request_type=request_type)

        return [action_response]

    def configure_system(self):
        """
        Description: Method for constructing Web API system requests that are
        further handled by the generic method.

        :return: the response from the generic method
        """
        url = '/system'
        method = 'PUT'
        return [self.configure(url=url, method=method, data=self.module.params)]

    def configure_ports(self):
        """
        Description: Method for constructing Web API ports requests that are
        further handled by the generic method.

        :return: the response from the generic method
        """
        url = '/ports/'

        # let Web API throw error
        if 'delete' in self.module.params:
            method = 'DELETE'
            self.module.params.pop('delete')
        else:
            method = 'PUT'

        response = []
        if self.resource_ids:
            for each in self.resource_ids:
                response.append(
                    self.configure(url=url + each, method=method,
                                   data=self.module.params))
        else:
            response.append(
                self.configure(url=url, method=method, data=self.module.params))

        return response

    def configure_port_groups(self):
        """
        Description: Method for constructing Web API port groups requests that
        are further handled by the generic method.

        :return: the response from the generic method
        """
        response = []

        if 'delete' in self.module.params:
            method = 'DELETE'
            self.module.params.pop('delete')
        else:
            method = None

        if self.resource_ids:
            for each in self.resource_ids:
                exists = self.does_object_exist('/port_groups', name=each)

                url = '/port_groups/' + each

                if method is None and exists:
                    method = 'PUT'
                elif method is None:
                    method = 'POST'
                    url = '/port_groups'

                response.append(
                    self.configure(url=url, method=method,
                                   data=self.module.params))
        else:
            if method is None:
                method = 'POST'
            response.append(
                self.configure(url='/port_groups/', method=method,
                               data=self.module.params))

        return response

    def configure_filters(self):
        """
        Description: Method for constructing Web API filters requests that are
        further handled by the generic method.

        :return: the response from the generic method
        """
        response = []

        if 'delete' in self.module.params:
            method = 'DELETE'
            self.module.params.pop('delete')
        else:
            method = None

        if self.resource_ids:
            for each in self.resource_ids:
                exists = self.does_object_exist('/filters', name=each)

                url = '/filters/' + each

                if method is None and exists:
                    method = 'PUT'
                elif method is None:
                    method = 'POST'
                    url = '/filters/'

                response.append(
                    self.configure(url=url, method=method, data=self.module.params))
        else:
            if method is None:
                method = 'POST'
            response.append(
                self.configure(url='/filters/', method=method, data=self.module.params))

        return response


def get_comma_list_items(object_list):
    """
    Description: Method that retrieves all objects of a particular type in
    NPB from a comma separated list.

    :param object_list: actual list expressed like "[P10, P20, P30]"
    :return: a list of names
    """
    if "'" in object_list:
        object_list = object_list.replace("'", "")
    if '"' in object_list:
        object_list = object_list.replace('"', '')

    tokens = object_list.split(',')
    stripped_tokens = [item.strip() for item in tokens]

    return stripped_tokens
