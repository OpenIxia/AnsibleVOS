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


Keysight Visibility Operating System (VOS) module used to issue Web API calls
implying the 'actions' resource from Ansbile.
"""

ANSIBLE_METADATA = {
    'metadata_version': '1.1',
    'supported_by': 'community',
    'status': ['preview']
}


DOCUMENTATION = '''
'''

EXAMPLES ='''
'''

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.connection import Connection
from ansible.module_utils.network.vos.resource_configurator import ResourceConfigurator


def run_module():
    # custom structure of the arguments, as actions do not follow a generic
    # format
    module = AnsibleModule(argument_spec={}, check_invalid_arguments=False)

    connection = Connection(module._socket_path)

    configurator = ResourceConfigurator(connection=connection, module=module)

    if module.params['type'] == 'packet_stack':
        resource_url = 'recirculated_afm_resources'
        resource_name = 'packetstack_resources'
    elif module.params['type'] == 'app_stack':
        resource_url = 'atip_resources'
        resource_name = 'appstack_resources'

    # fetch using Web API the python dictionary representing the argument_spec
    properties = configurator.connection.get_python_representation_of_object(resource_url=resource_url,
                                                                             resource_name=resource_name)

    properties['type'] = dict(type='str')
    properties['resource'] = dict(type='str')
    properties['operation'] = dict(type='str')
    properties['payload'] = dict(type='dict')
    # synthetic key used to specify the software version
    properties['software_version'] = dict(type='str')

    module = AnsibleModule(argument_spec=properties)
    result = dict(
        changed=False,
        messages=[]
    )

    try:
        configurator.clear_payload(module.params)
        configurator.module = module

        if 'resource' in module.params:
            configurator.get_target('resource', '/' + module.params['type'])
        elif 'name' in module.params:
            configurator.get_target('name', '/' + module.params['type'])

        output = configurator.configure_resources()

        for each in output:
            if each['status_code'] not in [200, 202, 401]:
                result['failed'] = True
            elif each['content'] != 'NOT CHANGED':
                result['changed'] = True

            result['messages'].append(each['content'])

        module.exit_json(**result)

    except Exception as e:
        module.fail_json(msg=e, **result)


def main():
    run_module()


if __name__ == '__main__':
    main()

