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
implying the 'packetstack' resource from Ansible.
"""

ANSIBLE_METADATA = {
    'metadata_version': '1.1',
    'supported_by': 'community',
    'status': ['preview']
}

DOCUMENTATION = '''
---
module: vos_resources

short_description: This module handles interactions with Keysight Visibility Operating
System (VOS) resources.

version_added: "2.8"

description:
    - This module handles interactions with VOS resources settings.
    - VOS version 5.2.0
    - Sub-options marked as required are mandatory only when the top parameter is used.
    

options:
    type:
        description:
            - The resource type.
        type: string
        required: true
        choices: [ packet_stack ]
    resource:
        description:
            - The name of the resource.
        type: string
        required: true
    operation:
        description:
            - The operation that is applied to the resource. Required only for resource attach (enable) and detach (disable).
        type: string
        required: false
        choices: [ enable, disable ]
    settings:
        description:
            - The properties to be changed.
        type: dict
        required: true
        suboptions: 
            allocated_bandwidth:
                description:
                    - Available on 7300 Series, Vision E10S.
                type: integer
            connect_disconnect_access_settings:
                description:
                    - Available on all platforms.
                type: dict
                suboptions:
                    groups:
                        description:
                            - List of items described below.
                            - The NAME property of a group
                        required: true
                        type: list
                    policy:
                        required: true
                        type: string
                        choices: ['ALLOW_ALL', 'REQUIRE_MEMBER', 'REQUIRE_ADMIN']
            description:
                description:
                    - Available on all platforms.
                type: string
            mod_count:
                description:
                    - Available on all platforms.
                type: integer
            modify_access_settings:
                description:
                    - Available on all platforms.
                type: dict
                suboptions:
                    groups:
                        description:
                            - List of items described below.
                            - The NAME property of a group
                        required: true
                        type: list
                    policy:
                        required: true
                        type: string
                        choices: ['ALLOW_ALL', 'REQUIRE_MEMBER', 'REQUIRE_ADMIN']
            name:
                description:
                    - Available on all platforms.
                type: string
            object_id:
                description:
                    - Available on 7300 Series, E100 Series, E40 Series, Vision E10S.
                type: string or integer
            port_mode:
                description:
                    - Available on 7300 Series, E100 Series, E40 Series, Vision E10S.
                type: string
                choices: ['LOOPBACK', 'NETWORK', 'BYPASS_BIDIRECTIONAL', 'HA_FABRIC', 'BIDIRECTIONAL', 'TOOL', 'SIMPLEX', 'INLINE_TOOL_BIDIRECTIONAL']
            view_access_settings:
                description:
                    - Available on all platforms.
                type: dict
                suboptions:
                    groups:
                        description:
                            - List of items described below.
                            - The NAME property of a group
                        required: true
                        type: list
                    policy:
                        required: true
                        type: string
                        choices: ['ALLOW_ALL', 'REQUIRE_MEMBER', 'REQUIRE_ADMIN']


author:
    - Keysight
'''

EXAMPLES = '''
  - name: Enable PacketStack
     vos_resources:
       type: packetstack
       operation: enable
       resource: L2-AFM
       settings:
         allocated_bandwidth: 100
         object_id: P2-03
         port_mode: NETWORK
   - name: Change resource name
     vos_resources:
       type: packetstack
       resource: L2-AFM
       settings:
         name: L2-AFM
   - name: Update resource
     vos_resources:
       type: packetstack
       resource: L2-AFM
       settings:
         description: PacketStack resource attached to P01
         modify_access_settings:
           groups: []
           policy: REQUIRE_ADMIN
   - name: Enable PacketStack features on port
     vos_ports:
       port: P2-03
       resource_attachment_config: 
         vxlan_strip_settings: 
           enabled: true
           port_mode: NETWORK
         etag_strip_settings:
           enabled: true
   - name: Detach PacketStack
     vos_resources:
       type: packetstack
       operation: disable
       resource: L2-AFM
       settings:
         object_id: P2-03
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

    if module.params['type'] == 'packetstack':
        resource_url = 'recirculated_afm_resources'
        resource_name = 'packetstack_resources'
    elif module.params['type'] == 'appstack':
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

