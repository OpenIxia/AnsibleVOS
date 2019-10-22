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


NVOS module used to issue Web API calls implying the 'actions' resource from
Ansbile.
"""

ANSIBLE_METADATA = {
    'metadata_version': '1.1',
    'supported_by': 'community',
    'status': ['preview']
}


DOCUMENTATION = '''
---
module: nvos_actions

short_description: This module handles interactions with NVOS actions.

version_added: "2.8"

description:
    - This module handles interactions with NVOS actions settings.
    - NVOS version 5.2.0
    - Sub-options marked as required are mandatory only when the top parameter is used.
    - The following actions are available.
    - Certificate Management. Selected by choice 'certificates'. Allows Syslog and TLS/HTTPS certificates to be uploaded and deleted.  Basic information can also be viewed for certificates installed on the system. Available on all platforms. 
    - Change Filter Priority. Selected by choice 'change_filter_priority'. Allows changing the priority of connections between source ports and port groups to out of band (i.e., non-inline) dynamic filters.  To update the priority of inline filters, update the inline_service_chain_priority_list of the corresponding inline Bypass connector.This should only be used when the filter build mode is PRIORITY (see system memory_allocation property, filter_build_settings).Note that this method cannot be used to modify which source ports and port groups are connected to a filter.  That is done by modifying a filters source_port_list and source_port_group_list.  But for a priority filter when modifying either of these two properties do not also re-prioritize.  First take the original source list, remove any un-needed ports or port groups, then append to the end of the list any new ports or port groups.  Once that has been done use this action to re-prioritize the lists. Available on E100 Series, E40 Series, Vision X Series, Vision E10S. 
    - Change speed configuration of a port. Selected by choice 'change_speed_configuration'. Changes the speed configuration of port.  On a 7300 and 7303 this method replaces the original change_qsfp28_port_mode action, which has been deprecated but is still available. Available on all platforms. 
    - Clear configuration. Selected by choice 'clear_config'. Clear the configuration by deleting all filters, regular users, groups, filter templates, filter template collections, port groups, and custom icons and by setting all ports to default values. Available on all platforms. 
    - Clear filters and ports. Selected by choice 'clear_filters_and_ports'. This command deletes all filters and port groups and sets all ports to default values. This is not available if the system is in CTE. Available on all platforms. 
    - Clear system. Selected by choice 'clear_system'. This command clears the system and restores it to a default state, including resetting the admin account to default values. The license currently installed will not be removed. Available on all platforms. 
    - Enable FIPS Encryption. Selected by choice 'enable_fips_server_encryption'. This commands causes FIPS encryption to be enabled on the server.Once FIPS encryption has been enabled, it can only be disabled by performing a system clear.All users will be logged off and the server rebooted. After restarting, all server data will be encrypted using FIPS compliant algorithms at FIPS compliant levels.Enabling FIPS encryption is not the only step required for the server to be completely FIPS compliant. See the Configuring FIPS Security Compliance Options chapter in the Users Guide for full information on what must be done to make the server fully FIPS compliant. Available on 7300 Series, TradeVision Series, E100 Series, E40 Series, Vision X Series, Vision E10S. 
    - Export. Selected by choice 'export'. Return configuration settings from an NTO to a file. Available on all platforms. 
    - Export KeyGen license to JSON. Selected by choice 'export_keygen_license_to_json'. Export the KeyGen license details to a json file that can be used on the migration portal to obtain a new style license for an NTO. Available on all platforms. 
    - Export the offline license activation request file.. Selected by choice 'export_offline_license_request_file'. Export the request file for FNOOD offline license activation for the current system. Available on all platforms. 
    - Factory reset. Selected by choice 'factory_reset'. This command clears the system and restores it to a factory default state, including resetting the admin account to default values. The license currently installed will also be removed. Available on all platforms. 
    - FIPS Server Encryption Status. Selected by choice 'fips_server_encryption_status'. This commands returns whether FIPS encryption has been enabled on the server. Available on 7300 Series, TradeVision Series, E100 Series, E40 Series, Vision X Series, Vision E10S. 
    - Force power port module. Selected by choice 'force_power_port_module'. This command will power on/off the port module in the given module location. Available on Vision X Series. 
    - Generate certificate signing request (CSR). Selected by choice 'generate_csr'. This command is used to generate a new key pair and create a certificate signing request. Available on all platforms. 
    - Get Available Filter Criteria. Selected by choice 'get_available_filter_criteria'. Return a list of filter criteria which can be used given an already present set of filter criteria.This action is useful for a user interface which defines a filter. Available on all platforms. 
    - Read the publicly available information about the installed FNOOD license.. Selected by choice 'get_fnood_license_public_info'. Read the publicly available information about the installed FNOOD license for the current system. Available on all platforms. 
    - Get HA Config for CLI. Selected by choice 'get_ha_config_for_cli'. Returns the HA config needed by CLI. Available on E100 Series, E40 Series, Vision Edge OS, Vision X Series. 
    - Get Login Info. Selected by choice 'get_login_info'. Return info helpful for login. Available on all platforms. 
    - Get Memory Meters. Selected by choice 'get_memory_meters'. Return the filter memory meters showing memory allocation and percentage used.Filter memory is divided into different categories called memory_types.  Within each memory_type the memory can be allocated for one or more uses.  A meter will be provided for each different allocation.  For example, the meter_type DYNAMIC_FILTER_NON_IP might have 70% of the memory allocated for FILTER_ETHERTYPE_VLAN_L3_L4 and the remaining 30% allocated for FILTER_L2_L3_L4.  This would result in two memory meters under meter_type DYNAMIC_FILTER_NON_IP, one named FILTER_ETHERTYPE_VLAN_L3_L4 (alloc_pcnt = 70) and the other named FILTER_L2_L3_L4 (alloc_pcnt = 30).Note that the sum of memory allocated for all meters in a particular memory_type may only reach 99%.  In such cases, the remaining 1% is understood to be divided proportionally among the meters.In the case of an unit in the 7300 family, the returned JSON array has an element for each line card in the system.In the case of an independent unit that is not in the 7300 series, the returned JSON array has only one element corresponding to the system itself.If no system name has been assigned to a unit, the unit_name will be null.In the case of an union, the returned JSON array has an element for each union member. Available on all platforms. 
    - Get neighbors of a list of ports. Selected by choice 'get_neighbors'. Get neighbors of a list of ports given as parameter. If the list given is empty or is not given at all, it will return all neighbors for all ports that are valid for LLDP and have valid neighbors registrations. Available on all platforms. 
    - Get object type. Selected by choice 'get_object_type'. Return the object type for an internal id. Available on all platforms. 
    - Get properties for a type. Selected by choice 'get_props'. Return a list of the properties that are available for a particular type of object. Available on all platforms. 
    - Get Transceiver Info. Selected by choice 'get_transceiver_info'. Return the transceiver information. Available on all platforms. 
    - Get values for a property. Selected by choice 'get_values'. Return a list of the valid values for a particular object type and property. Available on all platforms. 
    - Import. Selected by choice 'import'. Copy configuration settings from a file. Available on all platforms. 
    - Install license. Selected by choice 'install_license'. This command installs a license file on an NTO. Available on all platforms. 
    - Install netservice. Selected by choice 'install_netservice'. This command installs a netservice upgrade file on an NTO. Available on Vision X Series. 
    - Install software. Selected by choice 'install_software'. This command installs a software upgrade file on an NTO or a union. Available on all platforms. 
    - MTU Query. Selected by choice 'mtu_query'. This commands returns the port, linecard and AFM MTUs based on the board type .Available on all platforms. 
    - Power down. Selected by choice 'power_down'. This command safely shuts down an NTO. Available on all platforms. 
    - Pull Config to HA Peer. Selected by choice 'pull_config_from_ha_peer'. Pulls the configuration from the HA peer machine. Available on 7300 Series, E100 Series, E40 Series, Vision Edge OS, Vision X Series, Vision E10S. 
    - Push Config to HA Peer. Selected by choice 'push_config_to_ha_peer'. Pushes the local configuration to the HA peer machine. Available on 7300 Series, E100 Series, E40 Series, Vision Edge OS, Vision X Series, Vision E10S. 
    - Remove license. Selected by choice 'remove_license'. This command will remove the license and power down the NTO. Available on all platforms. 
    - Remove netservice. Selected by choice 'remove_netservice'. This command will remove (uninstall) a netservice based on the given service id. Available on Vision X Series. 
    - Remove port module configuration. Selected by choice 'remove_port_module_config'. This command will remove the port module configuration based on the given module location. Available on Vision X Series. 
    - Restart. Selected by choice 'restart'. This command safely restarts an NTO. Available on all platforms. 
    - Restore firewall. Selected by choice 'restore_firewall'. This command will restore the default firewall rules to allow all servers to access NTO. Available on all platforms. 
    - Revert software. Selected by choice 'revert_software'. This command revert software to its previous version. Available on all platforms. 
    - Save logs. Selected by choice 'save_logs'. Save the current system log files for subsequent delivery to Ixia Support. Available on all platforms. 
    - Set HA sync port. Selected by choice 'set_ha_sync_port'. Set the HA sync port. Available on 7300 Series, E100 Series, E40 Series, Vision Edge OS, Vision X Series, Vision E10S. 
    - Set IP Config. Selected by choice 'set_ip_config'. Changes the IP configuration of a system.All properties are optional when setting ip_config. Any properties omitted from the JSON input are left at their current value.However, at least one property must be included in the JSON input. Available on all platforms. 
    - Swap Port Licenses. Selected by choice 'swap_port_licenses'. Swaps port licenses. Available on all platforms. 
    - Validate auth calls.. Selected by choice 'validate_auth'. This command checks auth for rest calls. Available on Vision X Series. 

options:
    action_name:
        description:
            - Selects what action will be executed.
            - certificates is available on all platforms.
            - change_filter_priority is available on E100 Series, E40 Series, Vision X Series, Vision E10S.
            - change_speed_configuration is available on all platforms.
            - clear_config is available on all platforms.
            - clear_filters_and_ports is available on all platforms.
            - clear_system is available on all platforms.
            - enable_fips_server_encryption is available on 7300 Series, TradeVision Series, E100 Series, E40 Series, Vision X Series, Vision E10S.
            - export is available on all platforms.
            - export_keygen_license_to_json is available on all platforms.
            - export_offline_license_request_file is available on all platforms.
            - factory_reset is available on all platforms.
            - fips_server_encryption_status is available on 7300 Series, TradeVision Series, E100 Series, E40 Series, Vision X Series, Vision E10S.
            - force_power_port_module is available on Vision X Series.
            - generate_csr is available on all platforms.
            - get_available_filter_criteria is available on all platforms.
            - get_fnood_license_public_info is available on all platforms.
            - get_ha_config_for_cli is available on E100 Series, E40 Series, Vision Edge OS, Vision X Series.
            - get_login_info is available on all platforms.
            - get_memory_meters is available on all platforms.
            - get_neighbors is available on all platforms.
            - get_object_type is available on all platforms.
            - get_props is available on all platforms.
            - get_transceiver_info is available on all platforms.
            - get_values is available on all platforms.
            - import is available on all platforms.
            - install_license is available on all platforms.
            - install_netservice is available on Vision X Series.
            - install_software is available on all platforms.
            - mtu_query is available on all platforms.
            - power_down is available on all platforms.
            - pull_config_from_ha_peer is available on 7300 Series, E100 Series, E40 Series, Vision Edge OS, Vision X Series, Vision E10S.
            - push_config_to_ha_peer is available on 7300 Series, E100 Series, E40 Series, Vision Edge OS, Vision X Series, Vision E10S.
            - remove_license is available on all platforms.
            - remove_netservice is available on Vision X Series.
            - remove_port_module_config is available on Vision X Series.
            - restart is available on all platforms.
            - restore_firewall is available on all platforms.
            - revert_software is available on all platforms.
            - save_logs is available on all platforms.
            - set_ha_sync_port is available on 7300 Series, E100 Series, E40 Series, Vision Edge OS, Vision X Series, Vision E10S.
            - set_ip_config is available on all platforms.
            - swap_port_licenses is available on all platforms.
            - validate_auth is available on Vision X Series.
        type: string
        required: true
        choices: ['certificates', 'change_filter_priority', 'change_speed_configuration', 'clear_config', 'clear_filters_and_ports', 'clear_system', 'enable_fips_server_encryption', 'export', 'export_keygen_license_to_json', 'export_offline_license_request_file', 'factory_reset', 'fips_server_encryption_status', 'force_power_port_module', 'generate_csr', 'get_available_filter_criteria', 'get_fnood_license_public_info', 'get_ha_config_for_cli', 'get_login_info', 'get_memory_meters', 'get_neighbors', 'get_object_type', 'get_props', 'get_transceiver_info', 'get_values', 'import', 'install_license', 'install_netservice', 'install_software', 'mtu_query', 'power_down', 'pull_config_from_ha_peer', 'push_config_to_ha_peer', 'remove_license', 'remove_netservice', 'remove_port_module_config', 'restart', 'restore_firewall', 'revert_software', 'save_logs', 'set_ha_sync_port', 'set_ip_config', 'swap_port_licenses', 'validate_auth']
    file_path:
        description:
            - The path to a file or folder. It is a required parameter for multi-part actions.
        type: string
    certificates_payload:
        description:
            - When the ACTION property is UPLOAD, the content type of the HTTP request must be multipart. In addition to the JSON string, one or two files may be uploaded for Syslog and one for TLS/HTTPS. For TLS/HTTPS, the file contains the server certificate and must be assigned the name authentication in the HTTP header. For Syslog, one file is the client certificate, which must be assigned the name client in the HTTP header. The second Syslog file is the trusted root certificate, which must be assigned the name trusted_root in the HTTP header. For TLS/HTTPS, there is also an optional property, ENABLE_RMI_ENCRYPTION. Including this property will enable or disable RMI TLS encryption; omitting this property will leave RMI TLS encryption in the same state.
            - For Syslog, it is allowed to upload EITHER the client authentication certificate, OR the trusted root certificate WITHOUT uploading both of them together. Whichever is not uploaded will be left on the server. If one or both files are missing on the server, TLS encryption cannot be enabled on any Syslog servers.
            - The default TLS/HTTPS cannot be deleted or changed, meaning if CERTIFICATE_USE is DEFAULT_TLS_HTTPS, the ACTION must be VIEW.
            - Available on all platforms.
        type: dict
        suboptions:
            action:
                description:
                    - 
                required: true
                type: string
                choices: ['DELETE', 'UPLOAD', 'VIEW']
            certificate_use:
                description:
                    - 
                required: true
                type: string
                choices: ['LDAP', 'SYSLOG_TRUSTED_ROOT', 'SYSLOG', 'TLS_HTTPS', 'SYSLOG_CLIENT', 'DEFAULT_TLS_HTTPS']
            enable_rmi_encryption:
                description:
                    - 
                required: true
                type: bool
    change_filter_priority_payload:
        description:
            - The action must contain the source_port_id or the source_port_group_id property, but not both.
            - The prioritized_dest_filter_id_list must be in priority order, where the first entry (lowest index) has highest priority.
            - Available on E100 Series, E40 Series, Vision X Series, Vision E10S.
        type: dict
        suboptions:
            prioritized_dest_filter_id_list:
                description:
                    - 
                    - List of items described below.
                    - The integer value of the ID property for an object
                required: true
                type: list
            source_port_group_id:
                description:
                    - 
                type: integer
            source_port_id:
                description:
                    - 
                type: integer
    change_speed_configuration_payload:
        description:
            - 
            - Available on all platforms.
        type: dict
        suboptions:
            num_ports:
                description:
                    - 
                required: true
                type: integer
            port_list:
                description:
                    - 
                    - List of items described below.
                    - The integer value of the ID property for an object
                required: true
                type: list
            qsfp28_port_mode:
                description:
                    - 
                required: true
                type: string
                choices: ['MODE_25G', 'MODE_QSFP', 'MODE_DUAL_QSFP', 'MODE_QSFP28', 'MODE_50G', 'MODE_SFP']
    clear_config_payload:
        description:
            - 
            - Available on all platforms.
        type: dict
        suboptions:
    clear_filters_and_ports_payload:
        description:
            - 
            - Available on all platforms.
        type: dict
        suboptions:
    clear_system_payload:
        description:
            - 
            - Available on all platforms.
        type: dict
        suboptions:
    enable_fips_server_encryption_payload:
        description:
            - 
            - Available on 7300 Series, TradeVision Series, E100 Series, E40 Series, Vision X Series, Vision E10S.
        type: dict
        suboptions:
    export_payload:
        description:
            - 
            - Available on all platforms.
        type: dict
        suboptions:
    export_keygen_license_to_json_payload:
        description:
            - 
            - Available on all platforms.
        type: dict
        suboptions:
            entity:
                description:
                    - 
                type: null
            file_name:
                description:
                    - 
                type: string
    export_offline_license_request_file_payload:
        description:
            - 
            - Available on all platforms.
        type: dict
        suboptions:
            file_name:
                description:
                    - 
                type: string
    factory_reset_payload:
        description:
            - 
            - Available on all platforms.
        type: dict
        suboptions:
    fips_server_encryption_status_payload:
        description:
            - 
            - Available on 7300 Series, TradeVision Series, E100 Series, E40 Series, Vision X Series, Vision E10S.
        type: dict
        suboptions:
    force_power_port_module_payload:
        description:
            - 
            - Available on Vision X Series.
        type: dict
        suboptions:
            port_module_location:
                description:
                    - 
                required: true
                type: string
            power_enable:
                description:
                    - 
                required: true
                type: bool
    generate_csr_payload:
        description:
            - If no csr_use property is included, its value will default to TLS.
            - Available on all platforms.
        type: dict
        suboptions:
            csr_use:
                description:
                    - 
                type: string
                choices: ['LDAP', 'SYSLOG', 'TLS']
            tls_cert_request_info:
                description:
                    - 
                type: dict
                suboptions:
                    city:
                        description:
                            - 
                        type: string
                    common_name:
                        description:
                            - 
                        type: string
                    country:
                        description:
                            - 
                        type: string
                    email_address:
                        description:
                            - 
                        type: string
                    organization:
                        description:
                            - 
                        type: string
                    organization_unit:
                        description:
                            - 
                        type: string
                    state:
                        description:
                            - 
                        type: string
                    subject_alt_name:
                        description:
                            - 
                        type: string
    get_available_filter_criteria_payload:
        description:
            - The source_port_list and source_port_group_list properties are ignored when filter_object_type is not FILTER.
            - If filter_criteria is not specified, all criterion types allowed by the memory allocation are returned.
            - The dynamic_filter_id property should always be included whenever querying the criteria available for an existing dynamic filter and the source_port_list and/or source_port_group_list properties are included.
            - If memory_allocation is not specified, the systems current memory allocation will be used. If the memory_allocation JSON does not specify a value for every property, the property will be added with a value from the systems current memory allocation.
            - Available on all platforms.
        type: dict
        suboptions:
            dynamic_filter_id:
                description:
                    - 
                type: integer
            filter_criteria:
                description:
                    - 
                type: dict
                suboptions:
                    custom_mac_dst:
                        description:
                            - 
                        type: dict
                        suboptions:
                            addr:
                                description:
                                    - 
                                    - List of items described below.
                                    - 
                                required: true
                                type: list
                            field_name:
                                description:
                                    - 
                                type: string
                            field_set:
                                description:
                                    - 
                                type: string
                                choices: ['FS2', 'FS1', 'BOTH']
                    custom_mac_flow:
                        description:
                            - 
                        type: dict
                        suboptions:
                            address_sets:
                                description:
                                    - 
                                    - List of items described below.
                                    - 
                                required: true
                                type: list
                                suboptions:
                                    addr_a:
                                        description:
                                            - 
                                            - List of items described below.
                                            - 
                                        required: true
                                        type: list
                                    addr_b:
                                        description:
                                            - 
                                            - List of items described below.
                                            - 
                                        required: true
                                        type: list
                            flow_type:
                                description:
                                    - 
                                required: true
                                type: string
                                choices: ['UNI', 'BIDI']
                    custom_mac_src:
                        description:
                            - 
                        type: dict
                        suboptions:
                            addr:
                                description:
                                    - 
                                    - List of items described below.
                                    - 
                                required: true
                                type: list
                            field_name:
                                description:
                                    - 
                                type: string
                            field_set:
                                description:
                                    - 
                                type: string
                                choices: ['FS2', 'FS1', 'BOTH']
                    custom_mac_src_or_dst:
                        description:
                            - 
                        type: dict
                        suboptions:
                            addr:
                                description:
                                    - 
                                    - List of items described below.
                                    - 
                                required: true
                                type: list
                            field_name:
                                description:
                                    - 
                                type: string
                            field_set:
                                description:
                                    - 
                                type: string
                                choices: ['FS2', 'FS1', 'BOTH']
                    custom_mac_srcdst_pair:
                        description:
                            - 
                        type: dict
                        suboptions:
                            addr_a:
                                description:
                                    - 
                                    - List of items described below.
                                    - 
                                required: true
                                type: list
                            addr_b:
                                description:
                                    - 
                                    - List of items described below.
                                    - 
                                required: true
                                type: list
                    dscp:
                        description:
                            - 
                        type: dict
                        suboptions:
                            value:
                                description:
                                    - 
                                required: true
                                type: string
                    ethertype:
                        description:
                            - 
                        type: dict
                        suboptions:
                            value:
                                description:
                                    - 
                                required: true
                                type: string
                    gtp_teid:
                        description:
                            - 
                        type: dict
                        suboptions:
                            field_name:
                                description:
                                    - 
                                type: string
                            field_set:
                                description:
                                    - 
                                type: string
                                choices: ['FS2', 'FS1', 'BOTH']
                            value:
                                description:
                                    - 
                                required: true
                                type: integer
                    inner_ip_protocol:
                        description:
                            - 
                        type: dict
                        suboptions:
                            field_name:
                                description:
                                    - 
                                type: string
                            field_set:
                                description:
                                    - 
                                type: string
                                choices: ['FS2', 'FS1', 'BOTH']
                            value:
                                description:
                                    - 
                                required: true
                                type: integer
                    inner_ip_version:
                        description:
                            - 
                        type: dict
                        suboptions:
                            field_name:
                                description:
                                    - 
                                type: string
                            field_set:
                                description:
                                    - 
                                type: string
                                choices: ['FS2', 'FS1', 'BOTH']
                            value:
                                description:
                                    - 
                                required: true
                                type: null
                    inner_ipv4_dst_addr:
                        description:
                            - 
                        type: dict
                        suboptions:
                            addr:
                                description:
                                    - 
                                    - List of items described below.
                                    - 
                                required: true
                                type: list
                            field_name:
                                description:
                                    - 
                                type: string
                            field_set:
                                description:
                                    - 
                                type: string
                                choices: ['FS2', 'FS1', 'BOTH']
                    inner_ipv4_flow:
                        description:
                            - 
                        type: dict
                        suboptions:
                            address_sets:
                                description:
                                    - 
                                    - List of items described below.
                                    - 
                                required: true
                                type: list
                                suboptions:
                                    addr_a:
                                        description:
                                            - 
                                            - List of items described below.
                                            - 
                                        required: true
                                        type: list
                                    addr_b:
                                        description:
                                            - 
                                            - List of items described below.
                                            - 
                                        required: true
                                        type: list
                            flow_type:
                                description:
                                    - 
                                required: true
                                type: string
                                choices: ['UNI', 'BIDI']
                    inner_ipv4_l4_dst_port:
                        description:
                            - 
                        type: dict
                        suboptions:
                            field_name:
                                description:
                                    - 
                                type: string
                            field_set:
                                description:
                                    - 
                                type: string
                                choices: ['FS2', 'FS1', 'BOTH']
                            port:
                                description:
                                    - 
                                required: true
                                type: integer
                    inner_ipv4_l4_port_flow:
                        description:
                            - 
                        type: dict
                        suboptions:
                            flow_type:
                                description:
                                    - 
                                required: true
                                type: string
                                choices: ['UNI', 'BIDI']
                            port_sets:
                                description:
                                    - 
                                    - List of items described below.
                                    - 
                                required: true
                                type: list
                                suboptions:
                                    port_a:
                                        description:
                                            - 
                                        required: true
                                        type: integer
                                    port_b:
                                        description:
                                            - 
                                        required: true
                                        type: integer
                    inner_ipv4_l4_src_or_dst_port:
                        description:
                            - 
                        type: dict
                        suboptions:
                            field_name:
                                description:
                                    - 
                                type: string
                            field_set:
                                description:
                                    - 
                                type: string
                                choices: ['FS2', 'FS1', 'BOTH']
                            port:
                                description:
                                    - 
                                required: true
                                type: integer
                    inner_ipv4_l4_src_port:
                        description:
                            - 
                        type: dict
                        suboptions:
                            field_name:
                                description:
                                    - 
                                type: string
                            field_set:
                                description:
                                    - 
                                type: string
                                choices: ['FS2', 'FS1', 'BOTH']
                            port:
                                description:
                                    - 
                                required: true
                                type: integer
                    inner_ipv4_l4_srcdst_port_pair:
                        description:
                            - 
                        type: dict
                        suboptions:
                            field_name:
                                description:
                                    - 
                                type: string
                            port_a:
                                description:
                                    - 
                                required: true
                                type: integer
                            port_b:
                                description:
                                    - 
                                required: true
                                type: integer
                    inner_ipv4_src_addr:
                        description:
                            - 
                        type: dict
                        suboptions:
                            addr:
                                description:
                                    - 
                                    - List of items described below.
                                    - 
                                required: true
                                type: list
                            field_name:
                                description:
                                    - 
                                type: string
                            field_set:
                                description:
                                    - 
                                type: string
                                choices: ['FS2', 'FS1', 'BOTH']
                    inner_ipv4_src_or_dst:
                        description:
                            - 
                        type: dict
                        suboptions:
                            addr:
                                description:
                                    - 
                                    - List of items described below.
                                    - 
                                required: true
                                type: list
                            field_name:
                                description:
                                    - 
                                type: string
                            field_set:
                                description:
                                    - 
                                type: string
                                choices: ['FS2', 'FS1', 'BOTH']
                    inner_ipv4_srcdst_pair:
                        description:
                            - 
                        type: dict
                        suboptions:
                            addr_a:
                                description:
                                    - 
                                    - List of items described below.
                                    - 
                                required: true
                                type: list
                            addr_b:
                                description:
                                    - 
                                    - List of items described below.
                                    - 
                                required: true
                                type: list
                            field_name:
                                description:
                                    - 
                                type: string
                    inner_ipv6_dst_addr:
                        description:
                            - 
                        type: dict
                        suboptions:
                            addr:
                                description:
                                    - 
                                    - List of items described below.
                                    - 
                                required: true
                                type: list
                            field_name:
                                description:
                                    - 
                                type: string
                            field_set:
                                description:
                                    - 
                                type: string
                                choices: ['FS2', 'FS1', 'BOTH']
                    inner_ipv6_dst_interface_id:
                        description:
                            - 
                        type: dict
                        suboptions:
                            field_name:
                                description:
                                    - 
                                type: string
                            field_set:
                                description:
                                    - 
                                type: string
                                choices: ['FS2', 'FS1', 'BOTH']
                            value:
                                description:
                                    - 
                                    - List of items described below.
                                    - 
                                required: true
                                type: list
                    inner_ipv6_flow:
                        description:
                            - 
                        type: dict
                        suboptions:
                            address_sets:
                                description:
                                    - 
                                    - List of items described below.
                                    - 
                                required: true
                                type: list
                                suboptions:
                                    addr_a:
                                        description:
                                            - 
                                            - List of items described below.
                                            - 
                                        required: true
                                        type: list
                                    addr_b:
                                        description:
                                            - 
                                            - List of items described below.
                                            - 
                                        required: true
                                        type: list
                            flow_type:
                                description:
                                    - 
                                required: true
                                type: string
                                choices: ['UNI', 'BIDI']
                    inner_ipv6_l4_dst_port:
                        description:
                            - 
                        type: dict
                        suboptions:
                            field_name:
                                description:
                                    - 
                                type: string
                            field_set:
                                description:
                                    - 
                                type: string
                                choices: ['FS2', 'FS1', 'BOTH']
                            port:
                                description:
                                    - 
                                required: true
                                type: integer
                    inner_ipv6_l4_port_flow:
                        description:
                            - 
                        type: dict
                        suboptions:
                            flow_type:
                                description:
                                    - 
                                required: true
                                type: string
                                choices: ['UNI', 'BIDI']
                            port_sets:
                                description:
                                    - 
                                    - List of items described below.
                                    - 
                                required: true
                                type: list
                                suboptions:
                                    port_a:
                                        description:
                                            - 
                                        required: true
                                        type: integer
                                    port_b:
                                        description:
                                            - 
                                        required: true
                                        type: integer
                    inner_ipv6_l4_src_or_dst_port:
                        description:
                            - 
                        type: dict
                        suboptions:
                            field_name:
                                description:
                                    - 
                                type: string
                            field_set:
                                description:
                                    - 
                                type: string
                                choices: ['FS2', 'FS1', 'BOTH']
                            port:
                                description:
                                    - 
                                required: true
                                type: integer
                    inner_ipv6_l4_src_port:
                        description:
                            - 
                        type: dict
                        suboptions:
                            field_name:
                                description:
                                    - 
                                type: string
                            field_set:
                                description:
                                    - 
                                type: string
                                choices: ['FS2', 'FS1', 'BOTH']
                            port:
                                description:
                                    - 
                                required: true
                                type: integer
                    inner_ipv6_l4_srcdst_port_pair:
                        description:
                            - 
                        type: dict
                        suboptions:
                            field_name:
                                description:
                                    - 
                                type: string
                            port_a:
                                description:
                                    - 
                                required: true
                                type: integer
                            port_b:
                                description:
                                    - 
                                required: true
                                type: integer
                    inner_ipv6_src_addr:
                        description:
                            - 
                        type: dict
                        suboptions:
                            addr:
                                description:
                                    - 
                                    - List of items described below.
                                    - 
                                required: true
                                type: list
                            field_name:
                                description:
                                    - 
                                type: string
                            field_set:
                                description:
                                    - 
                                type: string
                                choices: ['FS2', 'FS1', 'BOTH']
                    inner_ipv6_src_interface_id:
                        description:
                            - 
                        type: dict
                        suboptions:
                            field_name:
                                description:
                                    - 
                                type: string
                            field_set:
                                description:
                                    - 
                                type: string
                                choices: ['FS2', 'FS1', 'BOTH']
                            value:
                                description:
                                    - 
                                    - List of items described below.
                                    - 
                                required: true
                                type: list
                    inner_ipv6_src_or_dst:
                        description:
                            - 
                        type: dict
                        suboptions:
                            addr:
                                description:
                                    - 
                                    - List of items described below.
                                    - 
                                required: true
                                type: list
                            field_name:
                                description:
                                    - 
                                type: string
                            field_set:
                                description:
                                    - 
                                type: string
                                choices: ['FS2', 'FS1', 'BOTH']
                    inner_ipv6_srcdst_pair:
                        description:
                            - 
                        type: dict
                        suboptions:
                            addr_a:
                                description:
                                    - 
                                    - List of items described below.
                                    - 
                                required: true
                                type: list
                            addr_b:
                                description:
                                    - 
                                    - List of items described below.
                                    - 
                                required: true
                                type: list
                            field_name:
                                description:
                                    - 
                                type: string
                    inner_vlan:
                        description:
                            - 
                        type: dict
                        suboptions:
                            priority:
                                description:
                                    - 
                                type: string
                            vlan_id:
                                description:
                                    - 
                                type: integer
                    ip_protocol:
                        description:
                            - 
                        type: dict
                        suboptions:
                            value:
                                description:
                                    - 
                                required: true
                                type: integer
                    ipv4_dst:
                        description:
                            - 
                        type: dict
                        suboptions:
                            addr:
                                description:
                                    - 
                                    - List of items described below.
                                    - 
                                required: true
                                type: list
                    ipv4_flow:
                        description:
                            - 
                        type: dict
                        suboptions:
                            address_sets:
                                description:
                                    - 
                                    - List of items described below.
                                    - 
                                required: true
                                type: list
                                suboptions:
                                    addr_a:
                                        description:
                                            - 
                                            - List of items described below.
                                            - 
                                        required: true
                                        type: list
                                    addr_b:
                                        description:
                                            - 
                                            - List of items described below.
                                            - 
                                        required: true
                                        type: list
                            flow_type:
                                description:
                                    - 
                                required: true
                                type: string
                                choices: ['UNI', 'BIDI']
                    ipv4_session_dst:
                        description:
                            - 
                        type: dict
                        suboptions:
                            sessions:
                                description:
                                    - 
                                    - List of items described below.
                                    - An IPv4 address and a port. The port may be left blank, as in 3.2.1.0/20.  If the CIDR is 0 or the Netmask is 0000, then the criterion will not filter on the address at all, meaning there would be no distinction between an IPv4 and IPv6 address. Examples (CIDR) 11.22.33.44/2415-17, 19, (Netmask) 10.11.12.13/255.255.255.10530, (No mask type) 90.80.70.60-6514, 17, 20-22
                                required: true
                                type: list
                    ipv4_session_flow:
                        description:
                            - 
                        type: dict
                        suboptions:
                            flow_type:
                                description:
                                    - 
                                required: true
                                type: string
                                choices: ['UNI', 'BIDI']
                            session_sets:
                                description:
                                    - 
                                    - List of items described below.
                                    - A flow set allows only one IPv4 specification where both the address is all dont care (CIDR is 0 or the Netmask is 0.0.0.0) and the port is dont care (left blank), whether in the a_session or b_session.
                                required: true
                                type: list
                                suboptions:
                                    a_sessions:
                                        description:
                                            - 
                                            - List of items described below.
                                            - An IPv4 address and a port. The port may be left blank, as in 3.2.1.0/20.  If the CIDR is 0 or the Netmask is 0000, then the criterion will not filter on the address at all, meaning there would be no distinction between an IPv4 and IPv6 address. Examples (CIDR) 11.22.33.44/2415-17, 19, (Netmask) 10.11.12.13/255.255.255.10530, (No mask type) 90.80.70.60-6514, 17, 20-22
                                        required: true
                                        type: list
                                    b_sessions:
                                        description:
                                            - 
                                            - List of items described below.
                                            - An IPv4 address and a port. The port may be left blank, as in 3.2.1.0/20.  If the CIDR is 0 or the Netmask is 0000, then the criterion will not filter on the address at all, meaning there would be no distinction between an IPv4 and IPv6 address. Examples (CIDR) 11.22.33.44/2415-17, 19, (Netmask) 10.11.12.13/255.255.255.10530, (No mask type) 90.80.70.60-6514, 17, 20-22
                                        required: true
                                        type: list
                    ipv4_session_src:
                        description:
                            - 
                        type: dict
                        suboptions:
                            sessions:
                                description:
                                    - 
                                    - List of items described below.
                                    - An IPv4 address and a port. The port may be left blank, as in 3.2.1.0/20.  If the CIDR is 0 or the Netmask is 0000, then the criterion will not filter on the address at all, meaning there would be no distinction between an IPv4 and IPv6 address. Examples (CIDR) 11.22.33.44/2415-17, 19, (Netmask) 10.11.12.13/255.255.255.10530, (No mask type) 90.80.70.60-6514, 17, 20-22
                                required: true
                                type: list
                    ipv4_session_src_or_dst:
                        description:
                            - 
                        type: dict
                        suboptions:
                            sessions:
                                description:
                                    - 
                                    - List of items described below.
                                    - An IPv4 address and a port. The port may be left blank, as in 3.2.1.0/20.  If the CIDR is 0 or the Netmask is 0000, then the criterion will not filter on the address at all, meaning there would be no distinction between an IPv4 and IPv6 address. Examples (CIDR) 11.22.33.44/2415-17, 19, (Netmask) 10.11.12.13/255.255.255.10530, (No mask type) 90.80.70.60-6514, 17, 20-22
                                required: true
                                type: list
                    ipv4_src:
                        description:
                            - 
                        type: dict
                        suboptions:
                            addr:
                                description:
                                    - 
                                    - List of items described below.
                                    - 
                                required: true
                                type: list
                    ipv4_src_or_dst:
                        description:
                            - 
                        type: dict
                        suboptions:
                            addr:
                                description:
                                    - 
                                    - List of items described below.
                                    - 
                                required: true
                                type: list
                    ipv4_srcdst_pair:
                        description:
                            - 
                        type: dict
                        suboptions:
                            addr_a:
                                description:
                                    - 
                                    - List of items described below.
                                    - 
                                required: true
                                type: list
                            addr_b:
                                description:
                                    - 
                                    - List of items described below.
                                    - 
                                required: true
                                type: list
                            field_name:
                                description:
                                    - 
                                type: string
                    ipv6_dst:
                        description:
                            - 
                        type: dict
                        suboptions:
                            addr:
                                description:
                                    - 
                                    - List of items described below.
                                    - 
                                required: true
                                type: list
                    ipv6_flow:
                        description:
                            - 
                        type: dict
                        suboptions:
                            address_sets:
                                description:
                                    - 
                                    - List of items described below.
                                    - 
                                required: true
                                type: list
                                suboptions:
                                    addr_a:
                                        description:
                                            - 
                                            - List of items described below.
                                            - 
                                        required: true
                                        type: list
                                    addr_b:
                                        description:
                                            - 
                                            - List of items described below.
                                            - 
                                        required: true
                                        type: list
                            flow_type:
                                description:
                                    - 
                                required: true
                                type: string
                                choices: ['UNI', 'BIDI']
                    ipv6_session_dst:
                        description:
                            - 
                        type: dict
                        suboptions:
                            sessions:
                                description:
                                    - 
                                    - List of items described below.
                                    - An IPv6 address and a port. The port may be left blank, as in 3210dcba. If a CIDR of 0 or a Netmask of 00000000 is used, then the criterion will not filter on the address at all, meaning there would be no distinction between an IPv4 and IPv6 address. Note that protocol calls for the IPv6 address portion to appear within square brackets [12345678]24.  However, since JSON already uses square brackets to denote an array, the address should not appear within square brackets - the port will be assumed to follow the last colon.  Examples (CIDR) 1122334455667788/2415-17, 19, (Netmask) 1011121314151617/255.255.255.10530, (No mask type) 90.80.70.605040302014, 17, 20-22  
                                required: true
                                type: list
                    ipv6_session_flow:
                        description:
                            - 
                        type: dict
                        suboptions:
                            flow_type:
                                description:
                                    - 
                                required: true
                                type: string
                                choices: ['UNI', 'BIDI']
                            session_sets:
                                description:
                                    - 
                                    - List of items described below.
                                    - A flow set allows only one IPv6 specification where both the address is all dont care (CIDR is 0 or the Netmask is 00000000) and the port is dont care (left blank), whether in the a_session or b_session.
                                required: true
                                type: list
                                suboptions:
                                    a_sessions:
                                        description:
                                            - 
                                            - List of items described below.
                                            - An IPv6 address and a port. The port may be left blank, as in 3210dcba. If a CIDR of 0 or a Netmask of 00000000 is used, then the criterion will not filter on the address at all, meaning there would be no distinction between an IPv4 and IPv6 address. Note that protocol calls for the IPv6 address portion to appear within square brackets [12345678]24.  However, since JSON already uses square brackets to denote an array, the address should not appear within square brackets - the port will be assumed to follow the last colon.  Examples (CIDR) 1122334455667788/2415-17, 19, (Netmask) 1011121314151617/255.255.255.10530, (No mask type) 90.80.70.605040302014, 17, 20-22  
                                        required: true
                                        type: list
                                    b_sessions:
                                        description:
                                            - 
                                            - List of items described below.
                                            - An IPv6 address and a port. The port may be left blank, as in 3210dcba. If a CIDR of 0 or a Netmask of 00000000 is used, then the criterion will not filter on the address at all, meaning there would be no distinction between an IPv4 and IPv6 address. Note that protocol calls for the IPv6 address portion to appear within square brackets [12345678]24.  However, since JSON already uses square brackets to denote an array, the address should not appear within square brackets - the port will be assumed to follow the last colon.  Examples (CIDR) 1122334455667788/2415-17, 19, (Netmask) 1011121314151617/255.255.255.10530, (No mask type) 90.80.70.605040302014, 17, 20-22  
                                        required: true
                                        type: list
                    ipv6_session_src:
                        description:
                            - 
                        type: dict
                        suboptions:
                            sessions:
                                description:
                                    - 
                                    - List of items described below.
                                    - An IPv6 address and a port. The port may be left blank, as in 3210dcba. If a CIDR of 0 or a Netmask of 00000000 is used, then the criterion will not filter on the address at all, meaning there would be no distinction between an IPv4 and IPv6 address. Note that protocol calls for the IPv6 address portion to appear within square brackets [12345678]24.  However, since JSON already uses square brackets to denote an array, the address should not appear within square brackets - the port will be assumed to follow the last colon.  Examples (CIDR) 1122334455667788/2415-17, 19, (Netmask) 1011121314151617/255.255.255.10530, (No mask type) 90.80.70.605040302014, 17, 20-22  
                                required: true
                                type: list
                    ipv6_session_src_or_dst:
                        description:
                            - 
                        type: dict
                        suboptions:
                            sessions:
                                description:
                                    - 
                                    - List of items described below.
                                    - An IPv6 address and a port. The port may be left blank, as in 3210dcba. If a CIDR of 0 or a Netmask of 00000000 is used, then the criterion will not filter on the address at all, meaning there would be no distinction between an IPv4 and IPv6 address. Note that protocol calls for the IPv6 address portion to appear within square brackets [12345678]24.  However, since JSON already uses square brackets to denote an array, the address should not appear within square brackets - the port will be assumed to follow the last colon.  Examples (CIDR) 1122334455667788/2415-17, 19, (Netmask) 1011121314151617/255.255.255.10530, (No mask type) 90.80.70.605040302014, 17, 20-22  
                                required: true
                                type: list
                    ipv6_src:
                        description:
                            - 
                        type: dict
                        suboptions:
                            addr:
                                description:
                                    - 
                                    - List of items described below.
                                    - 
                                required: true
                                type: list
                    ipv6_src_or_dst:
                        description:
                            - 
                        type: dict
                        suboptions:
                            addr:
                                description:
                                    - 
                                    - List of items described below.
                                    - 
                                required: true
                                type: list
                    ipv6_srcdst_pair:
                        description:
                            - 
                        type: dict
                        suboptions:
                            addr_a:
                                description:
                                    - 
                                    - List of items described below.
                                    - 
                                required: true
                                type: list
                            addr_b:
                                description:
                                    - 
                                    - List of items described below.
                                    - 
                                required: true
                                type: list
                            field_name:
                                description:
                                    - 
                                type: string
                    layer4_dst_port:
                        description:
                            - 
                        type: dict
                        suboptions:
                            port:
                                description:
                                    - 
                                required: true
                                type: integer
                    layer4_port_flow:
                        description:
                            - 
                        type: dict
                        suboptions:
                            flow_type:
                                description:
                                    - 
                                required: true
                                type: string
                                choices: ['UNI', 'BIDI']
                            port_sets:
                                description:
                                    - 
                                    - List of items described below.
                                    - 
                                required: true
                                type: list
                                suboptions:
                                    port_a:
                                        description:
                                            - 
                                        required: true
                                        type: integer
                                    port_b:
                                        description:
                                            - 
                                        required: true
                                        type: integer
                    layer4_src_or_dst_port:
                        description:
                            - 
                        type: dict
                        suboptions:
                            port:
                                description:
                                    - 
                                required: true
                                type: integer
                    layer4_src_port:
                        description:
                            - 
                        type: dict
                        suboptions:
                            port:
                                description:
                                    - 
                                required: true
                                type: integer
                    layer4_srcdst_port_pair:
                        description:
                            - 
                        type: dict
                        suboptions:
                            field_name:
                                description:
                                    - 
                                type: string
                            port_a:
                                description:
                                    - 
                                required: true
                                type: integer
                            port_b:
                                description:
                                    - 
                                required: true
                                type: integer
                    logical_operation:
                        description:
                            - 
                        type: string
                        choices: ['OR', 'AND']
                    mac_dst:
                        description:
                            - 
                        type: dict
                        suboptions:
                            addr:
                                description:
                                    - 
                                    - List of items described below.
                                    - 
                                type: list
                            admin_type:
                                description:
                                    - 
                                type: string
                                choices: ['UNIVERSAL', 'LOCAL', 'ANY']
                            dest_addr_type:
                                description:
                                    - 
                                required: true
                                type: string
                                choices: ['GROUP', 'ANY', 'INDIVIDUAL']
                    mac_flow:
                        description:
                            - 
                        type: dict
                        suboptions:
                            address_sets:
                                description:
                                    - 
                                    - List of items described below.
                                    - 
                                required: true
                                type: list
                                suboptions:
                                    addr_a:
                                        description:
                                            - 
                                            - List of items described below.
                                            - 
                                        required: true
                                        type: list
                                    addr_b:
                                        description:
                                            - 
                                            - List of items described below.
                                            - 
                                        required: true
                                        type: list
                            flow_type:
                                description:
                                    - 
                                required: true
                                type: string
                                choices: ['UNI', 'BIDI']
                    mac_src:
                        description:
                            - 
                        type: dict
                        suboptions:
                            addr:
                                description:
                                    - 
                                    - List of items described below.
                                    - 
                                type: list
                            admin_type:
                                description:
                                    - 
                                type: string
                                choices: ['UNIVERSAL', 'LOCAL', 'ANY']
                    mac_src_or_dst:
                        description:
                            - 
                        type: dict
                        suboptions:
                            addr:
                                description:
                                    - 
                                    - List of items described below.
                                    - 
                                required: true
                                type: list
                    mac_srcdst_pair:
                        description:
                            - 
                        type: dict
                        suboptions:
                            addr_a:
                                description:
                                    - 
                                    - List of items described below.
                                    - 
                                required: true
                                type: list
                            addr_b:
                                description:
                                    - 
                                    - List of items described below.
                                    - 
                                required: true
                                type: list
                    mpls_label:
                        description:
                            - 
                        type: dict
                        suboptions:
                            field_name:
                                description:
                                    - 
                                type: string
                            field_set:
                                description:
                                    - 
                                type: string
                                choices: ['FS2', 'FS1', 'BOTH']
                            is_capture_mpls_label:
                                description:
                                    - The is_capture_mpls_label property should be set to true only when creating an MPLS label trigger criteria for a Capture Resource.
                                type: bool
                            label_level:
                                description:
                                    - The label_level property is required only when creating an MPLS label trigger criteria for a Capture Resource.
                                type: integer
                            value:
                                description:
                                    - 
                                required: true
                                type: integer
                    raw_custom:
                        description:
                            - 
                        type: dict
                    tcp_control:
                        description:
                            - 
                        type: dict
                        suboptions:
                            value:
                                description:
                                    - 
                                required: true
                                type: string
                    vlan:
                        description:
                            - 
                        type: dict
                        suboptions:
                            priority:
                                description:
                                    - 
                                type: string
                            vlan_id:
                                description:
                                    - 
                                type: integer
                    vntag:
                        description:
                            - 
                        type: dict
                        suboptions:
                            value:
                                description:
                                    - 
                                required: true
                                type: integer
                    vxlan_vni:
                        description:
                            - 
                        type: dict
                        suboptions:
                            field_name:
                                description:
                                    - 
                                type: string
                            field_set:
                                description:
                                    - 
                                type: string
                                choices: ['FS2', 'FS1', 'BOTH']
                            value:
                                description:
                                    - 
                                required: true
                                type: integer
            filter_object_type:
                description:
                    - 
                required: true
                type: string
                choices: ['FILTER', 'NETWORK_PORT', 'TOOL_PORT', 'CAPTURE_RESOURCE', 'INLINE_SERVICE_CHAIN', 'FILTER_TEMPLATE']
            memory_allocation:
                description:
                    - 
                type: dict
                suboptions:
                    custom:
                        description:
                            - 
                        type: string
                        choices: ['CUSTOM_32_BYTE', 'CUSTOM_16_BYTE', 'CUSTOM_NONE']
                    dynamic:
                        description:
                            - 
                        type: string
                        choices: ['L2_075_L3L4_025', 'IPV4_100_IPV6_000', 'IPV4_075_IPV6_025', 'IPV4_050_IPV6_050', 'L2L3L4_11_L2L3L4_NOMAC_89', 'L2_000_IPV4_066_IPV6_033_VLAN_100_L4_000', 'IPV4_067_IPV6_033', 'L2L3L4_33_L3L4_67', 'L2L3L4_050_IPV6_050', 'IPV4_025_IPV6_075', 'L2_100_L3L4_000', 'L2L3L4_50_IPV6_50_VLAN_000_L4_100', 'IPV4_033_IPV6_067', 'L2L3L4_30_L2L3L4_NOMAC_70', 'L2L3L4_NOMAC_100', 'L2_050_L3L4_050', 'L2_000_IPV4_000_IPV6_100_VLAN_000_L4_100', 'L2_066_IPV4_000_IPV6_033', 'L2_066_IPV4_000_IPV6_033_VLAN_000_L4_100', 'L2_000_IPV4_000_IPV6_100_VLAN_050_L4_050', 'L2L3L4_50_IPV6_50_VLAN_100_L4_000', 'DISABLED', 'L2L3L4_58_L2L3L4_NOMAC_42', 'L2L3L4_04_L2L3L4_NOMAC_96', 'IPV4_000_IPV6_100', 'L2_025_L3L4_075', 'L2_000_L3L4_100', 'L2_000_IPV4_000_IPV6_100_VLAN_100_L4_000', 'L2_033_IPV4_033_IPV6_033', 'L2_000_IPV4_066_IPV6_033_VLAN_000_L4_100', 'L2L3L4_100', 'L2_066_IPV4_000_IPV6_033_VLAN_100_L4_000']
                    dynamic_sip:
                        description:
                            - 
                        type: string
                        choices: ['L2_075_L3L4_025', 'IPV4_100_IPV6_000', 'IPV4_075_IPV6_025', 'IPV4_050_IPV6_050', 'L2L3L4_11_L2L3L4_NOMAC_89', 'L2_000_IPV4_066_IPV6_033_VLAN_100_L4_000', 'IPV4_067_IPV6_033', 'L2L3L4_33_L3L4_67', 'L2L3L4_050_IPV6_050', 'IPV4_025_IPV6_075', 'L2_100_L3L4_000', 'L2L3L4_50_IPV6_50_VLAN_000_L4_100', 'IPV4_033_IPV6_067', 'L2L3L4_30_L2L3L4_NOMAC_70', 'L2L3L4_NOMAC_100', 'L2_050_L3L4_050', 'L2_000_IPV4_000_IPV6_100_VLAN_000_L4_100', 'L2_066_IPV4_000_IPV6_033', 'L2_066_IPV4_000_IPV6_033_VLAN_000_L4_100', 'L2_000_IPV4_000_IPV6_100_VLAN_050_L4_050', 'L2L3L4_50_IPV6_50_VLAN_100_L4_000', 'DISABLED', 'L2L3L4_58_L2L3L4_NOMAC_42', 'L2L3L4_04_L2L3L4_NOMAC_96', 'IPV4_000_IPV6_100', 'L2_025_L3L4_075', 'L2_000_L3L4_100', 'L2_000_IPV4_000_IPV6_100_VLAN_100_L4_000', 'L2_033_IPV4_033_IPV6_033', 'L2_000_IPV4_066_IPV6_033_VLAN_000_L4_100', 'L2L3L4_100', 'L2_066_IPV4_000_IPV6_033_VLAN_100_L4_000']
                    filter_build_settings:
                        description:
                            - 
                        type: dict
                        suboptions:
                            filter_build_mode:
                                description:
                                    - 
                                required: true
                                type: string
                                choices: ['INTERSECTION', 'PRIORITY']
                            priority_port_id_list:
                                description:
                                    - 
                                    - List of items described below.
                                    - The integer value of the ID property for an object
                                type: list
                    network:
                        description:
                            - 
                        type: string
                        choices: ['L2_075_L3L4_025', 'IPV4_100_IPV6_000', 'IPV4_075_IPV6_025', 'IPV4_050_IPV6_050', 'L2L3L4_11_L2L3L4_NOMAC_89', 'L2_000_IPV4_066_IPV6_033_VLAN_100_L4_000', 'IPV4_067_IPV6_033', 'L2L3L4_33_L3L4_67', 'L2L3L4_050_IPV6_050', 'IPV4_025_IPV6_075', 'L2_100_L3L4_000', 'L2L3L4_50_IPV6_50_VLAN_000_L4_100', 'IPV4_033_IPV6_067', 'L2L3L4_30_L2L3L4_NOMAC_70', 'L2L3L4_NOMAC_100', 'L2_050_L3L4_050', 'L2_000_IPV4_000_IPV6_100_VLAN_000_L4_100', 'L2_066_IPV4_000_IPV6_033', 'L2_066_IPV4_000_IPV6_033_VLAN_000_L4_100', 'L2_000_IPV4_000_IPV6_100_VLAN_050_L4_050', 'L2L3L4_50_IPV6_50_VLAN_100_L4_000', 'DISABLED', 'L2L3L4_58_L2L3L4_NOMAC_42', 'L2L3L4_04_L2L3L4_NOMAC_96', 'IPV4_000_IPV6_100', 'L2_025_L3L4_075', 'L2_000_L3L4_100', 'L2_000_IPV4_000_IPV6_100_VLAN_100_L4_000', 'L2_033_IPV4_033_IPV6_033', 'L2_000_IPV4_066_IPV6_033_VLAN_000_L4_100', 'L2L3L4_100', 'L2_066_IPV4_000_IPV6_033_VLAN_100_L4_000']
                    network_dynamic_sip_allocation_mix:
                        description:
                            - 
                        type: string
                        choices: ['NP_050_VRF_050', 'NP_050_DSIP_050', 'NP_025_DSIP_075', 'NP_000_DSIP_100']
                    tool:
                        description:
                            - 
                        type: string
                        choices: ['L2_075_L3L4_025', 'IPV4_100_IPV6_000', 'IPV4_075_IPV6_025', 'IPV4_050_IPV6_050', 'L2L3L4_11_L2L3L4_NOMAC_89', 'L2_000_IPV4_066_IPV6_033_VLAN_100_L4_000', 'IPV4_067_IPV6_033', 'L2L3L4_33_L3L4_67', 'L2L3L4_050_IPV6_050', 'IPV4_025_IPV6_075', 'L2_100_L3L4_000', 'L2L3L4_50_IPV6_50_VLAN_000_L4_100', 'IPV4_033_IPV6_067', 'L2L3L4_30_L2L3L4_NOMAC_70', 'L2L3L4_NOMAC_100', 'L2_050_L3L4_050', 'L2_000_IPV4_000_IPV6_100_VLAN_000_L4_100', 'L2_066_IPV4_000_IPV6_033', 'L2_066_IPV4_000_IPV6_033_VLAN_000_L4_100', 'L2_000_IPV4_000_IPV6_100_VLAN_050_L4_050', 'L2L3L4_50_IPV6_50_VLAN_100_L4_000', 'DISABLED', 'L2L3L4_58_L2L3L4_NOMAC_42', 'L2L3L4_04_L2L3L4_NOMAC_96', 'IPV4_000_IPV6_100', 'L2_025_L3L4_075', 'L2_000_L3L4_100', 'L2_000_IPV4_000_IPV6_100_VLAN_100_L4_000', 'L2_033_IPV4_033_IPV6_033', 'L2_000_IPV4_066_IPV6_033_VLAN_000_L4_100', 'L2L3L4_100', 'L2_066_IPV4_000_IPV6_033_VLAN_100_L4_000']
            source_port_group_list:
                description:
                    - 
                    - List of items described below.
                    - The integer value of the ID property for an object
                type: list
            source_port_list:
                description:
                    - 
                    - List of items described below.
                    - The integer value of the ID property for an object
                type: list
    get_fnood_license_public_info_payload:
        description:
            - 
            - Available on all platforms.
        type: dict
        suboptions:
    get_ha_config_for_cli_payload:
        description:
            - 
            - Available on E100 Series, E40 Series, Vision Edge OS, Vision X Series.
        type: dict
        suboptions:
    get_login_info_payload:
        description:
            - 
            - Available on all platforms.
        type: dict
        suboptions:
    get_memory_meters_payload:
        description:
            - 
            - Available on all platforms.
        type: dict
        suboptions:
    get_neighbors_payload:
        description:
            - 
            - Available on all platforms.
        type: dict
        suboptions:
            port_id_list:
                description:
                    - 
                    - List of items described below.
                    - The integer value of the ID property for an object
                type: list
    get_object_type_payload:
        description:
            - 
            - Available on all platforms.
        type: dict
        suboptions:
            id:
                description:
                    - 
                required: true
                type: integer
    get_props_payload:
        description:
            - 
            - Available on all platforms.
        type: dict
        suboptions:
            filter:
                description:
                    - 
                type: string
                choices: ['READABLE_OR_WRITABLE', 'WRITABLE', 'READABLE', 'WRITABLE_ONLY', 'READABLE_ONLY']
            object_type:
                description:
                    - 
                required: true
                type: string
                choices: ['SYSTEM', 'ATIP_RESOURCE', 'FILTER', 'NETFLOW_GENERATOR_RESOURCE', 'PORT', 'MONITOR', 'CAPTURE_RESOURCE', 'PORT_GROUP', 'USER', 'GROUP', 'CUSTOM_ICON', 'AE_RESOURCE', 'FILTER_TEMPLATE_COLLECTION', 'FILTER_TEMPLATE']
    get_transceiver_info_payload:
        description:
            - 
            - Available on all platforms.
        type: dict
        suboptions:
    get_values_payload:
        description:
            - 
            - Available on all platforms.
        type: dict
        suboptions:
            object_type:
                description:
                    - 
                required: true
                type: string
                choices: ['SYSTEM', 'ATIP_RESOURCE', 'FILTER', 'NETFLOW_GENERATOR_RESOURCE', 'PORT', 'MONITOR', 'CAPTURE_RESOURCE', 'PORT_GROUP', 'USER', 'GROUP', 'CUSTOM_ICON', 'AE_RESOURCE', 'FILTER_TEMPLATE_COLLECTION', 'FILTER_TEMPLATE']
            prop_name:
                description:
                    - 
                required: true
                type: string
    import_payload:
        description:
            - 
            - Available on all platforms.
        type: dict
        suboptions:
    install_license_payload:
        description:
            - 
            - Available on all platforms.
        type: dict
        suboptions:
    install_netservice_payload:
        description:
            - 
            - Available on Vision X Series.
        type: dict
        suboptions:
    install_software_payload:
        description:
            - 
            - Available on all platforms.
        type: dict
        suboptions:
    mtu_query_payload:
        description:
            - Although every parameter is optional, you should specify either a default name, or a filter/port/port_group id.
            - Available on all platforms.
        type: dict
        suboptions:
            default_name:
                description:
                    - 
                type: string
            filter_id:
                description:
                    - 
                type: integer
            port_id:
                description:
                    - 
                type: integer
            portgroup_id:
                description:
                    - 
                type: integer
    power_down_payload:
        description:
            - 
            - Available on all platforms.
        type: dict
        suboptions:
    pull_config_from_ha_peer_payload:
        description:
            - 
            - Available on 7300 Series, E100 Series, E40 Series, Vision Edge OS, Vision X Series, Vision E10S.
        type: dict
        suboptions:
    push_config_to_ha_peer_payload:
        description:
            - 
            - Available on 7300 Series, E100 Series, E40 Series, Vision Edge OS, Vision X Series, Vision E10S.
        type: dict
        suboptions:
    remove_license_payload:
        description:
            - 
            - Available on all platforms.
        type: dict
        suboptions:
    remove_netservice_payload:
        description:
            - 
            - Available on Vision X Series.
        type: dict
        suboptions:
            service_id:
                description:
                    - 
                required: true
                type: string
    remove_port_module_config_payload:
        description:
            - 
            - Available on Vision X Series.
        type: dict
        suboptions:
            port_module_location:
                description:
                    - 
                required: true
                type: string
    restart_payload:
        description:
            - 
            - Available on all platforms.
        type: dict
        suboptions:
    restore_firewall_payload:
        description:
            - 
            - Available on all platforms.
        type: dict
        suboptions:
    revert_software_payload:
        description:
            - 
            - Available on all platforms.
        type: dict
        suboptions:
    save_logs_payload:
        description:
            - 
            - Available on all platforms.
        type: dict
        suboptions:
            entity:
                description:
                    - 
                type: null
            file_name:
                description:
                    - 
                required: true
                type: string
    set_ha_sync_port_payload:
        description:
            - 
            - Available on 7300 Series, E100 Series, E40 Series, Vision Edge OS, Vision X Series, Vision E10S.
        type: dict
        suboptions:
            port:
                description:
                    - 
                required: true
                type: null
    set_ip_config_payload:
        description:
            - 
            - Available on all platforms.
        type: dict
        suboptions:
            configured_static_ipv4_address:
                description:
                    - 
                type: string
            configured_static_ipv4_gateway:
                description:
                    - 
                type: string
            configured_static_ipv4_netmask:
                description:
                    - 
                type: string
            dhcp_enabled:
                description:
                    - 
                type: bool
            ipv4_address:
                description:
                    - 
                type: string
            ipv4_enabled:
                description:
                    - 
                type: bool
            ipv4_gateway:
                description:
                    - 
                type: string
            ipv4_netmask:
                description:
                    - 
                type: string
            ipv6_address:
                description:
                    - 
                type: string
            ipv6_allow_autoconfig:
                description:
                    - 
                type: bool
            ipv6_enabled:
                description:
                    - 
                type: bool
            ipv6_gateway:
                description:
                    - 
                type: string
            ipv6_prefix_length:
                description:
                    - 
                type: integer
    swap_port_licenses_payload:
        description:
            - 
            - Available on all platforms.
        type: dict
        suboptions:
    validate_auth_payload:
        description:
            - 
            - Available on Vision X Series.
        type: dict
        suboptions:

author:
    - Keysight
'''

EXAMPLES = '''
  - name: Create port group
    nvos_port_groups:
      mode: NETWORK
      name: PG_1
      port_list: P04
      type: INTERCONNECT
  - name: Create first dynamic filter
    nvos_filters:
      dynamic_filter_type: TWO_STAGE
      mode: PASS_ALL
      name: DF1
      source_port_group_list: PG_1
      source_port_list: P03
  - name: Create second dynamic filter
    nvos_filters:
      dynamic_filter_type: TWO_STAGE
      mode: PASS_ALL
      name: DF2
      source_port_group_list: PGtest
      source_port_list: P03
  - name: Configure memory allocation
    nvos_system:
      memory_allocation:
        custom: CUSTOM_NONE
        dynamic: L2L3L4_100
        dynamic_sip: IPV4_100_IPV6_000
        filter_build_settings:
          filter_build_mode: PRIORITY
          priority_port_id_list: []
        network: L2L3L4_50_IPV6_50_VLAN_100_L4_000
        network_dynamic_sip_allocation_mix: NP_050_DSIP_050
        tool: L2_033_IPV4_033_IPV6_033
  - name: Set the following filter priority for P03 DF2, DF1
    nvos_actions: 
      action_name: change_filter_priority 
      change_filter_priority_payload: 
        prioritized_dest_filter_id_list: [DF2,DF1]
        source_port_id: P03
  - name: Set the following filter priority for PG_1: DF2, DF1
    nvos_actions: 
      action_name: change_filter_priority
      change_filter_priority_payload: 
        prioritized_dest_filter_id_list: [DF2,DF1]
        source_port_group_id: PG_1
  - name: Clear current configuration
    nvos_actions: 
      action_name: clear_config
  - name: Clear dynamic filters and ports
    nvos_actions: 
      action_name: clear_filters_and_ports      
	    - name: Clear the system
    nvos_actions:
      action_name: clear_system
  - name: Enable FIPS encryption
    nvos_actions: 
      action_name: enable_fips_server_encryption	  
  - name: Get login information
    nvos_actions: 
      action_name: get_login_info	  
  - name: Change port P04 mode to TOOL
    nvos_ports: 
      mode: TOOL
      name: P04
  - name: Change port P03 mode to TOOL
    nvos_ports:
      mode: TOOL
      name: P03
  - name: Change port P02 mode to TOOL
    nvos_ports: 
      mode: TOOL
      name: P02
  - name: Create port group PG_1
    nvos_port_groups:
      mode: TOOL
      name: PG_1
      port_list: [P04]
      type: INTERCONNECT
  - name: Create port group PG_2
    nvos_port_groups:
      mode: TOOL
      name: PG_2
      port_list: [P03]
      type: INTERCONNECT
  - name: Create port group PG_3
    nvos_port_groups:
      mode: TOOL
      name: PG_3
      port_list: [P02]
      type: INTERCONNECT
  - name: Create dynamic filter DF1
    nvos_filters:
      dest_port_group_list: [PG_1, PG_2, PG_3]
      mode: PASS_ALL
      name: DF1
  - name: Export current configuration into a .ata file
    nvos_actions:
      action_name: export
      export_payload: 
        boundary: INCLUDE
        export_type: FULL_BACKUP
        file_name: /home/testuser/Desktop/
  - name: Clear current configuration
    nvos_actions:
      action_name: clear_config
  - name: Import a configuration from a .ata file
    nvos_actions:
      action_name: import
      file_path: /home/testuser/Desktop/
      import_payload: 
        boundary: INCLUDE
        import_type: FULL_IMPORT_FROM_BACKUP	  
  - name: NTO restart
    nvos_actions: 
      action_name: restart		
  - name: Revert NTO to a previous installed version
    nvos_actions: 
      action_name: revert_software	  
  - name: Save log files from the NTO
    nvos_actions: 
      action_name: save_logs
      save_logs_payload: 
        file_name: /home/testuser/logs.zip	  
'''

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.network.nvos.nvos import HttpApi


def run_module():
    # custom structure of the arguments, as actions do not follow a generic
    # format
    module = AnsibleModule(argument_spec={}, check_invalid_arguments=False)
    httpApi = HttpApi(module)

    # fetch using Web API the python dictionary representing the argument_spec
    properties = eval(httpApi._connection.get_actions_py_dictionary())

    properties['action_name'] = dict(type='str')
    properties['file_path'] = dict(type='str')

    action_name = httpApi._module.params['action_name']

    # flag used to replace integer identifiers with their corresponding
    # string names
    add_substitution_flag = None
    if action_name in (
            'change_speed_configuration', 'change_filter_priority',
            'get_available_filter_criteria', 'get_filter_priorities',
            'get_neighbors', 'set_ha_sync_port'):
        add_substitution_flag = True
        properties[action_name + "_payload"] = {}

    httpApi._module = AnsibleModule(argument_spec=properties)

    result = dict(
        changed=False,
    )

    try:
        clear_payload(httpApi._module.params)

        # some actions only retrieve information, without changing the state
        # on the equipment
        actions_returning_ok = ['export', 'export_keygen_license_to_json',
                                'export_offline_license_request_file',
                                'fips_server_encryption_status',
                                'get_available_filter_criteria',
                                'get_fnood_license_public_info',
                                'get_ha_config_for_cli', 'get_login_info',
                                'get_memory_meters', 'get_transceiver_info',
                                'get_neighbors', 'get_object_type',
                                'get_props', 'get_values', 'save_logs']

        output = httpApi.handle_actions(add_substitution_flag)

        result['messages'] = []

        if type(output) is str:
            output = eval(output)

        if output['code'] not in [200, 202, 401]:
            result['failed'] = True
        elif action_name in actions_returning_ok:
            result['changed'] = False
        elif output['msg'] != 'NOT CHANGED':
            result['changed'] = True

        result['messages'].append(output['msg'])

        module.exit_json(**result)

    except Exception as e:
        module.fail_json(msg=e, **result)


def clear_payload(input_dict):
    """
    Description: Removes from the input dictionary the keys with None values,
    as they do not produce changes and either override existing values or
    trigger Web API errors.

    :param input_dict: dictionary to be processed
    """
    copy = {k: v for k, v in input_dict.items()}
    for key, value in copy.items():
        if value is None:
            input_dict.pop(key)
        elif isinstance(value, dict):
            clear_payload(value)


def main():
    run_module()


if __name__ == '__main__':
    main()
