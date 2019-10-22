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


NVOS module used to issue Web API calls implying the 'filters' resource from
Ansbile.
"""

ANSIBLE_METADATA = {
    'metadata_version': '1.1',
    'supported_by': 'community',
    'status': ['preview']
}


DOCUMENTATION = '''
---
module: nvos_filters

short_description: This module handles interactions with NVOS filters.

version_added: "2.8"

description:
    - This module handles interactions with NVOS filters settings.
    - NVOS version 5.2.0
    - Sub-options marked as required are mandatory only when the top parameter is used.

options:
    application_forwarding_map:
        description:
            - The application forwarding map for an ATIP filter.
            - Available on 7300 Series, TradeVision Series, Vision X Series.
        type: dict
        suboptions:
            application_name:
                description:
                    - 
                required: true
                type: string
            dest_port_group_list:
                description:
                    - 
                    - List of items described below.
                    - The integer value of the ID property for an object
                type: list
            dest_port_list:
                description:
                    - 
                    - List of items described below.
                    - The integer value of the ID property for an object
                type: list
            vlan_id:
                description:
                    - 
                required: true
                type: string
            weight:
                description:
                    - 
                type: string
    connect_in_access_settings:
        description:
            - The settings that control who can perform connect-in operations on the filter.
            - Available on all platforms.
        type: dict
        suboptions:
            groups:
                description:
                    - 
                    - List of items described below.
                    - The NAME property of a group
                required: true
                type: list
            policy:
                description:
                    - 
                required: true
                type: string
                choices: ['ALLOW_ALL', 'REQUIRE_MEMBER', 'INHERITED', 'REQUIRE_ADMIN']
    connect_out_access_settings:
        description:
            - The settings that control who can perform connect-out operations on the filter.
            - Available on all platforms.
        type: dict
        suboptions:
            groups:
                description:
                    - 
                    - List of items described below.
                    - The NAME property of a group
                required: true
                type: list
            policy:
                description:
                    - 
                required: true
                type: string
                choices: ['ALLOW_ALL', 'REQUIRE_MEMBER', 'INHERITED', 'REQUIRE_ADMIN']
    criteria:
        description:
            - The list of criteria indicating which traffic this filter will pass.
            - Available on all platforms.
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
    description:
        description:
            - The user-assigned filter description.
            - Available on all platforms.
        type: string
    dest_port_group_list:
        description:
            - The list of port groups to which this filter will send traffic.
            - List of items described below.
            - The integer value of the ID property for an object
            - Available on all platforms.
        type: list
    dest_port_list:
        description:
            - The list of ports to which this filter will send traffic.
            - List of items described below.
            - The integer value of the ID property for an object
            - Available on all platforms.
        type: list
    keywords:
        description:
            - The set of keywords used by the filter.
            - List of items described below.
            - A lowercase version of the value, like port for PORT or Port.
            - Available on all platforms.
        type: list
    match_count_unit:
        description:
            - The unit of measure for filter matches counts.
            - Available on all platforms.
        type: string
        choices: ['BYTES', 'PACKETS']
    mod_count:
        description:
            - 
            - Available on all platforms.
        type: integer
    mode:
        description:
            - The mode which controls filter throughput.
            - Available on all platforms.
        type: string
        choices: ['PASS_ALL', 'DISABLE', 'PBC_UNMATCHED', 'PASS_BY_CRITERIA', 'DENY_BY_CRITERIA', 'DBC_MATCHED', 'EXCLUDE_BY_CRITERIA']
    modify_access_settings:
        description:
            - The settings that control who can perform modify operations on the filter.
            - Available on all platforms.
        type: dict
        suboptions:
            groups:
                description:
                    - 
                    - List of items described below.
                    - The NAME property of a group
                required: true
                type: list
            policy:
                description:
                    - 
                required: true
                type: string
                choices: ['ALLOW_ALL', 'REQUIRE_MEMBER', 'INHERITED', 'REQUIRE_ADMIN']
    name:
        description:
            - The user-defined name of the filter.
            - Available on all platforms.
        type: string
    resource_access_settings:
        description:
            - The settings that control who can assign resources on the filter.
            - Available on 7300 Series, TradeVision Series, Vision X Series, Vision E10S.
        type: dict
        suboptions:
            groups:
                description:
                    - 
                    - List of items described below.
                    - The NAME property of a group
                required: true
                type: list
            policy:
                description:
                    - 
                required: true
                type: string
                choices: ['ALLOW_ALL', 'REQUIRE_MEMBER', 'INHERITED', 'REQUIRE_ADMIN']
    snmp_tag:
        description:
            - The tag used by the SNMP component.
            - Available on all platforms.
        type: string
    source_port_group_list:
        description:
            - The list of port groups that send traffic to this filter.
            - List of items described below.
            - The integer value of the ID property for an object
            - Available on all platforms.
        type: list
    source_port_list:
        description:
            - The list of ports that send traffic to this filter.
            - List of items described below.
            - The integer value of the ID property for an object
            - Available on all platforms.
        type: list
    view_access_settings:
        description:
            - The settings that control who can view a dynamic filter.
            - Available on all platforms.
        type: dict
        suboptions:
            groups:
                description:
                    - 
                    - List of items described below.
                    - The NAME property of a group
                required: true
                type: list
            policy:
                description:
                    - 
                required: true
                type: string
                choices: ['ALLOW_ALL', 'REQUIRE_MEMBER', 'INHERITED', 'REQUIRE_ADMIN']
    vlan_replace_setting:
        description:
            - The setting of a filter that can replace packet VLAN when matching a filter rule.
            - Available on all platforms.
        type: dict
        suboptions:
            enabled:
                description:
                    - 
                required: true
                type: bool
            vlan_id:
                description:
                    - 
                required: true
                type: integer

author:
    - Keysight
'''

EXAMPLES = '''
  - name: Create dynamic filter DF1
    nvos_filters:
      criteria:
        logical_operation: AND
        mac_flow:
          address_sets:
          - addr_a:
            - 00-00-00-55-55-55
            addr_b:
            - 33-33-33-33-33-33
          flow_type: UNI
      mode: PASS_BY_CRITERIA
      name: DF1
      source_port_list:
      - P04
      dest_port_group_list:
      - P10
      - P11
      - P12
  - name: Create dynamic filter DF2
    nvos_filters:
      criteria:
        logical_operation: AND
        mac_flow:
          address_sets:
          - addr_a:
            - 44-44-44-44-44-44
            addr_b:
            - 66-66-66-66-66-66
          flow_type: BIDI
      mode: PASS_BY_CRITERIA
      name: DF2
      source_port_list:
      - P04
      dest_port_group_list:
      - P10
      - P11
      - P12
  - name: Create dynamic filter DF3
    nvos_filters:
      criteria:
        ipv4_session_flow:
          flow_type: UNI
          session_sets:
          - a_sessions:
            - 1.1.1.1/24:1
            b_sessions:
            - 2.2.2.2/24:1
        logical_operation: AND
      mode: PASS_BY_CRITERIA
      name: DF3
      source_port_list:
      - P04
      dest_port_group_list: 
      - P01
  - name: Create dynamic filter DF4
    nvos_filters:
      criteria:
        ipv4_session_flow:
          flow_type: BIDI
          session_sets:
          - a_sessions:
            - 3.3.3.3/24:1
            b_sessions:
            - 4.4.4.4/24:1
        logical_operation: AND
      mode: PASS_BY_CRITERIA
      name: DF4
      source_port_list:
      - P04
      dest_port_group_list: 
      - P01
  - name: Configure memory allocation
    nvos_system:
      memory_allocation:
        custom: CUSTOM_NONE
        dynamic: L2L3L4_11_L2L3L4_NOMAC_89
        dynamic_sip: IPV4_067_IPV6_033
        filter_build_settings:
          filter_build_mode: INTERSECTION
          priority_port_id_list: []
        network: L2L3L4_100
        network_dynamic_sip_allocation_mix: NP_025_DSIP_075
        tool: L2L3L4_100
  - name: Create dynamic filter DF5
    nvos_filters:
      criteria:
        ipv6_session_flow:
          flow_type: UNI
          session_sets:
          - a_sessions:
            - 1:1:1:1:1:1:1:1/64:1
            b_sessions:
            - 2:2:2:2:2:2:2:2/64:1
        logical_operation: AND
      mode: PASS_BY_CRITERIA
      name: DF5
      source_port_list:
      - P04
      dest_port_group_list: 
      - P01
  - name: Change memory allocation
    nvos_system:
      memory_allocation:
        custom: CUSTOM_16_BYTE
        dynamic: L2L3L4_100
        dynamic_sip: IPV4_100_IPV6_000
        filter_build_settings:
          filter_build_mode: INTERSECTION
          priority_port_id_list: []
        network: L2L3L4_100
        network_dynamic_sip_allocation_mix: NP_025_DSIP_075
        tool: L2L3L4_100
  - name: Create custom field
    nvos_system:
      custom_field_set_config:
        combined: false
        field_set_1:
          enabled: true
          fields:
          - field_size: 2
            name: Custom
            offset: 2
            offset_base: START_OF_L4_OR_INNER_L3
            packet_type: RAW
            size: 2
  - name: Create dynamic filter DF1
    nvos_filters:
      criteria:
        logical_operation: AND
        raw_custom:
          field_name: Custom
          value: xxxxxx1111110000
      mode: PASS_BY_CRITERIA
      name: DF1	  
  - name: Create dynamic filter DF1
    nvos_filters:
      mode: PASS_ALL
      modify_access_settings:
        groups: []
        policy: REQUIRE_MEMBER
      name: DF1
  - name: Create dynamic filter DF2
    nvos_filters:
      mode: PASS_ALL
      modify_access_settings:
        groups: []
        policy: INHERITED
      name: DF2
  - name: Create dynamic filter DF3
    nvos_filters:
      mode: PASS_ALL
      modify_access_settings:
        groups: []
        policy: ALLOW_ALL
      name: DF3
  - name: Create dynamic filter DF4
    nvos_filters:
      mode: PASS_ALL
      modify_access_settings:
        groups: []
        policy: REQUIRE_ADMIN
      name: DF4	  
  - name: Create dynamic filter DF1
    nvos_filters:
      mode: PASS_ALL
      name: DF1
      source_port_list:
      - P03
      - P02
      - P04
  - name: Update filter DF1
    nvos_filters:
      mode: PASS_ALL
      name: DF1
      source_port_list:
      - P03
      - P02	  
'''

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.network.nvos.nvos import HttpApi


def run_module():
    module = AnsibleModule(argument_spec={}, check_invalid_arguments=False)
    httpApi = HttpApi(module)

    # fetch using Web API the python dictionary representing the argument_spec
    properties = eval(httpApi._connection.get_py_dictionary('filters'))
    # synthetic key used to refer to a dynamic filter whose name we want to
    # change
    properties['filter'] = dict(type='str')
    # synthetic key used to delete an existing dynamic filter
    properties['delete'] = dict(type='bool')

    httpApi._module = AnsibleModule(argument_spec=properties)

    result = dict(
        changed=False,
    )

    try:
        clear_payload(httpApi._module.params)

        if 'filter' in httpApi._module.params:
            httpApi.get_target('filter', '/filters')
        elif 'name' in httpApi._module.params:
            httpApi.get_target('name', '/filters')
        else:
            httpApi._module.resource_id = None

        output = httpApi.handle_filters()

        result['messages'] = []

        for each in output:

            if type(each) is str:
                each = eval(each)

            if each['code'] not in [200, 202, 401]:
                result['failed'] = True
            elif each['msg'] != 'NOT CHANGED':
                result['changed'] = True

            result['messages'].append(each['msg'])

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
