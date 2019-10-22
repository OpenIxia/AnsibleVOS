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


NVOS module used to issue Web API calls implying the 'port_groups' resource from
Ansbile.
"""

ANSIBLE_METADATA = {
    'metadata_version': '1.1',
    'supported_by': 'community',
    'status': ['preview']
}


DOCUMENTATION = '''
---
module: nvos_port_groups

short_description: This module handles interactions with NVOS port_groups.

version_added: "2.8"

description:
    - This module handles interactions with NVOS port_groups settings.
    - NVOS version 5.2.0
    - Sub-options marked as required are mandatory only when the top parameter is used.

options:
    afm_pipeline_direction:
        description:
            - The AFM pipeline direction is a read-only property in most cases, reflecting the mode of any enabled advanced features.  The direction is automatically updated any time the mode of an enabled advanced features is changed or when the port mode requires a particular direction. The only case where this property can be updated is when adding a port configured to the SIMPLEX port mode into a port group.  If no advanced features are enabled on the port, the system will default to allowing AFM features on the network side and not on the tool side.  If the network-side port needs to be put in a port group that doesnt allow advanced features, or the tool-side port needs to be put in an advanced port group, the AFM_PIPELINE_DIRECTION will need to be set to EGRESS.
            - Available on all platforms.
        type: string
        choices: ['EGRESS', 'INGRESS']
    custom_icon_id:
        description:
            - 
            - Available on all platforms.
        type: integer
    description:
        description:
            - Sets the optional, user-assigned port description.
            - Available on all platforms.
        type: string
    failover_mode:
        description:
            - 
            - Available on all platforms.
        type: string
        choices: ['RESILIENT', 'REBALANCE', 'NONE']
    filter_criteria:
        description:
            - 
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
    filter_mode:
        description:
            - 
            - Available on all platforms.
        type: string
        choices: ['PASS_ALL', 'DISABLE', 'PBC_UNMATCHED', 'PASS_BY_CRITERIA', 'DENY_BY_CRITERIA', 'DBC_MATCHED', 'EXCLUDE_BY_CRITERIA']
    filtering_direction:
        description:
            - 
            - Available on all platforms.
        type: string
        choices: ['EGRESS', 'INGRESS']
    filtering_options:
        description:
            - 
            - Available on all platforms.
        type: dict
        suboptions:
            optimize_connected_df_rules:
                description:
                    - The optimize_connected_df_rules property defaults to true.
                required: true
                type: bool
    icon_type:
        description:
            - 
            - Available on all platforms.
        type: string
        choices: ['TAP', 'INLINE_BYPASS_PORT_SFP', 'INTERCONNECT', 'QSFP_PLUS', 'LOOPBACK_PORT_SFP', 'INLINE_BYPASS_PORT_CFP', 'BIDIRECTIONAL_PORT_QSFP28', 'INLINE_TOOL_PORT_GROUP', 'RJ45', 'OPENFLOW_PORT_CHANNEL', 'DESKTOP_CRT', 'XFP', 'NETSERVICE_INLINE_BYPASS_PORT_GROUP', 'LOAD_BALANCE', 'BIDIRECTIONAL_PORT_CFP', 'DUAL_QSFP_PLUS', 'ROUTER', 'INLINE_BYPASS_PORT_QSFP_PLUS', 'BIDIRECTIONAL_PORT_SFP', 'INLINE_TOOL_PORT_SFP', 'TOWER', 'WRENCH', 'LAPTOP', 'NETFLOW_INTERCONNECT', 'SIMPLEX_PORT_QSFP_PLUS', 'GTP_LOAD_BALANCE', 'MULTI_SERVICES_SWITCH', 'LAYER_3_SWITCH', 'PHONE', 'LOOPBACK_PORT_QSFP_PLUS', 'NETSERVICE_INLINE_TOOL_PORT_GROUP', 'HA_FABRIC_SFP', 'DESKTOP_LCD', 'SIMPLEX_PORT_SFP_PLUS', 'CFP', 'LOOPBACK_PORT_GROUP', 'LOOPBACK_PORT_QSFP28', 'INLINE_BYPASS_PORT_GROUP', 'SERVER', 'CUSTOM', 'QSFP28', 'AGGREGATION_PORT', 'SFP', 'INLINE_TOOL_PORT_CFP', 'MAGNIFYING_GLASS', 'WORKGROUP_SWITCH', 'CX4', 'BIDIRECTIONAL_PORT_QSFP_PLUS', 'SFP_PLUS', 'INLINE_TOOL_PORT_QSFP_PLUS', 'BIDI_INTERCONNECT', 'RACK', 'NETSERVICE_PASSIVE_DECRYPTED', 'HA_FABRIC_QSFP_PLUS']
    inline_bypass_connector_id:
        description:
            - 
            - Available on TradeVision Series, E100 Series, E40 Series, Vision X Series, Vision E10S.
        type: integer
    inline_tool_connector_id:
        description:
            - 
            - Available on TradeVision Series, E100 Series, E40 Series, Vision X Series, Vision E10S.
        type: integer
    interconnect_info:
        description:
            - 
            - Available on all platforms.
        type: dict
        suboptions:
            addr:
                description:
                    - 
                required: true
                type: string
            port_group:
                description:
                    - 
                required: true
                type: string
    keywords:
        description:
            - The list of keywords used by the filter.
            - List of items described below.
            - A lowercase version of the value, like port for PORT or Port.
            - Available on all platforms.
        type: list
    mod_count:
        description:
            - 
            - Available on all platforms.
        type: integer
    mode:
        description:
            - 
            - Available on all platforms.
        type: string
        choices: ['LOOPBACK', 'NETWORK', 'BYPASS_BIDIRECTIONAL', 'HA_FABRIC', 'BIDIRECTIONAL', 'TOOL', 'SIMPLEX', 'INLINE_TOOL_BIDIRECTIONAL']
    name:
        description:
            - Sets the optional, user-assigned port name.
            - Available on all platforms.
        type: string
    packet_length_trailer_settings:
        description:
            - 
            - Available on all platforms.
        type: dict
        suboptions:
            adjust_length:
                description:
                    - The adjust_length property defaults to false. It must be set to true if the length.
                type: bool
            enabled:
                description:
                    - The enabled property defaults to false.
                required: true
                type: bool
            port_mode:
                description:
                    - The port_mode may be set to either NETWORK or TOOL. It defaults to null and will be set based on a network or tool ports mode. For bidirectional ports, it must be set to either NETWORK or TOOL.      
                type: string
                choices: ['LOOPBACK', 'NETWORK', 'BYPASS_BIDIRECTIONAL', 'HA_FABRIC', 'BIDIRECTIONAL', 'TOOL', 'SIMPLEX', 'INLINE_TOOL_BIDIRECTIONAL']
    port_list:
        description:
            - The id list of ports aggregated to make up this PortGroup.
            - List of items described below.
            - The integer value of the ID property for an object
            - Available on all platforms.
        type: list
    pppoe_strip_settings:
        description:
            - 
            - Available on 7300 Series, Vision X Series.
        type: dict
        suboptions:
            enabled:
                description:
                    - The enabled property defaults to false.
                required: true
                type: bool
            port_mode:
                description:
                    - The port_mode property may be set to either NETWORK or TOOL. It defaults to null and will be set based on a network or tool ports mode. For bidirectional ports, it must be set to either NETWORK or TOOL.
                type: string
                choices: ['LOOPBACK', 'NETWORK', 'BYPASS_BIDIRECTIONAL', 'HA_FABRIC', 'BIDIRECTIONAL', 'TOOL', 'SIMPLEX', 'INLINE_TOOL_BIDIRECTIONAL']
    snmp_tag:
        description:
            - Sets the tag used by the SNMP component for a port.
            - Available on all platforms.
        type: string
    std_strip_by_vlan_settings:
        description:
            - 
            - Available on all platforms.
        type: dict
        suboptions:
            enabled:
                description:
                    - The enabled property defaults to false.
                required: true
                type: bool
            strip_mode:
                description:
                    - This is an egress-only feature, so the ports mode must support egress traffic. This setting will be applied to the egress side regardless of the value in the strip_mode property, so this property may safely be ignored.
                type: string
                choices: ['EGRESS', 'INGRESS', 'INGRESS_AGGREGATION_SWITCH_FABRIC', 'BOTH']
            vlan_id:
                description:
                    - The vlan_id property is optional (ignored) when disabling this setting but required when enabling.
                type: integer
    std_vlan_strip_settings:
        description:
            - 
            - Available on all platforms.
        type: dict
        suboptions:
            egress_count:
                description:
                    - Egress count is the maximum number of VLAN tags to strip in the egress direction.
                type: integer
            enabled:
                description:
                    - Will be true if the VLAN stripping feature is enabled, false otherwise.
                required: true
                type: bool
            ingress_count:
                description:
                    - Ingress count is the maximum number of VLAN tags to strip in the ingress direction.
                type: integer
            strip_mode:
                description:
                    - Stripping mode. This is either INGRESS, EGRESS, or BOTH.
                type: string
                choices: ['EGRESS', 'INGRESS', 'INGRESS_AGGREGATION_SWITCH_FABRIC', 'BOTH']
    timestamp_translation_settings:
        description:
            - 
            - Available on Vision X Series.
        type: dict
        suboptions:
            enabled:
                description:
                    - The enabled property defaults to false.
                required: true
                type: bool
            port_mode:
                description:
                    - The port_mode defaults to null but will be set based on the ports mode.
                type: string
                choices: ['LOOPBACK', 'NETWORK', 'BYPASS_BIDIRECTIONAL', 'HA_FABRIC', 'BIDIRECTIONAL', 'TOOL', 'SIMPLEX', 'INLINE_TOOL_BIDIRECTIONAL']
            ts_arista_48_64b_l2_insertion_enabled:
                description:
                    - Arista 48/64b L2 Insertion (7280R, 7500R).
                required: true
                type: bool
            ts_arista_src_mac_enabled:
                description:
                    - Arista MAC Substitution (7280R, 7500R).
                required: true
                type: bool

author:
    - Keysight
'''

EXAMPLES = '''
  - name: Create port group PG1_test_network
    nvos_port_groups:
      filtering_options:
        optimize_connected_df_rules: true
      mode: NETWORK
      name: PG1_test_network
      type: INTERCONNECT
  - name: Create port group PG2_test_tool
    nvos_port_groups:
      filtering_options:
        optimize_connected_df_rules: true
      mode: BIDIRECTIONAL
      name: PG2_test_tool
      type: INTERCONNECT
  - name: Create port group PG3_test_bidi
    nvos_port_groups:
      filtering_options:
        optimize_connected_df_rules: true
      mode: LOOPBACK
      name: PG3_test_bidi
      type: INTERCONNECT
  - name: Create port group PG4_test_loopback
    nvos_port_groups:
      filtering_options:
        optimize_connected_df_rules: true
      mode: TOOL
      name: PG4_test_loopback
      type: INTERCONNECT
  - name: Create port group PG5_test_load_balance
    nvos_port_groups:
      filtering_options:
        optimize_connected_df_rules: true
      mode: TOOL
      name: PG4_test_load_balance
      type: LOAD_BALANCE
  - name: Create port group PG1_test
    nvos_port_groups:
      description: This is a NETWORK port group
      keywords:
      - keyword1
      - keyword2
      - keyword3
      mode: NETWORK
      name: PG1_test
      type: INTERCONNECT
  - name: Change keywords
    nvos_port_groups:
      description: This is a NETWORK port group
      keywords:
      - keyword2
      - keyword5
      mode: NETWORK
      name: PG1_test
      type: INTERCONNECT	  
  - name: Create port group PG1_test
    nvos_port_groups:
      mode: NETWORK
      name: PG1_test
      port_list:
      - P04
      - P03
      - P02
      type: INTERCONNECT
  - name: Change the port list
    nvos_port_groups:
      mode: NETWORK
      name: PG1_test
      port_list:
      - P04
      type: INTERCONNECT	  
'''

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.network.nvos.nvos import HttpApi


def run_module():
    module = AnsibleModule(argument_spec={}, check_invalid_arguments=False)
    httpApi = HttpApi(module)

    # fetch using Web API the python dictionary representing the argument_spec
    properties = eval(httpApi._connection.get_py_dictionary('port_groups'))
    # synthetic key used to refer to a port_group whose name we want to change
    properties['port_group'] = dict(type='str')
    # synthetic key used to delete an existing port group
    properties['delete'] = dict(type='bool')

    httpApi._module = AnsibleModule(argument_spec=properties)

    result = dict(
        changed=False,
    )

    try:
        clear_payload(httpApi._module.params)

        if 'port_group' in httpApi._module.params:
            httpApi.get_target('port_group', '/port_groups')
        elif 'name' in httpApi._module.params:
            httpApi.get_target('name', '/port_groups')
        else:
            httpApi._module.resource_id = None

        output = httpApi.handle_port_groups()

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
