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


NVOS module used to issue Web API calls implying the 'system' resource from
Ansbile.
"""

ANSIBLE_METADATA = {
    'metadata_version': '1.1',
    'supported_by': 'community',
    'status': ['preview']
}


DOCUMENTATION = '''
---
module: nvos_system

short_description: This module handles interactions with NVOS system.

version_added: "2.8"

description:
    - This module handles interactions with NVOS system settings.
    - NVOS version 5.2.0
    - Sub-options marked as required are mandatory only when the top parameter is used.

options:
    allow_serial_port_access:
        description:
            - Value that indicates if serial port access is allowed.
            - Available on all platforms.
        type: bool
    allow_serial_port_login:
        description:
            - Value that indicates if serial port login is enabled/disabled.
            - Available on all platforms.
        type: bool
    authentication_mode:
        description:
            - Value that indicates the authentication mode.
            - Available on all platforms.
        type: string
        choices: ['TACACS', 'RADIUS', 'LDAP', 'LOCAL']
    cli_config:
        description:
            - Updating any cli_config property will cause the CLI service restart. As a result, the request will be terminated with HTTP status 202 Accepted and not 200 OK.  Also note that restarting the CLI service can take up to one minute to complete.
            - Available on 7300 Series, E100 Series, E40 Series, Vision Edge OS, Vision X Series, Vision E10S.
        type: dict
        suboptions:
            enabled:
                description:
                    - 
                required: true
                type: bool
            port:
                description:
                    - 
                required: true
                type: integer
    custom_field_set_config:
        description:
            - The custom field set configuration is for user-defined fields to match on up to 16 2-byte fields up to 128 bytes deep into Ethernet packets, measured from the beginning of the packet. The custom field set can hold one or two custom field sets. Only users with system administrator privileges can update this property.
            - Available on all platforms.
        type: dict
        suboptions:
            combined:
                description:
                    - 
                required: true
                type: bool
            field_set_1:
                description:
                    - 
                required: true
                type: dict
                suboptions:
                    enabled:
                        description:
                            - 
                        required: true
                        type: bool
                    fields:
                        description:
                            - 
                            - List of items described below.
                            - 
                        required: true
                        type: list
                    free_fields:
                        description:
                            - The free_fields property is only present on output.
                            - List of items described below.
                            - 
                        required: true
                        type: list
                        suboptions:
                            field_size:
                                description:
                                    - 
                                required: true
                                type: integer
                            field_type:
                                description:
                                    - 
                                required: true
                                type: string
                                choices: ['IPV6_SRC', 'IPV6_DST', 'TCP_CONTROL', 'INNER_VLAN', 'VLAN', 'IP_PROTOCOL', 'LAYER4_SRC_PORT', 'MAC_DST', 'MAC_SRC', 'LAYER4_DST_PORT', 'IPV4_SRC', 'IPV4_DST', 'DSCP', 'ETHERTYPE']
                            name:
                                description:
                                    - 
                                required: true
                                type: string
                            system_generated:
                                description:
                                    - 
                                required: true
                                type: bool
                    outer_header_type:
                        description:
                            - The outer_header_type property defaults to L34_IPV4.
                        type: string
                        choices: ['L234_IPV4_PLUS', 'L2', 'L34_IPV4', 'L2_PLUS']
            field_set_2:
                description:
                    - 
                type: dict
                suboptions:
                    enabled:
                        description:
                            - 
                        required: true
                        type: bool
                    fields:
                        description:
                            - 
                            - List of items described below.
                            - 
                        required: true
                        type: list
                    free_fields:
                        description:
                            - The free_fields property is only present on output.
                            - List of items described below.
                            - 
                        required: true
                        type: list
                        suboptions:
                            field_size:
                                description:
                                    - 
                                required: true
                                type: integer
                            field_type:
                                description:
                                    - 
                                required: true
                                type: string
                                choices: ['IPV6_SRC', 'IPV6_DST', 'TCP_CONTROL', 'INNER_VLAN', 'VLAN', 'IP_PROTOCOL', 'LAYER4_SRC_PORT', 'MAC_DST', 'MAC_SRC', 'LAYER4_DST_PORT', 'IPV4_SRC', 'IPV4_DST', 'DSCP', 'ETHERTYPE']
                            name:
                                description:
                                    - 
                                required: true
                                type: string
                            system_generated:
                                description:
                                    - 
                                required: true
                                type: bool
                    outer_header_type:
                        description:
                            - The outer_header_type property defaults to L34_IPV4.
                        type: string
                        choices: ['L234_IPV4_PLUS', 'L2', 'L34_IPV4', 'L2_PLUS']
    dns_config:
        description:
            - The DNS configuration of the switch.
            - Available on all platforms.
        type: dict
        suboptions:
            active_alt_server:
                description:
                    - 
                type: string
            active_primary_server:
                description:
                    - 
                required: true
                type: string
            active_suffix1:
                description:
                    - 
                type: string
            active_suffix2:
                description:
                    - 
                type: string
            alt_is_ipv6:
                description:
                    - 
                type: bool
            alt_server:
                description:
                    - 
                type: string
            primary_is_ipv6:
                description:
                    - 
                type: bool
            primary_server:
                description:
                    - 
                required: true
                type: string
            suffix1:
                description:
                    - 
                type: string
            suffix2:
                description:
                    - 
                type: string
    enhanced_security_settings:
        description:
            - Collection of properties for increasing validation and other security related enhancements.
            - Available on all platforms.
        type: dict
        suboptions:
            syslog_unknown_cert:
                description:
                    - 
                required: true
                type: bool
            validate_crl:
                description:
                    - When uploading a new certificate that has a CRL distribution point (DP), validate that the certificate has not been revoked.  Only applies when the DP is HTTP based.   
                required: true
                type: bool
            validate_root_cert_use:
                description:
                    - When uploading a new certificate, validate that the root certificate (CA) has the extended key usage (EKU) bit set indicating the certificates authentication purpose is as a server or client certificate (depending on how the certificate is used by the system). 
                required: true
                type: bool
    firewall_config:
        description:
            - Value that indicates the firewall configuration, the list of servers that are considered secure and allowed to communicate with the NTO.
            - Available on all platforms.
        type: dict
        suboptions:
            ipv6_disallow_dst_unreachable_pkt:
                description:
                    - 
                type: bool
            ipv6_disallow_mc_echo_reply:
                description:
                    - 
                type: bool
            ipv6_dscp_class:
                description:
                    - 
                type: string
            ipv6_rate_limit:
                description:
                    - 
                type: string
            require_whitelist:
                description:
                    - 
                required: true
                type: bool
            servers:
                description:
                    - 
                    - List of items described below.
                    - 
                required: true
                type: list
                suboptions:
                    address:
                        description:
                            - 
                        required: true
                        type: string
    gtp_fd_restore_timeout:
        description:
            - The gtp_fd_restore_timeout value represents minutes. Zero indicates no timeout. Valid values are from 0 to 30.
            - Available on 7300 Series, Vision X Series.
        type: integer
    gtp_lb_group_config:
        description:
            - Value that indicates the GTP load balancing port groups configuration.
            - Available on all platforms.
        type: dict
        suboptions:
            ip_ranges:
                description:
                    - 
                required: true
                type: dict
                suboptions:
                    gtp_lb_group_id:
                        description:
                            - 
                        required: true
                        type: integer
                    ipv4_addr_criterion:
                        description:
                            - The criterion for matching one or more IPv4 addresses.
                        required: true
                        type: dict
                        suboptions:
                    ipv6_addr_criterion:
                        description:
                            - The criterion for matching one or more IPv6 addresses.
                        required: true
                        type: dict
                        suboptions:
    gtp_lb_user_ip_config:
        description:
            - The value that indicates the GTP user IP ranges configuration.
            - Available on all platforms.
        type: dict
        suboptions:
            ip_ranges:
                description:
                    - 
                required: true
                type: dict
                suboptions:
                    gtp_lb_group_id:
                        description:
                            - 
                        required: true
                        type: integer
                    ipv4_addr_criterion:
                        description:
                            - The criterion for matching one or more IPv4 addresses.
                        required: true
                        type: dict
                        suboptions:
                    ipv6_addr_criterion:
                        description:
                            - The criterion for matching one or more IPv6 addresses.
                        required: true
                        type: dict
                        suboptions:
    ha_config_sync_mode:
        description:
            - The mode for the configuration synchronization.
            - Available on TradeVision Series, E100 Series, E40 Series, Vision Edge OS, Vision X Series, Vision E10S.
        type: string
        choices: ['MANUAL_SYNC', 'AUTO_SYNC']
    ha_mode:
        description:
            - HA mode.
            - Available on TradeVision Series, E100 Series, E40 Series, Vision Edge OS, Vision X Series, Vision E10S.
        type: string
        choices: ['ACTIVE_ACTIVE', 'STANDALONE']
    ha_switch_role:
        description:
            - HA role of a switch.
            - Available on TradeVision Series, E100 Series, E40 Series, Vision Edge OS, Vision X Series, Vision E10S.
        type: string
        choices: ['SECONDARY', 'PRIMARY']
    ha_sync_selective:
        description:
            - Marks if selective properties should be synchronized in HA.
            - Available on TradeVision Series, E100 Series, E40 Series, Vision Edge OS, Vision X Series, Vision E10S.
        type: bool
    ldap_servers:
        description:
            - 
            - Available on all platforms.
        type: dict
        suboptions:
            common:
                description:
                    - 
                required: true
                type: dict
                suboptions:
                    attrs:
                        description:
                            - 
                            - List of items described below.
                            - 
                        required: true
                        type: list
                        suboptions:
                            logical_operation:
                                description:
                                    - 
                                type: string
                                choices: ['OR', 'AND']
                            pairs:
                                description:
                                    - 
                                required: true
                                type: dict
                                suboptions:
                                    name:
                                        description:
                                            - 
                                        required: true
                                        type: string
                                    value:
                                        description:
                                            - 
                                        required: true
                                        type: string
                            type:
                                description:
                                    - 
                                required: true
                                type: string
                                choices: ['AUTHZ_REGULAR', 'GROUP_SERVICE', 'GROUP_NAMES', 'ACCT_AUTHN_SUCCESS', 'ACCT_AUTHN_FAILURE', 'SERVICE', 'ACCT_AUTHZ_REGULAR', 'AUTHZ_ADMIN', 'ACCT_AUTHZ_ADMIN']
                    enable_authz:
                        description:
                            - 
                        type: bool
                    ldap_mode:
                        description:
                            - 
                        type: string
                        choices: ['CAC', 'NO_CAC']
            servers:
                description:
                    - 
                    - List of items described below.
                    - 
                type: list
                suboptions:
                    host:
                        description:
                            - The IP address of the AAA server.
                        required: true
                        type: string
                    ldap_string:
                        description:
                            - 
                        type: string
                    port:
                        description:
                            - The port of the AAA server.
                        type: integer
                    retry_count:
                        description:
                            - The number of times a login to the AAA server will be attempted.
                        type: integer
                    timeout:
                        description:
                            - The timeout (in seconds) for an attempt to login to the AAA server.
                        type: integer
                    tls_enabled:
                        description:
                            - 
                        type: bool
    lldp_config:
        description:
            - Configuration of LLDP receive and LLDP transmit settings common for all ports.
            - Available on all platforms.
        type: dict
        suboptions:
            lldp_receive:
                description:
                    - 
                required: true
                type: dict
                suboptions:
                    keep_neighbors_expired_enabled:
                        description:
                            - 
                        required: true
                        type: bool
                    keep_neighbors_time_unit:
                        description:
                            - 
                        required: true
                        type: string
                        choices: ['SEC', 'MIN', 'HOUR', 'DAY']
                    keep_neighbors_value:
                        description:
                            - 
                        required: true
                        type: integer
            lldp_transmit:
                description:
                    - 
                required: true
                type: dict
                suboptions:
                    retransmit_interval:
                        description:
                            - 
                        required: true
                        type: integer
                    tlv_list:
                        description:
                            - 
                            - List of items described below.
                            - 
                        required: true
                        type: list
    load_balance_settings:
        description:
            - The hashing algorithm to use for port groups.
            - Available on all platforms.
        type: dict
        suboptions:
            inline_asymmetric_hashing_enabled:
                description:
                    - 
                required: true
                type: bool
            inline_asymmetric_hashing_mode:
                description:
                    - 
                required: true
                type: string
                choices: ['SIP_SIDE_A_DIP_SIDE_B', 'SIP_SIDE_B_DIP_SIDE_A']
            ipv4:
                description:
                    - 
                required: true
                type: string
                choices: ['ADDR_PROTOCOL_PORT', 'ADDR_PROTOCOL']
            ipv6:
                description:
                    - 
                required: true
                type: string
                choices: ['ADDR_PROTOCOL_PORT', 'ADDR_PROTOCOL']
            l2:
                description:
                    - 
                required: true
                type: string
                choices: ['MAC', 'MAC_ETHERTYPE']
            mpls:
                description:
                    - 
                required: true
                type: string
                choices: ['TUNNELED_IP', 'MPLS_LABELS', 'MPLS_LABELS_TUNNELED_IP', 'NONE']
            use_l2_for_all:
                description:
                    - 
                required: true
                type: bool
    log_level:
        description:
            - User-requested log level of the switch application.
            - Available on all platforms.
        type: string
        choices: ['TRACE', 'ERROR', 'INFO', 'DEBUG', 'WARN']
    login_banner_config:
        description:
            - The value of the security warning for this NTO.
            - Available on all platforms.
        type: dict
        suboptions:
            text:
                description:
                    - 
                required: true
                type: string
    memory_allocation:
        description:
            - The filter memory allocation for network dynamic and tool filters using the new filter compiler.
            - Available on all platforms.
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
    mgmt_port_link_settings:
        description:
            - The requested speed and duplex of the management port.
            - Available on all platforms.
        type: string
        choices: ['10M_HALF', '25G_FULL', '10M_FULL', 'G20_FULL', '100M_HALF', 'G42_FULL', '1G_FULL', '10G_FULL', '100M_FULL', '40G_FULL', '50G_FULL', 'AUTO', '100G_FULL']
    mod_count:
        description:
            - 
            - Available on all platforms.
        type: integer
    ntp_server_list:
        description:
            - List of NTP servers.
            - Available on all platforms.
        type: dict
        suboptions:
            enabled:
                description:
                    - 
                required: true
                type: bool
            servers:
                description:
                    - 
                    - List of items described below.
                    - 
                type: list
                suboptions:
                    address:
                        description:
                            - 
                        required: true
                        type: string
                    authentication_enabled:
                        description:
                            - 
                        type: bool
                    key:
                        description:
                            - 
                            - List of items described below.
                            - A byte value
                        required: true
                        type: list
                    key_id:
                        description:
                            - 
                        required: true
                        type: integer
    password_policies:
        description:
            - Property holding a PasswordPolicies object with configuration options for password policies.
            - Available on all platforms.
        type: dict
        suboptions:
            days_to_track_successful_logins:
                description:
                    - 
                type: integer
            enabled:
                description:
                    - 
                required: true
                type: bool
            expiration_days:
                description:
                    - 
                required: true
                type: integer
            max_failures_allowed:
                description:
                    - 
                type: integer
            min_password_length:
                description:
                    - 
                required: true
                type: integer
            type:
                description:
                    - 
                required: true
                type: string
                choices: ['FIPS_DOD_SECURITY', 'STRONG']
            user_inactive_days:
                description:
                    - 
                type: integer
    port_assigned_license_map:
        description:
            - In a union, port_assigned_license_map must be updated on a member-by-member basis.  The URL of the PUT command must include the ID of the member being updated.  For example, to update the map of member S2, the URL would be similar to the following https//{system IP address}/api/system/S2
            - Available on all platforms.
        type: dict
    power_on_self_test_enabled:
        description:
            - Value that indicates if POST is enabled.
            - Available on all platforms.
        type: bool
    ptp_config:
        description:
            - PTP configuration.
            - Available on 7300 Series, TradeVision Series, E100 Series, E40 Series, Vision Edge OS, Vision X Series.
        type: dict
        suboptions:
            address_mode:
                description:
                    - 
                required: true
                type: string
                choices: ['UNICAST_ONLY', 'MULTICAST_ONLY']
            announce_receipt_timeout:
                description:
                    - 
                required: true
                type: integer
            clock_domain:
                description:
                    - 
                required: true
                type: integer
            dscp:
                description:
                    - 
                required: true
                type: integer
            enabled:
                description:
                    - 
                required: true
                type: bool
            master_address:
                description:
                    - 
                required: true
                type: dict
                suboptions:
                    ipv4_address:
                        description:
                            - 
                        required: true
                        type: string
                    ipv4_gateway:
                        description:
                            - 
                        required: true
                        type: string
                    ipv4_netmask:
                        description:
                            - 
                        required: true
                        type: string
            master_interface_speed:
                description:
                    - 
                required: true
                type: string
                choices: ['AUTO', 'M100', 'G1']
            phase_lag:
                description:
                    - 
                required: true
                type: integer
            slave_address:
                description:
                    - 
                required: true
                type: dict
                suboptions:
                    ipv4_address:
                        description:
                            - 
                        required: true
                        type: string
                    ipv4_gateway:
                        description:
                            - 
                        required: true
                        type: string
                    ipv4_netmask:
                        description:
                            - 
                        required: true
                        type: string
            vlan_config:
                description:
                    - 
                required: true
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
                    vlan_priority:
                        description:
                            - 
                        required: true
                        type: integer
    radius_servers:
        description:
            - List of configured radius servers.
            - Available on all platforms.
        type: dict
        suboptions:
            common:
                description:
                    - 
                required: true
                type: dict
                suboptions:
                    attrs:
                        description:
                            - 
                            - List of items described below.
                            - 
                        required: true
                        type: list
                        suboptions:
                            logical_operation:
                                description:
                                    - 
                                type: string
                                choices: ['OR', 'AND']
                            pairs:
                                description:
                                    - 
                                required: true
                                type: dict
                                suboptions:
                                    name:
                                        description:
                                            - 
                                        required: true
                                        type: string
                                    value:
                                        description:
                                            - 
                                        required: true
                                        type: string
                            type:
                                description:
                                    - 
                                required: true
                                type: string
                                choices: ['AUTHZ_REGULAR', 'GROUP_SERVICE', 'GROUP_NAMES', 'ACCT_AUTHN_SUCCESS', 'ACCT_AUTHN_FAILURE', 'SERVICE', 'ACCT_AUTHZ_REGULAR', 'AUTHZ_ADMIN', 'ACCT_AUTHZ_ADMIN']
                    enable_authz:
                        description:
                            - 
                        type: bool
                    enable_groups:
                        description:
                            - 
                        type: bool
                    local_admin_disabled:
                        description:
                            - 
                        type: bool
            servers:
                description:
                    - 
                    - List of items described below.
                    - This is the set of properties that define a Radius AAA server.
                type: list
                suboptions:
                    aaa_user_password:
                        description:
                            - The password to be used when enable_aaa_validation is set to true.
                        type: string
                    aaa_username:
                        description:
                            - The username to be used when enable_aaa_validation is set to true.
                        type: string
                    acct_attrs:
                        description:
                            - This property does not apply to the RADIUS server.
                            - List of items described below.
                            - 
                        type: list
                        suboptions:
                            logical_operation:
                                description:
                                    - 
                                type: string
                                choices: ['OR', 'AND']
                            pairs:
                                description:
                                    - 
                                required: true
                                type: dict
                                suboptions:
                                    name:
                                        description:
                                            - 
                                        required: true
                                        type: string
                                    value:
                                        description:
                                            - 
                                        required: true
                                        type: string
                            type:
                                description:
                                    - 
                                required: true
                                type: string
                                choices: ['AUTHZ_REGULAR', 'GROUP_SERVICE', 'GROUP_NAMES', 'ACCT_AUTHN_SUCCESS', 'ACCT_AUTHN_FAILURE', 'SERVICE', 'ACCT_AUTHZ_REGULAR', 'AUTHZ_ADMIN', 'ACCT_AUTHZ_ADMIN']
                    acct_port:
                        description:
                            - The port used for accounting on the Radius AAA server.
                        type: integer
                    authn_type:
                        description:
                            - The authentication type to use for the AAA server (PAP or CHAP).
                        type: string
                        choices: ['CHAP', 'PAP']
                    enable_aaa_validation:
                        description:
                            - If set to true along with disable_local_admin in the common settings, validation of authentication and authorization will take place when updating the AAA server settings. 
                        type: bool
                    enable_acct:
                        description:
                            - When set to true, the AAA server will enable accounting.
                        type: bool
                    host:
                        description:
                            - The IP address of the AAA server.
                        required: true
                        type: string
                    port:
                        description:
                            - The port of the AAA server.
                        type: integer
                    retry_count:
                        description:
                            - The number of times a login to the AAA server will be attempted.
                        type: integer
                    secret:
                        description:
                            - The shared secret for the AAA server.
                        type: string
                    timeout:
                        description:
                            - The timeout (in seconds) for an attempt to login to the AAA server.
                        type: integer
    serial_port_config:
        description:
            - Values for the serial port banner and the session timeout.
            - Available on all platforms.
        type: dict
        suboptions:
            allow_disabling_auth_at_startup:
                description:
                    - When authentication is enabled on the serial console, an option exists to disable it within the first minute or so (depending on hardware) after system startup (boot).  This is a fallback for recovering the box should no one be able to log in.
                required: true
                type: bool
            banner:
                description:
                    - 
                required: true
                type: string
            session_timeout:
                description:
                    - 
                required: true
                type: dict
                suboptions:
                    unit:
                        description:
                            - 
                        required: true
                        type: string
                        choices: ['MSEC', 'SEC', 'MIN', 'HOUR', 'WEEK', 'DAY']
                    value:
                        description:
                            - 
                        required: true
                        type: integer
    session_timeout_interval:
        description:
            - The session_timeout_interval value represents seconds. Zero indicates no timeout. Valid values are from 0 to 216000.
            - Available on all platforms.
        type: integer
    snmp_config:
        description:
            - Value that indicates the SNMP configuration.
            - Available on all platforms.
        type: dict
        suboptions:
            get_access:
                description:
                    - 
                    - List of items described below.
                    - 
                required: true
                type: list
                suboptions:
                    community_string:
                        description:
                            - 
                        type: string
                    local_user:
                        description:
                            - 
                        type: dict
                        suboptions:
                            authn_password:
                                description:
                                    - 
                                type: string
                            authn_protocol:
                                description:
                                    - 
                                type: string
                                choices: ['SHA1', 'MD5']
                            context_name:
                                description:
                                    - 
                                required: true
                                type: string
                            engine_id:
                                description:
                                    - 
                                required: true
                                type: string
                            name:
                                description:
                                    - 
                                required: true
                                type: string
                            privacy_password:
                                description:
                                    - 
                                type: string
                            privacy_protocol:
                                description:
                                    - 
                                type: string
                                choices: ['DES', 'AES128', 'AES192', 'AES256']
                            security_level:
                                description:
                                    - 
                                required: true
                                type: string
                                choices: ['AUTHN_AND_PRIVACY', 'NONE', 'AUTHN_ONLY']
                    version:
                        description:
                            - 
                        type: string
                        choices: ['V1', 'V2', 'V3']
            gets_enabled:
                description:
                    - 
                required: true
                type: bool
            preferred_ip:
                description:
                    - 
                type: string
                choices: ['IPV6', 'IPV4']
            refresh_time:
                description:
                    - 
                required: true
                type: integer
            trap_recipients:
                description:
                    - 
                    - List of items described below.
                    - The snmp trap recipient community string is not optional when using traps of version V1 or V2.
                required: true
                type: list
                suboptions:
                    community_string:
                        description:
                            - 
                        type: string
                    host:
                        description:
                            - 
                        required: true
                        type: dict
                        suboptions:
                            value:
                                description:
                                    - 
                                required: true
                                type: string
                    port:
                        description:
                            - 
                        type: integer
                    remote_user:
                        description:
                            - 
                        type: dict
                        suboptions:
                            authn_password:
                                description:
                                    - 
                                type: string
                            authn_protocol:
                                description:
                                    - 
                                type: string
                                choices: ['SHA1', 'MD5']
                            context_name:
                                description:
                                    - 
                                required: true
                                type: string
                            engine_id:
                                description:
                                    - 
                                required: true
                                type: string
                            name:
                                description:
                                    - 
                                required: true
                                type: string
                            privacy_password:
                                description:
                                    - 
                                type: string
                            privacy_protocol:
                                description:
                                    - 
                                type: string
                                choices: ['DES', 'AES128', 'AES192', 'AES256']
                            security_level:
                                description:
                                    - 
                                required: true
                                type: string
                                choices: ['AUTHN_AND_PRIVACY', 'NONE', 'AUTHN_ONLY']
                    retry_count:
                        description:
                            - 
                        type: integer
                    timeout:
                        description:
                            - 
                        type: integer
                    traps:
                        description:
                            - 
                            - List of items described below.
                            - INLINE_HA_LINK_STATE_CHANGE, INLINE_HA_SYNC_STATUS_CHANGE, INLINE_TOOL_STATUS_CHANGE, LOAD_DISTRIBUTION, INLINE_HA_STATE_CHANGE are allowed only on the following models 8000
                        required: true
                        type: list
                    version:
                        description:
                            - 
                        type: string
                        choices: ['V1', 'V2', 'V3']
            traps_enabled:
                description:
                    - 
                required: true
                type: bool
    stats_polling_interval:
        description:
            - stats_polling_interval is in seconds. Valid values are from 1 to 15.
            - Available on all platforms.
        type: integer
    syslog_server_list:
        description:
            - List of syslog servers.
            - List of items described below.
            - 
            - Available on all platforms.
        type: list
        suboptions:
            facility:
                description:
                    - 
                type: string
                choices: ['Local5', 'Local6', 'Local3', 'Local4', 'User', 'Local7', 'Local1', 'Local2', 'Local0']
            host:
                description:
                    - 
                required: true
                type: string
            port:
                description:
                    - 
                type: integer
            tls_enabled:
                description:
                    - 
                type: bool
    syslog_tls_handshake_enabled:
        description:
            - Indicates if TLS handshake interactions should create a syslog entry.
            - Available on all platforms.
        type: bool
    system_access_settings_map:
        description:
            - The system level (default) access settings.
            - Available on all platforms.
        type: dict
        suboptions:
            user_groups:
                description:
                    - 
                required: true
                type: dict
                suboptions:
                    view:
                        description:
                            - 
                        required: true
                        type: dict
                        suboptions:
                            access_policy:
                                description:
                                    - 
                                required: true
                                type: string
                                choices: ['ALLOW_ALL', 'REQUIRE_ADMIN']
            users:
                description:
                    - 
                required: true
                type: dict
                suboptions:
                    view:
                        description:
                            - 
                        required: true
                        type: dict
                        suboptions:
                            access_policy:
                                description:
                                    - 
                                required: true
                                type: string
                                choices: ['ALLOW_ALL', 'REQUIRE_ADMIN']
    system_info:
        description:
            - Value that contains the {@link SystemInfo}, which nominally consists of human-friendly name and location strings among other things.
            - Available on all platforms.
        type: dict
        suboptions:
            asset_info:
                description:
                    - 
                type: string
            contact_info:
                description:
                    - 
                type: string
            hardware:
                description:
                    - 
                type: string
            location:
                description:
                    - 
                type: string
            manufacturer:
                description:
                    - 
                type: string
            name:
                description:
                    - 
                type: string
    system_settings:
        description:
            - Various system settings.
            - Available on all platforms.
        type: dict
        suboptions:
            filter_multi_tenancy_option:
                description:
                    - Allow an admin user to opt to restrict regular users use of dynamic filters such that when filters are created or edited, there must always be at least one port or port group connection.
                type: string
                choices: ['NO_RESTRICTION_SHOW_WARNING', 'NO_RESTRICTION_NO_WARNING', 'RESTRICTED']
            password_field_id:
                description:
                    - This is used on the Web console login page as the html id in the password field. If this is set, the id of the password field will not be generated randomly with every refresh. Instead this text will be used as the html id every time. This allows an external application such as Cyber Ark to launch the NTO.
                type: string
    tac_ssh_enabled:
        description:
            - Indicates if SSH access is enabled through the TAC TOOL one-time login challenge script.
            - Available on all platforms.
        type: bool
    tacacs_servers:
        description:
            - List of configured TACACS servers.
            - Available on all platforms.
        type: dict
        suboptions:
            common:
                description:
                    - 
                required: true
                type: dict
                suboptions:
                    attrs:
                        description:
                            - 
                            - List of items described below.
                            - 
                        required: true
                        type: list
                        suboptions:
                            logical_operation:
                                description:
                                    - 
                                type: string
                                choices: ['OR', 'AND']
                            pairs:
                                description:
                                    - 
                                required: true
                                type: dict
                                suboptions:
                                    name:
                                        description:
                                            - 
                                        required: true
                                        type: string
                                    value:
                                        description:
                                            - 
                                        required: true
                                        type: string
                            type:
                                description:
                                    - 
                                required: true
                                type: string
                                choices: ['AUTHZ_REGULAR', 'GROUP_SERVICE', 'GROUP_NAMES', 'ACCT_AUTHN_SUCCESS', 'ACCT_AUTHN_FAILURE', 'SERVICE', 'ACCT_AUTHZ_REGULAR', 'AUTHZ_ADMIN', 'ACCT_AUTHZ_ADMIN']
                    enable_authz:
                        description:
                            - 
                        type: bool
                    enable_groups:
                        description:
                            - 
                        type: bool
                    local_admin_disabled:
                        description:
                            - 
                        type: bool
            servers:
                description:
                    - 
                    - List of items described below.
                    - This is the set of properties that define a TACACS+ AAA server.
                type: list
                suboptions:
                    aaa_user_password:
                        description:
                            - The password to be used when enable_aaa_validation is set to true.
                        type: string
                    aaa_username:
                        description:
                            - The username to be used when enable_aaa_validation is set to true.
                        type: string
                    acct_attrs:
                        description:
                            - The set of name/value pair attributes to be used during TACACS+ server accounting.
                            - List of items described below.
                            - 
                        type: list
                        suboptions:
                            logical_operation:
                                description:
                                    - 
                                type: string
                                choices: ['OR', 'AND']
                            pairs:
                                description:
                                    - 
                                required: true
                                type: dict
                                suboptions:
                                    name:
                                        description:
                                            - 
                                        required: true
                                        type: string
                                    value:
                                        description:
                                            - 
                                        required: true
                                        type: string
                            type:
                                description:
                                    - 
                                required: true
                                type: string
                                choices: ['AUTHZ_REGULAR', 'GROUP_SERVICE', 'GROUP_NAMES', 'ACCT_AUTHN_SUCCESS', 'ACCT_AUTHN_FAILURE', 'SERVICE', 'ACCT_AUTHZ_REGULAR', 'AUTHZ_ADMIN', 'ACCT_AUTHZ_ADMIN']
                    acct_port:
                        description:
                            - This property does not apply to the TACACS+ server.
                        type: integer
                    authn_type:
                        description:
                            - The authentication type to use for the AAA server (PAP or CHAP).
                        type: string
                        choices: ['CHAP', 'PAP']
                    enable_aaa_validation:
                        description:
                            - If set to true along with disable_local_admin in the common settings, validation of authentication and authorization will take place when updating the AAA server settings. 
                        type: bool
                    enable_acct:
                        description:
                            - When set to true, the AAA server will enable accounting.
                        type: bool
                    host:
                        description:
                            - The IP address of the AAA server.
                        required: true
                        type: string
                    port:
                        description:
                            - The port of the AAA server.
                        type: integer
                    retry_count:
                        description:
                            - The number of times a login to the AAA server will be attempted.
                        type: integer
                    secret:
                        description:
                            - The shared secret for the AAA server.
                        type: string
                    timeout:
                        description:
                            - The timeout (in seconds) for an attempt to login to the AAA server.
                        type: integer
    time_zone_display:
        description:
            - Value that indicates the time zone display configuration.
            - Available on all platforms.
        type: dict
        suboptions:
            default_time_zone:
                description:
                    - Default time zone.
                required: true
                type: string
                choices: ['LOCAL', 'GMT']
    timestamp_config:
        description:
            - Value that indicates the time stamping configuration.
            - Available on all platforms.
        type: dict
        suboptions:
            time_source:
                description:
                    - 
                required: true
                type: string
                choices: ['LOCAL', 'NTP', 'GPS', 'PTP']
    tool_management_view_enabled:
        description:
            - Toggle to enable/disable display and stats/filter configuration of Tool Management View (TMV)
            - Available on all platforms.
        type: bool
    union_name:
        description:
            - 
            - Available on all platforms.
        type: string
    web_api_config:
        description:
            - Updating any web_api_config property will cause a Web API service restart. As a result, the request will be terminated with HTTP status 202 Accepted and not 200 OK.  Also note that restarting the Web API service can take up to one minute to complete, during which time all console sessions will be unresponsive as well as the web API interface itself.
            - Available on all platforms.
        type: dict
        suboptions:
            enabled:
                description:
                    - 
                required: true
                type: bool
            max_login_sessions_per_user:
                description:
                    - 
                type: integer
            port:
                description:
                    - 
                required: true
                type: integer
            token_lifespan:
                description:
                    - 
                type: dict
                suboptions:
                    unit:
                        description:
                            - 
                        required: true
                        type: string
                        choices: ['MSEC', 'SEC', 'MIN', 'HOUR', 'WEEK', 'DAY']
                    value:
                        description:
                            - 
                        required: true
                        type: integer
            token_timeout:
                description:
                    - 
                required: true
                type: dict
                suboptions:
                    unit:
                        description:
                            - 
                        required: true
                        type: string
                        choices: ['MSEC', 'SEC', 'MIN', 'HOUR', 'WEEK', 'DAY']
                    value:
                        description:
                            - 
                        required: true
                        type: integer

author:
    - Keysight
'''

EXAMPLES = '''
  - name: Enable CLI settings
    nvos_system:
      cli_config: 
        enabled: true
        port: 22222
  - name: Configure DNS server
    nvos_system:
      dns_config: 
        alt_is_ipv6: true
        alt_server: 2001:428:e203::7
        primary_server: 8.8.8.8
        suffix1: dns_suffix1
        suffix2: dns_suffix2
  - name: Configure System information
    nvos_system:
      system_info: 
        asset_info: This is an asset info text
        contact_info: user@mail.com
        location: YourLocation
        name: test device
  - name: Configure LLDP settings
    nvos_system:
      lldp_config:
        lldp_receive:
          keep_neighbors_expired_enabled: true
          keep_neighbors_time_unit: HOUR
          keep_neighbors_value: 12
        lldp_transmit:
          retransmit_interval: 10
          tlv_list:
          - tlv_name: Time to Live
            tlv_type: 3
            tlv_value: 60
          - tlv_name: Port Description
            tlv_type: 4
            tlv_value:
              tlv_enabled: true
          - tlv_name: System Name
            tlv_type: 5
            tlv_value:
              tlv_enabled: false
          - tlv_name: Management Address
            tlv_type: 8
            tlv_value:
              options:
                ipv4_address_enabled: true
                ipv6_address_enabled: true
                mac_address_enabled: true
              tlv_enabled: true
  - name: Configure NTP server list
    nvos_system:
      ntp_server_list:
        enabled: true
        servers:
        - address: time.google.com
          authentication_enabled: false
        - address: 2001:610:508:110:192:87:110:2
          authentication_enabled: false
        - address: 10.10.10.10
          authentication_enabled: false
        - address: 0.ro.pool.ntp.org
          authentication_enabled: false
        - address: ntp1.bit.nl
          authentication_enabled: false
  - name: Configure Radius servers
    nvos_system:
      radius_servers:
        common:
          attrs:
          - logical_operation: OR
            pairs:
            - name: Your-Role
              value: REG
            type: AUTHZ_REGULAR
          - logical_operation: OR
            pairs:
            - name: Your-Role
              value: ADMIN
            type: AUTHZ_ADMIN
          - logical_operation: OR
            pairs:
            - name: Your-Groups
              value: (group list)
            type: GROUP_NAMES
          enable_authz: true
          enable_groups: false
          local_admin_disabled: false
        servers:
        - aaa_username: ''
          acct_attrs: []
          acct_port: 1813
          authn_type: PAP
          enable_aaa_validation: false
          enable_acct: false
          host: 10.10.10.10
          port: 1812
          retry_count: 2
          secret: YourRadius
          timeout: 10		  
  - name: Configure SNMP requests
    nvos_system:
      snmp_config:
        get_access:
        - community_string: community_v1
          local_user: null
          version: V1
        - community_string: community_v2
          local_user: null
          version: V2
        - local_user:
            authn_password: v3_password
            authn_protocol: SHA1
            context_name: ''
            engine_id: ''
            name: YourUser
            privacy_password: password_v3
            privacy_protocol: AES128
            security_level: AUTHN_AND_PRIVACY
          version: V3
        gets_enabled: true
        preferred_ip: IPV4
        refresh_time: 1
        trap_recipients: []
        traps_enabled: false		  
  - name: Configure SNMP traps
    nvos_system:
      snmp_config:
        get_access: []
        gets_enabled: false
        preferred_ip: IPV4
        refresh_time: 1
        trap_recipients:
        - community_string: community_v1
          host:
            value: 192.168.1.100
          port: 162
          remote_user: null
          traps:
          - CONSOLE_AUTHENTICATION_FAILED
          - COLD_START
          - WARM_START
          - ENTITY_CONFIG_CHANGE
          - LINK_UP_DOWN
          - AUTHENTICATION_FAILED
          version: V1
        - community_string: community_v2
          host:
            value: 192.168.1.100
          port: 162
          remote_user: null
          retry_count: 3
          timeout: 5
          traps:
          - CONSOLE_AUTHENTICATION_FAILED
          - TX_DROPPED_PKTS
          - COLD_START
          - RX_INVALID_PKTS
          - WARM_START
          - ENTITY_CONFIG_CHANGE
          - RX_UTILIZATION
          - LINK_UP_DOWN
          - TX_UTILIZATION
          - AUTHENTICATION_FAILED
          version: V2
        traps_enabled: true
  - name: Configure SNMP traps
    nvos_system:
      snmp_config:
        get_access: []
        gets_enabled: false
        preferred_ip: IPV4
        refresh_time: 1
        trap_recipients:
        - community_string: null
          host:
            value: 10.10.10.10
          port: 162
          remote_user:
            authn_password: v3_password
            authn_protocol: SHA1
            context_name: ''
            engine_id: ''
            name: your_user
            privacy_password: password_v3
            privacy_protocol: AES128
            security_level: AUTHN_AND_PRIVACY
          retry_count: 0
          timeout: 5
          traps:
          - CONSOLE_AUTHENTICATION_FAILED
          - TX_DROPPED_PKTS
          - COLD_START
          - WARM_START
          - ENTITY_CONFIG_CHANGE
          - LINK_UP_DOWN
          - AUTHENTICATION_FAILED
          version: V3
        traps_enabled: true		
  - name: Change authentication mode
    nvos_system:
      authentication_mode: TACACS
  - name: Configure Tacacs servers
    nvos_system:
      tacacs_servers:
        common:
          attrs:
          - logical_operation: OR
            pairs:
            - name: role
              value: REG
            type: AUTHZ_REGULAR
          - logical_operation: OR
            pairs:
            - name: role
              value: ADMIN
            type: AUTHZ_ADMIN
          - logical_operation: OR
            pairs:
            - name: service
              value: your_service
            type: GROUP_SERVICE
          - logical_operation: OR
            pairs:
            - name: service
              value: your_service
            type: SERVICE
          enable_authz: true
          enable_groups: false
          local_admin_disabled: false
        servers:
        - aaa_username: ''
          acct_attrs: []
          acct_port: null
          authn_type: CHAP
          enable_aaa_validation: false
          enable_acct: false
          host: 10.10.10.10
          port: 49
          retry_count: 2
          secret: your_secret
          timeout: 10		
'''

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.network.nvos.nvos import HttpApi


def run_module():
    module = AnsibleModule(argument_spec={}, check_invalid_arguments=False)
    httpApi = HttpApi(module)

    # fetch using Web API the python dictionary representing the argument_spec
    properties = eval(httpApi._connection.get_py_dictionary('system'))

    httpApi.__module = AnsibleModule(argument_spec=properties)

    result = dict(
        changed=False,
    )

    try:
        clear_payload(httpApi._module.params)

        output = httpApi.handle_system()

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

    result['changed'] = True
    module.exit_json(**result)


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
