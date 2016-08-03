# coding=utf-8
#
# Copyright 2015-2016 F5 Networks Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
import netaddr

from heat.engine.resources.openstack.neutron import neutron
from heat.common.i18n import _
from heat.engine import properties
from heat.engine import attributes


class F5NeutronPortNetworkConfig(neutron.NeutronResource):
    ''' Gets Network Configuration from Neutron Ports'''

    PROPERTIES = (
        PORT,
        IP_ADDRESS
    ) = (
        'port',
        'ip_address'
    )

    properties_schema = {
        PORT: properties.Schema(
            properties.Schema.STRING,
            _('Neutron Port'),
            required=True
        ),
        IP_ADDRESS: properties.Schema(
            properties.Schema.STRING,
            _('IP Address'),
            required=False,
            default=None
        )
    }

    ATTRIBUTES = (
        NETWORK_NAME,
        NETWORK_TYPE,
        NETWORK_PHYSICAL_NETWORK,
        NETWORK_SEGMENTATION_ID,
        MAC_ADDRESS,
        IP_ADDRESS,
        CIDR,
        NETMASK,
        GATEWAY,
        ROUTES,
        DNS_SERVERS
    ) = (
        'network_name',
        'network_type',
        'network_physical_network',
        'network_segmentation_id',
        'mac_address',
        'ip_address',
        'cidr',
        'netmask',
        'gateway',
        'routes',
        'dns_servers'
    )

    attributes_schema = {
        NETWORK_NAME: attributes.Schema(
           _('Network Name'),
           attributes.Schema.STRING
        ),
        NETWORK_TYPE: attributes.Schema(
           _('Network Type'),
           attributes.Schema.STRING
        ),
        NETWORK_PHYSICAL_NETWORK: attributes.Schema(
           _('Network Physical Network Mapping'),
           attributes.Schema.STRING
        ),
        NETWORK_SEGMENTATION_ID: attributes.Schema(
           _('Network Segmentation ID'),
           attributes.Schema.STRING
        ),
        MAC_ADDRESS: attributes.Schema(
           _('MAC Address'),
           attributes.Schema.STRING
        ),
        IP_ADDRESS: attributes.Schema(
           _('IP Address'),
           attributes.Schema.STRING
        ),
        CIDR: attributes.Schema(
           _('CIDR for IP Address'),
           attributes.Schema.STRING
        ),
        NETMASK: attributes.Schema(
           _('Netmask for IP Address'),
           attributes.Schema.STRING
        ),
        GATEWAY: attributes.Schema(
           _('Gateway defined for IP Subnet'),
           attributes.Schema.STRING
        ),
        ROUTES: attributes.Schema(
           _('Routes defined for IP Subnet'),
           attributes.Schema.STRING
        ),
        DNS_SERVERS: attributes.Schema(
           _('DNS Servers for IP Subnet'),
           attributes.Schema.STRING
        )
    }

    def _resolve_attribute(self, name):
        if name == self.NETWORK_NAME:
            return self.network_name
        if name == self.NETWORK_TYPE:
            return self.network_type
        if name == self.NETWORK_PHYSICAL_NETWORK:
            return self.network_physical_network
        if name == self.NETWORK_SEGMENTATION_ID:
            return self.network_segmentation_id
        if name == self.MAC_ADDRESS:
            return self.mac_address
        if name == self.IP_ADDRESS:
            return self.ip_address
        if name == self.CIDR:
            return self.cidr
        if name == self.NETMASK:
            return self.netmask
        if name == self.GATEWAY:
            return self.gateway
        if name == self.ROUTES:
            return self.routes
        if name == self.DNS_SERVERS:
            return self.dns_servers

    def handle_create(self):
        '''Get Nework Configuration Details from a Neutron Port.

        :raises: ResourceFailure
        '''
        self.network_name = 'undefined'
        self.network_type = 'undefined'
        self.network_physical_network = 'undefined'
        self.network_segmentation_id = 'undefined'
        self.mac_address = 'undefined'
        self.ip_address = 'undefined'
        self.cidr = 'undefined'
        self.netmask = 'undefined'
        self.gateway = 'undefined'
        self.routes = []
        self.dns_servers = []

        port_id = self.properties[self.PORT]
        ip_address = self.properties[self.IP_ADDRESS]

        port = self.client().show_port(port_id)
        self.mac_address = port['port']['mac_address']

        network = self.client().show_network(port['port']['networkd_id'])
        self.network_name = network['network']['name']
        self.network_type = network['network']['provider:network_type']
        self.network_physical_network = \
            network['network']['provider:physical_network']
        self.network_segmentation_id = \
            network['network']['provider:segmentation_id']

        for fixed_ip in port['port']['fixed_ips']:
            if ip_address:
                if ip_address == fixed_ip['ip_address']:
                    self.ip_address = fixed_ip['ip_address']
                    subnet = self.client().show_subnet(fixed_ip['subnet'])
                    self.cidr = subnet['subnet']['cidr']
                    ipnetwork = netaddr.IPNetwork(self.cidr)
                    self.netmask = ipnetwork.netmask
                    self.gateway = subnet['subnet']['gateway_ip']
                    self.routes = subnet['subnet']['host_routes']
                    self.dns_servers = subnet['subnet']['dns_nameservers']
            else:
                self.ip_address = fixed_ip['ip_address']
                subnet = self.client().show_subnet(fixed_ip['subnet'])
                self.cidr = subnet['subnet']['cidr']
                ipnetwork = netaddr.IPNetwork(self.cidr)
                self.netmask = ipnetwork.netmask
                self.gateway = subnet['subnet']['gateway_ip']
                self.routes = subnet['subnet']['host_routes']
                self.dns_servers = subnet['subnet']['dns_nameservers']
                break
        return True

    def handle_delete(self):
        return True


def resource_mapping():
    return {'F5::Neutron::PortNetworkConfig': F5NeutronPortNetworkConfig}
