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
import logging
import json

from heat.engine.resources.openstack.neutron import neutron
from heat.common.i18n import _
from heat.engine import properties
from heat.engine import attributes


class IPAddressAlreadyAllocated(Exception):
    pass


class F5NeutronAddFixedIP(neutron.NeutronResource):
    ''' Update Allowed Address Attributes on Neutron Ports'''

    PROPERTIES = (
        PORT,
        SUBNET,
        IP_ADDRESS
    ) = (
        'port',
        'subnet',
        'ip_address'
    )

    properties_schema = {
        PORT: properties.Schema(
            properties.Schema.STRING,
            _('Neutron Port'),
            required=True,
            update_allowed=False
        ),
        SUBNET: properties.Schema(
            properties.Schema.STRING,
            _('Neutron Subnet'),
            required=False,
            update_allowed=False
        ),
        IP_ADDRESS: properties.Schema(
            properties.Schema.STRING,
            _('IP Addresses to attempt to allocate'),
            required=False,
            update_allowed=False
        )
    }

    ATTRIBUTES = (
        SUBNET,
        IP_ADDRESS
    ) = (
        'subnet',
        'ip_address'
    )

    attributes_schema = {
        SUBNET: attributes.Schema(
           _('Fixed IP Subnet ID.'),
           attributes.Schema.STRING
        ),
        IP_ADDRESS: attributes.Schema(
           _('Fixed IP Address.'),
           attributes.Schema.STRING
        )
    }

    def _resolve_attribute(self, name):
        if name == self.SUBNET:
            res = json.loads(self.resource_id)
            return res['subnet_id']
        if name == self.IP_ADDRESS:
            res = json.loads(self.resource_id)
            return res['ip_address']
        return None

    def handle_create(self):
        '''Allocate a fixed IP for a Neutron Port.

        :raises: ResourceFailure
        '''
        port_id = self.properties[self.PORT]
        subnet_id = self.properties[self.SUBNET]
        ip_address = self.properties[self.IP_ADDRESS]

        port = self.client().show_port(port_id)
        current_fixed_ips = port['port']['fixed_ips']

        if not subnet_id:
            subnet_id = current_fixed_ips[0]['subnet_id']
        self.subnet = subnet_id
        logging.error('setting self.subnet %s' % subnet_id)

        for fixed_ip in current_fixed_ips:
            if fixed_ip['subnet_id'] == subnet_id:
                if ip_address and fixed_ip['ip_address'] == ip_address:
                    raise IPAddressAlreadyAllocated(
                        'Address %s is already allocated to port %s' %
                        (ip_address, port_id)
                    )

        fixed_ip = {'subnet_id': subnet_id}
        if ip_address:
            fixed_ip['ip_address'] = ip_address
        current_fixed_ips.append(fixed_ip)

        update_port = {'port': {'fixed_ips': current_fixed_ips}}
        new_port = self.client().update_port(
            port_id,
            update_port
        )

        if ip_address:
            resource_id = {'ip_address': ip_address, 'subnet_id': subnet_id}
            self.resource_id_set(json.dumps(resource_id))
        else:
            new_fixed_ips = new_port['port']['fixed_ips']
            for x in new_fixed_ips:
                if x in current_fixed_ips:
                    new_fixed_ips.remove(x)
        if len(new_fixed_ips):
            ip_address = new_fixed_ips[-1]['ip_address']
            resource_id = {'ip_address': ip_address, 'subnet_id': subnet_id}
            self.resource_id_set(json.dumps(resource_id))

    def handle_delete(self):
        '''Removes allocated fixed IP address from Neutron Port.

        :raises: ResourceFailure
        '''

        if not self.resource_id:
            return True

        res = json.loads(self.resource_id)
        port_id = self.properties[self.PORT]
        port = self.client().show_port(port_id)
        current_fixed_ips = port['port']['fixed_ips']
        current_fixed_ips.remove(res)
        update_port = {'port': {'fixed_ips': current_fixed_ips}}
        self.client().update_port(
            port_id,
            update_port
        )
        return True

    def check_delete_complete(self, ip_address):
        return True


def resource_mapping():
    return {'F5::Neutron::AddFixedIP': F5NeutronAddFixedIP}
