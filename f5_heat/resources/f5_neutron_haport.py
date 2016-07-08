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

from heat.engine.resources.openstack.neutron import neutron
from heat.common.i18n import _
from heat.engine import properties


class F5NeutronHAPort(neutron.NeutronResource):
    ''' Update Allowed Address Attributes on Neutron Ports'''

    PROPERTIES = (
        PORT,
        IP_ADDRESSES,
        MAC_ADDRESSES,
    ) = (
        'port',
        'ip_addresses',
        'mac_addresses'
    )

    properties_schema = {
        PORT: properties.Schema(
            properties.Schema.STRING,
            _('Neutron Port'),
            required=True
        ),
        IP_ADDRESSES: properties.Schema(
            properties.Schema.LIST,
            _('IP Addresses to add to Allowed-Address-Pairs'),
            required=True,
            update_allowed=False
        ),
        MAC_ADDRESSES: properties.Schema(
            properties.Schema.LIST,
            _('MAC Addresses to add to Allowed-Address-Pairs'),
            required=False,
            update_allowed=False
        )
    }

    def handle_create(self):
        '''Replace the allowed-address-pairs on a Neutron Port.

        :raises: ResourceFailure
        '''
        port_id = self.properties[self.PORT]
        ip_addresses = self.properties[self.IP_ADDRESSES]
        mac_addresses = self.properties[self.MAC_ADDRESSES]
        if not mac_addresses:
            mac_addresses = []
        allowedaddresses = []
        for idx, ip_address in enumerate(ip_addresses):
            if idx < len(mac_addresses):
                allowedaddresses.append({'ip_address': ip_address,
                                         'mac_address': mac_addresses[idx]})
            else:
                allowedaddresses.append({'ip_address': ip_address})
        self.client().update_port(
            port_id,
            {'port': {'allowed_address_pairs': allowedaddresses}}
        )

    def handle_delete(self):
        '''Removes all allowed-address-pairs from a Neutron Port.

        :raises: ResourceFailure
        '''
        port_id = self.properties[self.PORT]
        self.client().update_port(
            port_id,
            {'port': {'allowed_address_pairs': []}}
        )

    def check_create_complete(self, ip_address):
        return True


def resource_mapping():
    return {'F5::Neutron::HAPort': F5NeutronHAPort}
