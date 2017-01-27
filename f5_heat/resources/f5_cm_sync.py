# coding=utf-8
#
# Copyright 2016 F5 Networks Inc.
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

from heat.common import exception
from heat.common.i18n import _
from heat.engine import properties
from heat.engine import resource

from f5.multi_device.cluster import DeviceGroup


class F5CmSync(resource.Resource):
    '''Sync the device configuration to the device group.'''

    PROPERTIES = (
        DEVICES,
        DEVICE_GROUP_NAME,
        DEVICE_GROUP_PARTITION,
        DEVICE_GROUP_TYPE
    ) = (
        'devices',
        'device_group_name',
        'device_group_partition',
        'device_group_type'
    )

    properties_schema = {
        DEVICES: properties.Schema(
            properties.Schema.LIST,
            _('BigIP resource references for devices to sync.'),
            required=True,
            update_allowed=True
        ),
        DEVICE_GROUP_NAME: properties.Schema(
            properties.Schema.STRING,
            _('Name of the device group to sync BIG-IP device to.'),
            required=True
        ),
        DEVICE_GROUP_PARTITION: properties.Schema(
            properties.Schema.STRING,
            _('Partition name where device group is located on the device.'),
            required=True
        ),
        DEVICE_GROUP_TYPE: properties.Schema(
            properties.Schema.STRING,
            _('The type of cluster to create (sync-failover)'),
            default='sync-failover',
            required=False
        )
    }

    def _set_devices(self):
        '''Retrieve the BIG-IP® connection from the F5::BigIP resource.'''

        self.devices = []
        for device in self.properties[self.DEVICES]:
            self.devices.append(
                self.stack.resource_by_refid(device).get_bigip()
            )

    def handle_create(self):
        '''Sync the configuration on the BIG-IP® device to the device group.

        :raises: ResourceFailure exception
        '''

        try:
            self._set_devices()
            dg_name = self.properties[self.DEVICE_GROUP_NAME]
            dg_partition = self.properties[self.DEVICE_GROUP_PARTITION]
            dg_type = self.properties[self.DEVICE_GROUP_TYPE]
            DeviceGroup(
                devices=self.devices,
                device_group_name=dg_name,
                device_group_type=dg_type,
                device_group_partition=dg_partition
            )
            return True
        except Exception as ex:
            raise exception.ResourceFailure(ex, None, action='CREATE')

    def handle_delete(self):
        '''Delete sync resource, which has no communication with the device.'''

        return True


def resource_mapping():
    return {'F5::Cm::Sync': F5CmSync}