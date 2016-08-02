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

from common.mixins import f5_bigip
from common.mixins import F5BigIPMixin


class F5CmSync(resource.Resource, F5BigIPMixin):
    '''Sync the device configuration to the device group.'''

    PROPERTIES = (
        BIGIP_SERVER,
        DEVICE_GROUP,
        DEVICE_GROUP_PARTITION
    ) = (
        'bigip_server',
        'device_group',
        'device_group_partition'
    )

    properties_schema = {
        BIGIP_SERVER: properties.Schema(
            properties.Schema.STRING,
            _('Reference to the BigIP Server resource.'),
            required=True
        ),
        DEVICE_GROUP: properties.Schema(
            properties.Schema.STRING,
            _('Name of the device group to sync BIG-IP device to.'),
            required=False
        ),
        DEVICE_GROUP_PARTITION: properties.Schema(
            properties.Schema.STRING,
            _('Partition name where device group is located on the device.'),
            required=False
        )
    }

    @f5_bigip
    def handle_create(self):
        '''Sync the configuration on the BIG-IP® device to the device group.

        :raises: ResourceFailure exception
        '''

        try:
            sync_status = self._get_sync_status(
                device_group_name=None
            )
            if not sync_status == 'in sync':
                (device_name, device_group) = self._get_recommended_sync()
                
                
            dgs = self.bigip.tm.cm.device_groups.get_collection()
            # until iControl REST support visibility into
            # each device group's sync state, you must sync
            # all non autoSync groups to make global
            # state maching 'in-sync'.
            for dg in dgs:
                if dg.autoSync == 'disabled':
                    config_sync_cmd = 'config-sync to-group {}'.format(
                        dg.name
                    )
                    self.bigip.tm.cm.exec_cmd(
                        'run', utilCmdArgs=config_sync_cmd
                    )
            sync_status = self.bigip.tm.cm.sync_status
            sync_status.refresh()
            
                    
        except Exception as ex:
            raise exception.ResourceFailure(ex, None, action='CREATE')

    def _get_sync_status(self, device_group_name):
        sync_status = self.bigip.tm.cm.sync_status
        sync_status.refresh()
        status = \
            (sync_status.entries['https://localhost/mgmt/tm/cm/sync-status/0']
             ['nestedStats']['entries']['status']['description'])
        return status.lower()

    def _get_recommended_sync(self):
        sync_status = self.bigip.tm.cm.sync_status
        sync_status.refresh()
        details = (sync_status.entries
                   ['https://localhost/mgmt/tm/cm/sync-status/0']
                   ['nestedStats']['entries']
                   ['https://localhost/mgmt/tm/cm/syncStatus/0/details']
                   ['nestedStats']['entries'])
        for detail in details:
            desc = (details[detail]['nestedStats']
                           ['entries']['details']['description'])
            if 'Recommended action' in desc:
                source_device = 


    @f5_bigip
    def check_create_complete(self, token):
        '''Determine whether the BIG-IP®'s sync status is 'In-Sync'.

        :raises: ResourceFailure
        '''

        sync_status = self.bigip.tm.cm.sync_status
        sync_status.refresh()
        status = \
            (sync_status.entries['https://localhost/mgmt/tm/cm/sync-status/0']
             ['nestedStats']['entries']['status']['description'])
        if status.lower() == 'in sync':
            return True
        return False

    def handle_delete(self):
        '''Delete sync resource, which has no communication with the device.'''

        return True


def resource_mapping():
    return {'F5::Cm::Sync': F5CmSync}
