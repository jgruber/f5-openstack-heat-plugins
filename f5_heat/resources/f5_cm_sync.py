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
from time import sleep

from heat.common import exception
from heat.common.i18n import _
from heat.engine import properties
from heat.engine import resource

from __builtin__ import True


class F5CmSync(resource.Resource):
    '''Sync the device configuration to the device group.'''

    PROPERTIES = (
        DEVICES,
        DELAY_BETWEEN_ATTEMPTS,
        MAX_ATTEMPTS
    ) = (
        'devices',
        'delay_between_attempts',
        'max_attempts'
    )

    properties_schema = {
        DEVICES: properties.Schema(
            properties.Schema.LIST,
            _('BigIP resource references for devices to sync.'),
            required=True,
            update_allowed=True
        ),
        DELAY_BETWEEN_ATTEMPTS: properties.Schema(
            properties.Schema.INTEGER,
            _('Seconds to wait between sync queries'),
            required=10,
            default=True
        ),
        MAX_ATTEMPTS: properties.Schema(
            properties.Schema.INTEGER,
            _('Maximum number of connection attempts to try'),
            required=False,
            default=10
        )
    }

    def _set_devices(self):
        '''Retrieve the BIG-IP® connection from the F5::BigIP resource.'''

        self.devices = []
        for device in self.properties[self.DEVICES]:
            self.devices.append(
                self.stack.resource_by_refid(device).get_bigip()
            )

    def _sync_all(self, bigip):
        dgs = bigip.tm.cm.device_groups.get_collection()
        for dg in dgs:
            if dg.autoSync == 'disabled':
                config_sync_cmd = 'config-sync to-group {}'.format(
                    dg.name
                )
                self.bigip.tm.cm.exec_cmd(
                    'run', utilCmdArgs=config_sync_cmd
                )

    def _sync_recommended(self):
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
                parse_recommed = desc.split('Recommended action: Synchronize')
                if len(parse_recommed) > 1:
                    parse_device_and_group = \
                        parse_recommed[1].split(' to group ')
                    if len(parse_device_and_group) > 1:
                        device_name = parse_device_and_group[0]
                        device_group_name = parse_device_and_group[1]
                        for device in self.devices:
                            ds = device.tm.cm.devices.get_collection()
                            for d in ds:
                                if d.name == device_name and \
                                   d.selfDevice == 'true':
                                    config_sync_cmd = \
                                        'config-sync to-group {}'.format(
                                            device_group_name
                                        )
                                    device.tm.cm.exec_cmd(
                                        'run', utilCmdArgs=config_sync_cmd
                                    )
                                    return True
                        else:
                            # no device in matched recommendation
                            return False
                    else:
                        # could not parse device group to sync
                        return False
                else:
                    # could not parse the recommendation
                    return False
            else:
                # no recommendation present
                return False

    def handle_create(self):
        '''Sync the configuration on the BIG-IP® devices.

        :raises: ResourceFailure exception
        '''
        self._set_devices()

        if(len(self.devices) < 2):
            return True

        try:
            number_of_attempts = 0
            sync_status = self.devices[0].tm.cm.sync_status
            while(number_of_attempts < self.properties[self.MAX_ATTEMPTS]):
                sync_status.refresh()
                if sync_status.lower() == 'in sync':
                    return True
                else:
                    if not self._sync_recommended():
                        self._sync_all(self.devices[0])
                    sleep(self.propertied[self.DELAY_BETWEEN_ATTEMPTS])
                    number_of_attempts += 1
            raise exception.ResourceFailure(
                'Sync failed after %d attempts' % self.properties[
                    self.MAX_ATTEMPTS
                ],
                None,
                action='CREATE'
            )
        except Exception as ex:
            raise exception.ResourceFailure(ex, None, action='CREATE')


def resource_mapping():
    return {'F5::Cm::Sync': F5CmSync}
