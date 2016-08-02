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
import os
import logging

from time import sleep

from heat.common import exception
from heat.common.i18n import _
from heat.engine import properties
from heat.engine import resource

from f5.multi_device.cluster import ClusterManager
from f5.multi_device import exceptions as de
from f5.sdk_exception import F5SDKError


class UpdateNotAllowed(object):
    pass


class F5CmCluster(resource.Resource):
    '''Manages creation of the F5::Cm::Cluster resource.'''

    PROPERTIES = (
        DEVICE_GROUP_NAME,
        DEVICES,
        DEVICE_GROUP_PARTITION,
        DEVICE_GROUP_TYPE,
        CONTINUE_ON_ERROR,
        DELAY_BETWEEN_ATTEMPTS,
        MAX_ATTEMPTS
    ) = (
        'device_group_name',
        'devices',
        'device_group_partition',
        'device_group_type',
        'continue_on_error',
        'delay_between_attempts',
        'max_attempts'
    )

    properties_schema = {
        DEVICE_GROUP_NAME: properties.Schema(
            properties.Schema.STRING,
            _('Name of the template.'),
            required=True
        ),
        DEVICES: properties.Schema(
            properties.Schema.LIST,
            _('BigIP resource references for devices to cluster.'),
            required=True,
            update_allowed=True
        ),
        DEVICE_GROUP_PARTITION: properties.Schema(
            properties.Schema.STRING,
            _('Partition where device group will be deployed.'),
            default='Common',
            required=False
        ),
        DEVICE_GROUP_TYPE: properties.Schema(
            properties.Schema.STRING,
            _('The type of cluster to create (sync-failover)'),
            default='sync-failover',
            required=False
        ),
        CONTINUE_ON_ERROR: properties.Schema(
            properties.Schema.BOOLEAN,
            _('Continue to try and connect despite network errors'),
            required=False,
            default=True
        ),
        DELAY_BETWEEN_ATTEMPTS: properties.Schema(
            properties.Schema.INTEGER,
            _('Seconds to wait between connection attempts'),
            required=5,
            default=True
        ),
        MAX_ATTEMPTS: properties.Schema(
            properties.Schema.INTEGER,
            _('Maximum number of connection attempts to try'),
            required=False,
            default=360
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
        '''Create the device service group (cluster) of devices.

        :raises: ResourceFailure
        '''

        self._set_devices()
        try:
            resource_id = '%s/%s' % (
                self.properties[self.DEVICE_GROUP_PARTITION],
                self.properties[self.DEVICE_GROUP_NAME]
            )
            cluster_mgr = ClusterManager()
            if self.properties[self.CONTINUE_ON_ERROR]:
                number_of_attempts = 0
                while(number_of_attempts < self.properties[self.MAX_ATTEMPTS]):
                    try:
                        cluster_mgr.create(
                            devices=self.devices,
                            device_group_name=self.properties[
                                self.DEVICE_GROUP_NAME
                            ],
                            device_group_partition=self.properties[
                                self.DEVICE_GROUP_PARTITION
                            ],
                            device_group_type=self.properties[
                                self.DEVICE_GROUP_TYPE
                            ]
                        )
                        self.resource_id_set(resource_id)
                        return self.resource_id
                    except de.DeviceNamesNotUnique:
                        self._rename_devices(self.devices)
                    except de.DeviceConfigSyncInterfaceNotConfigured:
                        self._configure_device_ha_interfaces(self.devices)
                    except de.DeviceInvalidState:
                        pass
                    except Exception as le:
                        logging.ERROR('exception in clustering attempt %s'
                                      % (le.message))
                        number_of_attempts += 1
                    sleep(self.properties[self.DELAY_BETWEEN_ATTEMPTS])
                if not self.resource_id:
                    raise exception.ResourceFailure(
                        'Clustering failed after %d attempts'
                        % self.properties[self.MAX_ATTEMPTS]
                    )
            else:
                cluster_mgr.create(
                    devices=self.devices,
                    device_group_name=self.properties[self.DEVICE_GROUP_NAME],
                    device_group_partition=self.properties[
                        self.DEVICE_GROUP_PARTITION
                    ],
                    device_group_type=self.properties[self.DEVICE_GROUP_TYPE]
                )
                self.resource_id_set(resource_id)
                return self.resource_id
        except F5SDKError as ex:
            raise exception.ResourceFailure(ex, None, action='CREATE')

    def handle_delete(self):
        '''Teardown the device service group (cluster).

        :raises: ResourceFailure
        '''
        if self.resource_id is not None:
            self._set_devices()
            try:
                if self.properties[self.CONTINUE_ON_ERROR]:
                    number_of_attempts = 0
                    while(number_of_attempts <
                          self.properties[self.MAX_ATTEMPTS]):
                        try:
                            cluster_mgr = ClusterManager(
                                devices=self.devices,
                                device_group_name=self.properties[
                                    self.DEVICE_GROUP_NAME
                                ],
                                device_group_partition=self.properties[
                                    self.DEVICE_GROUP_PARTITION
                                ],
                                device_group_type=self.properties[
                                    self.DEVICE_GROUP_TYPE
                                ]
                            )
                            cluster_mgr.teardown()
                        except de.DeviceInvalidState:
                            pass
                        sleep(self.properties[self.DELAY_BETWEEN_ATTEMPTS])
                else:
                    cluster_mgr = ClusterManager(
                        devices=self.devices,
                        device_group_name=self.properties[
                            self.DEVICE_GROUP_NAME
                        ],
                        device_group_partition=self.properties[
                            self.DEVICE_GROUP_PARTITION
                        ],
                        device_group_type=self.properties[
                            self.DEVICE_GROUP_TYPE
                        ]
                    )
                    cluster_mgr.teardown()
            except F5SDKError as ex:
                raise exception.ResourceFailure(ex, None, action='DELETE')
        return True

    def _rename_devices(self, devices):
        for device in devices:
            ds = device.tm.cm.devices.get_collection()
            for d in ds:
                if d.selfDevice == 'true':
                    device_name = str(d.managementIp).replace('.', '_')
                    cmd = "tmsh mv cm device %s %s" % (d.name, device_name)
                    logging.debug('Running: %s' % cmd)
                    device.tm.util.bash(cmd)

    def _configure_device_ha_interfaces(self, devices):
        for device in devices:
            ds = device.tm.cm.devices.get_collection()
            for d in ds:
                set_ha = False
                if d.selfDevice == 'true':
                    selfips = device.tm.net.selfips.get_collection()
                    for selfip in selfips:
                        vlan = device.tm.net.vlans.vlan.load(
                            name=os.path.basename(selfip.vlan)
                        )
                        interfaces = vlan.interfaces_s.get_collection()
                        for interface in interfaces:
                            if interface.name == '1.1':
                                ha_ip = os.path.dirname(selfip.address)
                                d.configsyncIp = ha_ip
                                unicast_ip = [
                                    {'effectiveIp': ha_ip,
                                     'effectivePort': 1026,
                                     'ip': ha_ip,
                                     'port': 1026}
                                ]
                                d.unicastAddress = unicast_ip
                                d.update()
                                set_ha = True
                                break
                if not set_ha:
                    raise de.DeviceConfigSyncInterfaceNotConfigured(
                        "no valid HA interface for device %s" % d.name
                    )


def resource_mapping():
    return {'F5::Cm::Cluster': F5CmCluster}
