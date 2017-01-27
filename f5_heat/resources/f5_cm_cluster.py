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
from f5.sdk_exception import F5SDKError
from f5.multi_device.exceptions import DeviceNotTrusted


class DeviceNameNotUnique(Exception):
    '''device name is not unique.'''
    def __init__(self, *args, **kwargs):
        super(DeviceNameNotUnique, self).__init__(*args, **kwargs)


class DeviceMissingHAInterface(Exception):
    '''device name is not unique.'''
    def __init__(self, *args, **kwargs):
        super(DeviceMissingHAInterface, self).__init__(*args, **kwargs)


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
        MAX_ATTEMPTS,
        HA_INTERFACE,
        IGNORE_DELETE
    ) = (
        'device_group_name',
        'devices',
        'device_group_partition',
        'device_group_type',
        'continue_on_error',
        'delay_between_attempts',
        'max_attempts',
        'ha_interface',
        'ignore_delete'
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
            required=False,
            default=5
        ),
        MAX_ATTEMPTS: properties.Schema(
            properties.Schema.INTEGER,
            _('Maximum number of connection attempts to try'),
            required=False,
            default=360
        ),
        HA_INTERFACE: properties.Schema(
            properties.Schema.STRING,
            _('TMOS interface to use for device group sync'),
            required=False,
            default=None
        ),
        IGNORE_DELETE: properties.Schema(
            properties.Schema.BOOLEAN,
            _('Do not remove device group on resource delete'),
            required=False,
            default=False
        )
    }

    def _set_devices(self):
        '''Retrieve the BIG-IP® connection from the F5::BigIP resource.'''

        self.devices = []
        for device in self.properties[self.DEVICES]:
            self.devices.append(
                self.stack.resource_by_refid(device).get_bigip()
            )

    def _assure_device_names(self):
        '''Assure that all devices have unique device names.'''
        try:
            device_names = []
            for d in self.devices:
                known_devices = d.tm.cm.devices.get_collection()
                for kd in known_devices:
                    if kd.selfDevice:
                        if kd.name in device_names:
                            raise DeviceNameNotUnique(kd.name)
                        else:
                            device_names.append(kd.name)
        except DeviceNameNotUnique:
            try:
                self._rename_devices(self.devices)
            except Exception as ex:
                raise exception.ResourceFailure(ex, None, action='CREATE')
        except Exception as ex:
            sdex = F5SDKError(
                "Could not rename devices while creating cluster: %s" %
                ex.message
            )
            raise exception.ResourceFailure(sdex, None, action='CREATE')

    def _rename_devices(self, devices):
        '''Rename all devices to make them unique.'''
        for device in devices:
            ds = device.tm.cm.devices.get_collection()
            for d in ds:
                if d.selfDevice == 'true':
                    device_name = str(d.managementIp).replace('.', '_')
                    cmd = "tmsh mv cm device %s %s" % (d.name, device_name)
                    bash_cmd = "-c '%s'" % cmd
                    logging.debug('Running: %s' % cmd)
                    device.tm.util.bash.exec_cmd(
                        'run',
                        utilCmdArgs=bash_cmd
                    )

    def _assure_ha_interface(self):
        '''Assure that all devices have their HA interface set.'''
        try:
            if self.properties[self.HA_INTERFACE]:
                self._configure_device_ha_interfaces(
                    self.devices, self.HA_INTERFACE
                )
            else:
                for d in self.devices:
                    known_devices = d.tm.cm.devices.get_collection()
                    for kd in known_devices:
                        if kd.configsyncIp == 'none':
                            raise DeviceMissingHAInterface(kd.name)
        except DeviceMissingHAInterface:
            try:
                self._configure_device_ha_interfaces(self.devices, '1.1')
            except Exception as ex:
                raise exception.ResourceFailure(ex, None, action='CREATE')
        except Exception as ex:
            sdex = F5SDKError(
                "Could not rename devices while creating cluster: %s" %
                ex.message
            )
            raise exception.ResourceFailure(sdex, None, action='CREATE')

    def _configure_device_ha_interfaces(self, devices, ha_int=None):
        '''Configure HA interface on all devices'''
        ha_interface = self.properties[self.HA_INTERFACE]
        if not ha_interface:
            ha_interface = '1.1'
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
                            if interface.name == ha_interface:
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
                    raise F5SDKError(
                        "no valid HA interface for device %s" % d.name
                    )

    def handle_create(self):
        '''Create the device service group (cluster) of devices.

        :raises: ResourceFailure
        '''
        # load devices
        try:
            self._set_devices()
        except Exception as ex:
            sdex = Exception(
                "Could not discover devices while creating cluster: %s" %
                ex.message
            )
            raise exception.ResourceFailure(sdex, None, action='CREATE')

        self._assure_device_names()
        self._assure_ha_interface()

        # cluster devices
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
                    except Exception as le:
                        logging.error('exception in clustering attempt %s'
                                      % (le.message))
                        number_of_attempts += 1
                        try:
                            cluster_mgr.teardown()
                        except Exception as cte:
                            logging.error('Error tearing down cluster %s'
                                          % (cte.message))
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
        if not hasattr(self, 'bigip'):
            return True

        if self.resource_id is not None:
            if self.properties[self.IGNORE_DELETE]:
                return True
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
                        except Exception:
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
            except DeviceNotTrusted:
                logging.error('devices are no longer in a trust relationship')
                return True
            except F5SDKError as ex:
                raise exception.ResourceFailure(ex, None, action='DELETE')
        return True


def resource_mapping():
    return {'F5::Cm::Cluster': F5CmCluster}
