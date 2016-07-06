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
from heat.common import exception
from heat.common.i18n import _
from heat.engine import properties
from heat.engine import attributes
from heat.engine import resource

from common.mixins import F5BigIQMixin
from common.mixins import F5BigIPMixin
from common.mixins import f5_bigip
from common.mixins import f5_bigiq


class BigIQInvalidLicensePool(Exception):
    pass


class BigIQLicenseTimeout(Exception):
    pass


class F5BigIQLicensePoolUnmanagedMember(resource.Resource,
                                        F5BigIQMixin, F5BigIPMixin):
    '''Manages unmanaged pool members in a F5® BigIQ License Pool.'''

    PROPERTIES = (
        LICENSE_POOL_NAME,
        BIGIQ_SERVER,
        BIGIP_SERVER
    ) = (
        'license_pool_name',
        'bigiq_server',
        'bigip_server',
    )

    properties_schema = {
        LICENSE_POOL_NAME: properties.Schema(
            properties.Schema.STRING,
            _('Name of the license pool resource.'),
            required=True
        ),
        BIGIQ_SERVER: properties.Schema(
            properties.Schema.STRING,
            _('Reference to the BigIQ server resource.'),
            required=True
        ),
        BIGIP_SERVER: properties.Schema(
            properties.Schema.STRING,
            _('Reference to the BigIP server resource.'),
            required=True
        )
    }

    ATTRIBUTES = (
        LICENSE_UUID
    ) = (
        'license_uuid'
    )

    attributes_schema = {
        LICENSE_UUID: attributes.Schema(
           _('License UUID.'),
           attributes.Schema.STRING
        )
    }

    def _resolve_attribute(self, name):
        if name == self.LICENSE_UUID:
            return self.resource_id

    @f5_bigip
    @f5_bigiq
    def handle_create(self):
        '''Create the BIG-IQ® License Pool unmanaged member.

        :rasies: ResourceFailure
        '''

        try:
            bigip_hostname = self.bigip._meta_data['hostname']
            bigip_username = self.bigip._meta_data['username']
            bigip_password = self.bigip._meta_data['password']

            found_pool = False
            member = None

            pools = self.bigiq.cm.shared.licensing.pools_s.get_collection()
            for pool in pools:
                if pool.name == self.properties[self.LICENSE_POOL_NAME]:
                    self.pooluuid = pool.uuid
                    member = pool.license_unmanaged_device(
                        hostname=bigip_hostname,
                        username=bigip_username,
                        password=bigip_password
                    )
                    self.member = member
                    found_pool = True
            if not found_pool:
                raise exception.ResourceFailure(
                    BigIQInvalidLicensePool(
                        'License pool %s not found' %
                        self.properties[self.LICENSE_POOL_NAME]
                    ),
                    None,
                    action='CREATE'
                )
        except Exception as ex:
            raise exception.ResourceFailure(ex, None, action='CREATE')
        finally:
            if member is not None:
                self.resource_id_set(member.uuid)

        return self.resource_id

    def check_create_complete(self, license_uuid):
        ''' Check device if device is licensed with license UUID '''
        self.member.refresh()
        if self.member.state.lower() == 'licensed':
            return True
        return False

    @f5_bigip
    @f5_bigiq
    def handle_delete(self):
        '''Delete the BIG-IP® LTM Pool resource on the given device.

        :raises: ResourceFailure
        '''
        if self.resource_id is not None:
            try:
                pools = self.bigiq.cm.shared.licensing.pools_s.get_collection()
                found_pool = False
                for pool in pools:
                    if pool.name == self.properties[self.LICENSE_POOL_NAME]:
                        members = pool.members_s.get_collection()
                        for member in members:
                            if member.uuid == self.resource_id:
                                bigip_username = \
                                    self.bigip._meta_data['username']
                                bigip_password = \
                                    self.bigip._meta_data['password']
                                member.delete(
                                    username=bigip_username,
                                    password=bigip_password
                                )
                    found_pool = True
                if not found_pool:
                    raise exception.ResourceFailure(
                        BigIQInvalidLicensePool(
                            'License pool %s not found' %
                            self.properties[self.LICENSE_POOL_NAME]
                        ),
                        None,
                        action='DELETE'
                    )
            except Exception as ex:
                    raise exception.ResourceFailure(ex, None, action='DELETE')
        return True


def resource_mapping():
    return {'F5::BigIQ::LicensePoolUnmanagedMember':
            F5BigIQLicensePoolUnmanagedMember}
