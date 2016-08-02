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

from time import sleep

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


class BigIQLicenseFailure(Exception):
    pass


class F5BigIQLicensePoolUnmanagedMember(resource.Resource,
                                        F5BigIQMixin, F5BigIPMixin):
    '''Manages unmanaged pool members in a F5® BigIQ License Pool.'''

    PROPERTIES = (
        LICENSE_POOL_NAME,
        BIGIQ_SERVER,
        BIGIP_SERVER,
        CONTINUE_ON_ERROR,
        DELAY_BETWEEN_ATTEMPTS,
        MAX_ATTEMPTS
    ) = (
        'license_pool_name',
        'bigiq_server',
        'bigip_server',
        'continue_on_error',
        'delay_between_attempts',
        'max_attempts'
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
            target_pool = None
            pools = self.bigiq.cm.shared.licensing.pools_s.get_collection()
            for pool in pools:
                if pool.name == self.properties[self.LICENSE_POOL_NAME]:
                    self.pooluuid = pool.uuid
                    target_pool = pool
                    found_pool = True
                    break
            if not found_pool:
                raise exception.ResourceFailure(
                    BigIQInvalidLicensePool(
                        'License pool %s not found' %
                        self.properties[self.LICENSE_POOL_NAME]
                    ),
                    None,
                    action='CREATE'
                )

            if self.properties[self.CONTINUE_ON_ERROR]:
                number_of_attempts = 0
                while(number_of_attempts < self.properties[self.MAX_ATTEMPTS]):
                    try:
                        member = target_pool.license_unmanaged_device(
                            hostname=bigip_hostname,
                            username=bigip_username,
                            password=bigip_password
                        )
                        break
                    except Exception as le:
                        logging.ERROR('exception in licensing attempt %s'
                                      % (le.message))
                        number_of_attempts += 1
                    logging.ERROR('sleeping')
                    sleep(self.properties[self.DELAY_BETWEEN_ATTEMPTS])
                if member is None:
                    raise BigIQLicenseFailure(
                        'Failed after %d attempts'
                        % self.properties[self.MAX_ATTEMPTS]
                    )
            else:
                member = target_pool.license_unmanaged_device(
                    hostname=bigip_hostname,
                    username=bigip_username,
                    password=bigip_password
                )
        except Exception as ex:
            raise exception.ResourceFailure(ex, None, action='CREATE')
        finally:
            if member is not None:
                self.member = member
                self.resource_id_set(member.uuid)
        return self.resource_id

    def check_create_complete(self, license_uuid):
        ''' Check device if device is licensed with license UUID '''
        self.member.refresh()
        if self.member.state.lower() == 'licensed':
            return True
        if self.member.state.lower() == 'failed':
            raise BigIQLicenseFailure(self.member.errorText)
        return False

    @f5_bigip
    @f5_bigiq
    def handle_delete(self):
        '''Delete the BIG-IP® LTM Pool resource on the given device.

        :raises: ResourceFailure
        '''
        if self.resource_id is not None:
            try:
                logging.warning('query bigiq for license pools')
                pools = self.bigiq.cm.shared.licensing.pools_s.get_collection()
                logging.warning('bigiq returned pool collection')
                found_pool = False
                for pool in pools:
                    if pool.name == self.properties[self.LICENSE_POOL_NAME]:
                        logging.warning('found pool %s' % pool.name)
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
                                return True
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
