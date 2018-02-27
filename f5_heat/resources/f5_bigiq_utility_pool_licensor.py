'''Manages F5 BIG-IQ License Resource for BIG-IPs.'''
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
from oslo_log import helpers as log_helpers

from f5_heat.licensors.bigiq.bigiq_host import F5BigIQHost
from f5_heat.licensors.bigiq.bigiq_pool_member import F5BigIQLicensePoolMember
from f5_heat.licensors.bigiq.utility_pool import UtilityPoolLicensor

from f5_heat.licensors.bigiq.exceptions import PoolNotFoundException
from f5_heat.licensors.bigiq.exceptions import NoOfferingAvailable
from f5_heat.licensors.bigiq.exceptions import MemberNotFoundException

from heat.common import exception
from heat.common.i18n import _
from heat.engine import attributes
from heat.engine import properties
from heat.engine import resource
from heat.engine import support


class F5BigIQUtilityPoolLicensor(resource.Resource):  #pylint: disable=too-many-instance-attributes
    '''Manages F5 BIG-IQ License Resource for BIG-IPs.'''

    support_status = support.SupportStatus(version='2014.1')

    PROPERTIES = (
        BIGIQ_HOST,
        BIGIQ_USERNAME,
        BIGIQ_PASSWORD,
        BIGIQ_CONNECTION_TIMEOUT,
        BIGIQ_LICENSE_POOL_NAME,
        BIGIQ_LICENSE_TYPE,
        BIGIP_MANAGEMENT_IP,
        BIGIP_MANAGEMENT_PORT,
        BIGIP_USERNAME,
        BIGIP_PASSWORD
    ) = (
        'bigiq_host',
        'bigiq_username',
        'bigiq_password',
        'biqiq_connection_timeout',
        'bigiq_license_pool_name',
        'bigiq_license_type',
        'bigip_management_ip',
        'bigip_management_port',
        'bigip_username',
        'bigip_password'
    )

    CONNECTION_TIMEOUT = 10

    properties_schema = {
        BIGIQ_HOST: properties.Schema(
            properties.Schema.STRING,
            _('BIGIQ hostname or IP address.'),
            required=True
        ),
        BIGIQ_USERNAME: properties.Schema(
            properties.Schema.STRING,
            _('BIGIQ Username.'),
            required=True,
            default='admin'
        ),
        BIGIQ_PASSWORD: properties.Schema(
            properties.Schema.STRING,
            _('BIGIQ Password.'),
            required=True
        ),
        BIGIQ_CONNECTION_TIMEOUT: properties.Schema(
            properties.Schema.INTEGER,
            _('Seconds to wait for BIG-IQ to connect.'),
            required=True,
            default=10
        ),
        BIGIQ_LICENSE_POOL_NAME: properties.Schema(
            properties.Schema.STRING,
            _('BIGIQ Pool to License BIG-IPs.'),
            required=True
        ),
        BIGIQ_LICENSE_TYPE: properties.Schema(
            properties.Schema.STRING,
            _('BIGIQ License Type for BIG-IPs.'),
            required=True
        ),
        BIGIP_MANAGEMENT_IP: properties.Schema(
            properties.Schema.STRING,
            _('BIGIP hostname or IP address to license.'),
            required=True
        ),
        BIGIP_MANAGEMENT_PORT: properties.Schema(
            properties.Schema.INTEGER,
            _('BIGIP management TCP port.'),
            required=True,
            default=443
        ),
        BIGIP_USERNAME: properties.Schema(
            properties.Schema.STRING,
            _('BIGIP Username.'),
            required=True,
            default='admin'
        ),
        BIGIP_PASSWORD: properties.Schema(
            properties.Schema.STRING,
            _('BIGIP Password.'),
            required=True
        )
    }

    ATTRIBUTES = (
        POOL_UUID,
        LICENSE_TYPE,
        LICENSE_TERM,
        OFFERING_UUID,
        LICENSE_UUID
    ) = (
        'pool_uuid',
        'license_type',
        'license_term',
        'offering_uuid',
        'license_uuid'
    )

    attributes_schema = {
        POOL_UUID: attributes.Schema(
           _('POOL UUID.'),
           type=attributes.Schema.STRING,
           support_status=support.SupportStatus(version='5.0.0')
        ),
        LICENSE_TYPE: attributes.Schema(
           _('LICENSE_TYPE.'),
           type=attributes.Schema.STRING,
           support_status=support.SupportStatus(version='5.0.0')
        ),
        LICENSE_TERM: attributes.Schema(
           _('LICENSE_TERM.'),
           type=attributes.Schema.STRING,
           support_status=support.SupportStatus(version='5.0.0')
        ),
        OFFERING_UUID: attributes.Schema(
           _('OFFERING_UUID.'),
           type=attributes.Schema.STRING,
           support_status=support.SupportStatus(version='5.0.0')
        ),
        LICENSE_UUID: attributes.Schema(
           _('License UUID.'),
           type=attributes.Schema.STRING,
           support_status=support.SupportStatus(version='5.0.0')
        )
    }

    licensor = None

    def _resolve_attribute(self, name):
        if self.resource_id is None:
            return
        if name == self.POOL_UUID:
            if self.licensor:
                return self.licensor.pool_uuid
        if name == self.LICENSE_TYPE:
            if self.licensor:
                return self.licensor.license_type
        if name == self.LICENSE_TERM:
            if self.licensor:
                return self.licensor.license_term
        if name == self.OFFERING_UUID:
            if self.licensor:
                return self.licensor.offering_uuid
        if name == self.LICENSE_UUID:
            if self.licensor:
                return self.licensor.member_uuid

    def get_reference_id(self):
        return resource.Resource.get_reference_id(self)

    @log_helpers.log_method_call
    def handle_create(self):
        '''License a BIG-IP from a BIG-IQ pool

        :raises: ResourceFailure exception
        '''
        try:
            bigiq = F5BigIQHost(
                bigiq_host=self.properties[self.BIGIQ_HOST],
                bigiq_username=self.properties[self.BIGIQ_USERNAME],
                bigiq_password=self.properties[self.BIGIQ_PASSWORD],
                bigiq_timeout=self.properties[self.BIGIQ_CONNECTION_TIMEOUT]
            )
            member = F5BigIQLicensePoolMember(
                bigiq_license_pool_name=self.properties[
                    self.BIGIQ_LICENSE_POOL_NAME],
                bigip_management_ip=self.properties[self.BIGIP_MANAGEMENT_IP],
                bigip_management_port=self.properties[
                    self.bigip_management_port],
                bigip_username=self.properties[self.BIGIP_USERNAME],
                bigip_password=self.properties[self.BIGIP_PASSWORD]
            )
            self.licensor = UtilityPoolLicensor(
                bigiq, member, self.properties[self.LICENSE_TYPE])
            self.licensor.activate_license()
        except Exception as ex:
            raise exception.ResourceFailure(ex, None, action='CREATE')
        return True

    @log_helpers.log_method_call
    def handle_delete(self):
        '''Unlicense a BIG-IP and release the license in the pool.

        :raises: ResourceFailure exception
        '''
        if self.resource_id is None:
            return True
        try:
            bigiq = F5BigIQHost(
                bigiq_host=self.properties[self.BIGIQ_HOST],
                bigiq_username=self.properties[self.BIGIQ_USERNAME],
                bigiq_password=self.properties[self.BIGIQ_PASSWORD],
                bigiq_timeout=self.properties[self.BIGIQ_CONNECTION_TIMEOUT]
            )
            member = F5BigIQLicensePoolMember(
                bigiq_license_pool_name=self.properties[
                    self.BIGIQ_LICENSE_POOL_NAME],
                bigip_management_ip=self.properties[self.BIGIP_MANAGEMENT_IP],
                bigip_management_port=self.properties[
                    self.bigip_management_port],
                bigip_username=self.properties[self.BIGIP_USERNAME],
                bigip_password=self.properties[self.BIGIP_PASSWORD]
            )
            self.licensor = UtilityPoolLicensor(
                bigiq, member, self.properties[self.LICENSE_TYPE])
            self.licensor.revoke_license()
        except PoolNotFoundException:
            # always allow delete, error will be logged
            pass
        except MemberNotFoundException:
            # always allow delete, error will be logged
            pass
        except NoOfferingAvailable:
            # always allow delete, error will be logged
            pass
        except Exception as ex:
            raise exception.ResourceFailure(ex, None, action='DELETE')
        return True


def resource_mapping():
    ''' Registration for Heat Resource '''
    return {'F5::BigIQ::UtilityPoolLicensor':
            F5BigIQUtilityPoolLicensor}
