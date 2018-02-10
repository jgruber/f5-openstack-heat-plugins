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
import json
import logging
import requests

from heat.common import exception
from heat.common.i18n import _
from heat.engine import attributes
from heat.engine import constraints
from heat.engine import properties
from heat.engine import resource
from heat.engine import support

from oslo_log import helpers as log_helpers

from time import sleep

class F5BigIQPurchasedPoolLicensor(resource.Resource):
    '''Manages F5® License Resources.'''

    support_status = support.SupportStatus(version='2014.1')

    PROPERTIES = (
        BIGIQ_HOST,
        BIGIQ_USERNAME,
        BIGIQ_PASSWORD,
        BIGIQ_CONNECTION_TIMEOUT,
        BIGIQ_LICENSE_POOL_NAME,
        BIGIP_MANAGEMENT_IP,
        BIGIP_USERNAME,
        BIGIP_PASSWORD
    ) = (
        'bigiq_host',
        'bigiq_username',
        'bigiq_password',
        'biqiq_connection_timeout',
        'bigiq_license_pool_name',
        'bigip_management_ip',
        'bigip_username',
        'bigip_password'
    )

    CONNECTION_TIMEOUT = 10

    properties_schema = {
        BIGIQ_HOST: properties.Schema(
            properties.Schema.STRING,
            _('BIGIQ hostname or IP address.'),
            required = True
        ),
        BIGIQ_USERNAME: properties.Schema(
            properties.Schema.STRING,
            _('BIGIQ Username.'),
            required = True,
            default = 'admin'
        ),
        BIGIQ_PASSWORD: properties.Schema(
            properties.Schema.STRING,
            _('BIGIQ Password.'),
            required = True
        ),
        BIGIQ_CONNECTION_TIMEOUT: properties.Schema(
            properties.Schema.INTEGER,
            _('Seconds to wait for BIG-IQ to connect.'),
            required = True,
            default = 10
        ),
        BIGIQ_LICENSE_POOL_NAME: properties.Schema(
            properties.Schema.STRING,
            _('BIGIQ Pool to License BIG-IPs.'),
            required = True
        ),
        BIGIP_MANAGEMENT_IP: properties.Schema(
            properties.Schema.STRING,
            _('BIGIP hostname or IP address to license.'),
            required = True
        ),
        BIGIP_USERNAME: properties.Schema(
            properties.Schema.STRING,
            _('BIGIP Username.'),
            required = True,
            default = 'admin'
        ),
        BIGIP_PASSWORD: properties.Schema(
            properties.Schema.STRING,
            _('BIGIP Password.'),
            required = True
        )
    }
    
    ATTRIBUTES = (
        POOL_UUID,
        LICENSE_UUID
    ) = (
        'pool_uuid',
        'license_uuid'
    )

    attributes_schema = {
        POOL_UUID: attributes.Schema(
           _('POOL UUID.'),
           type=attributes.Schema.STRING,
           support_status=support.SupportStatus(version='5.0.0')
        ),
        LICENSE_UUID: attributes.Schema(
           _('License UUID.'),
           type=attributes.Schema.STRING,
           support_status=support.SupportStatus(version='5.0.0')
        )
    }
        

    license_uuid = None
    pool_uuid = None

    def _resolve_attribute(self, name):
        if self.resource_id is None:
            return
        if name == self.POOL_UUID:
            return self.pool_UUID
        if name == self.LICENSE_UUID:
            return self.license_UUID
                       
    def get_reference_id(self):
        return resource.Resource.get_reference_id(self)

    def _license(self, bigiq_host, bigiq_username, 
                 bigiq_password, bigiq_timeout, 
                 bigiq_license_pool_name, bigip_management_ip, 
                 bigip_username, bigip_password):
        '''License BIG-IP from BIG-IQ Pool.

        :returns: license_uuid
        '''
        self._delete_member(bigiq_host, bigiq_username, 
                            bigiq_password, bigiq_timeout, 
                            bigiq_license_pool_name,
                            bigip_management_ip, bigip_username,
                            bigip_password)

        # license as an unmanaged device
        self._create_member(bigiq_host, bigiq_username, 
                            bigiq_password, bigiq_timeout, 
                            bigiq_license_pool_name,
                            bigip_management_ip, bigip_username,
                            bigip_password)
        return self.member_uuid

    def _release_license(self, bigiq_host, bigiq_username, 
                         bigiq_password, bigiq_timeout, 
                         bigiq_license_pool_name, bigip_management_ip, 
                         bigip_username, bigip_password):
        '''Release license to BIG-IQ Pool.

        :returns: None
        '''
        self._delete_member(bigiq_host, bigiq_username, 
                            bigiq_password, bigiq_timeout, 
                            bigiq_license_pool_name,
                            bigip_management_ip, bigip_username,
                            bigip_password)
        self.license_uuid = None
        return None

    def _delete_member(self, bigiq_host, bigiq_username, 
                       bigiq_password, bigiq_timeout, 
                       bigiq_license_pool_name, bigip_management_ip, 
                       bigip_username, bigip_password):
        bigiq_timeout = self.CONNECTION_TIMEOUT
        biq = self._get_bigiq_session(bigiq_host, bigiq_username,
                                      bigiq_password, bigiq_timeout)
        pool_uuid = self._get_pool_id(biq, bigiq_license_pool_name)
        member_uuid = self._get_member_id(biq, pool_uuid,
                                          bigip_management_ip)
        if member_uuid:
            member_url = '%s/purchased-pool/licenses/%s/members/%s' %  (
                biq.base_url,
                pool_uuid,
                member_uuid
            )
            delete_body = {
                'uuid': member['uuid'],
                'username': bigip_username,
                'password': bigip_password
            }
            response = biq.delete(member_url,json = delete_body)
            attempts = 30
            while True:
                if attempts == 0:
                    raise Exception(
                        "error deleting existing license %s" % \
                        bigip_management_ip
                    )
                attempts -= 1
                response = biq.get(member_url)
                if not response.status_code == 404:
                    if response.status_code > 399:
                        logging.error('GET %s:status:%d' % (
                            member_url, response.status_code))
                    sleep(5)
                else:
                    return True
            return False
        return True

    def _create_member(self, bigiq_host, bigiq_username, 
                       bigiq_password, bigiq_timeout, 
                       bigiq_license_pool_name, bigip_management_ip, 
                       bigip_username, bigip_password):
        bigiq_timeout = self.CONNECTION_TIMEOUT
        biq = self._get_bigiq_session(bigiq_host, bigiq_username,
                                      bigiq_password, bigiq_timeout)
        pool_uuid = self._get_pool_id(biq, bigiq_license_pool_name)
        member_uuid = self._get_member_id(biq, pool_uuid,
                                          bigip_management_ip)
        if not member_uuid:
            member_body = {
                'deviceAddress': bigip_management_ip,
                'username': bigip_username,
                'password': bigip_password
            }
            members_url = '%s/purchased-pool/licenses/%s/members' %  (
                biq.base_url,
                pool_uuid
            )
            response = biq.post(members_url, json = member_body)
            response.raise_for_status()
            respJson = response.json()
            self.license_uuid = respJson['uuid']            
            self.pool_uuid = pool_uuid
            self.regkey = regkey
            self.resource_id_set(respJson['uuid'])
            attempts = 30
            member_licensing = True
            member_last_state = 'UNKNOWN'
            while member_licensing:
                if attempts == 0:
                    ex = Exception(
                        "device %s activation state is %s" % \
                        (bigip_management_ip, member_last_state)
                    )
                    raise exception.ResourceFailure(
                        ex,
                        None,
                        action='CREATE'
                    )
                attempts -= 1
                member_url = '%s/%s' % (members_url, self.license_uuid)
                response = biq.get(member_url)
                response.raise_for_status()
                respJson = response.json()
                if respJson['status'] == 'LICENSED':
                    member_licensing = False
                else:
                    member_last_state = respJson['status']
                    sleep(5)

    def _get_bigiq_session(self, bigiq_host, bigiq_username,
                           bigiq_password, bigiq_timeout):
        if requests.__version__ < '2.9.1':
            requests.packages.urllib3.disable_warnings()
        bigiq = requests.Session()
        bigiq.verify = False
        bigiq.headers.update({'Content-Type': 'application/json'})
        bigiq.timeout = bigiq_timeout
        token_auth_body = { 'username': bigiq_username,
                            'password': bigiq_password,
                            'loginProviderName': 'local' }
        login_url = "https://%s/mgmt/shared/authn/login" % (bigiq_host)
        response = bigiq.post(login_url,
                              json=token_auth_body,
                              verify=False,
                              auth=requests.auth.HTTPBasicAuth(
                                  bigiq_username, bigiq_password))
        respJson = response.json()
        bigiq.headers.update(
            {'X-F5-Auth-Token': respJson['token']['token']})
        bigiq.base_url='https://%s/mgmt/cm/device/licensing/pool' % bigiq_host
        return bigiq

    def _get_bigiq_session(self, bigiq_host, bigiq_username,
                           bigiq_password, bigiq_timeout):
        if requests.__version__ < '2.9.1':
            requests.packages.urllib3.disable_warnings()
        bigiq = requests.Session()
        bigiq.verify = False
        bigiq.headers.update({'Content-Type': 'application/json'})
        bigiq.timeout = bigiq_timeout
        token_auth_body = { 'username': bigiq_username,
                            'password': bigiq_password,
                            'loginProviderName': 'local' }
        login_url = "https://%s/mgmt/shared/authn/login" % (bigiq_host)
        response = bigiq.post(login_url,
                              json=token_auth_body,
                              verify=False,
                              auth=requests.auth.HTTPBasicAuth(
                                  bigiq_username, bigiq_password))
        respJson = response.json()
        bigiq.headers.update(
            {'X-F5-Auth-Token': respJson['token']['token']})
        bigiq.base_url='https://%s/mgmt/cm/device/licensing/pool' % bigiq_host
        return bigiq
        
    def _get_pool_id(self, bigiq_session, pool_name):
        pools_url = '%s/purchased-pool/licenses' %  \
                                                  bigiq_session.base_url
        response = bigiq_session.get(pools_url)
        response.raise_for_status()
        respJson = response.json()
        pools = respJson['items']
        for pool in pools:
            if pool['name'] == pool_name:
                return pool['uuid']
        raise  Exception('No RegKey License pool %s found' % pool_name)

    def _get_member_id(self, bigiq_session, pool_id, mgmt_ip):
        pools_url = '%s/purchased-pool/licenses' %  \
                                                  bigiq_session.base_url
        members_url = '%s/%s/members' % (pools_url, pool_id)
        response = biq.get(members_url)
        response.raise_for_status()
        respJson = response.json()
        members = respJson['items']
        for member in members:
            if member['deviceAddress'] == mgmt_ip:
                return member['uuid']
        return None

    @log_helpers.log_method_call
    def handle_create(self):
        '''License a BIG-IP from a BIG-IQ pool

        :raises: ResourceFailure exception
        '''
        try:
            bigiq_host = self.properties[self.BIGIQ_HOST]
            bigiq_username = self.properties[self.BIGIQ_USERNAME]
            bigiq_password = self.properties[self.BIGIQ_PASSWORD]
            bigiq_timeout = \
                self.properties[self.BIGIQ_CONNECTION_TIMEOUT]
            bigiq_license_pool_name = \
                self.properties[self.BIGIQ_LICENSE_POOL_NAME]
            bigip_management_ip = \
                self.properties[self.BIGIP_MANAGEMENT_IP]
            bigip_username = self.properties[self.BIGIP_USERNAME]
            bigip_password = self.properties[self.BIGIP_PASSWORD]
            self._license(bigiq_host, bigiq_username, 
                          bigiq_password, bigiq_timeout, 
                          bigiq_license_pool_name, bigip_management_ip, 
                          bigip_username, bigip_password)
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
            bigiq_host = self.properties[self.BIGIQ_HOST]
            bigiq_username = self.properties[self.BIGIQ_USERNAME]
            bigiq_password = self.properties[self.BIGIQ_PASSWORD]
            bigiq_timeout = \
                self.properties[self.BIGIQ_CONNECTION_TIMEOUT]
            bigiq_license_pool_name = \
                self.properties[self.BIGIQ_LICENSE_POOL_NAME]
            bigip_management_ip = \
                self.properties[self.BIGIP_MANAGEMENT_IP]
            bigip_username = self.properties[self.BIGIP_USERNAME]
            bigip_password = self.properties[self.BIGIP_PASSWORD]
            self._release_license(bigiq_host, bigiq_username, 
                                  bigiq_password, bigiq_timeout, 
                                  bigiq_license_pool_name,
                                  bigip_management_ip, bigip_username,
                                  bigip_password)
        except Exception as ex:
            raise exception.ResourceFailure(ex, None, action='DELETE')
        return True

def resource_mapping():
    return {'F5::BigIQ::PurchasedPoolLicensor':
             F5BigIQPurchasedPoolLicensor}
