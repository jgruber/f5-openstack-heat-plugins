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

import logging
from time import sleep
from oslo_log import helpers as log_helpers
import requests

from heat.common import exception
from heat.common.i18n import _
from heat.engine import attributes
from heat.engine import properties
from heat.engine import resource
from heat.engine import support


class PoolNotFoundException(Exception):
    ''' No Pool Found By Supplied Name '''
    pass


class MemberNotFoundException(Exception):
    ''' No Member Found By Management Address '''
    pass


class NoRegKeyAvailable(Exception):
    ''' No RegKey Available in Pool '''
    pass

class F5BigIQHost(object):
    ''' Configurations for BIG-IQ Host '''
    bigiq_host = None
    bigiq_username = None
    bigiq_password = None
    bigiq_timeout = None

    def __init__(self, bigiq_host=None, bigiq_username=None,
                 bigiq_password=None, bigiq_timeout=None):
        self.bigiq_host = bigiq_host
        self.bigiq_username = bigiq_username
        self.biqiq_password = bigiq_password
        self.bigiq_timeout = bigiq_timeout

    def get_config(self):
        ''' Returns BIG-IQ host configuration '''
        config = {'bigiq_host': self.bigiq_host,
                  'bigiq_username': self.bigiq_username,
                  'bigiq_password': self.bigiq_password,
                  'bigiq_timeout': self.bigiq_timeout
        }
        return config

    def get_bigiq_session(self):
        ''' Creates a Requests Session to the BIG-IQ host configured '''
        if requests.__version__ < '2.9.1':
            requests.packages.urllib3.disable_warnings()  #pylint: disable=no-member
        bigiq = requests.Session()
        bigiq.verify = False
        bigiq.headers.update({'Content-Type': 'application/json'})
        bigiq.timeout = self.bigiq_timeout
        token_auth_body = {'username': self.bigiq_username,
                           'password': self.bigiq_password,
                           'loginProviderName': 'local'}
        login_url = "https://%s/mgmt/shared/authn/login" % (self.bigiq_host)
        response = bigiq.post(login_url,
                              json=token_auth_body,
                              verify=False,
                              auth=requests.auth.HTTPBasicAuth(
                                  self.bigiq_username, self.bigiq_password))
        response_json = response.json()
        bigiq.headers.update(
            {'X-F5-Auth-Token': response_json['token']['token']})
        bigiq.base_url = 'https://%s/mgmt/cm/device/licensing/pool' % \
            self.bigiq_host
        return bigiq


class F5BigIQLicensePoolMember(object):
    ''' Configurations for BIG-IQ Pool Member Licensing '''
    bigiq_license_pool_name = None
    bigip_management_ip = None
    bigip_username = None
    bigip_password = None
    bigip_mgmt_port = 443

    member_id = None
    regkey = None

    def __init__(self, bigiq_license_pool_name=None,
                 bigip_management_ip=None, bigip_username=None,
                 bigip_password=None):
        self.bigiq_license_pool_name = bigiq_license_pool_name
        self.bigip_management_ip = bigip_management_ip
        self.bigip_username = bigip_username
        self.bigip_password = bigip_password

    def create_defintiion(self):
        ''' Create Member Body '''
        member = {
            'deviceAddress': self.bigip_management_ip,
            'username': self.bigip_username,
            'password': self.bigip_password
        }
        return member

    def delete_definition(self):
        ''' Delete Member Body '''
        member = {
            'id': self.member_id,
            'username': self.bigip_username,
            'password': self.bigip_password
        }
        return member


class F5BigIQUtilizationPoolLicensor(resource.Resource):
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
            _('BIGIQ License Type to License BIG-IPs.'),
            required=True
        ),
        BIGIP_MANAGEMENT_IP: properties.Schema(
            properties.Schema.STRING,
            _('BIGIP hostname or IP address to license.'),
            required=True
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
        REGKEY,
        LICENSE_UUID
    ) = (
        'pool_uuid',
        'license_type'
        'regkey',
        'license_uuid'
    )

    attributes_schema = {
        POOL_UUID: attributes.Schema(
           _('POOL UUID.'),
           type=attributes.Schema.STRING,
           support_status=support.SupportStatus(version='5.0.0')
        ),
        LICENSE_TYPE: attributes.Schema(
           _('License Type.'),
           type=attributes.Schema.STRING,
           support_status=support.SupportStatus(version='5.0.0')
        ),
        REGKEY: attributes.Schema(
           _('REGKEY.'),
           type=attributes.Schema.STRING,
           support_status=support.SupportStatus(version='5.0.0')
        ),
        LICENSE_UUID: attributes.Schema(
           _('License UUID.'),
           type=attributes.Schema.STRING,
           support_status=support.SupportStatus(version='5.0.0')
        )
    }

    bigiq = F5BigIQHost()
    member = F5BigIQLicensePoolMember()

    pool_uuid = None
    license_type = None
    regkey = None
    license_uuid = None

    def _resolve_attribute(self, name):
        if self.resource_id is None:
            return
        if name == self.POOL_UUID:
            return self.pool_uuid
        if name == self.LICENSE_TYPE:
            return self.license_type
        if name == self.REGKEY:
            return self.regkey
        if name == self.LICENSE_UUID:
            return self.license_uuid

    def get_reference_id(self):
        return resource.Resource.get_reference_id(self)

    def _license(self):
        '''License BIG-IP from BIG-IQ Pool.

        :returns: license_uuid
        '''
        self._delete_member()
        # license as an unmanaged device
        self._create_member()
        return self.license_uuid

    def _release_license(self):
        '''Release license to BIG-IQ Pool.

        :returns: None
        '''
        try:
            self._delete_member()
        except MemberNotFoundException:
            msg = 'request to release license %s for % failed because no \
                   allocated license was found.' % (
                       self.license_uuid, self.member.bigip_management_ip)
            logging.error(msg)
            self.license_uuid = None
            self.member.member_id = None
            self.member.regkey = None
        except PoolNotFoundException:
            msg = 'request to release license %s for %s failed because %s \
                   pool was not found.' % (
                       self.license_uuid, self.member.bigip_management_ip,
                       self.member.bigiq_license_pool_name)
            self.license_uuid = None
            self.member.member_id = None
            self.member.regkey = None
        self.license_uuid = None
        self.member.member_id = None
        self.member.regkey = None
        return None

    def _delete_member(self):
        biq = self.bigiq.get_bigiq_session()
        if not self.pool_uuid:
            self.pool_uuid = self._get_pool_id(biq, self.member.bigiq_license_pool_name)
        if not self.regkey:
            self.regkey = self._get_first_available_regkey(biq, self.pool_uuid)
            self.member.regkey = self.regkey
        if not self.license_uuid:
            self.license_uuid = self._get_member_id(
                biq, self.pool_uuid, self.regkey, self.member.bigip_management_ip)
        if self.license_uuid:
            member_url = \
                '%s/regkey/licenses/%s/offerings/%s/members/%s' % (
                    biq.base_url,
                    self.pool_uuid,
                    self.regkey,
                    self.license_uuid
                )
            self.member.member_id = self.license_uuid
            logging.debug(str('DELETING: %s' % member_url))
            biq.delete(member_url, json=self.member.delete_definition())
            attempts = 30
            while True:
                if attempts == 0:
                    raise requests.exceptions.HTTPError(
                        "error deleting existing license %s" %
                        self.member.bigip_management_ip
                    )
                attempts -= 1
                response = biq.get(member_url)
                if response.status_code != 404:
                    if response.status_code > 399:
                        logging.error(str('GET %s:status:%d' % (
                            member_url, response.status_code)))
                    sleep(5)
                else:
                    self.license_uuid = None
                    return True
            return False
        return True

    def _create_member(self):
        biq = self.bigiq.get_bigiq_session()
        if not self.pool_uuid:
            self.pool_uuid = self._get_pool_id(biq, self.member.bigiq_license_pool_name)
        if not self.regkey:
            self.regkey = self._get_first_available_regkey(biq, self.pool_uuid)
        if not self.license_uuid:
            try:
                self.license_uuid = self._get_member_id(
                    biq, self.pool_uuid, self.regkey, self.member.bigip_management_ip)
                self.member.member_id = self.license_uuid
            except MemberNotFoundException:
                attempts = 30
                member_licensing = True
                member_last_state = 'UNKNOWN'
                while member_licensing:
                    if attempts == 0:
                        ex = Exception(
                            "device %s activation state is %s" %
                            (self.member.bigip_management_ip, member_last_state)
                        )
                        raise exception.ResourceFailure(
                            ex,
                            None,
                            action='CREATE'
                        )
                    attempts -= 1
                    try:
                        if not self.regkey:
                            self.regkey = self._get_first_available_regkey(
                                biq, self.pool_uuid)
                            self.member.regkey = self.regkey
                        if not self.license_uuid:
                            members_url = \
                                '%s/regkey/licenses/%s/offerings/%s/members' \
                                % (biq.base_url,
                                   self.pool_uuid,
                                   self.regkey)
                            response = biq.post(members_url,
                                                json=self.member.create_defintiion())
                            response.raise_for_status()
                            response_json = response.json()
                            self.license_uuid = response_json['id']
                            self.member.member_id = self.license_uuid
                            self.resource_id_set(response_json['id'])
                        member_url = '%s/%s' % (members_url, self.license_uuid)
                        response = biq.get(member_url)
                        response.raise_for_status()
                        response_json = response.json()
                        if response_json['status'] == 'LICENSED':
                            member_licensing = False
                        else:
                            member_last_state = response_json['status']
                            logging.debug(str('%s license state %s'
                                              % (self.member.bigip_management_ip,
                                              member_last_state)))
                            sleep(5)
                    except requests.exceptions.HTTPError as ex:
                        logging.error(str('error allocating license to %s: %s'
                                          % (self.member.bigip_management_ip, ex.message)))
                        logging.error(str('%d remaining licensing attempts for %s'
                                          % attempts, self.member.bigip_management_ip))
                        self.license_uuid = None
                        self.member.member_id = None
                        self.regkey = None
                        sleep(5)

    @staticmethod
    def _get_pool_id(bigiq_session, pool_name):
        pools_url = '%s/regkey/licenses' % bigiq_session.base_url
        response = bigiq_session.get(pools_url)
        response.raise_for_status()
        response_json = response.json()
        pools = response_json['items']
        for pool in pools:
            if pool['name'] == pool_name:
                if str(pool['kind']).find('pool:regkey') > 1:
                    return pool['id']
        raise PoolNotFoundException('No RegKey pool %s found' % pool_name)

    @staticmethod
    def _get_member_id(bigiq_session, pool_id, regkey, mgmt_ip):
        pools_url = '%s/regkey/licenses' % bigiq_session.base_url
        offerings_url = '%s/%s/offerings' % (pools_url, pool_id)
        members_url = '%s/%s/members' % (offerings_url, regkey)
        response = bigiq_session.get(members_url)
        if response.status_code != 404:
            response.raise_for_status()
        response_json = response.json()
        members = response_json['items']
        for member in members:
            if member['deviceAddress'] == mgmt_ip:
                return member['id']
        raise MemberNotFoundException('No member %s found in pool %s' % (
            mgmt_ip, pool_id))

    @staticmethod
    def _get_first_available_regkey(bigiq_session, pool_id):
        pools_url = '%s/regkey/licenses' % bigiq_session.base_url
        offerings_url = '%s/%s/offerings' % (pools_url, pool_id)
        response = bigiq_session.get(offerings_url)
        response.raise_for_status()
        response_json = response.json()
        offerings = response_json['items']
        for offering in offerings:
            members_url = '%s/%s/members' % (
                offerings_url, offering['regKey'])
            response = bigiq_session.get(members_url)
            response.raise_for_status()
            response_json = response.json()
            if len(response_json['items']) == 0:
                return offering['regKey']
        raise NoRegKeyAvailable('No RegKey available in pool %s' % pool_id)

    @log_helpers.log_method_call
    def handle_create(self):
        '''License a BIG-IP from a BIG-IQ pool

        :raises: ResourceFailure exception
        '''
        try:
            self.bigiq = F5BigIQHost(
                bigiq_host=self.properties[self.BIGIQ_HOST],
                bigiq_username=self.properties[self.BIGIQ_USERNAME],
                bigiq_password=self.properties[self.BIGIQ_PASSWORD],
                bigiq_timeout=self.properties[self.BIGIQ_CONNECTION_TIMEOUT]
            )
            self.member = F5BigIQLicensePoolMember(
                 bigiq_license_pool_name=\
                     self.properties[self.BIGIQ_LICENSE_POOL_NAME],
                 bigip_management_ip=\
                     self.properties[self.BIGIP_MANAGEMENT_IP],
                 bigip_username=\
                     self.properties[self.BIGIP_USERNAME],
                 bigip_password=\
                     self.properties[self.BIGIP_PASSWORD]
            )
            self._license()
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
            self.bigiq = F5BigIQHost(
                bigiq_host=self.properties[self.BIGIQ_HOST],
                bigiq_username=self.properties[self.BIGIQ_USERNAME],
                bigiq_password=self.properties[self.BIGIQ_PASSWORD],
                bigiq_timeout=self.properties[self.BIGIQ_CONNECTION_TIMEOUT]
            )
            self.member = F5BigIQLicensePoolMember(
                 bigiq_license_pool_name=\
                     self.properties[self.BIGIQ_LICENSE_POOL_NAME],
                 bigip_management_ip=\
                     self.properties[self.BIGIP_MANAGEMENT_IP],
                 bigip_username=\
                     self.properties[self.BIGIP_USERNAME],
                 bigip_password=\
                     self.properties[self.BIGIP_PASSWORD]
            )
            self._release_license()
        except Exception as ex:
            raise exception.ResourceFailure(ex, None, action='DELETE')
        return True


def resource_mapping():
    ''' Registration for Heat Resource '''
    return {'F5::BigIQ::UtilizationPoolLicensor':
            F5BigIQUtilizationPoolLicensor}
