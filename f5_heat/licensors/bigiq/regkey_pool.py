'''Provides a BIG-IQ activation and revoke workflows for regkey pools.'''
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
import requests

from f5_heat.licensors.bigiq.bigiq_host import F5BigIQHost
from f5_heat.licensors.bigiq.bigiq_pool_member import F5BigIQLicensePoolMember
from f5_heat.licensors.bigiq.exceptions import LicenseActivationError
from f5_heat.licensors.bigiq.exceptions import LicenseRevokeError
from f5_heat.licensors.bigiq.exceptions import MemberNotFoundException
from f5_heat.licensors.bigiq.exceptions import NoOfferingAvailable
from f5_heat.licensors.bigiq.exceptions import PoolNotFoundException


class RegkeyPoolLicensor(object):
    '''Workflows to support BIG-IQ regkey pools'''

    member_uuid = None
    regkey = None
    pool_uuid = None

    bigiq = None
    member = None

    def __init__(self, bigiq_host=None,
                 bigiq_pool_member=None):
        if not isinstance(bigiq_host, F5BigIQHost):
            raise AssertionError(str(
                'bigiq_host must be an instance of ',
                'f5_heat.licensors.bigiq.bigiq_host.F5BigIQHost'))
        self.bigiq = bigiq_host
        if not isinstance(bigiq_pool_member, F5BigIQLicensePoolMember):
            raise AssertionError(str(
                'bigiq_host must be an instance of ',
                'f5_heat.licensors.',
                'bigiq.bigiq_pool_member.F5BigIQLicensePoolMember'))
        self.member = bigiq_pool_member

    def activate_license(self):
        '''License BIG-IP from BIG-IQ Pool.
        :returns: member_uuid
        '''
        # premptively clean up any orphaned
        # member with the same bigip_management_ip
        biq = self.bigiq.get_bigiq_session()
        if not self.pool_uuid:
            self.pool_uuid = self._get_pool_id(
                biq, self.member.bigiq_license_pool_name)
        try:
            if not self.regkey:
                (self.regkey, self.member_uuid) = \
                    self._get_regkey_by_management_ip(
                        biq, self.pool_uuid, self.member.bigip_management_ip)
            self._revoke_member(
                biq, self.pool_uuid, self.regkey,
                self.member_uuid, self.member)
        except MemberNotFoundException:
            pass
        except NoOfferingAvailable:
            pass

        self.member_uuid = None
        self.regkey = self._get_first_available_regkey(biq, self.pool_uuid)
        (self.regkey, self.member_uuid) = self._activate_member(
            biq, self.pool_uuid, self.regkey, self.member)
        return self.member_uuid

    def revoke_license(self):
        '''Release license to BIG-IQ Pool.
        :returns: None
        '''
        try:
            biq = self.bigiq.get_bigiq_session()
            if not self.pool_uuid:
                self.pool_uuid = self._get_pool_id(
                    biq, self.member.bigiq_license_pool_name)
            if not self.regkey:
                (self.regkey, self.member_uuid) = \
                    self._get_regkey_by_management_ip(
                        biq, self.pool_uuid, self.member.bigip_management_ip)
            if self.member_uuid:
                self._revoke_member(biq, self.pool_uuid, self.regkey,
                                    self.member_uuid, self.member)
        except NoOfferingAvailable as noe:
            msg = 'request to release license %s for %s failed. %s' % (
                self.member_uuid,
                self.member.bigip_management_ip,
                noe.message)
            logging.error(msg)
            self.regkey = None
            self.member_uuid = None
            raise noe
        except MemberNotFoundException as mnfe:
            msg = 'request to release license %s for % failed because no \
                   allocated license was found.' % (
                self.member_uuid, self.member.bigip_management_ip)
            logging.error(msg)
            self.regkey = None
            self.member_uuid = None
            raise mnfe

        self.regkey = None
        self.member_uuid = None
        return None

    @classmethod
    def _revoke_member(cls, bigiq_session=None, pool_id=None, regkey=None,  # pylint: disable=too-many-arguments
                       member_id=None, member=None):
        ''' Revoke a license based
        :param: bigiq_session: BIG-IQ session object
        :param: pool_id: BIG-IQ pool ID
        :param: regkey: BIG-IQ regky in pool
        :param: member_id: BIG-IQ pool Member ID
        :param: member: BIG-IP Pool Member object containing credentials
        :returns: None
        :raises: LicenseRevokeError
        :raises: NoRegKeyAvailable
        :raises: MemberNotFoundException
        :raises: requests.exceptions.HTTPError
        '''
        # attempt to discover member_id if not set
        if not member_id:
            if not regkey:
                (regkey, member_id) = \
                    cls._get_regkey_by_management_ip(
                        bigiq_session, pool_id,
                        member.bigip_management_ip)
            else:
                member_id = \
                    cls._get_member_id(
                        bigiq_session, pool_id,
                        regkey, member.bigip_management_ip)
        # delete the member - only allow 404 errors raise others
        try:
            cls._delete_member(
                bigiq_session, pool_id, regkey, member_id,
                member.bigip_username, member.bigip_password
            )
        except requests.exceptions.HTTPError as httpex:
            if httpex.response.status_code != 404:
                raise httpex
        # query member state until it is no longer present
        attempts = member.license_attempts
        while True:
            if attempts == 0:
                break
            attempts -= 1
            try:
                cls._get_member_status(
                    bigiq_session, pool_id, regkey, member_id
                )
            except requests.exceptions.HTTPError as httpex:
                if httpex.response.status_code == 404:
                    return
                logging.error(str(
                    'error revoking license to %s:%s'
                    % (member.bigip_management_ip, httpex.message)))
                logging.error(str(
                    '%d remaining revocation attempts for %s'
                    % (attempts, member.bigip_management_ip)))
                sleep(member.error_delay)
        raise LicenseRevokeError(
            "error revoking existing license %s" % member.bigip_management_ip
        )

    @classmethod
    def _activate_member(cls, bigiq_session=None, pool_id=None,
                         regkey=None, member=None):
        ''' Activate a BIG-IP as a BIG-IQ license pool member
        :param: bigiq_session: BIG-IQ session object
        :param: pool_id: BIG-IQ pool ID
        :param: regkey: BIG-IQ regky in pool (optional)
        :param: member: BIG-IP Pool Member object containing credentials
        :returns: (Regkey string, Member ID string)
        :raises: requests.exceptions.HTTPError
        '''
        member_uuid = None
        try:
            member_uuid = cls._get_member_id(
                bigiq_session, pool_id, regkey, member.bigip_management_ip)
            return member_uuid
        except MemberNotFoundException:
            member_last_state = 'UNKNOWN'
            attempts = member.license_attempts
            while True:
                if attempts == 0:
                    raise LicenseActivationError(
                        "device %s activation state is %s" %
                        (member.bigip_management_ip, member_last_state)
                    )
                attempts -= 1
                try:
                    if not member_uuid:
                        if not regkey:
                            regkey = cls._get_first_available_regkey(
                                bigiq_session, pool_id)
                        member_uuid = \
                            cls._create_member(
                                bigiq_session, pool_id, regkey,
                                member.bigip_management_ip,
                                member.bigip_username, member.bigip_password)
                    member_last_state = \
                        cls._get_member_status(
                            bigiq_session, pool_id, regkey, member_uuid)
                    if member_last_state == 'LICENSED':
                        return (regkey, member_uuid)
                    else:
                        sleep(member.error_delay)
                except requests.exceptions.HTTPError as ex:
                    logging.error(str(
                        'error allocating license to %s: %s %s'
                        % (member.bigip_management_ip,
                           ex.request.method, ex.message)))
                    logging.error(str(
                        '%d remaining licensing attempts for %s'
                        % (attempts, member.bigip_management_ip)))
                    # force a new regkey from pool
                    member_uuid = None
                    regkey = None
                    sleep(member.error_delay)

    @staticmethod
    def _get_pool_id(bigiq_session, pool_name):
        ''' Get a BIG-IQ license pool by its pool name. Returns first
            match of the specific pool type.
        :param: bigiq_session: BIG-IQ session object
        :param: pool_name: BIG-IQ pool name
        :returns: Pool ID string
        :raises: PoolNotFoundException
        :raises: requests.exceptions.HTTPError
        '''
        pools_url = '%s/regkey/licenses?$select=id,kind,name' % \
            bigiq_session.base_url
        # No need to check both name and uuid for match. Can't filter.
        # query_filter = '&$filter=name%20eq%20%27'+pool_name+'%27'
        # pools_url = "%s%s" % (pools_url, query_filter)
        response = bigiq_session.get(pools_url)
        response.raise_for_status()
        response_json = response.json()
        pools = response_json['items']
        for pool in pools:
            if pool['name'] == pool_name or pool['id'] == pool_name:
                if str(pool['kind']).find('pool:regkey') > 1:
                    return pool['id']
        raise PoolNotFoundException('No RegKey pool %s found' % pool_name)

    @staticmethod
    def _get_member_id(bigiq_session, pool_id, regkey, mgmt_ip):
        ''' Get a BIG-IQ license pool member ID by the pool ID and BIG-IP
            management IP address.
        :param: bigiq_session: BIG-IQ session object
        :param: pool_id: BIG-IQ pool ID
        :param: regkey: BIG-IQ regky in pool
        :param: mgmt_ip: BIG-IP management IP address
        :returns: Member ID string
        :raises: MemberNotFoundException
        :raises: requests.exceptions.HTTPError
        '''
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
    def _get_member_status(bigiq_session, pool_id, regkey, member_id):
        ''' Get a BIG-IQ license pool member status.
        :param: bigiq_session: BIG-IQ session object
        :param: pool_id: BIG-IQ pool ID
        :param: regkey: BIG-IQ regky in pool
        :param: member_id: BIG-IP pool member ID
        :returns: Member state string
        :raises: requests.exceptions.HTTPError
        '''
        member_url = \
            '%s/regkey/licenses/%s/offerings/%s/members/%s?$select=status' % (
                bigiq_session.base_url, pool_id, regkey, member_id)
        response = bigiq_session.get(member_url)
        response.raise_for_status()
        response_json = response.json()
        return response_json['status']

    @staticmethod
    def _create_member(bigiq_session, pool_id, regkey, bigip_management_ip,  # pylint: disable=too-many-arguments
                       bigip_username, bigip_password):
        ''' Create a BIG-IP License Pool Member.
        :param: bigiq_session: BIG-IQ session object
        :param: pool_id: BIG-IQ pool ID
        :param: regkey: BIG-IQ regky in pool
        :param: bigip_management_ip: BIG-IP management IP
        :param: bigip_username: BIG-IP username
        :param: bigip_password: BIG-IP password
        :returns: Member ID string
        :raises: requests.exceptions.HTTPError
        '''
        members_url = '%s/regkey/licenses/%s/offerings/%s/members' % (
            bigiq_session.base_url, pool_id, regkey)
        member = {
            'deviceAddress': bigip_management_ip,
            'username': bigip_username,
            'password': bigip_password
        }
        response = bigiq_session.post(members_url,
                                      json=member)
        response.raise_for_status()
        response_json = response.json()
        return response_json['id']

    @staticmethod
    def _delete_member(bigiq_session, pool_id, regkey, member_id,  # pylint: disable=too-many-arguments
                       bigip_username, bigip_password):
        ''' Delete a BIG-IP License Pool Member.
        :param: bigiq_session: BIG-IQ session object
        :param: pool_id: BIG-IQ pool ID
        :param: regkey: BIG-IQ regky in pool
        :param: member_id: BIG-IQ member ID
        :param: bigip_username: BIG-IP username
        :param: bigip_password: BIG-IP password
        :returns: None
        :raises: requests.exceptions.HTTPError
        '''
        member_url = \
            '%s/regkey/licenses/%s/offerings/%s/members/%s' % (
                bigiq_session.base_url, pool_id, regkey, member_id)
        member = {
            'id': member_id,
            'username': bigip_username,
            'password': bigip_password
        }
        response = bigiq_session.delete(member_url,
                                        json=member)
        response.raise_for_status()

    @staticmethod
    def _get_regkey_by_management_ip(bigiq_session, pool_id, mgmt_ip):
        ''' Get regkey, member_id tuple by management IP address
        :param: bigiq_session: BIG-IQ session object
        :param: pool_id: BIG-IQ pool ID
        :param: mgmt_ip: BIG-IP management IP address
        :returns: (Regkey string, Member ID string)
        :raises: NoRegKeyAvailable
        :raises: requests.exceptions.HTTPError
        '''
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
            members = response_json['items']
            for member in members:
                if member['deviceAddress'] == mgmt_ip:
                    return (offering['regKey'], member['id'])
        raise NoOfferingAvailable('No regkey has %s as a member' % mgmt_ip)

    @staticmethod
    def _get_first_available_regkey(bigiq_session, pool_id):
        ''' Get first regkey from pool without an assigned BIG-IP device
        :param: bigiq_session: BIG-IQ session object
        :param: pool_id: BIG-IQ pool ID
        :returns: Regkey string
        :raises: NoRegKeyAvailable
        :raises: requests.exceptions.HTTPError
        '''
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
        raise NoOfferingAvailable('No RegKey available in pool %s' % pool_id)
