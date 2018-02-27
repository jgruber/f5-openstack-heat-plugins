'''Provides a BIG-IQ activation and revoke workflows for purchased pools.'''
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
from f5_heat.licensors.bigiq.exceptions import PoolNotFoundException


class PurchasedPoolLicensor(object):
    '''Workflows to support BIG-IQ purchased pools'''

    member_uuid = None
    pool_uuid = None

    bigiq = None
    member = None

    def __init__(self, bigiq_host=None, bigiq_pool_member=None):
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
            self._revoke_member(
                biq, self.pool_uuid, self.member_uuid, self.member)
        except MemberNotFoundException:
            pass

        self.member_uuid = None

        self.member_uuid = self._activate_member(
            biq, self.pool_uuid, self.member)
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
            if not self.member_uuid:
                self.member_uuid = self._get_member_id(
                    biq, self.pool_uuid, self.member.bigip_management_ip)
            if self.member_uuid:
                self._revoke_member(
                    biq, self.pool_uuid, self.member_uuid, self.member)
        except MemberNotFoundException as mnfe:
            msg = 'request to release license %s for %s failed because no \
                   allocated license was found.' % (
                       self.member_uuid, self.member.bigip_management_ip)
            logging.error(msg)
            self.member_uuid = None
            raise mnfe
        self.member_uuid = None
        return None

    @classmethod
    def _revoke_member(cls, bigiq_session=None, pool_id=None,
                       member_id=None, member=None):
        ''' Revoke a license based
        :param: bigiq_session: BIG-IQ session object
        :param: pool_id: BIG-IQ pool ID
        :param: member_id: BIG-IQ pool Member ID
        :param: member: BIG-IP Pool Member object containing credentials
        :returns: None
        :raises: LicenseRevokeError
        :raises: requests.exceptions.HTTPError
        '''
        # attempt to discover member_id if not set
        if not member_id:
            member_id = \
                cls._get_member_id(
                    bigiq_session, pool_id, member.bigip_management_ip)
        # delete the member - only allow 404 errors raise others
        try:
            cls._delete_member(
                bigiq_session, pool_id, member_id,
                member.bigip_username, member.bigip_password)
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
                cls._get_member_state(bigiq_session, pool_id, member_id)
            except requests.exceptions.HTTPError as ex:
                if ex.response.status_code == 404:
                    return
                logging.error(str(
                    'error revoking license to %s:%s'
                    % (member.bigip_management_ip, ex.message)))
                logging.error(str(
                    '%d remaining revocation attempts for %s'
                    % (attempts, member.bigip_management_ip)))
                sleep(member.error_delay)
        raise LicenseRevokeError(
            "error revoking existing license %s" % member.bigip_management_ip
        )

    @classmethod
    def _activate_member(cls, bigiq_session=None, pool_id=None,  member=None):
        ''' Activate a BIG-IP as a BIG-IQ license pool member
        :param: bigiq_session: BIG-IQ session object
        :param: pool_id: BIG-IQ pool ID
        :param: member: BIG-IP Pool Member object containing credentials
        :returns: Member ID string
        :raises: requests.exceptions.HTTPError
        '''
        member_uuid = None
        try:
            member_uuid = cls._get_member_id(
                bigiq_session, pool_id, member.bigip_management_ip)
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
                        member_uuid = \
                            cls._create_member(
                                bigiq_session, pool_id,
                                member.bigip_management_ip,
                                member.bigip_username,
                                member.bigip_password)
                    member_last_state = \
                        cls._get_member_state(
                            bigiq_session, pool_id, member_uuid)
                    if member_last_state == 'LICENSED':
                        return member_uuid
                    else:
                        sleep(member.error_delay)
                except requests.exceptions.HTTPError as httpex:
                    logging.error(str(
                        'error allocating license to %s: %s %s'
                        % (member.bigip_management_ip,
                           httpex.request.method, httpex.message)))
                    logging.error(str(
                        '%d remaining licensing attempts for %s'
                        % (attempts, member.bigip_management_ip)))
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
        pools_url = "%s/purchased-pool/licenses?$select=uuid,kind,name" %  \
                    bigiq_session.base_url
        query_filter = '&$filter=name%20eq%20%27'+pool_name+'%27'
        pools_url = "%s%s" % (pools_url, query_filter)
        response = bigiq_session.get(pools_url)
        response.raise_for_status()
        response_json = response.json()
        pools = response_json['items']
        for pool in pools:
            if pool['name'] == pool_name:
                if str(pool['kind']).find('pool:purchased') > 1:
                    return pool['uuid']
        raise PoolNotFoundException('No Purchased pool %s found' % pool_name)

    @staticmethod
    def _get_member_id(bigiq_session, pool_id, mgmt_ip):
        ''' Get a BIG-IQ license pool member ID by the pool ID and BIG-IP
            management IP address.
        :param: bigiq_session: BIG-IQ session object
        :param: pool_id: BIG-IQ pool ID
        :param: mgmt_ip: BIG-IP management IP address
        :returns: Member ID string
        :raises: MemberNotFoundException
        :raises: requests.exceptions.HTTPError
        '''
        pools_url = '%s/purchased-pool/licenses' % bigiq_session.base_url
        members_url = '%s/%s/members?$select=uuid,deviceAddress' % (
            pools_url, pool_id)
        # this filter does not work
        # query_filter = '&$filter=deviceAddress%20eq%20%27'+mgmt_ip+'%27'
        query_filter = ''
        members_url = "%s%s" % (members_url, query_filter)
        response = bigiq_session.get(members_url)
        response.raise_for_status()
        response_json = response.json()
        members = response_json['items']
        for member in members:
            if member['deviceAddress'] == mgmt_ip:
                return member['uuid']
        raise MemberNotFoundException(str('No member %s found in pool %s' % (
            mgmt_ip, pool_id)))

    @staticmethod
    def _get_member_state(bigiq_session, pool_id, member_id):
        ''' Get a BIG-IQ license pool member state.
        :param: bigiq_session: BIG-IQ session object
        :param: pool_id: BIG-IQ pool ID
        :param: member_id: BIG-IP pool member ID
        :returns: Member state string
        :raises: requests.exceptions.HTTPError
        '''
        pools_url = '%s/purchased-pool/licenses' % bigiq_session.base_url
        member_url = '%s/%s/members/%s?$select=state' % (
            pools_url, pool_id, member_id)
        response = bigiq_session.get(member_url)
        response.raise_for_status()
        response_json = response.json()
        return response_json['state']

    @staticmethod
    def _create_member(bigiq_session, pool_id, bigip_management_ip,
                       bigip_username, bigip_password):
        ''' Create a BIG-IP License Pool Member.
        :param: bigiq_session: BIG-IQ session object
        :param: pool_id: BIG-IQ pool ID
        :param: bigip_management_ip: BIG-IP management IP
        :param: bigip_username: BIG-IP username
        :param: bigip_password: BIG-IP password
        :returns: Member ID string
        :raises: requests.exceptions.HTTPError
        '''
        members_url = '%s/purchased-pool/licenses/%s/members' % (
            bigiq_session.base_url, pool_id)
        member = {
            'deviceAddress': bigip_management_ip,
            'username': bigip_username,
            'password': bigip_password
        }
        response = bigiq_session.post(members_url,
                                      json=member)
        response.raise_for_status()
        response_json = response.json()
        return response_json['uuid']

    @staticmethod
    def _delete_member(bigiq_session, pool_id, member_id,
                       bigip_username, bigip_password):
        ''' Delete a BIG-IP License Pool Member.
        :param: bigiq_session: BIG-IQ session object
        :param: pool_id: BIG-IQ pool ID
        :param: member_id: BIG-IQ member ID
        :param: bigip_username: BIG-IP username
        :param: bigip_password: BIG-IP password
        :returns: None
        :raises: requests.exceptions.HTTPError
        '''
        member_url = '%s/purchased-pool/licenses/%s/members/%s' % (
            bigiq_session.base_url,
            pool_id,
            member_id
        )
        member = {
            'uuid': member_id,
            'username': bigip_username,
            'password': bigip_password
        }
        response = bigiq_session.delete(member_url,
                                        json=member)
        response.raise_for_status()
