'''Provides a BIG-IQ activation and revoke workflows for utility pools.'''
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


class UtilityPoolLicensor(object):
    '''Workflows to support BIG-IQ utility pools'''

    license_type = None
    license_term = None

    member_uuid = None
    offering_uuid = None
    pool_uuid = None

    bigiq = None
    member = None

    def __init__(self, bigiq_host=None,
                 bigiq_pool_member=None, license_type=None):
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
        if not license_type:
            raise NoOfferingAvailable('license type is not defined')
        self.license_type = license_type

    def activate_license(self):
        '''License BIG-IP from BIG-IQ Pool.
        :returns: member_uuid
        '''
        # premptively clean up any orphaned
        # member with the same bigip_management_ip
        biq = self.bigiq.get_bigiq_session()
        if not self.pool_uuid:
            (self.pool_uuid, self.license_term) = \
                self._get_pool_id(
                    biq, self.member.bigiq_license_pool_name)
        if not self.offering_uuid:
            self.offering_uuid = self._get_offering(
                biq, self.pool_uuid, self.license_type)
        try:
            if not self.member_uuid:
                self.member_uuid = self._get_member_id(
                    biq, self.pool_uuid, self.offering_uuid,
                    self.member.bigip_management_ip)
            self._revoke_member(biq, self.pool_uuid,
                                self.offering_uuid,
                                self.member_uuid, self.member)
        except MemberNotFoundException:
            pass

        self.member_uuid = None
        self.member_uuid = self._activate_member(
            biq, self.pool_uuid, self.offering_uuid,
            self.license_term, self.member)
        return self.member_uuid

    def revoke_license(self):
        '''Release license to BIG-IQ Pool.
        :returns: None
        '''
        try:
            biq = self.bigiq.get_bigiq_session()
            if not self.pool_uuid:
                (self.pool_uuid, self.license_term) = \
                    self._get_pool_id(
                        biq, self.member.bigiq_license_pool_name)
            if not self.offering_uuid:
                self.offering_uuid = self._get_offering(
                    biq, self.pool_uuid, self.license_type)
            if not self.member_uuid:
                self.member_uuid = self._get_member_id(
                    biq, self.pool_uuid, self.offering_uuid,
                    self.member.bigip_management_ip)
            self._revoke_member(biq, self.pool_uuid, self.offering_uuid,
                                self.member_uuid, self.member)
        except NoOfferingAvailable as noae:
            msg = 'request to release license %s for %s failed. %s' % (
                       self.member_uuid,
                       self.member.bigip_management_ip,
                       noae.message)
            logging.error(msg)
            self.member_uuid = None
            raise noae
        except MemberNotFoundException as mnfe:
            msg = 'request to release license %s for % failed because no \
                   allocated license was found.' % (
                       self.member_uuid, self.member.bigip_management_ip)
            logging.error(msg)
            self.member_uuid = None
            raise mnfe
        self.member_uuid = None
        return None

    @classmethod
    def _revoke_member(cls, bigiq_session=None, pool_id=None, offering_id=None,  #pylint: disable=too-many-arguments
                       member_id=None, member=None):
        ''' Revoke a license based
        :param: bigiq_session: BIG-IQ session object
        :param: pool_id: BIG-IQ pool ID
        :param: offering_id: Regkey offering type
        :param: member_id: BIG-IQ pool Member ID
        :param: member: BIG-IP Pool Member object containing credentials
        :returns: None
        :raises: LicenseRevokeError
        :raises: NoOfferingAvailable
        :raises: MemberNotFoundException
        :raises: requests.exceptions.HTTPError
        '''
        # attempt to discover member_id if not set
        if not member_id:
            member_id = \
                cls._get_member_id(
                    bigiq_session, pool_id,
                    offering_id, member.bigip_management_ip)
        # delete the member - only allow 404 errors raise others
        try:
            cls._delete_member(
                bigiq_session, pool_id, offering_id, member_id,
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
                cls._get_member_status(bigiq_session, pool_id,
                                       offering_id, member_id)
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
    def _activate_member(cls, bigiq_session=None, pool_id=None,  #pylint: disable=too-many-arguments
                         offering_id=None, license_term=None, member=None):
        ''' Activate a BIG-IP as a BIG-IQ license pool member
        :param: bigiq_session: BIG-IQ session object
        :param: pool_id: BIG-IQ pool ID
        :param: offering_id: Regkey offering type
        :param: license_term: The unit_of_measurement for the pool
        :param: member: BIG-IP Pool Member object containing credentials
        :returns: Member ID string
        :raises: requests.exceptions.HTTPError
        '''
        member_uuid = None
        try:
            member_uuid = cls._get_member_id(
                bigiq_session, pool_id, offering_id,
                member.bigip_management_ip)
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
                                bigiq_session, pool_id, offering_id,
                                license_term,
                                member.bigip_management_ip,
                                member.bigip_management_port,
                                member.bigip_username,
                                member.bigip_password)
                    member_last_state = \
                        cls._get_member_status(
                            bigiq_session, pool_id, offering_id, member_uuid)
                    if member_last_state == 'LICENSED':
                        return member_uuid
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
                    sleep(member.error_delay)

    @staticmethod
    def _get_pool_id(bigiq_session, pool_name):
        ''' Get a BIG-IQ license pool by its pool name. Returns first
            match of the specific pool type.
        :param: bigiq_session: BIG-IQ session object
        :param: pool_name: BIG-IQ pool name
        :returns: (Pool ID string, license term string)
        :raises: PoolNotFoundException
        :raises: requests.exceptions.HTTPError
        '''
        pools_url = \
            '%s/utility/licenses?$select=regKey,kind,name,unitsOfMeasure' % \
            bigiq_session.base_url
        query_filter = '&$filter=name%20eq%20%27'+pool_name+'%27'
        pools_url = "%s%s" % (pools_url, query_filter)
        response = bigiq_session.get(pools_url)
        response.raise_for_status()
        response_json = response.json()
        pools = response_json['items']
        for pool in pools:
            if pool['name'] == pool_name:
                if str(pool['kind']).find('pool:utility') > 1:
                    license_term = pool['unitsOfMeasure'][0]
                    return (pool['regKey'], license_term)
        raise PoolNotFoundException('No Utility pool %s found' % pool_name)

    @staticmethod
    def _get_member_id(bigiq_session, pool_id, offering_id, mgmt_ip):
        ''' Get a BIG-IQ license pool member ID by the pool ID,
            offering ID, and BIG-IP management IP address.
        :param: bigiq_session: BIG-IQ session object
        :param: pool_id: BIG-IQ pool ID
        :param: offering_id: Regkey ID
        :param: mgmt_ip: BIG-IP management IP address
        :returns: Member ID string
        :raises: MemberNotFoundException
        :raises: requests.exceptions.HTTPError
        '''
        pools_url = '%s/utility/licenses' % bigiq_session.base_url
        offerings_url = '%s/%s/offerings' % (pools_url, pool_id)
        members_url = '%s/%s/members' % (offerings_url, offering_id)
        response = bigiq_session.get(members_url)
        if response.status_code != 404:
            response.raise_for_status()
            response_json = response.json()
            members = response_json['items']
            for member in members:
                if member['deviceAddress'] == mgmt_ip:
                    return member['id']
        raise MemberNotFoundException(
            'No member %s found in pool %s for %s'
            % (mgmt_ip, pool_id, offering_id))

    @staticmethod
    def _get_offering(bigiq_session, pool_id, license_type):
        ''' Get Regkey offering by license type
        :param: bigiq_session: BIG-IQ session object
        :param: pool_id: BIG-IQ pool ID
        :param: license_type: Regkey offering type
        :returns: Regkey string
        :raises: NoOfferingAvailable
        :raises: requests.exceptions.HTTPError
        '''
        pools_url = '%s/utility/licenses' % bigiq_session.base_url
        offerings_url = '%s/%s/offerings?$select=id,kind,name' % (
            pools_url, pool_id)
        query_filter = '&$filter=name%20eq%20%27'+license_type+'%27'
        offerings_url = "%s%s" % (offerings_url, query_filter)
        response = bigiq_session.get(offerings_url)
        response.raise_for_status()
        response_json = response.json()
        offerings = response_json['items']
        for offering in offerings:
            if offering['name'] == license_type:
                return offering['id']
        raise NoOfferingAvailable('No Offering for %s available in pool %s'
                                  % (license_type, pool_id))

    @staticmethod
    def _get_member_status(bigiq_session, pool_id, offering_id, member_id):
        ''' Get a BIG-IQ license pool member state.
        :param: bigiq_session: BIG-IQ session object
        :param: pool_id: BIG-IQ pool ID
        :param: offering_id: Regkey offering type
        :param: member_id: BIG-IP pool member ID
        :returns: Member state string
        :raises: requests.exceptions.HTTPError
        '''
        member_url = \
            '%s/utility/licenses/%s/offerings/%s/members/%s' % (
                bigiq_session.base_url,
                pool_id,
                offering_id,
                member_id
            )
        response = bigiq_session.get(member_url)
        response.raise_for_status()
        response_json = response.json()
        return response_json['status']

    @staticmethod
    def _create_member(bigiq_session, pool_id, offering_id, license_term, #pylint: disable=too-many-arguments
                       bigip_management_ip, bigip_management_port,
                       bigip_username, bigip_password):
        ''' Create a BIG-IP License Pool Member.
        :param: bigiq_session: BIG-IQ session object
        :param: pool_id: BIG-IQ pool ID
        :param: offering_id: Regkey offering type
        :param: license_term: The unit_of_measurement for the pool
        :param: bigip_management_ip: BIG-IP management IP
        :param: bigip_managemnt_port: BIG-IP management TCP port
        :param: bigip_username: BIG-IP username
        :param: bigip_password: BIG-IP password
        :returns: Member ID string
        :raises: requests.exceptions.HTTPError
        '''
        members_url = \
            '%s/utility/licenses/%s/offerings/%s/members' \
            % (bigiq_session.base_url, pool_id, offering_id)
        member = {
            'deviceAddress': bigip_management_ip,
            'httpsPort': bigip_management_port,
            'unitOfMeasure': license_term,
            'username': bigip_username,
            'password': bigip_password
        }
        response = bigiq_session.post(members_url,
                                      json=member)
        response.raise_for_status()
        response_json = response.json()
        return response_json['id']

    @staticmethod
    def _delete_member(bigiq_session, pool_id, offering_id,  #pylint: disable=too-many-arguments
                       member_id, bigip_username, bigip_password):
        ''' Delete a BIG-IP License Pool Member.
        :param: bigiq_session: BIG-IQ session object
        :param: pool_id: BIG-IQ pool ID
        :param: member_id: BIG-IQ member ID
        :param: bigip_username: BIG-IP username
        :param: bigip_password: BIG-IP password
        :returns: None
        :raises: requests.exceptions.HTTPError
        '''
        member_url = \
            '%s/utility/licenses/%s/offerings/%s/members/%s' % (
                bigiq_session.base_url,
                pool_id,
                offering_id,
                member_id
            )
        member = {
            'id': member_id,
            'username': bigip_username,
            'password': bigip_password
        }
        response = bigiq_session.delete(member_url,
                                        json=member)
        response.raise_for_status()
