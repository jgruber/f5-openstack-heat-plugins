'''Provides a BIG-IP license pool member and requests session to member.'''
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

import requests


class F5BigIQLicensePoolMember(object):  # pylint: disable=too-many-instance-attributes
    ''' BIG-IQ Pool Member Licensing '''
    bigiq_license_pool_name = None
    bigip_management_ip = None
    bigip_username = None
    bigip_password = None
    bigip_management_port = 443
    bigip_timeout = 10
    license_attempts = 30
    error_delay = 10

    def __init__(self, bigiq_license_pool_name=None,  # pylint: disable=too-many-arguments
                 bigip_management_ip=None, bigip_username=None,
                 bigip_password=None, bigip_management_port=443,
                 bigip_timeout=10, license_attempts=30, error_delay=10):
        self.bigiq_license_pool_name = bigiq_license_pool_name
        self.bigip_management_ip = bigip_management_ip
        self.bigip_management_port = bigip_management_port
        self.bigip_username = bigip_username
        self.bigip_password = bigip_password
        self.bigip_timeout = bigip_timeout
        self.license_attempts = license_attempts
        self.error_delay = error_delay

    def get_config(self):
        ''' Returns BIG-IQ host configuration '''
        config = {
            'bigiq_license_pool_name': self.bigiq_license_pool_name,
            'bigip_management_ip': self.bigip_management_ip,
            'bigip_management_port': self.bigip_management_port,
            'bigip_username': self.bigip_username,
            'bigip_password': self.bigip_password,
            'bigip_timeout': self.bigip_timeout,
            'attempts': self.license_attempts,
            'error_delay': self.error_delay
        }
        return config

    def get_bigip_session(self):
        ''' Creates a Requests Session to the BIG-IP member configured '''
        if requests.__version__ < '2.9.1':
            requests.packages.urllib3.disable_warnings()  # pylint: disable=no-member
        bigip = requests.Session()
        bigip.verify = False
        bigip.headers.update({'Content-Type': 'application/json'})
        bigip.timeout = self.bigip_timeout
        token_auth_body = {'username': self.bigip_username,
                           'password': self.bigip_password,
                           'loginProviderName': 'local'}
        login_url = "https://%s:%d/mgmt/shared/authn/login" % (
            self.bigip_management_ip, self.bigip_management_port)
        response = bigip.post(login_url,
                              json=token_auth_body,
                              verify=False,
                              auth=requests.auth.HTTPBasicAuth(
                                  self.bigip_username, self.bigip_password))
        response_json = response.json()
        bigip.headers.update(
            {'X-F5-Auth-Token': response_json['token']['token']})
        bigip.base_url = 'https://%s:%d/mgmt/tm/' % \
            (self.bigip_management_ip, self.bigip_management_port)
        return bigip
