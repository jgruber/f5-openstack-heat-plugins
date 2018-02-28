'''Provides a BIG-IQ requests session.'''
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


class F5BigIQHost(object):
    ''' BIG-IQ Host Session'''
    bigiq_host = None
    bigiq_username = None
    bigiq_password = None
    bigiq_timeout = 10

    def __init__(self, bigiq_host=None, bigiq_username=None,
                 bigiq_password=None, bigiq_timeout=10):
        self.bigiq_host = bigiq_host
        self.bigiq_username = bigiq_username
        self.bigiq_password = bigiq_password
        self.bigiq_timeout = bigiq_timeout

    def get_config(self):
        ''' Returns BIG-IQ host configuration '''
        config = {
            'bigiq_host': self.bigiq_host,
            'bigiq_username': self.bigiq_username,
            'bigiq_password': self.bigiq_password,
            'bigiq_timeout': self.bigiq_timeout
        }
        return config

    def get_bigiq_session(self):
        ''' Creates a Requests Session to the BIG-IQ host configured '''
        if requests.__version__ < '2.9.1':
            requests.packages.urllib3.disable_warnings()  # pylint: disable=no-member
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
