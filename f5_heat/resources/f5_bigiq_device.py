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

from f5.bigiq import ManagementRoot
from heat.common.i18n import _
from heat.engine import properties
from heat.engine import resource
from requests.exceptions import ConnectionError
from requests import HTTPError
from icontrol.session import iControlUnexpectedHTTPError
from time import sleep


class BigIQConnectionFailed(HTTPError):
    pass


class F5BigIQDevice(resource.Resource):
    '''
    Holds BigIQ
    server, username, password, timeout,
    continue_on_error, delay_between_attempts, max_attempts
    '''

    PROPERTIES = (
        IP,
        USERNAME,
        PASSWORD,
        TIMEOUT,
        CONTINUE_ON_ERROR,
        DELAY_BETWEEN_ATTEMPTS,
        MAX_ATTEMPTS
    ) = (
        'ip',
        'username',
        'password',
        'timeout',
        'continue_on_error',
        'delay_between_attempts',
        'max_attempts'
    )

    properties_schema = {
        IP: properties.Schema(
            properties.Schema.STRING,
            _('IP address of BigIP device.'),
            required=True
        ),
        USERNAME: properties.Schema(
            properties.Schema.STRING,
            _('Username for logging into the BigIP.'),
            required=True
        ),
        PASSWORD: properties.Schema(
            properties.Schema.STRING,
            _('Password for logging into the BigIP.'),
            required=True
        ),
        TIMEOUT: properties.Schema(
            properties.Schema.INTEGER,
            _('Seconds to wait for BigIP to connect.'),
            required=False,
            default=30
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

    def get_bigiq(self):
        if self.properties[self.CONTINUE_ON_ERROR]:
            number_of_attempts = 0
            while(number_of_attempts < self.properties[self.MAX_ATTEMPTS]):
                try:
                    return ManagementRoot(
                        self.properties[self.IP],
                        self.properties[self.USERNAME],
                        self.properties[self.PASSWORD],
                        timeout=self.properties[self.TIMEOUT]
                    )
                except ConnectionError as ce:
                    number_of_attempts += 1
                    logging.warning(ce.message)
                except iControlUnexpectedHTTPError as icrderror:
                    number_of_attempts += 1
                    logging.warning(icrderror.message)
                except Exception as readtimeout:
                    number_of_attempts += 1
                    logging.warning(readtimeout.message)
                sleep(self.properties[self.DELAY_BETWEEN_ATTEMPTS])
            raise ConnectionError('Connection failed after %d attempts'
                                  % self.properties[self.MAX_ATTEMPTS])
        else:
            return ManagementRoot(
                self.properties[self.IP],
                self.properties[self.USERNAME],
                self.properties[self.PASSWORD],
                timeout=self.properties[self.TIMEOUT]
            )

    def handle_create(self):
        '''Create the BigIQ resource.

        Attempt to initialize a bigiq connection to test connectivity

        raises: BigIPConnectionFailed
        '''

        try:
            self.get_bigiq()
        except HTTPError as ex:
            raise BigIQConnectionFailed(ex)

        self.resource_id_set(self.physical_resource_name())

    def handle_delete(self):
        '''Delete this connection to the BIG-IP® device.'''

        return True


def resource_mapping():
    return {'F5::BigIQ::Device': F5BigIQDevice}
