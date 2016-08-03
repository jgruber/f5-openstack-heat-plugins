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
import json

from heat.common import exception
from heat.common.i18n import _
from heat.engine import properties
from heat.engine import attributes
from heat.engine import resource

from common.mixins import F5BigIPMixin
from common.mixins import f5_bigip


class F5BigIPProvisioningLevels(resource.Resource, F5BigIPMixin):
    '''Manages module provisioning levels for a F5® BigIP.'''

    PROPERTIES = (
        BIGIP_SERVER,
        AFM,
        AM,
        APM,
        ASM,
        AVR,
        FPS,
        GTM,
        LC,
        LTM,
        PEM,
        SWG
    ) = (
        'bigip_server',
        'afm',
        'am',
        'apm',
        'asm',
        'avr',
        'fps',
        'gtm',
        'lc',
        'ltm',
        'pem',
        'swg'
    )

    properties_schema = {
        BIGIP_SERVER: properties.Schema(
            properties.Schema.STRING,
            _('Reference to the BigIP server resource.'),
            required=True
        ),
        AFM: properties.Schema(
            properties.Schema.STRING,
            _('Provisioning Level for AFM'),
            required=False,
            default='none'
        ),
        AM: properties.Schema(
            properties.Schema.STRING,
            _('Provisioning Level for AM'),
            required=False,
            default='none'
        ),
        APM: properties.Schema(
            properties.Schema.STRING,
            _('Provisioning Level for APM'),
            required=False,
            default='none'
        ),
        ASM: properties.Schema(
            properties.Schema.STRING,
            _('Provisioning Level for ASM'),
            required=False,
            default='none'
        ),
        AVR: properties.Schema(
            properties.Schema.STRING,
            _('Provisioning Level for AVR'),
            required=False,
            default='none'
        ),
        FPS: properties.Schema(
            properties.Schema.STRING,
            _('Provisioning Level for FPS'),
            required=False,
            default='none'
        ),
        GTM: properties.Schema(
            properties.Schema.STRING,
            _('Provisioning Level for GTM'),
            required=False,
            default='none'
        ),
        LC: properties.Schema(
            properties.Schema.STRING,
            _('Provisioning Level for LC'),
            required=False,
            default='none'
        ),
        LTM: properties.Schema(
            properties.Schema.STRING,
            _('Provisioning Level for LTM'),
            required=False,
            default='nominal'
        ),
        PEM: properties.Schema(
            properties.Schema.STRING,
            _('Provisioning Level for PEM'),
            required=False,
            default='none'
        ),
        SWG: properties.Schema(
            properties.Schema.STRING,
            _('Provisioning Level for SWG'),
            required=False,
            default='none'
        )
    }

    ATTRIBUTES = (
        AFM,
        AM,
        APM,
        ASM,
        AVR,
        FPS,
        GTM,
        LC,
        LTM,
        PEM,
        SWG
    ) = (
        'afm',
        'am',
        'apm',
        'asm',
        'avr',
        'fps',
        'gtm',
        'lc',
        'ltm',
        'pem',
        'swg'
    )

    attributes_schema = {
        AFM: attributes.Schema(
           _('AFM Provisioning Level.'),
           attributes.Schema.STRING
        ),
        AM: attributes.Schema(
           _('AM Provisioning Level.'),
           attributes.Schema.STRING
        ),
        APM: attributes.Schema(
           _('APM Provisioning Level.'),
           attributes.Schema.STRING
        ),
        ASM: attributes.Schema(
           _('ASM Provisioning Level.'),
           attributes.Schema.STRING
        ),
        AVR: attributes.Schema(
           _('AVR Provisioning Level.'),
           attributes.Schema.STRING
        ),
        FPS: attributes.Schema(
           _('FPS Provisioning Level.'),
           attributes.Schema.STRING
        ),
        GTM: attributes.Schema(
           _('GTM Provisioning Level.'),
           attributes.Schema.STRING
        ),
        LC: attributes.Schema(
           _('LC Provisioning Level.'),
           attributes.Schema.STRING
        ),
        LTM: attributes.Schema(
           _('LTM Provisioning Level.'),
           attributes.Schema.STRING
        ),
        PEM: attributes.Schema(
           _('PEM Provisioning Level.'),
           attributes.Schema.STRING
        ),
        SWG: attributes.Schema(
           _('SWG Provisioning Level.'),
           attributes.Schema.STRING
        )
    }

    def _resolve_attribute(self, name):
        if name == self.AFM:
            return self.afm_level
        if name == self.AM:
            return self.am_level
        if name == self.APM:
            return self.apm_level
        if name == self.ASM:
            return self.asm_level
        if name == self.AVR:
            return self.avr_level
        if name == self.FPS:
            return self.fps_level
        if name == self.GTM:
            return self.gtm_level
        if name == self.LC:
            return self.lc_level
        if name == self.LTM:
            return self.ltm_level
        if name == self.PEM:
            return self.pem_level
        if name == self.SWG:
            return self.swg_level

    @f5_bigip
    def handle_create(self):
        '''Set BIG-IP Provisioning Levels.

        :rasies: ResourceFailure
        '''

        self.afm_level = 'undefined'
        self.am_level = 'undefined'
        self.apm_level = 'undefined'
        self.asm_level = 'undefined'
        self.avr_level = 'undefined'
        self.fps_level = 'undefined'
        self.gtm_level = 'undefined'
        self.lc_level = 'undefined'
        self.ltm_level = 'undefined'
        self.pem_level = 'undefined'
        self.swg_level = 'undefined'

        provisions = self.bigip.tm.sys.provisions.get_collection()
        for provision in provisions:
            try:
                self._update_provisioning_level(provision)
            except Exception as ex:
                raise exception.ResourceFailure(ex, None, action='CREATE')

        resource_id_dict = {
            'afm': self.afm_level,
            'am': self.am_level,
            'apm': self.apm_level,
            'asm': self.asm_level,
            'avr': self.avr_level,
            'fps': self.fps_level,
            'gtm': self.gtm_level,
            'lc': self.lc_level,
            'ltm': self.ltm_level,
            'pem': self.pem_level,
            'swg': self.swg_level
        }

        self.resource_id_set(json.dumps(resource_id_dict))

        return self.resource_id

    def _update_provisioning_level(self, provision):
        if hasattr(self, provision.name.upper()):
            desired_level = self.properties[provision.name.upper()]
            if not provision.level.lower() == desired_level:
                provision.level = desired_level
                provision.update()
                attribute_name = "%s_level" % provision.name
                setattr(self, attribute_name, provision.level)

    def handle_delete(self):
        '''Leave BIG-IP Provisioning Levels.

        :raises: ResourceFailure
        '''

        return True


def resource_mapping():
    return {'F5::BigIP::ProvisioningLevels':
            F5BigIPProvisioningLevels}
