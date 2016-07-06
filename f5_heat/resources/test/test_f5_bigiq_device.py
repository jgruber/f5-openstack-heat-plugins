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

from f5.bigip import ManagementRoot
from f5_heat.resources import f5_bigiq_device
from f5_heat.resources.f5_bigiq_device import BigIQConnectionFailed
from heat.common import exception
from heat.common import template_format
from heat.engine.hot.template import HOTemplate20150430
from heat.engine import rsrc_defn
from heat.engine import template

import mock
import pytest

f5_bigiq_defn = '''
heat_template_version: 2015-04-30
description: Testing BigIQ Device
resources:
  bigiq_rsrc:
    type: F5::BigIQ::Device
    properties:
      ip: 10.0.0.1
      username: admin
      password: admin
'''


bad_f5_bigiq_defn = '''
heat_template_version: 2015-04-30
description: Testing BigIQ Device
resources:
  bigiq_rsrc:
    type: F5::BigIQ::Device
    properties:
      ip: good_ip
      username: admin
      password: admin
      bad_property: bad_prop
'''


test_uuid = '8ab7ea3a-5185-4295-9420-a6a5162928eb'

versions = ('2015-04-30', '2015-04-30')


@mock.patch.object(template, 'get_version', return_value=versions)
@mock.patch.object(
    template,
    'get_template_class',
    return_value=HOTemplate20150430
)
def mock_template(templ_vers, templ_class, test_templ=f5_bigiq_defn):
    '''Mock a Heat template for the Kilo version.'''
    templ_dict = template_format.parse(test_templ)
    return templ_dict


def create_resource_definition(templ_dict):
    '''Create resource definition.'''
    rsrc_def = rsrc_defn.ResourceDefinition(
        'test_stack',
        templ_dict['resources']['bigiq_rsrc']['type'],
        properties=templ_dict['resources']['bigiq_rsrc']['properties']
    )
    return rsrc_def


@pytest.fixture
@mock.patch('f5_heat.resources.f5_bigiq_device.ManagementRoot')
def F5BigIQ(mock_mr):
    '''Instantiate the F5BigIP resource.'''
    template_dict = mock_template()
    rsrc_def = create_resource_definition(template_dict)
    f5_bigiq_obj = f5_bigiq_device.F5BigIQDevice(
        "testing_service", rsrc_def, mock.MagicMock()
    )
    f5_bigiq_obj.uuid = test_uuid
    f5_bigiq_obj.validate()
    return f5_bigiq_obj


@pytest.fixture
def F5BigIPSideEffect(F5BigIQ):
    F5BigIQ.get_bigip = mock.MagicMock()
    return F5BigIQ


@pytest.fixture
def F5BigIQHTTPError(F5BigIQ):
    '''Instantiate the F5BigIP resource.'''
    mock_get_bigip = mock.MagicMock(side_effect=BigIQConnectionFailed)
    F5BigIQ.get_bigip = mock_get_bigip
    return F5BigIQ


# Tests

# Removed __init__ override, so removing test
@mock.patch.object(
    f5_bigiq_device.ManagementRoot,
    '__init__',
    side_effect=Exception()
)
def itest__init__error(mocked_bigiq):
    template_dict = mock_template()
    rsrc_def = create_resource_definition(template_dict)
    with pytest.raises(Exception):
        f5_bigiq_device.F5BigIQDevice(
            'test_template',
            rsrc_def,
            mock.MagicMock()
        )


def test_handle_create(F5BigIQSideEffect):
    create_result = F5BigIQSideEffect.handle_create()
    assert create_result is None
    assert F5BigIQSideEffect.resource_id is not None


def test_handle_create_http_error(F5BigIQHTTPError):
    with pytest.raises(BigIQConnectionFailed):
        F5BigIQHTTPError.handle_create()


def test_handle_delete(F5BigIQ):
    delete_result = F5BigIQ.handle_delete()
    assert delete_result is True


@mock.patch(
    'f5_heat.resources.f5_bigiq_device.ManagementRoot.__init__',
    return_value=None
)
def test_bigip_getter(mock_mr_init):
    template_dict = mock_template(test_templ=bad_f5_bigiq_defn)
    rsrc_def = create_resource_definition(template_dict)
    f5_bigiq_obj = f5_bigiq_device.F5BigIQDevice(
        'test',
        rsrc_def,
        mock.MagicMock()
    )
    bigiq = f5_bigiq_obj.get_bigiq()
    assert isinstance(bigiq, ManagementRoot)


@mock.patch('f5_heat.resources.f5_bigiq_device.ManagementRoot')
def test_bad_property(mock_mr):
    template_dict = mock_template(test_templ=bad_f5_bigiq_defn)
    rsrc_def = create_resource_definition(template_dict)
    f5_bigiq_obj = f5_bigiq_device.F5BigIQDevice(
        'test',
        rsrc_def,
        mock.MagicMock()
    )
    with pytest.raises(exception.StackValidationFailed):
        f5_bigiq_obj.validate()


def test_resource_mapping():
    rsrc_map = f5_bigiq_device.resource_mapping()
    assert rsrc_map == {
        'F5::BigIQ::Device': f5_bigiq_device.F5BigIQDevice
    }
