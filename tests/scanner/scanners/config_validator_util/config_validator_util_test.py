# Copyright 2019 The Forseti Security Authors. All rights reserved.
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

"""Tests the Config Validator utils functionality."""

from google.cloud.forseti.scanner.scanners.config_validator_util \
    import cv_data_converter
from tests.unittest_utils import ForsetiTestCase
from tests.scanner.test_data import fake_data_models


class Resource(object):
    def __init__(self, cai_resource_name, cai_resource_type, full_name,
                 type_name, data):
        self.cai_resource_name = cai_resource_name
        self.cai_resource_type = cai_resource_type
        self.full_name = full_name
        self.type_name = type_name
        self.data = data


def _mock_gcp_resource_iter(resource_type):
    """Creates a list of GCP resource mocks retrieved by the scanner."""
    resource = Resource(
        cai_resource_name=resource_type.get('resource').get('cai_resource_name'),
        cai_resource_type=resource_type.get('resource').get('cai_resource_type'),
        full_name=resource_type.get('resource').get('full_name'),
        type_name=resource_type.get('resource').get('type_name'),
        data=resource_type.get('resource').get('data')
    )

    return resource


class ConfigValidatorUtilTest(ForsetiTestCase):
    """Test for the Config Validator Util."""

    def test_convert_data_to_cai_asset(self):
        """Validate convert_data_to_cai_asset() with test resource."""
        expected_resource = _mock_gcp_resource_iter(
            fake_data_models.EXPECTED_NON_CAI_RESOURCE)

        resource = (
            _mock_gcp_resource_iter(fake_data_models.FAKE_NON_CAI_RESOURCE))
        primary_key = fake_data_models.FAKE_NON_CAI_RESOURCE.get('primary_key')
        resource_type = (
            fake_data_models.FAKE_NON_CAI_RESOURCE.get('resource_type'))

        converted_resource = cv_data_converter.convert_data_to_cai_asset(
            primary_key, resource, resource_type)

        self.assertEqual(expected_resource.__dict__, converted_resource.__dict__)

    def test_convert_data_to_cv_asset(self):
        """Validate convert_data_to_cv_asset() with test resource."""
        resource = _mock_gcp_resource_iter(
            fake_data_models.EXPECTED_NON_CAI_RESOURCE)

        expected_name = "//cloudresourcemanager.googleapis.com/Lien/lien/p123"
        expected_asset_type = "cloudresourcemanager.googleapis.com/Lien"
        expected_ancestry_path = "folder/folder-1/project/project-2/"

        converted_resource = cv_data_converter.convert_data_to_cv_asset(
            resource, fake_data_models.EXPECTED_NON_CAI_RESOURCE["data_type"])

        self.assertEqual(expected_name, converted_resource.name, )
        self.assertEqual(expected_asset_type, converted_resource.asset_type)
        self.assertEqual(expected_ancestry_path,
                         converted_resource.ancestry_path)
