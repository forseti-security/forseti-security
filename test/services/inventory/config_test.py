# Copyright 2017 The Forseti Security Authors. All rights reserved.
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
"""Unit Tests: Inventory crawler for Forseti Server."""

import unittest
from test import unittest_utils

from google.cloud.forseti.services.base.config import InventoryConfig


class ConfigTest(unittest_utils.ForsetiTestCase):

    def test_inventory_config_exclude_resource_invalid_ids(self):
        self.inventory_config = InventoryConfig('test-org-id',
                                                '',
                                                {},
                                                0,
                                                {'enabled': True,
                                                 'gcs_path': 'gs://test-bucket'},
                                                excluded_resources=[
                                                    'asd',
                                                    'projects/aqwedas',
                                                    'projects/222',
                                                    'folders/badfolder',
                                                    'organizations/testing',
                                                    'organizations/12345',
                                                    'folders/12345'])
        self.assertSetEqual(set(self.inventory_config.excluded_resources),
                            {'project/aqwedas',
                             'project/222',
                             'organization/12345',
                             'folder/12345'})


if __name__ == '__main__':
    unittest.main()
