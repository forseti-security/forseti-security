# Copyright 2018 The Forseti Security Authors. All rights reserved.
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
"""Tests for resourceScanner."""

import collections
import json
import unittest
import mock

from tests.scanner.test_data import fake_resource_scanner_data as data
from tests.unittest_utils import ForsetiTestCase
from google.cloud.forseti.common.gcp_type import resource_util
from google.cloud.forseti.scanner.scanners import resource_scanner


def _mock_gcp_resource_iter(_, resource_type):
    """Creates a list of GCP resource mocks retrieved by the scanner."""

    Resource = collections.namedtuple(
        'Resource',
        # fields based on required fields from Resource in dao.py.
        ['full_name', 'type', 'name', 'parent_type_name', 'parent',
         'data'],
    )

    project_resource = Resource(
        full_name=data.PROJECT.full_name,
        type=data.PROJECT.type,
        name=data.PROJECT.name,
        parent_type_name='',
        parent=None,
        data='',
    )


    def _create_child_resource(res):
        return Resource(
            full_name=res.full_name,
            type=res.type,
            parent_type_name='project/' + res.parent.id,
            name=res.id,
            data=res.data,
            parent=project_resource,
        )

    if resource_type == 'bucket':
        resource = _create_child_resource(data.BUCKET)
    elif resource_type == 'project':
        return project_resource
    return [resource] if resource else []


class ResourceScannerTest(ForsetiTestCase):

    @mock.patch.object(resource_scanner, 'resource_rules_engine', autospec=True)
    def setUp(self, mock_rule_engine):
        self.scanner = resource_scanner.LocationScanner(
            {}, {}, mock.MagicMock(), '', '', '')

        mock_rule_engine.get_applicable_resource_types = set(
            ['project', 'bucket'])

    def test_retrieve(self):
        mock_data_access = mock.MagicMock()
        mock_data_access.scanner_iter.side_effect = _mock_gcp_resource_iter
        mock_service_config = mock.MagicMock()
        mock_service_config.model_manager = mock.MagicMock()
        mock_service_config.model_manager.get.return_value = (
            mock.MagicMock(), mock_data_access)
        self.scanner.service_config = mock_service_config

        got = set(self.scanner._retrieve())
        want = {data.BUCKET, data.PROJECT}
        self.assertEqual(got, want)

if __name__ == '__main__':
    unittest.main()
