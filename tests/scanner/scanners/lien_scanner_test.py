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
"""Tests for LienScanner."""

import collections
import json
import unittest
import mock

from tests.scanner.test_data import fake_lien_scanner_data
from tests.unittest_utils import ForsetiTestCase
from google.cloud.forseti.common.gcp_type import resource as resource_mod
from google.cloud.forseti.scanner.scanners import lien_scanner


def _mock_gcp_resource_iter(_, resource_type):
    """Creates a list of GCP resource mocks retrieved by the scanner."""
    resources = []
    if resource_type != 'lien':
        raise ValueError(
            'unexpected resource type: got %s, want lien',
            resource_type,
        )

    Resource = collections.namedtuple(
        'Resource',
        # fields based on required fields from Resource in dao.py.
        ['full_name', 'type', 'name', 'parent_type_name', 'parent',
         'data'],
    )

    for lien in fake_lien_scanner_data.LIENS:
        project_resource = Resource(
            full_name=fake_lien_scanner_data.PROJECT_WITH_LIEN.full_name,
            type='project',
            name=fake_lien_scanner_data.PROJECT_WITH_LIEN.id,
            parent_type_name='',
            parent=None,
            data='',
        )

        lien_resource = Resource(
            full_name=fake_lien_scanner_data.LIENS[0].full_name,
            type='lien',
            parent_type_name='project',
            name=fake_lien_scanner_data.LIENS[0].full_name.split('/')[-2],
            parent=project_resource,
            data=lien.raw_json,
        )
        resources.append(lien_resource)
    return resources


class LienScannerTest(ForsetiTestCase):

    @mock.patch.object(lien_scanner, 'lien_rules_engine', autospec=True)
    def setUp(self, _):
        self.scanner = lien_scanner.LienScanner(
            {}, {}, mock.MagicMock(), '', '', '')

    def test_retrieve(self):
        """Tests _retrieve gets all bq acls and parent resources."""
        mock_data_access = mock.MagicMock()
        mock_data_access.scanner_iter.side_effect = _mock_gcp_resource_iter
        mock_service_config = mock.MagicMock()
        mock_service_config.model_manager = mock.MagicMock()
        mock_service_config.model_manager.get.return_value = (
            mock.MagicMock(), mock_data_access)
        self.scanner.service_config = mock_service_config

        liens = self.scanner._retrieve()

        self.assertEqual(1, len(liens))
        self.assertEqual(liens[0].parent.full_name,
                         'organization/234/project/p1/')
        self.assertEqual(liens[0].name, 'projects/p1/liens/l1')


if __name__ == '__main__':
    unittest.main()
