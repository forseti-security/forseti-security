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
"""Tests for BigqueryScanner."""

import collections
import json
import unittest
import mock

from tests.scanner.test_data import fake_bigquery_scanner_data as fbsd
from tests.unittest_utils import ForsetiTestCase
from google.cloud.forseti.common.gcp_type import resource as resource_mod
from google.cloud.forseti.scanner.scanners import bigquery_scanner


def _mock_gcp_resource_iter(_, resource_type):
    """Creates a list of GCP resource mocks retrieved by the scanner."""
    resources = []
    if resource_type != 'dataset_policy':
        raise ValueError(
            'unexpected resource type: got %s, want dataset_policy',
            resource_type,
        )

    Resource = collections.namedtuple(
        'Resource',
        # fields based on required fields from Resource in dao.py.
        ['full_name', 'type', 'name', 'parent_type_name', 'parent',
         'data'],
    )

    for resource in fbsd.BIGQUERY_DATA:
        policy_name = resource['full_name']
        dataset_name =  '/'.join(policy_name.split('/')[:-3]) + '/'
        proj_name = '/'.join(dataset_name.split('/')[:-3]) + '/'

        proj = Resource(
            full_name=proj_name,
            type='project',
            name='projects/' + resource['project_id'],
            parent_type_name='',
            parent=None,
            data='',
        )

        dataset= Resource(
            full_name=dataset_name,
            type='dataset',
            name='dataset/' + resource['dataset_id'],
            parent_type_name='project',
            parent=proj,
            data='',
        )

        policy = Resource(
            full_name=policy_name,
            type='dataset_policy',
            parent_type_name='dataset',
            name='dataset_policies/' + resource['dataset_id'],
            parent=dataset,
            data=json.dumps([{}]),
        )
        resources.append(policy)
    return resources


class BigqueryScannerTest(ForsetiTestCase):

    @mock.patch(
        'google.cloud.forseti.scanner.scanners.bigquery_scanner.'
        'bigquery_rules_engine',
        autospec=True)
    def setUp(self, _):
        self.scanner = bigquery_scanner.BigqueryScanner(
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

        bq_acl_data = self.scanner._retrieve()

        expected_projects = [
            'organization/234/project/p1/',
            'organization/234/folder/56/project/p2/',
        ]

        expected_dataset_ids = ['dataset/d1', 'dataset/d2']

        self.assertEqual(2, len(bq_acl_data))

        for i in xrange(2):
            self.assertEqual(expected_projects[i],
                             bq_acl_data[i].parent_project.full_name)

            self.assertEqual(expected_dataset_ids[i],
                             bq_acl_data[i].bigquery_acl.dataset_id)

    def test_find_violations(self):
        """Tests _find_violations passes log sink configs to the rule engine."""
        bq_acl_data = [
            bigquery_scanner.BigqueryAccessControlsData('resource-1', 'acl-1'),
            bigquery_scanner.BigqueryAccessControlsData('resource-2', 'acl-2'),
            bigquery_scanner.BigqueryAccessControlsData('resource-3', 'acl-3'),
        ]

        self.scanner.rules_engine.find_violations.side_effect = [
            ['viol-1', 'viol-2'], [], ['viol-3']]

        violations = self.scanner._find_violations(bq_acl_data)

        self.scanner.rules_engine.find_violations.assert_has_calls(
            [mock.call(d.parent_project, d.bigquery_acl) for d in bq_acl_data])

        self.assertEquals(['viol-1', 'viol-2', 'viol-3'], violations)


if __name__ == '__main__':
    unittest.main()
