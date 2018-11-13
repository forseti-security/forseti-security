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

"""Tests for RetentionScanner."""

import collections
import json
import unittest
import mock
import tempfile

from tests.scanner.test_data import fake_retention_scanner_data as frsd
from tests.unittest_utils import ForsetiTestCase
from tests.unittest_utils import get_datafile_path
from google.cloud.forseti.common.gcp_type import organization
from google.cloud.forseti.common.gcp_type import project
from google.cloud.forseti.common.gcp_type import folder
from google.cloud.forseti.scanner.audit import retention_rules_engine as rre
from google.cloud.forseti.scanner.scanners import retention_scanner

def get_expect_violation_item(res_map, bucket_id, rule_name, rule_index):
    """Create violations for expected violation list"""
    lifecycle_str = json.dumps(res_map.get(bucket_id).get_lifecycle_rule())

    return rre.RuleViolation(
        resource_id=bucket_id,
        resource_name=u'buckets/'+bucket_id,
        resource_type=res_map.get(bucket_id).type,
        full_name=res_map.get(bucket_id).full_name,
        rule_name=rule_name,
        rule_index=rule_index,
        violation_type=rre.VIOLATION_TYPE,
        violation_data=lifecycle_str,
        resource_data=res_map.get(bucket_id).data)


def get_mock_bucket_retention(bucket_data):
    """Get the mock function for testcases"""

    def _mock_bucket_retention(_=None, resource_type='bucket'):
        """Creates a list of GCP resource mocks retrieved by the scanner"""

        if resource_type != 'bucket':
            raise ValueError(
                'unexpected resource type: got %s, bucket',
                resource_type,
            )

        ret = []
        for data in bucket_data:
            ret.append(frsd.get_fake_bucket_resource(data))

        return ret
    return _mock_bucket_retention


class RetentionScannerTest(ForsetiTestCase):

    def setUp(self):
        """Set up."""

    def test_bucket_retention_on_multi_buckets(self):
        """Test a rule that includes more than one bucket IDs"""

        rule_yaml = """
rules:
  - name: multiple buckets in a single rule
    applies_to:
      - bucket
    resource:
      - type: bucket
        resource_ids:
          - fake-bucket-1
          - fake-bucket-2
          - fake-bucket-3
    minimum_retention: 90

"""

        bucket_test_data=[
            frsd.FakeBucketDataInput(
                id='fake-bucket-1',
                project=frsd.PROJECT1,
                lifecycles=[frsd.LifecycleInput(action='Delete', conditions={'age':89})]
            ),
            frsd.FakeBucketDataInput(
                id='fake-bucket-2',
                project=frsd.PROJECT1,
                lifecycles=[frsd.LifecycleInput(action='Delete', conditions={'age':90})]
            ),
            frsd.FakeBucketDataInput(
                id='fake-bucket-3',
                project=frsd.PROJECT1,
                lifecycles=[frsd.LifecycleInput(action='Delete', conditions={'age':89})]
            ),
            frsd.FakeBucketDataInput(
                id='fake-bucket-4',
                project=frsd.PROJECT1,
                lifecycles=[frsd.LifecycleInput(action='Delete', conditions={'age':89})]
            ),
        ]

        _mock_bucket = get_mock_bucket_retention(bucket_test_data)

        with tempfile.NamedTemporaryFile(suffix='.yaml') as f:
            f.write(rule_yaml)
            f.flush()
            _fake_bucket_list = _mock_bucket(None, 'bucket')

            self.scanner = retention_scanner.RetentionScanner(
                {}, {}, mock.MagicMock(), '', '', f.name)

            mock_data_access = mock.MagicMock()
            mock_data_access.scanner_iter.side_effect = _mock_bucket

            mock_service_config = mock.MagicMock()
            mock_service_config.model_manager = mock.MagicMock()
            mock_service_config.model_manager.get.return_value = (
                mock.MagicMock(), mock_data_access)
            self.scanner.service_config = mock_service_config

            all_lifecycle_info = self.scanner._retrieve()
            all_violations = self.scanner._find_violations(all_lifecycle_info)

            res_map = {}
            for i in _fake_bucket_list:
                res_map[i.id] = i

            expected_violations = set([
                get_expect_violation_item(res_map, 'fake-bucket-1',
                                        'multiple buckets in a single rule', 0),
                get_expect_violation_item(res_map, 'fake-bucket-3',
                                        'multiple buckets in a single rule', 0)
            ])

            self.assertEqual(expected_violations, set(all_violations))

    def test_bucket_retention_on_multi_projects(self):
        """Test a rule that includes more than one project IDs"""

        rule_yaml = """
rules:
  - name: multiple projects in a single rule
    applies_to:
      - bucket
    resource:
      - type: project
        resource_ids:
          - def-project-1
          - def-project-2
          - def-project-3
    minimum_retention: 90

"""

        bucket_test_data=[
            frsd.FakeBucketDataInput(
                id='fake-bucket-11',
                project=frsd.PROJECT1,
                lifecycles=[frsd.LifecycleInput(action='Delete', conditions={'age':89})]
            ),
            frsd.FakeBucketDataInput(
                id='fake-bucket-12',
                project=frsd.PROJECT1,
                lifecycles=[frsd.LifecycleInput(action='Delete', conditions={'age':90})]
            ),
            frsd.FakeBucketDataInput(
                id='fake-bucket-13',
                project=frsd.PROJECT1,
                lifecycles=[frsd.LifecycleInput(action='Delete', conditions={'age':89})]
            ),
            frsd.FakeBucketDataInput(
                id='fake-bucket-2',
                project=frsd.PROJECT2,
                lifecycles=[frsd.LifecycleInput(action='Delete', conditions={'age':90})]
            ),
            frsd.FakeBucketDataInput(
                id='fake-bucket-3',
                project=frsd.PROJECT3,
                lifecycles=[frsd.LifecycleInput(action='Delete', conditions={'age':89})]
            ),
            frsd.FakeBucketDataInput(
                id='fake-bucket-4',
                project=frsd.PROJECT4,
                lifecycles=[frsd.LifecycleInput(action='Delete', conditions={'age':89})]
            ),
        ]

        _mock_bucket = get_mock_bucket_retention(bucket_test_data)

        with tempfile.NamedTemporaryFile(suffix='.yaml') as f:
            f.write(rule_yaml)
            f.flush()
            _fake_bucket_list = _mock_bucket(None, resource_type='bucket')

            self.scanner = retention_scanner.RetentionScanner(
                {}, {}, mock.MagicMock(), '', '', f.name)

            mock_data_access = mock.MagicMock()
            mock_data_access.scanner_iter.side_effect = _mock_bucket

            mock_service_config = mock.MagicMock()
            mock_service_config.model_manager = mock.MagicMock()
            mock_service_config.model_manager.get.return_value = (
                mock.MagicMock(), mock_data_access)
            self.scanner.service_config = mock_service_config

            all_lifecycle_info = self.scanner._retrieve()
            all_violations = self.scanner._find_violations(all_lifecycle_info)

            res_map = {}
            for i in _fake_bucket_list:
                res_map[i.id] = i

            expected_violations = set([
                get_expect_violation_item(res_map, 'fake-bucket-11',
                                        'multiple projects in a single rule', 0),
                get_expect_violation_item(res_map, 'fake-bucket-13',
                                        'multiple projects in a single rule', 0),
                get_expect_violation_item(res_map, 'fake-bucket-3',
                                        'multiple projects in a single rule', 0)
            ])

            self.assertEqual(expected_violations, set(all_violations))

    def test_bucket_retention_on_mix_project_and_bucket(self):
        """Test yaml file that includes more than one rules"""

        rule_yaml = """
rules:
  - name: project 1 min 90
    applies_to:
      - bucket
    resource:
      - type: project
        resource_ids:
          - def-project-1
    minimum_retention: 90
  - name: buckets max 100
    applies_to:
      - bucket
    resource:
      - type: bucket
        resource_ids:
          - fake-bucket-11
          - fake-bucket-12
          - fake-bucket-13
    maximum_retention: 100

"""

        bucket_test_data=[
            frsd.FakeBucketDataInput(
                id='fake-bucket-11',
                project=frsd.PROJECT1,
                lifecycles=[frsd.LifecycleInput(action='Delete', conditions={'age':90})]
            ),
            frsd.FakeBucketDataInput(
                id='fake-bucket-12',
                project=frsd.PROJECT1,
                lifecycles=[frsd.LifecycleInput(action='Delete', conditions={'age':89})]
            ),
            frsd.FakeBucketDataInput(
                id='fake-bucket-13',
                project=frsd.PROJECT1,
                lifecycles=[]
            ),
        ]

        _mock_bucket = get_mock_bucket_retention(bucket_test_data)

        with tempfile.NamedTemporaryFile(suffix='.yaml') as f:
            f.write(rule_yaml)
            f.flush()
            _fake_bucket_list = _mock_bucket(resource_type='bucket')

            self.scanner = retention_scanner.RetentionScanner(
                {}, {}, mock.MagicMock(), '', '', f.name)

            mock_data_access = mock.MagicMock()
            mock_data_access.scanner_iter.side_effect = _mock_bucket

            mock_service_config = mock.MagicMock()
            mock_service_config.model_manager = mock.MagicMock()
            mock_service_config.model_manager.get.return_value = (
                mock.MagicMock(), mock_data_access)
            self.scanner.service_config = mock_service_config

            all_lifecycle_info = self.scanner._retrieve()
            all_violations = self.scanner._find_violations(all_lifecycle_info)

            res_map = {}
            for i in _fake_bucket_list:
                res_map[i.id] = i

            expected_violations = set([
                get_expect_violation_item(res_map, 'fake-bucket-12',
                                        'project 1 min 90', 0),
                get_expect_violation_item(res_map, 'fake-bucket-13',
                                        'buckets max 100', 1)
            ])

            self.assertEqual(expected_violations, set(all_violations))

    def test_bucket_retention_on_multi_rules_on_a_project(self):
        """Test yaml file that includes more than one rules that works on the same project"""

        rule_yaml = """
rules:
  - name: project 1 min 90
    applies_to:
      - bucket
    resource:
      - type: project
        resource_ids:
          - def-project-1
    minimum_retention: 90
  - name: project 1 min 100
    applies_to:
      - bucket
    resource:
      - type: project
        resource_ids:
          - def-project-1
    minimum_retention: 100
  - name: project 1 min 110
    applies_to:
      - bucket
    resource:
      - type: project
        resource_ids:
          - def-project-1
    minimum_retention: 110

"""

        bucket_test_data=[
            frsd.FakeBucketDataInput(
                id='fake-bucket-11',
                project=frsd.PROJECT1,
                lifecycles=[frsd.LifecycleInput(action='Delete', conditions={'age':90})]
            ),
            frsd.FakeBucketDataInput(
                id='fake-bucket-12',
                project=frsd.PROJECT1,
                lifecycles=[frsd.LifecycleInput(action='Delete', conditions={'age':100})]
            ),
            frsd.FakeBucketDataInput(
                id='fake-bucket-13',
                project=frsd.PROJECT1,
                lifecycles=[frsd.LifecycleInput(action='Delete', conditions={'age':110})]
            ),
        ]

        _mock_bucket = get_mock_bucket_retention(bucket_test_data)

        with tempfile.NamedTemporaryFile(suffix='.yaml') as f:
            f.write(rule_yaml)
            f.flush()
            _fake_bucket_list = _mock_bucket(resource_type='bucket')

            self.scanner = retention_scanner.RetentionScanner(
                {}, {}, mock.MagicMock(), '', '', f.name)

            mock_data_access = mock.MagicMock()
            mock_data_access.scanner_iter.side_effect = _mock_bucket

            mock_service_config = mock.MagicMock()
            mock_service_config.model_manager = mock.MagicMock()
            mock_service_config.model_manager.get.return_value = (
                mock.MagicMock(), mock_data_access)
            self.scanner.service_config = mock_service_config

            all_lifecycle_info = self.scanner._retrieve()
            all_violations = self.scanner._find_violations(all_lifecycle_info)

            res_map = {}
            for i in _fake_bucket_list:
                res_map[i.id] = i

            expected_violations = set([
                get_expect_violation_item(res_map, 'fake-bucket-11',
                                        'project 1 min 100', 1),
                get_expect_violation_item(res_map, 'fake-bucket-11',
                                        'project 1 min 110', 2),
                get_expect_violation_item(res_map, 'fake-bucket-12',
                                        'project 1 min 110', 2)
            ])

            self.assertEqual(expected_violations, set(all_violations))
