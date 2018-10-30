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
from collections import namedtuple
import tempfile

from tests.scanner.test_data import fake_retention_scanner_data as frsd
from tests.unittest_utils import ForsetiTestCase
from tests.unittest_utils import get_datafile_path
from google.cloud.forseti.common.gcp_type import organization
from google.cloud.forseti.common.gcp_type import project
from google.cloud.forseti.common.gcp_type import folder
from google.cloud.forseti.scanner.audit import retention_rules_engine as rre
from google.cloud.forseti.scanner.scanners import retention_scanner

do_not_test_old_cases = True

def get_expect_violation_item(res_map, bucket_id, rule_name, rule_index):
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

yaml_str_multi_buckets_in_a_rule = """
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

_fake_bucket_list_for_multi_buckets_in_a_rule = []

def generate_res_bucket_retention_multi_buckets_in_a_rule():
    res = []

    data_creater = frsd.FakeBucketDataCreater('fake-bucket-1', frsd.PROJECT1)
    data_creater.AddLefecycleDict("Delete", 89, None, None, None, None)
    res.append(data_creater.get_resource())

    data_creater = frsd.FakeBucketDataCreater('fake-bucket-2', frsd.PROJECT1)
    data_creater.AddLefecycleDict("Delete", 90, None, None, None, None)
    res.append(data_creater.get_resource())

    data_creater = frsd.FakeBucketDataCreater('fake-bucket-3', frsd.PROJECT1)
    data_creater.AddLefecycleDict("Delete", 89, None, None, None, None)
    res.append(data_creater.get_resource())

    data_creater = frsd.FakeBucketDataCreater('fake-bucket-4', frsd.PROJECT1)
    data_creater.AddLefecycleDict("Delete", 89, None, None, None, None)
    res.append(data_creater.get_resource())

    return res

def _mock_bucket_retention_multi_buckets_in_a_rule(_, resource_type):
    if resource_type != 'bucket':
        raise ValueError(
            'unexpected resource type: got %s, bucket',
            resource_type,
        )

    return _fake_bucket_list_for_multi_buckets_in_a_rule


yaml_str_multi_projects_in_a_rule = """
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

_fake_bucket_list_for_multi_projects_in_a_rule = []

def generate_res_bucket_retention_multi_projects_in_a_rule():
    res = []

    data_creater = frsd.FakeBucketDataCreater('fake-bucket-11', frsd.PROJECT1)
    data_creater.AddLefecycleDict("Delete", 89, None, None, None, None)
    res.append(data_creater.get_resource())

    data_creater = frsd.FakeBucketDataCreater('fake-bucket-12', frsd.PROJECT1)
    data_creater.AddLefecycleDict("Delete", 90, None, None, None, None)
    res.append(data_creater.get_resource())

    data_creater = frsd.FakeBucketDataCreater('fake-bucket-13', frsd.PROJECT1)
    data_creater.AddLefecycleDict("Delete", 89, None, None, None, None)
    res.append(data_creater.get_resource())

    data_creater = frsd.FakeBucketDataCreater('fake-bucket-2', frsd.PROJECT2)
    data_creater.AddLefecycleDict("Delete", 90, None, None, None, None)
    res.append(data_creater.get_resource())

    data_creater = frsd.FakeBucketDataCreater('fake-bucket-3', frsd.PROJECT3)
    data_creater.AddLefecycleDict("Delete", 89, None, None, None, None)
    res.append(data_creater.get_resource())

    data_creater = frsd.FakeBucketDataCreater('fake-bucket-4', frsd.PROJECT4)
    data_creater.AddLefecycleDict("Delete", 89, None, None, None, None)
    res.append(data_creater.get_resource())

    return res

def _mock_bucket_retention_multi_projects_in_a_rule(_, resource_type):
    if resource_type != 'bucket':
        raise ValueError(
            'unexpected resource type: got %s, bucket',
            resource_type,
        )

    return _fake_bucket_list_for_multi_projects_in_a_rule


yaml_str_mix_projects_and_buckets_in_a_rule = """
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

_fake_bucket_list_for_mix_project_and_bucket = []

def generate_res_bucket_retention_mix_project_and_bucket():
    res = []

    data_creater = frsd.FakeBucketDataCreater('fake-bucket-11', frsd.PROJECT1)
    data_creater.AddLefecycleDict("Delete", 90, None, None, None, None)
    res.append(data_creater.get_resource())

    data_creater = frsd.FakeBucketDataCreater('fake-bucket-12', frsd.PROJECT1)
    data_creater.AddLefecycleDict("Delete", 89, None, None, None, None)
    res.append(data_creater.get_resource())

    data_creater = frsd.FakeBucketDataCreater('fake-bucket-13', frsd.PROJECT1)
    res.append(data_creater.get_resource())

    return res

def _mock_bucket_retention_mix_project_and_bucket(_, resource_type):
    if resource_type != 'bucket':
        raise ValueError(
            'unexpected resource type: got %s, bucket',
            resource_type,
        )

    return _fake_bucket_list_for_mix_project_and_bucket


yaml_str_multi_rules_on_a_project = """
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

_fake_bucket_list_for_multi_rules_on_a_project = []

def generate_res_bucket_retention_multi_rules_on_a_project():
    res = []

    data_creater = frsd.FakeBucketDataCreater('fake-bucket-11', frsd.PROJECT1)
    data_creater.AddLefecycleDict("Delete", 90, None, None, None, None)
    res.append(data_creater.get_resource())

    data_creater = frsd.FakeBucketDataCreater('fake-bucket-12', frsd.PROJECT1)
    data_creater.AddLefecycleDict("Delete", 100, None, None, None, None)
    res.append(data_creater.get_resource())

    data_creater = frsd.FakeBucketDataCreater('fake-bucket-13', frsd.PROJECT1)
    data_creater.AddLefecycleDict("Delete", 110, None, None, None, None)
    res.append(data_creater.get_resource())

    return res

def _mock_bucket_retention_multi_rules_on_a_project(_, resource_type):
    if resource_type != 'bucket':
        raise ValueError(
            'unexpected resource type: got %s, bucket',
            resource_type,
        )

    return _fake_bucket_list_for_multi_rules_on_a_project


class RetentionScannerTest(ForsetiTestCase):

    def setUp(self):
        """Set up."""

    def test_bucket_retention_on_multi_buckets(self):
        with tempfile.NamedTemporaryFile(suffix='.yaml') as f:
            f.write(yaml_str_multi_buckets_in_a_rule)
            f.flush()
            global _fake_bucket_list_for_multi_buckets_in_a_rule
            _fake_bucket_list_for_multi_buckets_in_a_rule = generate_res_bucket_retention_multi_buckets_in_a_rule()

            self.scanner = retention_scanner.RetentionScanner(
                {}, {}, mock.MagicMock(), '', '', f.name)

            mock_data_access = mock.MagicMock()
            mock_data_access.scanner_iter.side_effect = _mock_bucket_retention_multi_buckets_in_a_rule

            mock_service_config = mock.MagicMock()
            mock_service_config.model_manager = mock.MagicMock()
            mock_service_config.model_manager.get.return_value = (
                mock.MagicMock(), mock_data_access)
            self.scanner.service_config = mock_service_config

            all_lifecycle_info = self.scanner._retrieve()
            all_violations = self.scanner._find_violations(all_lifecycle_info)

            res_map = {}
            for i in _fake_bucket_list_for_multi_buckets_in_a_rule:
                res_map[i.id] = i

            expected_violations = set([
                get_expect_violation_item(res_map, 'fake-bucket-1',
                                        'multiple buckets in a single rule', 0),
                get_expect_violation_item(res_map, 'fake-bucket-3',
                                        'multiple buckets in a single rule', 0)
            ])

            self.assertEqual(expected_violations, set(all_violations))

    def test_bucket_retention_on_multi_projects(self):
        with tempfile.NamedTemporaryFile(suffix='.yaml') as f:
            f.write(yaml_str_multi_projects_in_a_rule)
            f.flush()
            global _fake_bucket_list_for_multi_projects_in_a_rule
            _fake_bucket_list_for_multi_projects_in_a_rule = generate_res_bucket_retention_multi_projects_in_a_rule()

            self.scanner = retention_scanner.RetentionScanner(
                {}, {}, mock.MagicMock(), '', '', f.name)

            mock_data_access = mock.MagicMock()
            mock_data_access.scanner_iter.side_effect = _mock_bucket_retention_multi_projects_in_a_rule

            mock_service_config = mock.MagicMock()
            mock_service_config.model_manager = mock.MagicMock()
            mock_service_config.model_manager.get.return_value = (
                mock.MagicMock(), mock_data_access)
            self.scanner.service_config = mock_service_config

            all_lifecycle_info = self.scanner._retrieve()
            all_violations = self.scanner._find_violations(all_lifecycle_info)

            res_map = {}
            for i in _fake_bucket_list_for_multi_projects_in_a_rule:
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
        with tempfile.NamedTemporaryFile(suffix='.yaml') as f:
            f.write(yaml_str_mix_projects_and_buckets_in_a_rule)
            f.flush()
            global _fake_bucket_list_for_mix_project_and_bucket
            _fake_bucket_list_for_mix_project_and_bucket = generate_res_bucket_retention_mix_project_and_bucket()

            self.scanner = retention_scanner.RetentionScanner(
                {}, {}, mock.MagicMock(), '', '', f.name)

            mock_data_access = mock.MagicMock()
            mock_data_access.scanner_iter.side_effect = _mock_bucket_retention_mix_project_and_bucket

            mock_service_config = mock.MagicMock()
            mock_service_config.model_manager = mock.MagicMock()
            mock_service_config.model_manager.get.return_value = (
                mock.MagicMock(), mock_data_access)
            self.scanner.service_config = mock_service_config

            all_lifecycle_info = self.scanner._retrieve()
            all_violations = self.scanner._find_violations(all_lifecycle_info)

            res_map = {}
            for i in _fake_bucket_list_for_mix_project_and_bucket:
                res_map[i.id] = i

            expected_violations = set([
                get_expect_violation_item(res_map, 'fake-bucket-12',
                                        'project 1 min 90', 0),
                get_expect_violation_item(res_map, 'fake-bucket-13',
                                        'buckets max 100', 1)
            ])

            self.assertEqual(expected_violations, set(all_violations))

    def test_bucket_retention_on_multi_rules_on_a_project(self):
        with tempfile.NamedTemporaryFile(suffix='.yaml') as f:
            f.write(yaml_str_multi_rules_on_a_project)
            f.flush()
            global _fake_bucket_list_for_multi_rules_on_a_project
            _fake_bucket_list_for_multi_rules_on_a_project = generate_res_bucket_retention_multi_rules_on_a_project()

            self.scanner = retention_scanner.RetentionScanner(
                {}, {}, mock.MagicMock(), '', '', f.name)

            mock_data_access = mock.MagicMock()
            mock_data_access.scanner_iter.side_effect = _mock_bucket_retention_multi_rules_on_a_project

            mock_service_config = mock.MagicMock()
            mock_service_config.model_manager = mock.MagicMock()
            mock_service_config.model_manager.get.return_value = (
                mock.MagicMock(), mock_data_access)
            self.scanner.service_config = mock_service_config

            all_lifecycle_info = self.scanner._retrieve()
            all_violations = self.scanner._find_violations(all_lifecycle_info)

            res_map = {}
            for i in _fake_bucket_list_for_multi_rules_on_a_project:
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
