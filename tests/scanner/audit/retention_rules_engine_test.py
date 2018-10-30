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

"""Tests the BigqueryRulesEngine."""

import copy
import itertools
import json
import mock
import unittest
import yaml
from collections import namedtuple
import tempfile

from tests.unittest_utils import ForsetiTestCase
from google.cloud.forseti.common.gcp_type import organization
from google.cloud.forseti.common.gcp_type import project
from google.cloud.forseti.common.util import file_loader
from google.cloud.forseti.scanner.audit.errors import InvalidRulesSchemaError
from google.cloud.forseti.scanner.audit import base_rules_engine as bre
from google.cloud.forseti.scanner.audit import retention_rules_engine as rre
from google.cloud.forseti.scanner.audit import rules as scanner_rules
from tests.unittest_utils import get_datafile_path
from google.cloud.forseti.scanner.audit import errors as audit_errors
from tests.scanner.test_data import fake_retention_scanner_data as frsd
from datetime import datetime, timedelta


import collections
from tests.unittest_utils import ForsetiTestCase
from google.cloud.forseti.scanner.scanners import retention_scanner

def get_rules_engine_with_rule(rule):
    with tempfile.NamedTemporaryFile(suffix='.yaml') as f:
        f.write(rule)
        f.flush()
        rules_engine = rre.RetentionRulesEngine(
            rules_file_path=f.name)
        rules_engine.build_rule_book()
    return rules_engine

def get_expect_violation_item(res_map, bucket_id, rule_name, rule_index):
    RuleViolation = namedtuple(
    'RuleViolation',
    ['resource_name', 'resource_type', 'full_name', 'rule_name',
     'rule_index', 'violation_type', 'violation_data', 'resource_data'])
    lifecycle_str = json.dumps(res_map.get(bucket_id).get_lifecycle_rule())

    return RuleViolation(
        resource_name=bucket_id,
        resource_type=res_map.get(bucket_id).type,
        full_name=res_map.get(bucket_id).full_name,
        rule_name=rule_name,
        rule_index=rule_index,
        violation_type=rre.VIOLATION_TYPE,
        violation_data=lifecycle_str,
        resource_data=res_map.get(bucket_id).data)


# TODO: More tests need to be added that cover the rule attributes and how they
#    are evaluated
class RetentionRulesEngineTest(ForsetiTestCase):
    """Tests for the BigqueryRulesEngine."""

    def setUp(self):
        """Set up."""

    def test_invalid_rule_with_no_applies_to(self):
        yaml_str_no_applies_to="""
rules:
  - name: No applies_to
    resource:
      - type: bucket
        resource_ids:
          - some-resource-id
    minimum_retention: 365
    maximum_retention: 365

"""
        with tempfile.NamedTemporaryFile(suffix='.yaml') as f:
            f.write(yaml_str_no_applies_to)
            f.flush()
            rules_local_path = get_datafile_path(__file__, f.name)
            with self.assertRaises(InvalidRulesSchemaError):
                self.scanner = retention_scanner.RetentionScanner(
                    {}, {}, mock.MagicMock(), '', '', rules_local_path)

    def test_invalid_rule_lack_of_min_max(self):
        yaml_str_lack_min_max="""
rules:
  - name: Lack of min and max retention
    applies_to:
      - bucket
    resource:
      - type: bucket
        resource_ids:
          - some-resource-id

"""
        with tempfile.NamedTemporaryFile(suffix='.yaml') as f:
            f.write(yaml_str_lack_min_max)
            f.flush()
            rules_local_path = get_datafile_path(__file__, f.name)
            with self.assertRaises(InvalidRulesSchemaError):
                self.scanner = retention_scanner.RetentionScanner(
                    {}, {}, mock.MagicMock(), '', '', rules_local_path)

    def test_invalid_rule_min_lgr_max(self):
        yaml_str_min_lgr_max="""
rules:
  - name: min larger than max
    applies_to:
      - bucket
    resource:
      - type: bucket
        resource_ids:
          - some-resource-id
    minimum_retention: 366
    maximum_retention: 365

"""
        with tempfile.NamedTemporaryFile(suffix='.yaml') as f:
            f.write(yaml_str_min_lgr_max)
            f.flush()
            rules_local_path = get_datafile_path(__file__, f.name)
            with self.assertRaises(InvalidRulesSchemaError):
                self.scanner = retention_scanner.RetentionScanner(
                    {}, {}, mock.MagicMock(), '', '', rules_local_path)

    def test_invalid_rule_with_duplicate_applies_to(self):
        yaml_str_duplicate_applies_to="""
rules:
  - name: Duplicate applies_to
    applies_to:
      - bucket
      - bucket
    resource:
      - type: bucket
        resource_ids:
          - some-resource-id
    minimum_retention: 365
    maximum_retention: 365

"""
        with tempfile.NamedTemporaryFile(suffix='.yaml') as f:
            f.write(yaml_str_duplicate_applies_to)
            f.flush()
            rules_local_path = get_datafile_path(__file__, f.name)
            with self.assertRaises(InvalidRulesSchemaError):
                self.scanner = retention_scanner.RetentionScanner(
                    {}, {}, mock.MagicMock(), '', '', rules_local_path)

    def test_invalid_rule_with_no_resource(self):
        yaml_str_no_resource="""
rules:
  - name: No resource
    applies_to:
      - bucket
    minimum_retention: 365
    maximum_retention: 365

"""
        with tempfile.NamedTemporaryFile(suffix='.yaml') as f:
            f.write(yaml_str_no_resource)
            f.flush()
            rules_local_path = get_datafile_path(__file__, f.name)
            with self.assertRaises(InvalidRulesSchemaError):
                self.scanner = retention_scanner.RetentionScanner(
                    {}, {}, mock.MagicMock(), '', '', rules_local_path)

    def test_invalid_rule_with_no_res_type(self):
        yaml_str_no_res_type="""
rules:
  - name: No resource type
    applies_to:
      - bucket
    resource:
        - resource_ids:
          - some-resource-id
    minimum_retention: 365
    maximum_retention: 365

"""
        with tempfile.NamedTemporaryFile(suffix='.yaml') as f:
            f.write(yaml_str_no_res_type)
            f.flush()
            rules_local_path = get_datafile_path(__file__, f.name)
            with self.assertRaises(InvalidRulesSchemaError):
                self.scanner = retention_scanner.RetentionScanner(
                    {}, {}, mock.MagicMock(), '', '', rules_local_path)

    def test_invalid_rule_with_no_res_id(self):
        yaml_str_no_res_id="""
rules:
  - name: No resource ids
    applies_to:
      - bucket
    resource:
      - type: bucket
    minimum_retention: 365
    maximum_retention: 365

"""
        with tempfile.NamedTemporaryFile(suffix='.yaml') as f:
            f.write(yaml_str_no_res_id)
            f.flush()
            rules_local_path = get_datafile_path(__file__, f.name)
            with self.assertRaises(InvalidRulesSchemaError):
                self.scanner = retention_scanner.RetentionScanner(
                    {}, {}, mock.MagicMock(), '', '', rules_local_path)

    yaml_str_only_max_retention = """
rules:
  - name: only max retention
    applies_to:
      - bucket
    resource:
      - type: bucket
        resource_ids:
          - fake_bucket
    maximum_retention: 365

"""

    def test_only_max_normal_nodelete(self):
        rules_engine = get_rules_engine_with_rule(RetentionRulesEngineTest.yaml_str_only_max_retention)
        self.assertEqual(1, len(rules_engine.rule_book.resource_rules_map))

        data_creater = frsd.FakeBucketDataCreater('fake_bucket', frsd.PROJECT1)
        data_creater.AddLefecycleDict(action="SetStorageClass", age=365)

        fake_bucket = data_creater.get_resource()
        got_violations = list(rules_engine.find_violations(fake_bucket))
        expect_violations = frsd.build_bucket_violations(
            fake_bucket, 'only max retention')
        self.assertEqual(got_violations, expect_violations)

    def test_only_max_larger_delete(self):
        rules_engine = get_rules_engine_with_rule(RetentionRulesEngineTest.yaml_str_only_max_retention)
        self.assertEqual(1, len(rules_engine.rule_book.resource_rules_map))

        data_creater = frsd.FakeBucketDataCreater('fake_bucket', frsd.PROJECT1)
        data_creater.AddLefecycleDict(action="Delete", age=366)

        fake_bucket = data_creater.get_resource()
        got_violations = list(rules_engine.find_violations(fake_bucket))
        expect_violations = frsd.build_bucket_violations(
            fake_bucket, 'only max retention')
        self.assertEqual(got_violations, expect_violations)

    def test_only_max_any_del_anynormal_del(self):
        rules_engine = get_rules_engine_with_rule(RetentionRulesEngineTest.yaml_str_only_max_retention)
        self.assertEqual(1, len(rules_engine.rule_book.resource_rules_map))

        data_creater = frsd.FakeBucketDataCreater('fake_bucket', frsd.PROJECT1)
        data_creater.AddLefecycleDict(action="Delete", age=365)
        d = datetime.today() - timedelta(days=90)
        dstr = d.strftime('%Y-%m-%d')
        data_creater.AddLefecycleDict(action="Delete", age=365, created_before=dstr)

        fake_bucket = data_creater.get_resource()
        got_violations = list(rules_engine.find_violations(fake_bucket))
        self.assertEqual(got_violations, [])

    def test_only_max_lgr_del_anynormal_del(self):
        rules_engine = get_rules_engine_with_rule(RetentionRulesEngineTest.yaml_str_only_max_retention)
        self.assertEqual(1, len(rules_engine.rule_book.resource_rules_map))

        data_creater = frsd.FakeBucketDataCreater('fake_bucket', frsd.PROJECT1)
        data_creater.AddLefecycleDict(action="Delete", age=366)
        d = datetime.today() - timedelta(days=90)
        dstr = d.strftime('%Y-%m-%d')
        data_creater.AddLefecycleDict(action="Delete", age=365, created_before=dstr)

        fake_bucket = data_creater.get_resource()
        got_violations = list(rules_engine.find_violations(fake_bucket))
        expect_violations = frsd.build_bucket_violations(
            fake_bucket, 'only max retention')
        self.assertEqual(got_violations, expect_violations)

    def test_only_max_lgr_del_normal_else(self):
        rules_engine = get_rules_engine_with_rule(RetentionRulesEngineTest.yaml_str_only_max_retention)
        self.assertEqual(1, len(rules_engine.rule_book.resource_rules_map))

        data_creater = frsd.FakeBucketDataCreater('fake_bucket', frsd.PROJECT1)
        data_creater.AddLefecycleDict(action="Delete", age=366)
        data_creater.AddLefecycleDict(action="SetStorageClass", age=365)

        fake_bucket = data_creater.get_resource()
        got_violations = list(rules_engine.find_violations(fake_bucket))
        expect_violations = frsd.build_bucket_violations(
            fake_bucket, 'only max retention')
        self.assertEqual(got_violations, expect_violations)

    def test_only_max_normal_del_any_del(self):
        rules_engine = get_rules_engine_with_rule(RetentionRulesEngineTest.yaml_str_only_max_retention)
        self.assertEqual(1, len(rules_engine.rule_book.resource_rules_map))

        data_creater = frsd.FakeBucketDataCreater('fake_bucket', frsd.PROJECT1)
        data_creater.AddLefecycleDict(action="Delete", age=365)
        data_creater.AddLefecycleDict(action="Delete", is_live=False)

        fake_bucket = data_creater.get_resource()
        got_violations = list(rules_engine.find_violations(fake_bucket))
        self.assertEqual(got_violations, [])

    def test_only_max_normal_del_lgr_del(self):
        rules_engine = get_rules_engine_with_rule(RetentionRulesEngineTest.yaml_str_only_max_retention)
        self.assertEqual(1, len(rules_engine.rule_book.resource_rules_map))

        data_creater = frsd.FakeBucketDataCreater('fake_bucket', frsd.PROJECT1)
        data_creater.AddLefecycleDict(action="Delete", age=365)
        data_creater.AddLefecycleDict(action="Delete", age=366)

        fake_bucket = data_creater.get_resource()
        got_violations = list(rules_engine.find_violations(fake_bucket))
        self.assertEqual(got_violations, [])

    def test_only_max_no_condition(self):
        rules_engine = get_rules_engine_with_rule(RetentionRulesEngineTest.yaml_str_only_max_retention)
        self.assertEqual(1, len(rules_engine.rule_book.resource_rules_map))

        data_creater = frsd.FakeBucketDataCreater('fake_bucket', frsd.PROJECT1)

        fake_bucket = data_creater.get_resource()
        got_violations = list(rules_engine.find_violations(fake_bucket))
        expect_violations = frsd.build_bucket_violations(
            fake_bucket, 'only max retention')
        self.assertEqual(got_violations, expect_violations)

    def test_only_max_anynormal_del(self):
        rules_engine = get_rules_engine_with_rule(RetentionRulesEngineTest.yaml_str_only_max_retention)
        self.assertEqual(1, len(rules_engine.rule_book.resource_rules_map))

        data_creater = frsd.FakeBucketDataCreater('fake_bucket', frsd.PROJECT1)
        data_creater.AddLefecycleDict(action="Delete", age=365, num_newer_versions=5)

        fake_bucket = data_creater.get_resource()
        got_violations = list(rules_engine.find_violations(fake_bucket))
        expect_violations = frsd.build_bucket_violations(
            fake_bucket, 'only max retention')
        self.assertEqual(got_violations, expect_violations)

    yaml_str_only_min_retention = """
rules:
  - name: only min retention
    applies_to:
      - bucket
    resource:
      - type: bucket
        resource_ids:
          - fake_bucket
    minimum_retention: 90

"""

    def test_only_min_normal_del(self):
        rules_engine = get_rules_engine_with_rule(RetentionRulesEngineTest.yaml_str_only_min_retention)
        self.assertEqual(1, len(rules_engine.rule_book.resource_rules_map))

        data_creater = frsd.FakeBucketDataCreater('fake_bucket', frsd.PROJECT1)
        data_creater.AddLefecycleDict(action="Delete", age=90)

        fake_bucket = data_creater.get_resource()
        got_violations = list(rules_engine.find_violations(fake_bucket))
        self.assertEqual(got_violations, [])

    def test_only_min_normal_else(self):
        rules_engine = get_rules_engine_with_rule(RetentionRulesEngineTest.yaml_str_only_min_retention)
        self.assertEqual(1, len(rules_engine.rule_book.resource_rules_map))

        data_creater = frsd.FakeBucketDataCreater('fake_bucket', frsd.PROJECT1)
        data_creater.AddLefecycleDict(action="SetStorageClass", age=90)

        fake_bucket = data_creater.get_resource()
        got_violations = list(rules_engine.find_violations(fake_bucket))
        self.assertEqual(got_violations, [])

    def test_only_min_less_else(self):
        rules_engine = get_rules_engine_with_rule(RetentionRulesEngineTest.yaml_str_only_min_retention)
        self.assertEqual(1, len(rules_engine.rule_book.resource_rules_map))

        data_creater = frsd.FakeBucketDataCreater('fake_bucket', frsd.PROJECT1)
        data_creater.AddLefecycleDict(action="SetStorageClass", age=89)

        fake_bucket = data_creater.get_resource()
        got_violations = list(rules_engine.find_violations(fake_bucket))
        self.assertEqual(got_violations, [])

    def test_only_min_no_condition(self):
        rules_engine = get_rules_engine_with_rule(RetentionRulesEngineTest.yaml_str_only_min_retention)
        self.assertEqual(1, len(rules_engine.rule_book.resource_rules_map))

        data_creater = frsd.FakeBucketDataCreater('fake_bucket', frsd.PROJECT1)

        fake_bucket = data_creater.get_resource()
        got_violations = list(rules_engine.find_violations(fake_bucket))
        self.assertEqual(got_violations, [])

    def test_only_min_lessver1_del(self):
        rules_engine = get_rules_engine_with_rule(RetentionRulesEngineTest.yaml_str_only_min_retention)
        self.assertEqual(1, len(rules_engine.rule_book.resource_rules_map))

        data_creater = frsd.FakeBucketDataCreater('fake_bucket', frsd.PROJECT1)
        data_creater.AddLefecycleDict(action="Delete", age=89, num_newer_versions=1)

        fake_bucket = data_creater.get_resource()
        got_violations = list(rules_engine.find_violations(fake_bucket))
        self.assertEqual(got_violations, [])

    def test_only_min_lessver0_del(self):
        rules_engine = get_rules_engine_with_rule(RetentionRulesEngineTest.yaml_str_only_min_retention)
        self.assertEqual(1, len(rules_engine.rule_book.resource_rules_map))

        data_creater = frsd.FakeBucketDataCreater('fake_bucket', frsd.PROJECT1)
        data_creater.AddLefecycleDict(action="Delete", age=89, num_newer_versions=0)

        fake_bucket = data_creater.get_resource()
        got_violations = list(rules_engine.find_violations(fake_bucket))
        expect_violations = frsd.build_bucket_violations(
            fake_bucket, 'only min retention')
        self.assertEqual(got_violations, expect_violations)

    def test_only_min_ver1_del(self):
        rules_engine = get_rules_engine_with_rule(RetentionRulesEngineTest.yaml_str_only_min_retention)
        self.assertEqual(1, len(rules_engine.rule_book.resource_rules_map))

        data_creater = frsd.FakeBucketDataCreater('fake_bucket', frsd.PROJECT1)
        data_creater.AddLefecycleDict(action="Delete", num_newer_versions=1)

        fake_bucket = data_creater.get_resource()
        got_violations = list(rules_engine.find_violations(fake_bucket))
        self.assertEqual(got_violations, [])

    def test_only_min_ver0_del(self):
        rules_engine = get_rules_engine_with_rule(RetentionRulesEngineTest.yaml_str_only_min_retention)
        self.assertEqual(1, len(rules_engine.rule_book.resource_rules_map))

        data_creater = frsd.FakeBucketDataCreater('fake_bucket', frsd.PROJECT1)
        data_creater.AddLefecycleDict(action="Delete", num_newer_versions=0)

        fake_bucket = data_creater.get_resource()
        got_violations = list(rules_engine.find_violations(fake_bucket))
        expect_violations = frsd.build_bucket_violations(
            fake_bucket, 'only min retention')
        self.assertEqual(got_violations, expect_violations)

    def test_only_min_ver0_else(self):
        rules_engine = get_rules_engine_with_rule(RetentionRulesEngineTest.yaml_str_only_min_retention)
        self.assertEqual(1, len(rules_engine.rule_book.resource_rules_map))

        data_creater = frsd.FakeBucketDataCreater('fake_bucket', frsd.PROJECT1)
        data_creater.AddLefecycleDict(action="SetStorageClass", num_newer_versions=0)

        fake_bucket = data_creater.get_resource()
        got_violations = list(rules_engine.find_violations(fake_bucket))
        self.assertEqual(got_violations, [])

    def test_only_min_lessold_del(self):
        rules_engine = get_rules_engine_with_rule(RetentionRulesEngineTest.yaml_str_only_min_retention)
        self.assertEqual(1, len(rules_engine.rule_book.resource_rules_map))

        data_creater = frsd.FakeBucketDataCreater('fake_bucket', frsd.PROJECT1)
        d = datetime.today() - timedelta(days=90)
        dstr = d.strftime('%Y-%m-%d')
        data_creater.AddLefecycleDict(action="Delete", age=89, created_before=dstr)

        fake_bucket = data_creater.get_resource()
        got_violations = list(rules_engine.find_violations(fake_bucket))
        self.assertEqual(got_violations, [])

    def test_only_min_lessnew_del(self):
        rules_engine = get_rules_engine_with_rule(RetentionRulesEngineTest.yaml_str_only_min_retention)
        self.assertEqual(1, len(rules_engine.rule_book.resource_rules_map))

        data_creater = frsd.FakeBucketDataCreater('fake_bucket', frsd.PROJECT1)
        d = datetime.today() - timedelta(days=89)
        dstr = d.strftime('%Y-%m-%d')
        data_creater.AddLefecycleDict(action="Delete", age=89, created_before=dstr)

        fake_bucket = data_creater.get_resource()
        got_violations = list(rules_engine.find_violations(fake_bucket))
        expect_violations = frsd.build_bucket_violations(
            fake_bucket, 'only min retention')
        self.assertEqual(got_violations, expect_violations)

    def test_only_min_normalnew_del(self):
        rules_engine = get_rules_engine_with_rule(RetentionRulesEngineTest.yaml_str_only_min_retention)
        self.assertEqual(1, len(rules_engine.rule_book.resource_rules_map))

        data_creater = frsd.FakeBucketDataCreater('fake_bucket', frsd.PROJECT1)
        d = datetime.today() - timedelta(days=89)
        dstr = d.strftime('%Y-%m-%d')
        data_creater.AddLefecycleDict(action="Delete", age=90, created_before=dstr)

        fake_bucket = data_creater.get_resource()
        got_violations = list(rules_engine.find_violations(fake_bucket))
        self.assertEqual(got_violations, [])

    def test_only_min_less_del_normal_del(self):
        rules_engine = get_rules_engine_with_rule(RetentionRulesEngineTest.yaml_str_only_min_retention)
        self.assertEqual(1, len(rules_engine.rule_book.resource_rules_map))

        data_creater = frsd.FakeBucketDataCreater('fake_bucket', frsd.PROJECT1)
        data_creater.AddLefecycleDict(action="Delete", age=89)
        data_creater.AddLefecycleDict(action="Delete", age=90)

        fake_bucket = data_creater.get_resource()
        got_violations = list(rules_engine.find_violations(fake_bucket))
        expect_violations = frsd.build_bucket_violations(
            fake_bucket, 'only min retention')
        self.assertEqual(got_violations, expect_violations)

    def test_only_min_less_else_normal_del(self):
        rules_engine = get_rules_engine_with_rule(RetentionRulesEngineTest.yaml_str_only_min_retention)
        self.assertEqual(1, len(rules_engine.rule_book.resource_rules_map))

        data_creater = frsd.FakeBucketDataCreater('fake_bucket', frsd.PROJECT1)
        data_creater.AddLefecycleDict(action="SetStorageClass", age=89)
        data_creater.AddLefecycleDict(action="Delete", age=90)

        fake_bucket = data_creater.get_resource()
        got_violations = list(rules_engine.find_violations(fake_bucket))
        self.assertEqual(got_violations, [])

    def test_only_min_less_del(self):
        rules_engine = get_rules_engine_with_rule(RetentionRulesEngineTest.yaml_str_only_min_retention)
        self.assertEqual(1, len(rules_engine.rule_book.resource_rules_map))

        data_creater = frsd.FakeBucketDataCreater('fake_bucket', frsd.PROJECT1)
        data_creater.AddLefecycleDict(action="Delete", age=89)

        fake_bucket = data_creater.get_resource()
        got_violations = list(rules_engine.find_violations(fake_bucket))
        expect_violations = frsd.build_bucket_violations(
            fake_bucket, 'only min retention')
        self.assertEqual(got_violations, expect_violations)

    def test_only_min_old_del(self):
        rules_engine = get_rules_engine_with_rule(RetentionRulesEngineTest.yaml_str_only_min_retention)
        self.assertEqual(1, len(rules_engine.rule_book.resource_rules_map))

        data_creater = frsd.FakeBucketDataCreater('fake_bucket', frsd.PROJECT1)
        d = datetime.today() - timedelta(days=90)
        dstr = d.strftime('%Y-%m-%d')
        data_creater.AddLefecycleDict(action="Delete", created_before=dstr)

        fake_bucket = data_creater.get_resource()
        got_violations = list(rules_engine.find_violations(fake_bucket))
        self.assertEqual(got_violations, [])

    def test_only_min_new_del(self):
        rules_engine = get_rules_engine_with_rule(RetentionRulesEngineTest.yaml_str_only_min_retention)
        self.assertEqual(1, len(rules_engine.rule_book.resource_rules_map))

        data_creater = frsd.FakeBucketDataCreater('fake_bucket', frsd.PROJECT1)
        d = datetime.today() - timedelta(days=89)
        dstr = d.strftime('%Y-%m-%d')
        data_creater.AddLefecycleDict(action="Delete", created_before=dstr)

        fake_bucket = data_creater.get_resource()
        got_violations = list(rules_engine.find_violations(fake_bucket))
        expect_violations = frsd.build_bucket_violations(
            fake_bucket, 'only min retention')
        self.assertEqual(got_violations, expect_violations)

    yaml_str_both_min_and_max_retention = """
rules:
  - name: both min and max retention
    applies_to:
      - bucket
    resource:
      - type: bucket
        resource_ids:
          - fake_bucket
    minimum_retention: 90
    maximum_retention: 365

"""

    def test_both_min_max_no_condition(self):
        rules_engine = get_rules_engine_with_rule(RetentionRulesEngineTest.yaml_str_both_min_and_max_retention)
        self.assertEqual(1, len(rules_engine.rule_book.resource_rules_map))

        data_creater = frsd.FakeBucketDataCreater('fake_bucket', frsd.PROJECT1)

        fake_bucket = data_creater.get_resource()
        got_violations = list(rules_engine.find_violations(fake_bucket))
        expect_violations = frsd.build_bucket_violations(
            fake_bucket, 'both min and max retention')
        self.assertEqual(got_violations, expect_violations)

    def test_both_min_max_normal_del_any_del(self):
        rules_engine = get_rules_engine_with_rule(RetentionRulesEngineTest.yaml_str_both_min_and_max_retention)
        self.assertEqual(1, len(rules_engine.rule_book.resource_rules_map))

        data_creater = frsd.FakeBucketDataCreater('fake_bucket', frsd.PROJECT1)
        data_creater.AddLefecycleDict(action="Delete", age=100)
        data_creater.AddLefecycleDict(action="Delete", is_live=True)

        fake_bucket = data_creater.get_resource()
        got_violations = list(rules_engine.find_violations(fake_bucket))
        expect_violations = frsd.build_bucket_violations(
            fake_bucket, 'both min and max retention')
        self.assertEqual(got_violations, expect_violations)

    def test_both_min_max_normal_del(self):
        rules_engine = get_rules_engine_with_rule(RetentionRulesEngineTest.yaml_str_both_min_and_max_retention)
        self.assertEqual(1, len(rules_engine.rule_book.resource_rules_map))

        data_creater = frsd.FakeBucketDataCreater('fake_bucket', frsd.PROJECT1)
        data_creater.AddLefecycleDict(action="Delete", age=100)

        fake_bucket = data_creater.get_resource()
        got_violations = list(rules_engine.find_violations(fake_bucket))
        self.assertEqual(got_violations, [])

    def test_both_min_max_3_conditions(self):
        rules_engine = get_rules_engine_with_rule(RetentionRulesEngineTest.yaml_str_both_min_and_max_retention)
        self.assertEqual(1, len(rules_engine.rule_book.resource_rules_map))

        data_creater = frsd.FakeBucketDataCreater('fake_bucket', frsd.PROJECT1)
        data_creater.AddLefecycleDict(action="Delete", age=100)
        data_creater.AddLefecycleDict(action="SetStorageClass", age=89)
        data_creater.AddLefecycleDict(action="Delete", age=500)

        fake_bucket = data_creater.get_resource()
        got_violations = list(rules_engine.find_violations(fake_bucket))
        self.assertEqual(got_violations, [])

    yaml_str_bucket_retention_on_correct_project = """
rules:
  - name: bucket retention on correct project
    applies_to:
      - bucket
    resource:
      - type: project
        resource_ids:
          - def-project-1
    minimum_retention: 90

"""

    def test_bucket_on_correct_project_no_vio(self):
        rules_engine = get_rules_engine_with_rule(RetentionRulesEngineTest.yaml_str_bucket_retention_on_correct_project)
        self.assertEqual(1, len(rules_engine.rule_book.resource_rules_map))

        data_creater = frsd.FakeBucketDataCreater('fake_bucket', frsd.PROJECT1)
        data_creater.AddLefecycleDict(action="Delete", age=90)

        fake_bucket = data_creater.get_resource()
        got_violations = list(rules_engine.find_violations(fake_bucket))
        self.assertEqual(got_violations, [])

    def test_bucket_on_correct_project_has_vio(self):
        rules_engine = get_rules_engine_with_rule(RetentionRulesEngineTest.yaml_str_bucket_retention_on_correct_project)
        self.assertEqual(1, len(rules_engine.rule_book.resource_rules_map))

        data_creater = frsd.FakeBucketDataCreater('fake_bucket', frsd.PROJECT1)
        data_creater.AddLefecycleDict(action="Delete", age=89)

        fake_bucket = data_creater.get_resource()
        got_violations = list(rules_engine.find_violations(fake_bucket))
        expect_violations = frsd.build_bucket_violations(
            fake_bucket, 'bucket retention on correct project')
        self.assertEqual(got_violations, expect_violations)

    yaml_str_bucket_retention_on_wrong_project = """
rules:
  - name: bucket retention on wrong project
    applies_to:
      - bucket
    resource:
      - type: project
        resource_ids:
          - def-project-wrong
    minimum_retention: 90

"""

    def test_bucket_on_correct_project_no_vio(self):
        rules_engine = get_rules_engine_with_rule(RetentionRulesEngineTest.yaml_str_bucket_retention_on_wrong_project)
        self.assertEqual(1, len(rules_engine.rule_book.resource_rules_map))

        data_creater = frsd.FakeBucketDataCreater('fake_bucket', frsd.PROJECT1)
        data_creater.AddLefecycleDict(action="Delete", age=90)

        fake_bucket = data_creater.get_resource()
        got_violations = list(rules_engine.find_violations(fake_bucket))
        self.assertEqual(got_violations, [])

    def test_bucket_on_correct_project_has_vio(self):
        rules_engine = get_rules_engine_with_rule(RetentionRulesEngineTest.yaml_str_bucket_retention_on_wrong_project)
        self.assertEqual(1, len(rules_engine.rule_book.resource_rules_map))

        data_creater = frsd.FakeBucketDataCreater('fake_bucket', frsd.PROJECT1)
        data_creater.AddLefecycleDict(action="Delete", age=89)

        fake_bucket = data_creater.get_resource()
        got_violations = list(rules_engine.find_violations(fake_bucket))
        self.assertEqual(got_violations, [])

    yaml_str_bucket_retention_on_multi_projects = """
rules:
  - name: bucket retention on multi projects
    applies_to:
      - bucket
    resource:
      - type: project
        resource_ids:
          - def-project-1
          - def-project-2
    minimum_retention: 90

"""

    def test_bucket_on_multi_project_no_vio(self):
        rules_engine = get_rules_engine_with_rule(RetentionRulesEngineTest.yaml_str_bucket_retention_on_multi_projects)
        self.assertEqual(1, len(rules_engine.rule_book.resource_rules_map))

        data_creater = frsd.FakeBucketDataCreater('fake_bucket_1', frsd.PROJECT1)
        data_creater.AddLefecycleDict(action="Delete", age=90)
        fake_bucket = data_creater.get_resource()
        got_violations = list(rules_engine.find_violations(fake_bucket))
        self.assertEqual(got_violations, [])

        data_creater = frsd.FakeBucketDataCreater('fake_bucket_2', frsd.PROJECT2)
        data_creater.AddLefecycleDict(action="Delete", age=90)
        fake_bucket = data_creater.get_resource()
        got_violations = list(rules_engine.find_violations(fake_bucket))
        self.assertEqual(got_violations, [])


    def test_bucket_on_correct_project_has_vio(self):
        rules_engine = get_rules_engine_with_rule(RetentionRulesEngineTest.yaml_str_bucket_retention_on_multi_projects)
        self.assertEqual(1, len(rules_engine.rule_book.resource_rules_map))

        data_creater = frsd.FakeBucketDataCreater('fake_bucket_1', frsd.PROJECT1)
        data_creater.AddLefecycleDict(action="Delete", age=89)
        fake_bucket = data_creater.get_resource()
        got_violations = list(rules_engine.find_violations(fake_bucket))
        expect_violations = frsd.build_bucket_violations(
            fake_bucket, 'bucket retention on multi projects')
        self.assertEqual(got_violations, expect_violations)

        data_creater = frsd.FakeBucketDataCreater('fake_bucket_2', frsd.PROJECT2)
        data_creater.AddLefecycleDict(action="Delete", age=89)
        fake_bucket = data_creater.get_resource()
        got_violations = list(rules_engine.find_violations(fake_bucket))
        expect_violations = frsd.build_bucket_violations(
            fake_bucket, 'bucket retention on multi projects')
        self.assertEqual(got_violations, expect_violations)


if __name__ == '__main__':
    unittest.main()
