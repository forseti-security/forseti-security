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

do_not_test_old_cases = False


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

def GetLefecycleDict(action, age, created_before, matches_storage_class,
                     num_newer_versions, is_live):
    result = {'action':{}, 'condition':{}}
    result['action']['type'] = action
    if age != None:
        result['condition']['age'] = age
    if created_before != None:
        result['condition']['createdBefore'] = created_before
    if matches_storage_class != None:
        result['condition']['matchesStorageClass'] = matches_storage_class
    if num_newer_versions != None:
        result['condition']['numNewerVersions'] = num_newer_versions
    if is_live != None:
        result['condition']['isLive'] = is_live
    return result

_fake_bucket_list_22 = []

def _mock_gcp_resource_iter_22(_, resource_type):
    """Creates a list of GCP resource mocks retrieved by the scanner."""
    """Used in test case 22"""
    if resource_type != 'bucket':
        raise ValueError(
            'unexpected resource type: got %s, bucket',
            resource_type,
        )

    return _fake_bucket_list_22

def generate_res_for_22():
    """Creates a list of GCP resource mocks retrieved by the scanner."""
    """Used in test case 22"""

    org = organization.Organization(
        organization_id='433655555569',
        full_name='organization/433655555569/')
    proj_max = project.Project(
        project_id='project-max',
        project_number='711111111111',
        full_name=org.full_name+'project/project-max/',
        parent=org
    )
    proj_min = project.Project(
        project_id='project-min',
        project_number='722222222222',
        full_name=org.full_name+'project/project-min/',
        parent=org
    )
    proj_both = project.Project(
        project_id='project-both',
        project_number='733333333333',
        full_name=org.full_name+'project/project-both/',
        parent=org
    )

    res = []

    # MAX
    normal = 365
    larger = 366

    data_creater = frsd.FakeBucketDataCreater('bkt_max_1', proj_max)
    data_creater.AddLefecycleDict("Delete", normal, None, None, None, None)
    res.append(data_creater.get_resource())

    data_creater = frsd.FakeBucketDataCreater('bkt_max_2', proj_max)
    data_creater.AddLefecycleDict("Else", normal, None, None, None, None)
    res.append(data_creater.get_resource())

    data_creater = frsd.FakeBucketDataCreater('bkt_max_3', proj_max)
    data_creater.AddLefecycleDict("Delete", larger, None, None, None, None)
    res.append(data_creater.get_resource())

    data_creater = frsd.FakeBucketDataCreater('bkt_max_4', proj_max)
    data_creater.AddLefecycleDict("Delete", normal, None, None, None, None)
    data_creater.AddLefecycleDict("Delete", normal, None, None, 0, None)
    res.append(data_creater.get_resource())

    data_creater = frsd.FakeBucketDataCreater('bkt_max_5', proj_max)
    data_creater.AddLefecycleDict("Delete", larger, None, None, None, None)
    data_creater.AddLefecycleDict("Delete", normal, None, None, 0, None)
    res.append(data_creater.get_resource())

    data_creater = frsd.FakeBucketDataCreater('bkt_max_6', proj_max)
    data_creater.AddLefecycleDict("Delete", larger, None, None, None, None)
    data_creater.AddLefecycleDict("Else", normal, None, None, None, None)
    res.append(data_creater.get_resource())

    data_creater = frsd.FakeBucketDataCreater('bkt_max_7', proj_max)
    data_creater.AddLefecycleDict("Delete", normal, None, None, None, None)
    data_creater.AddLefecycleDict("Delete", None, None, None, 0, None)
    res.append(data_creater.get_resource())

    data_creater = frsd.FakeBucketDataCreater('bkt_max_8', proj_max)
    data_creater.AddLefecycleDict("Delete", normal, None, None, None, None)
    data_creater.AddLefecycleDict("Delete", larger, None, None, None, None)
    res.append(data_creater.get_resource())

    data_creater = frsd.FakeBucketDataCreater('bkt_max_9_1', proj_max)
    data_creater.SetLefecycleDict()
    res.append(data_creater.get_resource())

    data_creater = frsd.FakeBucketDataCreater('bkt_max_9_2', proj_max)
    res.append(data_creater.get_resource())

    data_creater = frsd.FakeBucketDataCreater('bkt_max_10', proj_max)
    data_creater.AddLefecycleDict("Delete", normal, None, None, 0, None)
    res.append(data_creater.get_resource())

    # MIN
    normal = 90
    less = 89

    data_creater = frsd.FakeBucketDataCreater('bkt_min_1', proj_min)
    data_creater.AddLefecycleDict("Delete", normal, None, None, None, None)
    res.append(data_creater.get_resource())

    data_creater = frsd.FakeBucketDataCreater('bkt_min_2', proj_min)
    data_creater.AddLefecycleDict("Else", normal, None, None, None, None)
    res.append(data_creater.get_resource())

    data_creater = frsd.FakeBucketDataCreater('bkt_min_3', proj_min)
    data_creater.AddLefecycleDict("Else", less, None, None, None, None)
    res.append(data_creater.get_resource())

    data_creater = frsd.FakeBucketDataCreater('bkt_min_4_1', proj_min)
    res.append(data_creater.get_resource())

    data_creater = frsd.FakeBucketDataCreater('bkt_min_4_2', proj_min)
    data_creater.SetLefecycleDict()
    res.append(data_creater.get_resource())

    data_creater = frsd.FakeBucketDataCreater('bkt_min_5', proj_min)
    data_creater.AddLefecycleDict("Delete", less, None, None, 1, None)
    res.append(data_creater.get_resource())

    data_creater = frsd.FakeBucketDataCreater('bkt_min_6', proj_min)
    data_creater.AddLefecycleDict("Delete", less, None, None, 0, None)
    res.append(data_creater.get_resource())

    data_creater = frsd.FakeBucketDataCreater('bkt_min_7', proj_min)
    data_creater.AddLefecycleDict("Delete", None, None, None, 1, None)
    res.append(data_creater.get_resource())

    data_creater = frsd.FakeBucketDataCreater('bkt_min_8', proj_min)
    data_creater.AddLefecycleDict("Delete", None, None, None, 0, None)
    res.append(data_creater.get_resource())

    data_creater = frsd.FakeBucketDataCreater('bkt_min_9', proj_min)
    data_creater.AddLefecycleDict("Else", None, None, None, 0, None)
    res.append(data_creater.get_resource())

    d = datetime.today() - timedelta(days=90)
    dstr = d.strftime('%Y-%m-%d')
    data_creater = frsd.FakeBucketDataCreater('bkt_min_10', proj_min)
    data_creater.AddLefecycleDict("Delete", less, dstr, None, None, None)
    res.append(data_creater.get_resource())

    d = datetime.today() - timedelta(days=89)
    dstr = d.strftime('%Y-%m-%d')
    data_creater = frsd.FakeBucketDataCreater('bkt_min_11', proj_min)
    data_creater.AddLefecycleDict("Delete", less, dstr, None, None, None)
    res.append(data_creater.get_resource())

    d = datetime.today() - timedelta(days=89)
    dstr = d.strftime('%Y-%m-%d')
    data_creater = frsd.FakeBucketDataCreater('bkt_min_12', proj_min)
    data_creater.AddLefecycleDict("Delete", normal, dstr, None, None, None)
    res.append(data_creater.get_resource())

    data_creater = frsd.FakeBucketDataCreater('bkt_min_13', proj_min)
    data_creater.AddLefecycleDict("Delete", less, None, None, None, None)
    data_creater.AddLefecycleDict("Delete", normal, None, None, None, None)
    res.append(data_creater.get_resource())

    data_creater = frsd.FakeBucketDataCreater('bkt_min_14', proj_min)
    data_creater.AddLefecycleDict("Else", less, None, None, None, None)
    data_creater.AddLefecycleDict("Delete", normal, None, None, None, None)
    res.append(data_creater.get_resource())

    data_creater = frsd.FakeBucketDataCreater('bkt_min_15', proj_min)
    data_creater.AddLefecycleDict("Delete", less, None, None, None, None)
    res.append(data_creater.get_resource())

    d = datetime.today() - timedelta(days=90)
    dstr = d.strftime('%Y-%m-%d')
    data_creater = frsd.FakeBucketDataCreater('bkt_min_16', proj_min)
    data_creater.AddLefecycleDict("Delete", None, dstr, None, None, None)
    res.append(data_creater.get_resource())

    d = datetime.today() - timedelta(days=89)
    dstr = d.strftime('%Y-%m-%d')
    data_creater = frsd.FakeBucketDataCreater('bkt_min_17', proj_min)
    data_creater.AddLefecycleDict("Delete", None, dstr, None, None, None)
    res.append(data_creater.get_resource())

    # Both
    normal = 100
    less = 89
    larger = 366

    data_creater = frsd.FakeBucketDataCreater('bkt_both_1', proj_both)
    res.append(data_creater.get_resource())

    data_creater = frsd.FakeBucketDataCreater('bkt_both_2', proj_both)
    data_creater.AddLefecycleDict("Delete", normal, None, None, None, None)
    data_creater.AddLefecycleDict("Delete", None, None, None, None, True)
    res.append(data_creater.get_resource())

    data_creater = frsd.FakeBucketDataCreater('bkt_both_3', proj_both)
    data_creater.AddLefecycleDict("Delete", normal, None, None, None, None)
    res.append(data_creater.get_resource())

    data_creater = frsd.FakeBucketDataCreater('bkt_both_4', proj_both)
    data_creater.AddLefecycleDict("Delete", normal, None, None, None, None)
    data_creater.AddLefecycleDict("Else", less, None, None, None, None)
    data_creater.AddLefecycleDict("Delete", larger, None, None, None, None)
    res.append(data_creater.get_resource())

    global _fake_bucket_list_22
    _fake_bucket_list_22 = res

    return res

_fake_bucket_list_0 = []

def _mock_gcp_resource_iter_0(_, resource_type):
    """Creates a list of GCP resource mocks retrieved by the scanner."""
    """Used in test case 22"""
    if resource_type != 'bucket':
        raise ValueError(
            'unexpected resource type: got %s, bucket',
            resource_type,
        )

    return _fake_bucket_list_0

def generate_res_for_0():
    """Creates a list of GCP resource mocks retrieved by the scanner."""
    """Used in test case 22"""

    org = organization.Organization(
        organization_id='433655558668',
        full_name='organization/433655558668/')
    proj = project.Project(
        project_id='project-demo',
        project_number='711111111111',
        full_name=org.full_name+'project/project-demo/',
        parent=org
    )

    res = []

    # bucket 1 with a smaller age
    data_creater = frsd.FakeBucketDataCreater('bkt1', proj)
    data_creater.AddLefecycleDict("Delete", 364, None, None, None, None)
    res.append(data_creater.get_resource())

    # bucket 2 with a larger age
    data_creater = frsd.FakeBucketDataCreater('bkt2', proj)
    data_creater.AddLefecycleDict("Delete", 366, None, None, None, None)
    res.append(data_creater.get_resource())

    # bucket 3 with created before
    data_creater = frsd.FakeBucketDataCreater('bkt3', proj)
    data_creater.AddLefecycleDict("Delete", 365, "2018-01-01", None, None, None)
    res.append(data_creater.get_resource())

    # bucket 4 with matches Storage Class
    data_creater = frsd.FakeBucketDataCreater('bkt4', proj)
    data_creater.AddLefecycleDict("Delete", 365, None, ["REGIONAL", "STANDARD", "DURABLE_REDUCED_AVAILABILITY", "NEARLINE", "COLDLINE"], None, None)
    res.append(data_creater.get_resource())

    # bucket 5 with numNewerVersions
    data_creater = frsd.FakeBucketDataCreater('bkt5', proj)
    data_creater.AddLefecycleDict("Delete", 365, None, None, 17, None)
    res.append(data_creater.get_resource())

    # bucket 6 with isLive
    data_creater = frsd.FakeBucketDataCreater('bkt6', proj)
    data_creater.AddLefecycleDict("Delete", 365, None, None, None, True)
    res.append(data_creater.get_resource())

    # bucket 7 with no "no match" violation
    data_creater = frsd.FakeBucketDataCreater('bkt7', proj)
    data_creater.AddLefecycleDict("Delete", 365, None, None, None, None)
    data_creater.AddLefecycleDict("Delete", 201, None, None, None, True)
    res.append(data_creater.get_resource())

    # bucket 11 with nothing
    data_creater = frsd.FakeBucketDataCreater('bkt11', proj)
    data_creater.AddLefecycleDict("Delete", 365, None, None, None, None)
    res.append(data_creater.get_resource())

    # bucket 12 with created before
    data_creater = frsd.FakeBucketDataCreater('bkt12', proj)
    data_creater.AddLefecycleDict("Delete", 365, None, None, None, None)
    data_creater.AddLefecycleDict("Delete", 365, "2018-01-01", None, None, None)
    res.append(data_creater.get_resource())

    # bucket 13 with matches Storage Class
    data_creater = frsd.FakeBucketDataCreater('bkt13', proj)
    data_creater.AddLefecycleDict("Delete", 365, None, None, None, None)
    data_creater.AddLefecycleDict("Delete", 365, None, ["REGIONAL", "STANDARD", "DURABLE_REDUCED_AVAILABILITY", "NEARLINE", "COLDLINE"], None, None)
    res.append(data_creater.get_resource())

    # bucket 14 with numNewerVersions
    data_creater = frsd.FakeBucketDataCreater('bkt14', proj)
    data_creater.AddLefecycleDict("Delete", 365, None, None, None, None)
    data_creater.AddLefecycleDict("Delete", 365, None, None, 17, None)
    res.append(data_creater.get_resource())

    # bucket 15 with is Live
    data_creater = frsd.FakeBucketDataCreater('bkt15', proj)
    data_creater.AddLefecycleDict("Delete", 365, None, None, None, None)
    data_creater.AddLefecycleDict("Delete", 365, None, None, None, True)
    res.append(data_creater.get_resource())

    global _fake_bucket_list_0
    _fake_bucket_list_0 = res
    return res


# TODO: More tests need to be added that cover the rule attributes and how they
#    are evaluated
class RetentionRulesEngineTest(ForsetiTestCase):
    """Tests for the BigqueryRulesEngine."""

    def setUp(self):
        """Set up."""

    @unittest.skipIf(do_not_test_old_cases, 'debug new test cases')
    def test_retention_retrieve_1(self):
        """No applies_to"""

        rules_local_path = get_datafile_path(
            __file__,
            'bucket_retention_test_rules_1.yaml')

        try:
            self.scanner = retention_scanner.RetentionScanner(
                {}, {}, mock.MagicMock(), '', '', rules_local_path)
        except audit_errors.InvalidRulesSchemaError as e:
            self.assertEquals("Lack of applies_to in rule 0", str(e))

    @unittest.skipIf(do_not_test_old_cases, 'debug new test cases')
    def test_retention_retrieve_3(self):
        """Lack of min and max retention"""

        rules_local_path = get_datafile_path(
            __file__,
            'bucket_retention_test_rules_3.yaml')

        try:
            self.scanner = retention_scanner.RetentionScanner(
                {}, {}, mock.MagicMock(), '', '', rules_local_path)
        except audit_errors.InvalidRulesSchemaError as e:
            expectErrStr = "Lack of minimum_retention and maximum_retention in rule 0"
            self.assertEquals(expectErrStr, str(e))

    @unittest.skipIf(do_not_test_old_cases, 'debug new test cases')
    def test_retention_retrieve_4(self):
        """min larger than max"""

        rules_local_path = get_datafile_path(
            __file__,
            'bucket_retention_test_rules_4.yaml')

        try:
            self.scanner = retention_scanner.RetentionScanner(
                {}, {}, mock.MagicMock(), '', '', rules_local_path)
        except audit_errors.InvalidRulesSchemaError as e:
            expectErrStr = "minimum_retention larger than maximum_retention in rule 0"
            self.assertEquals(expectErrStr, str(e))

    @unittest.skipIf(do_not_test_old_cases, 'debug new test cases')
    def test_retention_retrieve_5(self):
        """Duplicate applies_to"""

        rules_local_path = get_datafile_path(
            __file__,
            'bucket_retention_test_rules_5.yaml')

        try:
            self.scanner = retention_scanner.RetentionScanner(
                {}, {}, mock.MagicMock(), '', '', rules_local_path)
        except audit_errors.InvalidRulesSchemaError as e:
            expectErrStr = "Duplicate applies_to in rule 0"
            self.assertEquals(expectErrStr, str(e))

    @unittest.skipIf(do_not_test_old_cases, 'debug new test cases')
    def test_retention_retrieve_11(self):
        """No resource"""

        rules_local_path = get_datafile_path(
            __file__,
            'bucket_retention_test_rules_11.yaml')

        try:
            self.scanner = retention_scanner.RetentionScanner(
                {}, {}, mock.MagicMock(), '', '', rules_local_path)
        except audit_errors.InvalidRulesSchemaError as e:
            expectErrStr = "Lack of resource in rule 0"
            self.assertEquals(expectErrStr, str(e))

    @unittest.skipIf(do_not_test_old_cases, 'debug new test cases')
    def test_retention_retrieve_12(self):
        """No resource type"""

        rules_local_path = get_datafile_path(
            __file__,
            'bucket_retention_test_rules_12.yaml')

        try:
            self.scanner = retention_scanner.RetentionScanner(
                {}, {}, mock.MagicMock(), '', '', rules_local_path)
        except audit_errors.InvalidRulesSchemaError as e:
            expectErrStr = "Lack of type in rule 0"
            self.assertEquals(expectErrStr, str(e))

    @unittest.skipIf(do_not_test_old_cases, 'debug new test cases')
    def test_retention_retrieve_13(self):
        """No resource ids"""

        rules_local_path = get_datafile_path(
            __file__,
            'bucket_retention_test_rules_13.yaml')

        try:
            self.scanner = retention_scanner.RetentionScanner(
                {}, {}, mock.MagicMock(), '', '', rules_local_path)
        except audit_errors.InvalidRulesSchemaError as e:
            expectErrStr = "Lack of resource_ids in rule 0"
            self.assertEquals(expectErrStr, str(e))

    @unittest.skipIf(do_not_test_old_cases, 'debug new test cases')
    def test_retention_retrieve_21(self):
        """a more complex test case, should be all right"""

        rules_local_path = get_datafile_path(
            __file__,
            'bucket_retention_test_rules_21.yaml')

        try:
            self.scanner = retention_scanner.RetentionScanner(
                {}, {}, mock.MagicMock(), '', '', rules_local_path)
        except audit_errors.InvalidRulesSchemaError as e:
            expectErrStr = ""
            self.assertEquals(expectErrStr, str(e))


    # @unittest.skipIf(do_not_test_old_cases, 'debug new test cases')
    def test_retention_retrieve_0(self):
        """test_retention_retrieve_0"""

        rules_local_path = get_datafile_path(
            __file__,
            'bucket_retention_test_rules_0.yaml')
        self.scanner = retention_scanner.RetentionScanner(
            {}, {}, mock.MagicMock(), '', '', rules_local_path)

        mock_data_access = mock.MagicMock()
        mock_data_access.scanner_iter.side_effect = _mock_gcp_resource_iter_0
        mock_service_config = mock.MagicMock()
        mock_service_config.model_manager = mock.MagicMock()
        mock_service_config.model_manager.get.return_value = (
            mock.MagicMock(), mock_data_access)
        self.scanner.service_config = mock_service_config

        generate_res_for_0()
        all_lifecycle_info = self.scanner._retrieve()
        all_violations = self.scanner._find_violations(all_lifecycle_info)

        res_map = {}
        for i in _fake_bucket_list_0:
            res_map[i.id] = i

        expected_violations = set([
            get_expect_violation_item(res_map, 'bkt1',
                                      'exact retention 365', 0),
            get_expect_violation_item(res_map, 'bkt2',
                                      'exact retention 365', 0),
            get_expect_violation_item(res_map, 'bkt3',
                                      'exact retention 365', 0),
            get_expect_violation_item(res_map, 'bkt4',
                                      'exact retention 365', 0),
            get_expect_violation_item(res_map, 'bkt5',
                                      'exact retention 365', 0),
            get_expect_violation_item(res_map, 'bkt6',
                                      'exact retention 365', 0),
            get_expect_violation_item(res_map, 'bkt7',
                                      'exact retention 365', 0),
        ])

        self.assertEqual(expected_violations, set(all_violations))

    @unittest.skipIf(do_not_test_old_cases, 'debug new test cases')
    def test_retention_retrieve_22(self):
        """test_retention_retrieve_22"""

        rules_local_path = get_datafile_path(
            __file__,
            'bucket_retention_test_rules_22.yaml')
        self.scanner = retention_scanner.RetentionScanner(
            {}, {}, mock.MagicMock(), '', '', rules_local_path)

        mock_data_access = mock.MagicMock()
        mock_data_access.scanner_iter.side_effect = _mock_gcp_resource_iter_22
        mock_service_config = mock.MagicMock()
        mock_service_config.model_manager = mock.MagicMock()
        mock_service_config.model_manager.get.return_value = (
            mock.MagicMock(), mock_data_access)
        self.scanner.service_config = mock_service_config

        generate_res_for_22()
        all_lifecycle_info = self.scanner._retrieve()
        all_violations = self.scanner._find_violations(all_lifecycle_info)

        res_map = {}
        for i in _fake_bucket_list_22:
            res_map[i.id] = i

        expected_violations = set([
            get_expect_violation_item(res_map, 'bkt_max_2',
                                      'only max retention', 0),
            get_expect_violation_item(res_map, 'bkt_max_3',
                                      'only max retention', 0),
            get_expect_violation_item(res_map, 'bkt_max_5',
                                      'only max retention', 0),
            get_expect_violation_item(res_map, 'bkt_max_6',
                                      'only max retention', 0),
            get_expect_violation_item(res_map, 'bkt_max_9_1',
                                      'only max retention', 0),
            get_expect_violation_item(res_map, 'bkt_max_9_2',
                                      'only max retention', 0),
            get_expect_violation_item(res_map, 'bkt_max_10',
                                      'only max retention', 0),

            get_expect_violation_item(res_map, 'bkt_min_6',
                                      'only min retention', 1),
            get_expect_violation_item(res_map, 'bkt_min_8',
                                      'only min retention', 1),
            get_expect_violation_item(res_map, 'bkt_min_11',
                                      'only min retention', 1),
            get_expect_violation_item(res_map, 'bkt_min_13',
                                      'only min retention', 1),
            get_expect_violation_item(res_map, 'bkt_min_15',
                                      'only min retention', 1),
            get_expect_violation_item(res_map, 'bkt_min_17',
                                      'only min retention', 1),

            get_expect_violation_item(res_map, 'bkt_both_1',
                                      'both max and min', 2),
            get_expect_violation_item(res_map, 'bkt_both_2',
                                      'both max and min', 2),
        ])

        self.assertEqual(expected_violations, set(all_violations))
        return



if __name__ == '__main__':
    unittest.main()
