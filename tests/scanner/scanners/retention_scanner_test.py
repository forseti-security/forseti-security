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

from tests.scanner.test_data import fake_retention_scanner_data as frsd
from tests.unittest_utils import ForsetiTestCase
from tests.unittest_utils import get_datafile_path
from google.cloud.forseti.common.gcp_type import organization
from google.cloud.forseti.common.gcp_type import project
from google.cloud.forseti.common.gcp_type import folder
from google.cloud.forseti.scanner.audit import retention_rules_engine as rre
from google.cloud.forseti.scanner.scanners import retention_scanner

do_not_test_old_cases = False

def CreateFakeBucket(organizationid, folderid, projectname, bucketname):
    name = projectname+bucketname
    full_name = 'organization/' + organizationid + '/'
    if folderid != None:
        full_name += 'folder/'+folderid+'/'
    full_name += 'project/'+projectname+'/bucket/'+name+'/'
    tp = 'bucket'
    parent_type_name = 'project/'+projectname
    data = '{"defaultObjectAcl": [{"entity": "project-owners-722028419187", "etag": "CAQ=", "kind": "storage#objectAccessControl", "projectTeam": {"projectNumber": "722028419187", "team": "owners"}, "role": "OWNER"}, {"entity": "project-editors-722028419187", "etag": "CAQ=", "kind": "storage#objectAccessControl", "projectTeam": {"projectNumber": "722028419187", "team": "editors"}, "role": "OWNER"}, {"entity": "project-viewers-722028419187", "etag": "CAQ=", "kind": "storage#objectAccessControl", "projectTeam": {"projectNumber": "722028419187", "team": "viewers"}, "role": "READER"}], "etag": "CAQ=", "id": "'+name+'", "kind": "storage#bucket", "lifecycle": {"rule": [{"action": {"type": "Delete"}, "condition": {"age": 29, "createdBefore": "2018-08-15", "isLive": false, "matchesStorageClass": ["REGIONAL", "STANDARD", "DURABLE_REDUCED_AVAILABILITY", "NEARLINE", "COLDLINE"], "numNewerVersions": 17}}, {"action": {"type": "Delete"}, "condition": {"age": 37, "isLive": true}}]}, "location": "US-EAST1", "logging": {"logBucket": "audit-logs-'+projectname+'", "logObjectPrefix": "'+name+'"}, "metageneration": "4", "name": "'+name+'", "owner": {"entity": "project-owners-722028419187"}, "projectNumber": "722028419187", "selfLink": "https://www.googleapis.com/storage/v1/b/'+name+'", "storageClass": "REGIONAL", "timeCreated": "2018-09-13T18:45:14.101Z", "updated": "2018-09-26T13:38:28.286Z", "versioning": {"enabled": true}}'
    return (full_name, tp, parent_type_name, name, data)

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

_fake_bucket_list_01 = []

def _mock_gcp_resource_iter_01(_, resource_type):
    """Creates a list of GCP resource mocks retrieved by the scanner."""
    """Used in test case 22"""
    if resource_type != 'bucket':
        raise ValueError(
            'unexpected resource type: got %s, bucket',
            resource_type,
        )

    return _fake_bucket_list_01

def generate_res_for_01():
    """Creates a list of GCP resource mocks retrieved by the scanner."""
    """Used in test case 22"""

    org = organization.Organization(
        organization_id='433655555569',
        full_name='organization/433655555569/')
    p1 = project.Project(
        project_id='p1',
        project_number='711111111111',
        full_name=org.full_name+'project/p1/',
        parent=org
    )
    fd = folder.Folder(
        folder_id='5358955555',
        full_name=org.full_name+'folder/5358955555/')
    p2 = project.Project(
        project_id='p2',
        project_number='722222222222',
        full_name=fd.full_name+'project/p2/',
        parent=org
    )

    res = []

    data_creater = frsd.FakeBucketDataCreater('p1bkt11', p1)
    data_creater.AddLefecycleDict("Delete", 499, None, None, None, None)
    res.append(data_creater.get_resource())

    data_creater = frsd.FakeBucketDataCreater('p1bkt12', p1)
    data_creater.AddLefecycleDict("Delete", 500, None, None, None, None)
    res.append(data_creater.get_resource())

    data_creater = frsd.FakeBucketDataCreater('p1bkt13', p1)
    data_creater.AddLefecycleDict("Delete", 501, None, None, None, None)
    res.append(data_creater.get_resource())

    data_creater = frsd.FakeBucketDataCreater('p1bkt21', p1)
    data_creater.AddLefecycleDict("Delete", 99, None, None, None, None)
    res.append(data_creater.get_resource())

    data_creater = frsd.FakeBucketDataCreater('p1bkt22', p1)
    data_creater.AddLefecycleDict("Delete", 100, None, None, None, None)
    res.append(data_creater.get_resource())

    data_creater = frsd.FakeBucketDataCreater('p1bkt23', p1)
    data_creater.AddLefecycleDict("Delete", 101, None, None, None, None)
    res.append(data_creater.get_resource())


    data_creater = frsd.FakeBucketDataCreater('p2bkt31', p2)
    data_creater.AddLefecycleDict("Delete", 149, None, None, None, None)
    res.append(data_creater.get_resource())

    data_creater = frsd.FakeBucketDataCreater('p2bkt32', p2)
    data_creater.AddLefecycleDict("Delete", 150, None, None, None, None)
    res.append(data_creater.get_resource())

    data_creater = frsd.FakeBucketDataCreater('p2bkt33', p2)
    data_creater.AddLefecycleDict("Delete", 300, None, None, None, None)
    res.append(data_creater.get_resource())

    data_creater = frsd.FakeBucketDataCreater('p2bkt34', p2)
    data_creater.AddLefecycleDict("Delete", 450, None, None, None, None)
    res.append(data_creater.get_resource())

    data_creater = frsd.FakeBucketDataCreater('p2bkt35', p2)
    data_creater.AddLefecycleDict("Delete", 451, None, None, None, None)
    res.append(data_creater.get_resource())

    data_creater = frsd.FakeBucketDataCreater('p2bkt4', p2)
    data_creater.AddLefecycleDict("Delete", 600, None, None, None, None)
    res.append(data_creater.get_resource())

    data_creater = frsd.FakeBucketDataCreater('p2bkt5', p2)
    data_creater.AddLefecycleDict("Delete", 200, None, None, None, None)
    res.append(data_creater.get_resource())

    global _fake_bucket_list_01
    _fake_bucket_list_01 = res
    return res


def ModifyBucketLifeCycle(proj_res, bucketdata, action, age, created_before, matches_storage_class, num_newer_versions, is_live):

    Resource = collections.namedtuple(
        'Resource',
        # fields based on required fields from Resource in dao.py.
        ['full_name', 'type', 'name', 'parent_type_name', 'parent',
            'data'],
    )
    datajson = json.loads(bucketdata[4])
    datajson["lifecycle"]["rule"] = []
    datajson["lifecycle"]["rule"].append(GetLefecycleDict(action, age, created_before, matches_storage_class, num_newer_versions, is_live))
    return Resource(full_name=bucketdata[0],type=bucketdata[1],parent_type_name=bucketdata[2],name=bucketdata[3],parent=proj_res,data=json.dumps(datajson))


class RetentionScannerTest(ForsetiTestCase):

    def setUp(self):
        """Set up."""


    #"lifecycle": {"rule": [{"action": {"type": "Delete"}, "condition": {"age": 20, "numNewerVersions": 5}}, {"action": {"type": "Delete"}, "condition": {"age": 10, "numNewerVersions": 99}}]},
    @unittest.skipIf(do_not_test_old_cases, 'debug new test cases')
    def test_scanner_01(self):
        """Tests the whole process of retention scanner"""
        rules_local_path = get_datafile_path(
            __file__,
            'fake_bucket_retention_scanner_rule.yaml')

        self.scanner = retention_scanner.RetentionScanner(
            {}, {}, mock.MagicMock(), '', '', rules_local_path)

        mock_data_access = mock.MagicMock()
        mock_data_access.scanner_iter.side_effect = _mock_gcp_resource_iter_01

        mock_service_config = mock.MagicMock()
        mock_service_config.model_manager = mock.MagicMock()
        mock_service_config.model_manager.get.return_value = (
            mock.MagicMock(), mock_data_access)
        self.scanner.service_config = mock_service_config

        generate_res_for_01()
        all_lifecycle_info = self.scanner._retrieve()
        all_violations = self.scanner._find_violations(all_lifecycle_info)

        res_map = {}
        for i in _fake_bucket_list_01:
            res_map[i.id] = i

        expected_violations = set([
            get_expect_violation_item(res_map, 'p1bkt11',
                                      'rules on buckets with only min', 3),
            get_expect_violation_item(res_map, 'p1bkt12',
                                      'rules on projects', 2),
            get_expect_violation_item(res_map, 'p1bkt12',
                                      'rules on organizations', 0),
            get_expect_violation_item(res_map, 'p1bkt13',
                                      'rules on projects', 2),
            get_expect_violation_item(res_map, 'p1bkt13',
                                      'rules on organizations', 0),
            get_expect_violation_item(res_map, 'p1bkt21',
                                      'rules on projects', 2),
            get_expect_violation_item(res_map, 'p1bkt22',
                                      'rules on projects', 2),
            get_expect_violation_item(res_map, 'p1bkt23',
                                      'rules on buckets with only max', 4),
            get_expect_violation_item(res_map, 'p2bkt31',
                                      'rules on folders', 1),
            get_expect_violation_item(res_map, 'p2bkt31',
                                      'rules on buckets with only both', 5),
            get_expect_violation_item(res_map, 'p2bkt35',
                                      'rules on buckets with only both', 5),
            get_expect_violation_item(res_map, 'p2bkt4',
                                      'rules on organizations', 0),
        ])


        self.assertEqual(expected_violations, set(all_violations))
        return
