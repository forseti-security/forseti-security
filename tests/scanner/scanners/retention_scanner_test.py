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
from tests.unittest_utils import ForsetiTestCase
import mock
from google.cloud.forseti.scanner.scanners import retention_scanner
from tests.unittest_utils import get_datafile_path
import json
from google.cloud.forseti.scanner.audit import retention_rules_engine as rre
import unittest

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

def GetLefecycleDict(action, age, created_before, matches_storage_class, num_newer_versions, is_live):
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


def _mock_gcp_resource_iter(_, resource_type):
    """Creates a list of GCP resource mocks retrieved by the scanner."""
    resources = []
    if resource_type != 'bucket':
        raise ValueError(
            'unexpected resource type: got %s, bucket',
            resource_type,
        )

    Resource = collections.namedtuple(
        'Resource',
        # fields based on required fields from Resource in dao.py.
        ['full_name', 'type', 'name', 'parent_type_name', 'parent',
         'data'],
    )

    p1_res = Resource(
        full_name='organization/31415926/project/p1/',
        type='project',
        name="p1",
        parent_type_name='project/p1/',
        parent=None,
        data='',
    )
    p2_res = Resource(
        full_name='organization/31415926/folder/5358979323/project/p2/',
        type='project',
        name="p2",
        parent_type_name='project/p2/',
        parent=None,
        data='',
    )

    tmpfakebucket = CreateFakeBucket("31415926", None, "p1", "bkt11")
    resources.append(ModifyBucketLifeCycle(p1_res, tmpfakebucket, "Delete", 499, None, None, None, None))
    tmpfakebucket = CreateFakeBucket("31415926", None, "p1", "bkt12")
    resources.append(ModifyBucketLifeCycle(p1_res, tmpfakebucket, "Delete", 500, None, None, None, None))
    tmpfakebucket = CreateFakeBucket("31415926", None, "p1", "bkt13")
    resources.append(ModifyBucketLifeCycle(p1_res, tmpfakebucket, "Delete", 501, None, None, None, None))
    tmpfakebucket = CreateFakeBucket("31415926", None, "p1", "bkt21")
    resources.append(ModifyBucketLifeCycle(p1_res, tmpfakebucket, "Delete", 99, None, None, None, None))
    tmpfakebucket = CreateFakeBucket("31415926", None, "p1", "bkt22")
    resources.append(ModifyBucketLifeCycle(p1_res, tmpfakebucket, "Delete", 100, None, None, None, None))
    tmpfakebucket = CreateFakeBucket("31415926", None, "p1", "bkt23")
    resources.append(ModifyBucketLifeCycle(p1_res, tmpfakebucket, "Delete", 101, None, None, None, None))

    tmpfakebucket = CreateFakeBucket("31415926", "5358979323", "p2", "bkt31")
    resources.append(ModifyBucketLifeCycle(p2_res, tmpfakebucket, "Delete", 149, None, None, None, None))
    tmpfakebucket = CreateFakeBucket("31415926", "5358979323", "p2", "bkt32")
    resources.append(ModifyBucketLifeCycle(p2_res, tmpfakebucket, "Delete", 150, None, None, None, None))
    tmpfakebucket = CreateFakeBucket("31415926", "5358979323", "p2", "bkt33")
    resources.append(ModifyBucketLifeCycle(p2_res, tmpfakebucket, "Delete", 300, None, None, None, None))
    tmpfakebucket = CreateFakeBucket("31415926", "5358979323", "p2", "bkt34")
    resources.append(ModifyBucketLifeCycle(p2_res, tmpfakebucket, "Delete", 450, None, None, None, None))
    tmpfakebucket = CreateFakeBucket("31415926", "5358979323", "p2", "bkt35")
    resources.append(ModifyBucketLifeCycle(p2_res, tmpfakebucket, "Delete", 451, None, None, None, None))
    tmpfakebucket = CreateFakeBucket("31415926", "5358979323", "p2", "bkt4")
    resources.append(ModifyBucketLifeCycle(p2_res, tmpfakebucket, "Delete", 600, None, None, None, None))
    tmpfakebucket = CreateFakeBucket("31415926", "5358979323", "p2", "bkt5")
    resources.append(ModifyBucketLifeCycle(p2_res, tmpfakebucket, "Delete", 200, None, None, None, None))

    return resources

class RetentionScannerTest(ForsetiTestCase):

    def setUp(self):
        """Set up."""


    #"lifecycle": {"rule": [{"action": {"type": "Delete"}, "condition": {"age": 20, "numNewerVersions": 5}}, {"action": {"type": "Delete"}, "condition": {"age": 10, "numNewerVersions": 99}}]},
    @unittest.skipIf(do_not_test_old_cases, 'debug new test cases')
    def test_all(self):
        """Tests _retrieve gets all bq acls and parent resources."""
        rules_local_path = get_datafile_path(
            __file__,
            'fake_bucket_retention_scanner_rule.yaml')

        self.scanner = retention_scanner.RetentionScanner(
            {}, {}, mock.MagicMock(), '', '', rules_local_path)

        mock_data_access = mock.MagicMock()
        mock_data_access.scanner_iter.side_effect = _mock_gcp_resource_iter

        res_data_map = {}
        res = _mock_gcp_resource_iter(None, 'bucket')
        for i in res:
            res_data_map[i.name] = i.data

        mock_service_config = mock.MagicMock()
        mock_service_config.model_manager = mock.MagicMock()
        mock_service_config.model_manager.get.return_value = (
            mock.MagicMock(), mock_data_access)
        self.scanner.service_config = mock_service_config
        all_lifecycle_info = self.scanner._retrieve()
        all_violations = self.scanner._find_violations(all_lifecycle_info)

        expected_violations = set([
       rre.Rule.RuleViolation(
           resource_name='p1bkt11',
           resource_type='bucket',
           full_name='organization/31415926/project/p1/bucket/p1bkt11/',
           rule_name='rules on buckets with only min',
           rule_index=3,
           violation_type='RETENTION_VIOLATION',
           violation_data=res_data_map['p1bkt11']),
       rre.Rule.RuleViolation(
           resource_name='p1bkt12',
           resource_type='bucket',
           full_name='organization/31415926/project/p1/bucket/p1bkt12/',
           rule_name='rules on projects',
           rule_index=2,
           violation_type='RETENTION_VIOLATION',
           violation_data=res_data_map['p1bkt12']),
       rre.Rule.RuleViolation(
           resource_name='p1bkt12',
           resource_type='bucket',
           full_name='organization/31415926/project/p1/bucket/p1bkt12/',
           rule_name='rules on organizations',
           rule_index=0,
           violation_type='RETENTION_VIOLATION',
           violation_data=res_data_map['p1bkt12']),
       rre.Rule.RuleViolation(
           resource_name='p1bkt13',
           resource_type='bucket',
           full_name='organization/31415926/project/p1/bucket/p1bkt13/',
           rule_name='rules on organizations',
           rule_index=0,
           violation_type='RETENTION_VIOLATION',
           violation_data=res_data_map['p1bkt13']),
       rre.Rule.RuleViolation(
           resource_name='p1bkt13',
           resource_type='bucket',
           full_name='organization/31415926/project/p1/bucket/p1bkt13/',
           rule_name='rules on projects',
           rule_index=2,
           violation_type='RETENTION_VIOLATION',
           violation_data=res_data_map['p1bkt13']),
       rre.Rule.RuleViolation(
           resource_name='p1bkt21',
           resource_type='bucket',
           full_name='organization/31415926/project/p1/bucket/p1bkt21/',
           rule_name='rules on projects',
           rule_index=2,
           violation_type='RETENTION_VIOLATION',
           violation_data=res_data_map['p1bkt21']),
       rre.Rule.RuleViolation(
           resource_name='p1bkt22',
           resource_type='bucket',
           full_name='organization/31415926/project/p1/bucket/p1bkt22/',
           rule_name='rules on projects',
           rule_index=2,
           violation_type='RETENTION_VIOLATION',
           violation_data=res_data_map['p1bkt22']),
       rre.Rule.RuleViolation(
           resource_name='p1bkt23',
           resource_type='bucket',
           full_name='organization/31415926/project/p1/bucket/p1bkt23/',
           rule_name='rules on buckets with only max',
           rule_index=4,
           violation_type='RETENTION_VIOLATION',
           violation_data=res_data_map['p1bkt23']),
       rre.Rule.RuleViolation(
           resource_name='p2bkt31',
           resource_type='bucket',
           full_name='organization/31415926/folder/5358979323/project/p2/bucket/p2bkt31/',
           rule_name='rules on folders',
           rule_index=1,
           violation_type='RETENTION_VIOLATION',
           violation_data=res_data_map['p2bkt31']),
       rre.Rule.RuleViolation(
           resource_name='p2bkt31',
           resource_type='bucket',
           full_name='organization/31415926/folder/5358979323/project/p2/bucket/p2bkt31/',
           rule_name='rules on buckets with only both',
           rule_index=5,
           violation_type='RETENTION_VIOLATION',
           violation_data=res_data_map['p2bkt31']),
       rre.Rule.RuleViolation(
           resource_name='p2bkt35',
           resource_type='bucket',
           full_name='organization/31415926/folder/5358979323/project/p2/bucket/p2bkt35/',
           rule_name='rules on buckets with only both',
           rule_index=5,
           violation_type='RETENTION_VIOLATION',
           violation_data=res_data_map['p2bkt35']),
       rre.Rule.RuleViolation(
           resource_name='p2bkt4',
           resource_type='bucket',
           full_name='organization/31415926/folder/5358979323/project/p2/bucket/p2bkt4/',
           rule_name='rules on organizations',
           rule_index=0,
           violation_type='RETENTION_VIOLATION',
           violation_data=res_data_map['p2bkt4'])
        ])


        self.assertEqual(expected_violations, set(all_violations))
        return
