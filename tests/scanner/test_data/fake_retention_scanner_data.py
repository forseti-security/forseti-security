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
"""Fake Retention scanner data."""

import json
from datetime import datetime, timedelta


from google.cloud.forseti.common.gcp_type import organization
from google.cloud.forseti.common.gcp_type import project
from google.cloud.forseti.common.gcp_type import bucket
from google.cloud.forseti.scanner.audit import retention_rules_engine as rre

ORGANIZATION = organization.Organization(
    '123456',
    display_name='Default Organization',
    full_name='organization/123456/',
    data='fake_org_data_123456',
)

PROJECT1 = project.Project(
    'def-project-1',
    project_number=11223344,
    display_name='default project 1',
    parent=ORGANIZATION,
    full_name='organization/123456/project/def-project-1/',
    data='fake_project_data_11223344',
)

PROJECT2 = project.Project(
    'def-project-2',
    project_number=55667788,
    display_name='default project 2',
    parent=ORGANIZATION,
    full_name='organization/123456/project/def-project-2/',
    data='fake_project_data_55667788',
)

PROJECT3 = project.Project(
    'def-project-3',
    project_number=12121212,
    display_name='default project 3',
    parent=ORGANIZATION,
    full_name='organization/123456/project/def-project-3/',
    data='fake_project_data_12121212',
)

PROJECT4 = project.Project(
    'def-project-4',
    project_number=34343434,
    display_name='default project 4',
    parent=ORGANIZATION,
    full_name='organization/123456/project/def-project-4/',
    data='fake_project_data_34343434',
)

def build_bucket_violations(bucket, rule_name):
    data_lifecycle = bucket.get_lifecycle_rule()
    data_lifecycle_str = json.dumps(data_lifecycle)

    return [rre.RuleViolation(
        resource_name='buckets/'+bucket.id,
        resource_id=bucket.id,
        resource_type=bucket.type,
        full_name=bucket.full_name,
        rule_index=0,
        rule_name=rule_name,
        violation_type='RETENTION_VIOLATION',
        violation_data=data_lifecycle_str,
        resource_data=bucket.data,
    )]

class FakeBucketDataCreater():
    def __init__(self, id, project):
        self._id = id
        self._parent = project
        self._data_lifecycle = None

    def id(self):
        return self._id

    def get_data(self):
        data = {}
        # 'storage#bucket'
        data['kind'] = ''
        data['name'] = self.id()
        # '2018-09-10T18:36:59.094Z'
        data['timeCreated'] = ''
        # 'STANDARD'
        data['storageClass'] = ''
        data['labels'] = {}
        # '2018-09-10T18:36:59.832Z'
        data['updated'] = ''
        # '711111111111'
        data['projectNumber'] = ''
        data['acl'] = []
        data['defaultObjectAcl'] = []
        # '2'
        data['metageneration'] = ''
        # 'CAI='
        data['etag'] = ''
        # {'entity': 'project-owners-711111111111'}
        data['owner'] = {}
        data['id'] = self.id()
        # 'https://www.googleapis.com/storage/v1/b/'+self.id()
        data['selfLink'] = ''
        # 'US-CENTRAL1'
        data['location'] = ''

        if self._data_lifecycle is not None:
            data['lifecycle'] = self._data_lifecycle
        return data

    def SetLefecycleDict(self):
        self._data_lifecycle = {"rule": []}

    def AddLefecycleDict(
            self,
            action,
            age,
            created_before,
            matches_storage_class,
            num_newer_versions,
            is_live):
        if not self._data_lifecycle:
            self.SetLefecycleDict()

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
        self._data_lifecycle['rule'].append(result)
        return result

    def get_resource(self):
        data_dict = self.get_data()
        data = json.dumps(data_dict)
        return bucket.Bucket(bucket_id=self.id(),
                             parent=self._parent,
                             full_name=self._parent.full_name+'bucket/'+self.id()+'/',
                             data=data)
