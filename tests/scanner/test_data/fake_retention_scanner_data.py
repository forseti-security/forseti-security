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
