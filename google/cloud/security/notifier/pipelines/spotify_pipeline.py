# Copyright 2017 Google Inc.
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

"""Internal pipeline to perform notifications"""

import json

# TODO: Investigate improving so we can avoid the pylint disable.
# pylint: disable=line-too-long
from google.cloud.security.common.data_access import errors as data_access_errors
from google.cloud.security.common.data_access import dao
from google.cloud.security.common.data_access import project_dao
from google.cloud.security.common.data_access import violation_dao
from google.cloud.security.common.util import log_util
from google.cloud.security.common.data_access import errors as db_errors
from google.cloud.security.inventory import errors as inventory_errors
from google.cloud.security.notifier.pipelines import notification_pipeline

# pylint: enable=line-too-long

LOGGER = log_util.get_logger(__name__)


class SpotifyPipeline(notification_pipeline.NotificationPipeline):
    """Spotify pipeline to perform notifications"""

    def _get_clean_violation(self, violation):
        resource_type = violation['resource_type']

        resource_id = violation['resource_id']

        violation_project = {
            'project_id': None,
            'ownership': None,
            'violation': violation
        }

        if resource_type == 'project':
            violation_project['project_id'] = resource_id
            violation_project['ownership'] = self._get_project_ownership(
                resource_id)

        return violation_project

    def _get_project_ownership(self, project_id):
        # currently the bucket scanner includes propject_number isntead of
        # project_id, so I must make this method tolerant until a fix is pushed.
        # TODO: push a fix to bucket scanner to add project_id instenad of
        # project_number

        if project_id.isdigit():
            # assume the provided project_id is instead the project_number
            print " i think it is a project number"
            project_raw = self.project_dao.get_project_raw_data(
                'projects',
                self.cycle_timestamp,
                project_number=project_id)
        else:
            project_raw = self.project_dao.get_project_raw_data(
                'projects',
                self.cycle_timestamp,
                project_id=project_id)

        project_raw_d = json.loads(project_raw[0])

        ownership = {
            'project_id': None,
            'owner': None,
            'creator': None
        }

        p_labels = project_raw_d.get('labels')
        ownership['project_id'] = project_raw_d.get('projectId')
        if p_labels is not None:
            ownership['owner'] = p_labels.get('owner')
            ownership['creator'] = p_labels.get('creator')

        return ownership


    def run(self):
        for v in self.violations['violations']:
            print self._get_clean_violation(v)

        for v in self.violations['bucket_acl_violations']:
            print self._get_clean_violation(v)
