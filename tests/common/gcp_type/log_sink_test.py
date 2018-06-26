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

"""Tests the Log Sink resource"""

import json
import unittest

from tests.unittest_utils import ForsetiTestCase
from google.cloud.forseti.common.gcp_type import log_sink
from google.cloud.forseti.common.gcp_type.folder import Folder
from google.cloud.forseti.common.gcp_type.organization import Organization
from google.cloud.forseti.common.gcp_type.project import Project


class LogSinkTest(ForsetiTestCase):
    """Test LogSink resource."""

    def setUp(self):
        """Set up parent GCP resources for tests."""
        self.org_234 = Organization(
            '234',
            display_name='Organization 234',
            full_name='organization/234/',
            data='fake_org_data_234')

        self.folder_56 = Folder(
            '56',
            display_name='Folder 56',
            full_name='folder/56',
            data='fake_folder_data456456')

        self.proj_1 = Project(
            'proj-1',
            project_number=11223344,
            display_name='My project 1',
            parent=self.org_234,
            full_name='organization/234/project/proj-1/',
            data='fake_project_data_2341')

    def test_create_from_json(self):
        """Tests creating a LogSink from a JSON string."""
        json_string = (
            r'{"filter": "logName:\"logs/cloudaudit.googleapis.com\"", '
            r'"destination": "storage.googleapis.com/big-logs-bucket", '
            r'"name": "a-log-sink", '
            r'"writerIdentity": "serviceAccount:a-log-sink@logging-123456789.'
            r'iam.gserviceaccount.com", '
            r'"outputVersionFormat": "V2"}')

        sink = log_sink.LogSink.from_json(self.proj_1, json_string)

        self.assertEqual('a-log-sink', sink.id)
        self.assertEqual('sink', sink.type)
        self.assertEqual('projects/proj-1/sinks/a-log-sink', sink.name)
        self.assertEqual('logName:"logs/cloudaudit.googleapis.com"',
                         sink.sink_filter)
        self.assertEqual('storage.googleapis.com/big-logs-bucket',
                         sink.destination)
        self.assertFalse(sink.include_children)
        self.assertEqual(json.loads(json_string), json.loads(sink.raw_json))

    def test_create_from_dict(self):
        """Tests creating a LogSink from a dictionary."""
        sink_dict = {
            'name': 'another-log-sink',
            'destination': 'pubsub.googleapis.com/projects/my-logs/topics/logs',
            'outputVersionFormat': 'V2',
            'includeChildren': True,
            'writerIdentity': (
                'serviceAccount:cloud-logs@system.gserviceaccount.com'),
        }

        sink = log_sink.LogSink.from_dict(self.folder_56, sink_dict)

        self.assertEqual('another-log-sink', sink.id)
        self.assertEqual('sink', sink.type)
        self.assertEqual('folders/56/sinks/another-log-sink', sink.name)
        self.assertEqual('', sink.sink_filter)
        self.assertEqual('pubsub.googleapis.com/projects/my-logs/topics/logs',
                         sink.destination)
        self.assertTrue(sink.include_children)
        self.assertEqual(sink_dict, json.loads(sink.raw_json))


if __name__ == '__main__':
    unittest.main()
