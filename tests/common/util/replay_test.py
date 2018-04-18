# Copyright 2017 The Forseti Security Authors. All rights reserved.
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
"""Tests for google.cloud.forseti.common.util.replay."""
import os
import tempfile
import unittest
import mock
import google.auth
from google.oauth2 import credentials

from tests import unittest_utils
from tests.common.gcp_api.test_data import fake_compute_responses as fake_compute
from tests.common.gcp_api.test_data import http_mocks
from google.cloud.forseti.common.gcp_api import compute
from google.cloud.forseti.common.gcp_api import errors as api_errors
from google.cloud.forseti.common.util import replay


class ReplayTest(unittest_utils.ForsetiTestCase):
    """Tests for the Record and Replay wrappers."""

    def setUp(self):
        """Set up."""
        self.fake_global_configs = {'max_compute_api_calls_per_second': 2000}
        self.project_id = fake_compute.FAKE_PROJECT_ID
        self.record_file = tempfile.NamedTemporaryFile(delete=False).name
        self.maxDiff = None

    def tearDown(self):
        """Clean up."""
        os.unlink(self.record_file)
        os.environ[replay.RECORD_ENVIRONMENT_VAR] = ''
        os.environ[replay.REPLAY_ENVIRONMENT_VAR] = ''

    def run_api_tests(self, record=False):
        """Run several API calls."""
        if record:
            os.environ[replay.RECORD_ENVIRONMENT_VAR] = self.record_file
            os.environ[replay.REPLAY_ENVIRONMENT_VAR] = ''

            mock_responses = []
            mock_responses.append(({'status': '200'},
                                   fake_compute.GET_PROJECT_RESPONSE))
            for page in fake_compute.LIST_NETWORKS_RESPONSES:
                mock_responses.append(({'status': '200'}, page))
            mock_responses.append((
                {'status': '403', 'content-type': 'application/json'},
                fake_compute.ACCESS_DENIED))
            http_mocks.mock_http_response_sequence(mock_responses)
        else:
            os.environ[replay.RECORD_ENVIRONMENT_VAR] = ''
            os.environ[replay.REPLAY_ENVIRONMENT_VAR] = self.record_file

        gce_api_client = None
        mock_creds = mock.Mock(spec_set=credentials.Credentials)
        with mock.patch.object(google.auth, 'default',
                               return_value=(mock_creds, 'test-project')):
            gce_api_client = compute.ComputeClient(
                global_configs=self.fake_global_configs)

        responses = []
        responses.append(gce_api_client.get_project(self.project_id))
        responses.append(gce_api_client.get_networks(self.project_id))
        try:
            gce_api_client.get_instances(self.project_id)
        except api_errors.ApiExecutionError as e:
            responses.append(str(e))

        return responses

    def test_record_and_replay(self):
        """Verify record and replay functionality."""
        expected_results = self.run_api_tests(record=True)
        results = self.run_api_tests(record=False)
        self.assertEqual(expected_results, results)


if __name__ == '__main__':
    unittest.main()
