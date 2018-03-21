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

"""Tests the Notifier runner."""

import mock

from google.cloud.security.notifier import notifier
from tests.unittest_utils import ForsetiTestCase


FAKE_VIOLATIONS_AS_DICTS = ({}, {}, {})

GOOD_CSCC_NOTIFIER_CONFIGS = {
    'resources': [{}],
    'violation': {
        'cscc': {
            'enabled': True,
            'gcs_path': 'gs://good_cscc_bucket/'}}}

BAD_CSCC_NOTIFIER_CONFIGS_WITH_MISSING_VIOLATION = {
    'resources': [{}]}

BAD_CSCC_NOTIFIER_CONFIGS_WITH_CSCC_DISABLED = {
    'resources': [{}],
    'violation': {
        'cscc': {
            'enabled': False,
            'gcs_path': 'gs://good_cscc_bucket/'}}}

BAD_CSCC_NOTIFIER_CONFIGS_WITH_CSCC_BUCKET_NOT_CONFIGURED = {
    'resources': [{}],
    'violation': {
        'cscc': {
            'enabled': False,
            'gcs_path': 'gs://{CSCC_BUCKET}/'}}}


class NotifierTest(ForsetiTestCase):

    def setUp(self):
        """Setup method."""
        ForsetiTestCase.setUp(self)

    def tearDown(self):
        """Tear down method."""
        ForsetiTestCase.tearDown(self)

    @mock.patch.object(notifier.CsccPipeline, 'run', autospec=True)
    def test_cscc_notification_does_run_with_proper_cscc_config(
            self, mock_cscc_pipeline_run):

        notifier.run_cscc_notification(
            GOOD_CSCC_NOTIFIER_CONFIGS,
            FAKE_VIOLATIONS_AS_DICTS)
        self.assertEqual(1, mock_cscc_pipeline_run.call_count)

    @mock.patch.object(notifier.CsccPipeline, 'run', autospec=True)
    def test_cscc_notification_does_not_run_without_proper_cscc_config(
            self, mock_cscc_pipeline_run):

        notifier.run_cscc_notification(
            BAD_CSCC_NOTIFIER_CONFIGS_WITH_MISSING_VIOLATION,
            FAKE_VIOLATIONS_AS_DICTS)
        self.assertEqual(0, mock_cscc_pipeline_run.call_count)

        notifier.run_cscc_notification(
            BAD_CSCC_NOTIFIER_CONFIGS_WITH_CSCC_DISABLED,
            FAKE_VIOLATIONS_AS_DICTS)
        self.assertEqual(0, mock_cscc_pipeline_run.call_count)

        notifier.run_cscc_notification(
            BAD_CSCC_NOTIFIER_CONFIGS_WITH_CSCC_BUCKET_NOT_CONFIGURED,
            FAKE_VIOLATIONS_AS_DICTS)
        self.assertEqual(0, mock_cscc_pipeline_run.call_count)
