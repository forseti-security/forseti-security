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
"""Tests the email inventory snapshot pipeline."""

from datetime import datetime

import mock
import unittest

from google.cloud.security.notifier.pipelines import email_inventory_snapshot_summary_pipeline
from tests.unittest_utils import ForsetiTestCase


class EmailInventorySnapshotSummaryPipelineTest(ForsetiTestCase):
    """Tests for the email_inventory_snapshot_summary_pipeline."""

    def test_can_compose_subject_and_content(self):
        email_pipeline = (
            email_inventory_snapshot_summary_pipeline
            .EmailInventorySnapshotSummaryPipeline(
                111111))

        snapshot_time = datetime.strptime('Dec 25 2000  1:00AM',
                                          '%b %d %Y %I:%M%p')
        snapshot_timestamp = '20001225T010000Z'
        status = 'SUCCESS'

        mock_inventory_pipeline1 = mock.MagicMock(
            RESOURCE_NAME='foo_resource',
            status='SUCCESS',
            count=10)
        mock_inventory_pipeline2 = mock.MagicMock(
            RESOURCE_NAME='bar_resource',
            status='PARTIAL_SUCCESS',
            count=10)
        mock_inventory_pipeline3 = mock.MagicMock(
            RESOURCE_NAME='baz_resource',
            status='FAILURE',
            count=10)
        mock_inventory_pipelines = [
            mock_inventory_pipeline1,
            mock_inventory_pipeline2,
            mock_inventory_pipeline3]

        email_subject, email_content = email_pipeline._compose(
            snapshot_time, snapshot_timestamp, status,
            mock_inventory_pipelines)

        expected_subject = ('Inventory Snapshot Complete: '
                            '20001225T010000Z SUCCESS')
        expected_content = (
            u'<!--\nCopyright 2017 Google Inc.\n\nLicensed under the Apache '
            'License, Version 2.0 (the \"License\");\nyou may not use this '
            'file except in compliance with the License.\nYou may obtain a '
            'copy of the License at\n\n    '
            'http://www.apache.org/licenses/LICENSE-2.0\n\nUnless required by '
            'applicable law or agreed to in writing, software\ndistributed '
            'under the License is distributed on an \"AS IS\" BASIS,\nWITHOUT '
            'WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.\n'
            'See the License for the specific language governing permissions '
            'and\nlimitations under the License.\n-->\n\n<!doctype html>\n'
            '<html>\n<body>\n    Timestamp: 20001225T010000Z; 2000 Dec 25, '
            '01:00:00 (UTC)<br>\n    Status Summary: '
            'SUCCESS<br>\n    <br>\n    <table>\n        <col width=\"250\">\n'
            '        <col width=\"150\">\n        <col width=\"150\">\n        '
            '<tr>\n            <th align=\"left\">Resource Name</th>\n'
            '            <th align=\"left\">Status</th>\n            '
            '<th align=\"left\"># in Snapshot</th>\n        </tr>\n        \n'
            '        <tr>\n            <td>foo_resource</td>\n            '
            '<td>SUCCESS</td>\n            \n              <td>10</td>\n'
            '            \n        </tr>\n        \n        <tr>\n'
            '            <td>bar_resource</td>\n            '
            '<td>PARTIAL_SUCCESS</td>\n            \n              '
            '<td>10</td>\n            \n        </tr>\n        \n        <tr>\n'
            '            <td>baz_resource</td>\n            <td>FAILURE</td>\n'
            '            \n              <td>10</td>\n            \n        '
            '</tr>\n        \n    </table>\n</body>\n</html>')

        self.assertEquals(expected_subject, email_subject)
        self.assertEquals(expected_content, email_content)


if __name__ == '__main__':
    unittest.main()
