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
"""Tests for LocationScanner."""

import collections
import json
import unittest
import mock

from tests.scanner.test_data import fake_location_scanner_data as data
from tests.unittest_utils import ForsetiTestCase
from google.cloud.forseti.common.gcp_type import resource_util
from google.cloud.forseti.scanner.scanners import location_scanner


def _mock_gcp_resource_iter(_, resource_type):
    """Creates a list of GCP resource mocks retrieved by the scanner."""

    Resource = collections.namedtuple(
        'Resource',
        # fields based on required fields from Resource in dao.py.
        ['full_name', 'type', 'name', 'parent_type_name', 'parent',
         'data'],
    )

    project_resource = Resource(
        full_name=data.PROJECT.full_name,
        type=data.PROJECT.type,
        name=data.PROJECT.name,
        parent_type_name='',
        parent=None,
        data='',
    )


    def _create_child_resource(res):
        return Resource(
            full_name=res.full_name,
            type=res.type,
            parent_type_name='project/' + res.parent.id,
            name=res.id,
            data=res.data,
            parent=project_resource,
        )

    if resource_type == 'bucket':
        resource = _create_child_resource(data.BUCKET)
    elif resource_type == 'cloudsqlinstance':
        resource = _create_child_resource(data.CLOUD_SQL_INSTANCE)
    elif resource_type == 'dataset':
        resource = _create_child_resource(data.DATASET)
    elif resource_type == 'kubernetes_cluster':
        resource = _create_child_resource(data.CLUSTER)
    elif resource_type == 'instance':
        resource = _create_child_resource(data.GCE_INSTANCE)
    else:
        raise ValueError('Unexpected resource type: ' + resource_type)

    return [resource]


class LocationScannerTest(ForsetiTestCase):

    @mock.patch.object(location_scanner, 'lre', autospec=True)
    def setUp(self, _):
        self.scanner = location_scanner.LocationScanner(
            {}, {}, mock.MagicMock(), '', '', '')

    def test_retrieve(self):
        mock_data_access = mock.MagicMock()
        mock_data_access.scanner_iter.side_effect = _mock_gcp_resource_iter
        mock_service_config = mock.MagicMock()
        mock_service_config.model_manager = mock.MagicMock()
        mock_service_config.model_manager.get.return_value = (
            mock.MagicMock(), mock_data_access)
        self.scanner.service_config = mock_service_config

        got = set(self.scanner._retrieve())
        want = {data.BUCKET, data.CLOUD_SQL_INSTANCE, data.CLUSTER,
                data.DATASET, data.GCE_INSTANCE}
        self.assertEqual(got, want)


if __name__ == '__main__':
    unittest.main()
