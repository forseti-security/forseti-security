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

"""Tests the RelationshipUtil."""

from tests.unittest_utils import ForsetiTestCase
import mock
import unittest

from google.cloud.forseti.common.util import relationship


class RelationshipUtilTest(ForsetiTestCase):
    """Test relationship_util."""

    def test_get_resource_ancestors_from_full_name(self):

        # resource is organization
        mock_starting_resource = mock.MagicMock()
        mock_starting_resource.type = 'organization'
        mock_starting_resource.id = 'org1'
        resource_ancestors = (
            relationship.find_ancestors(
                mock_starting_resource,
                'organization/org1/'))

        self.assertEquals(1, len(resource_ancestors))

        # resource is project
        mock_starting_resource.type = 'project'
        mock_starting_resource.id = 'project3'
        resource_ancestors = (
            relationship.find_ancestors(
                mock_starting_resource,
                'organization/org1/folder/folder2/project/project3/'))

        self.assertEquals(3, len(resource_ancestors))
        self.assertEquals(mock_starting_resource, resource_ancestors[0])
        self.assertEquals('folder2', resource_ancestors[1].id)
        self.assertEquals('org1', resource_ancestors[2].id)        

        # resource has multiple folders, and subproject resources
        mock_starting_resource.type = 'firewall'        
        mock_starting_resource.id = 'firewall5'
        resource_ancestors = (
            relationship.find_ancestors(
                mock_starting_resource,
                ('organization/org1/folder/folder2/folder/folder3/'
                 'project/project4/firewall/firewall5/')))
        
        self.assertEquals(5, len(resource_ancestors))
        self.assertEquals(mock_starting_resource, resource_ancestors[0])
        self.assertEquals('project4', resource_ancestors[1].id)
        self.assertEquals('folder3', resource_ancestors[2].id)
        self.assertEquals('folder2', resource_ancestors[3].id)        
        self.assertEquals('org1', resource_ancestors[4].id)


if __name__ == '__main__':
    unittest.main()
