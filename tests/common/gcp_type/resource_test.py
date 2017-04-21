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

"""Tests the GCP Resource base class."""

import mock

from google.apputils import basetest
from google.cloud.security.common.gcp_type.errors import InvalidResourceTypeError
from google.cloud.security.common.gcp_type.organization import Organization
from google.cloud.security.common.gcp_type.project import Project
from google.cloud.security.common.gcp_type.resource import LifecycleState
from google.cloud.security.common.gcp_type.resource import Resource
from google.cloud.security.common.gcp_type.resource import ResourceType
from google.cloud.security.common.gcp_type.resource_util import ResourceUtil


class ResourceTest(basetest.TestCase):
    """Test Resource."""

    def test_create_resource_raises_notimplemented(self):
        """Test create Resource raises NotImplemented due to abstract method."""
        my_resource_id = 'resource-id-1'
        my_resource_name = 'My resource name'
        Resource.__abstractmethods__ = frozenset()
        abs_res = Resource(resource_id=my_resource_id,
                           resource_type=ResourceType.PROJECT,
                           name='projects/%s' % my_resource_id,
                           display_name=my_resource_name)
        with self.assertRaises(NotImplementedError):
            abs_res.exists()

    def test_get_resource_types_exist(self):
        """Test that the Resource Types exist."""
        self.assertEqual(ResourceType.ORGANIZATION,
                         ResourceType.verify('organization'))
        self.assertEqual(ResourceType.FOLDER, ResourceType.verify('folder'))
        self.assertEqual(ResourceType.PROJECT, ResourceType.verify('project'))

    def test_get_invalid_resource_type_does_not_exist(self):
        """Test fake resource type raises exception."""
        with self.assertRaises(InvalidResourceTypeError):
            ResourceType.verify('fake')

class ResourceUtilTest(basetest.TestCase):
    """Test ResourceUtil."""

    def test_create_resource_is_ok(self):
        """Test the ResourceUtil.create_resource() creates the types."""
        expect_org = Organization(12345)
        actual_org = ResourceUtil.create_resource(
            12345, ResourceType.ORGANIZATION)
        self.assertEqual(expect_org, actual_org)
        expect_proj = Project('abcd', 54321)
        actual_proj = ResourceUtil.create_resource(
            'abcd', ResourceType.PROJECT, project_number=54321)
        self.assertEqual(expect_proj, actual_proj)
        self.assertEqual(expect_proj.project_number, actual_proj.project_number)

    def test_plural_is_correct(self):
        """Test that the resource type is pluralized correctly."""
        self.assertEqual('Organizations',
            ResourceUtil.pluralize(ResourceType.ORGANIZATION))
        self.assertEqual('Projects',
            ResourceUtil.pluralize(ResourceType.PROJECT))


if __name__ == '__main__':
    basetest.main()
