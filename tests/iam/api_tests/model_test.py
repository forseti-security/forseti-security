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

"""Tests the IAM Explain model."""

import unittest

from google.cloud.security.iam.explain.service import GrpcExplainerFactory
from google.cloud.security.iam.playground.service import GrpcPlaygrounderFactory
from google.cloud.security.iam.inventory.service import GrpcInventoryFactory
from google.cloud.security.iam.dao import ModelManager

from tests.iam.api_tests.api_tester import ModelTestRunner, create_test_engine
from tests.unittest_utils import ForsetiTestCase


class TestServiceConfig(object):
    """ServiceConfig stub."""
    def __init__(self):
        self.engine = create_test_engine()
        self.model_manager = ModelManager(self.engine)

    def run_in_background(self, function):
        """Stub."""
        function()
        return self

    def get_engine(self):
        """Stub."""
        return self.engine


MODEL = {
        'resources': {
                'organization/org1': {
                        'project/project1': {
                                'bucket/bucket1': {},
                            },
                        'project/project2': {
                                'bucket/bucket2': {},
                                'vm/instance-1': {},
                            },
                    },
            },
        'memberships': {
                'group/a': {
                        'user/a': {},
                        'user/b': {},
                        'user/c': {},
                        'group/b': {
                                'user/a': {},
                                'user/d': {},
                            },
                    },
                'user/e': {},
            },
        'roles': {
                'a': ['a', 'b', 'c', 'd', 'e'],
                'b': ['a', 'b', 'c'],
                'c': ['f', 'g', 'h'],
                'd': ['f', 'g', 'i']
            },
        'bindings': {
                'organization/org1': {
                        'b': ['group/a'],
                    },
                'project/project2': {
                        'a': ['group/b'],
                    },
                'vm/instance-1': {
                        'a': ['user/a'],
                    },
            },
    }


def create_tester():
    """Creates a model based test runner."""
    return ModelTestRunner(MODEL,
                           TestServiceConfig(),
                           [GrpcExplainerFactory,
                            GrpcPlaygrounderFactory,
                            GrpcInventoryFactory])


class ModelTest(ForsetiTestCase):
    """Test based on declarative model."""

    def setUp(self):
        self.setup = create_tester()

    def test_check_policy(self):
        """Test check policy."""

        def test(client):
            """Test implementation with API client."""
            self.assertTrue(client.playground.check_iam_policy(
                'vm/instance-1',
                'c',
                'user/d').result)
            self.assertTrue(client.playground.check_iam_policy(
                'vm/instance-1',
                'e',
                'user/d').result)
            self.assertTrue(client.playground.check_iam_policy(
                'vm/instance-1',
                'e',
                'user/a').result)
            self.assertFalse(client.playground.check_iam_policy(
                'organization/org1',
                'e',
                'user/a').result)
            self.assertFalse(client.playground.check_iam_policy(
                'project/project2',
                'e',
                'user/c').result)
            self.assertFalse(client.playground.check_iam_policy(
                'vm/instance-1',
                'e',
                'user/c').result)

        self.setup.run(test)

    def test_query_role_permissions(self):
        """Test query_role_permissions."""
        def test(client):
            """Test implementation with API client."""
            response = client.explain.query_permissions_by_roles(
                role_names=['a', 'b'])
            self.assertTrue(len(response.permissionsbyroles) == 2)
            for mapping in response.permissionsbyroles:
                if mapping.role == 'a':
                    self.assertEquals(
                        set(mapping.permissions),
                        set(['a', 'b', 'c', 'd', 'e']))
                elif mapping.role == 'b':
                    self.assertEquals(
                        set(mapping.permissions),
                        set(['a', 'b', 'c']))
        self.setup.run(test)

    def test_query_access_by_resources(self):
        """Test query_access_by_resources."""
        def test(client):
            """Test implementation with API client."""
            response = client.explain.query_access_by_resources(
                resource_name='project/project2',
                permission_names=['a', 'c'],
                expand_groups=True)
            self.assertTrue(len(response.accesses) == 2)
            for access in response.accesses:
                if access.role == 'a':
                    self.assertEqual(
                        set(access.members),
                        set(['group/b', 'user/a', 'user/d']))
                elif access.role == 'b':
                    self.assertEqual(
                        set(access.members),
                        set(['group/a',
                             'user/a',
                             'user/b',
                             'user/c',
                             'user/d',
                             'group/b']))
        self.setup.run(test)

    def test_query_access_by_members(self):
        """Test query_access_by_members."""
        def test(client):
            """Test implementation with API client."""
            response = client.explain.query_access_by_members(
                'group/a',
                'a',
                expand_resources=True)
            for access in response.accesses:
                if access.role == 'b':
                    self.assertEqual(set(access.resources),
                                     set([
                                         'bucket/bucket1',
                                         'project/project1',
                                         'vm/instance-1',
                                         'bucket/bucket2',
                                         'project/project2',
                                         'organization/org1',
                                         ]))
        self.setup.run(test)

    def test_explain_granted(self):
        """Test explain_granted."""
        def test(client):
            """Test implementation with API client."""
            response = client.explain.explain_granted(
                member_name='user/d',
                resource_name='bucket/bucket2',
                role='b')
            self.assertTrue(response, 'Expected to get a grant explanation')
        self.setup.run(test)

    def test_explain_denied(self):
        """Test explain_denied."""
        def test(client):
            """Test implementation with API client."""
            response = client.explain.explain_denied(
                member_name='user/d',
                resource_names=[
                    'bucket/bucket2'],
                permission_names=['f', 'i'])
            self.assertTrue(response, 'Expected to get a deny explanation')

            response = client.explain.explain_denied(
                member_name='user/e',
                resource_names=[
                    'bucket/bucket2'],
                permission_names=['a'])
            self.assertTrue(response, 'Expected to get a deny explanation')
        self.setup.run(test)


if __name__ == '__main__':
    unittest.main()
