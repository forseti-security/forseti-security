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
"""Tests the Forseti Server model service."""

import unittest

from tests.services.api_tests.api_tester import ModelTestRunner
from tests.services.inventory import gcp_api_mocks
from tests.services.util.db import create_test_engine
from tests.unittest_utils import ForsetiTestCase
from google.cloud.forseti.services.base.config import InventoryConfig
from google.cloud.forseti.services.dao import ModelManager
from google.cloud.forseti.services.explain.service import GrpcExplainerFactory
from google.cloud.forseti.services.inventory.service import GrpcInventoryFactory
from google.cloud.forseti.services.model import model_pb2
from google.cloud.forseti.services.model.service import GrpcModellerFactory


class TestServiceConfig(object):
    """ServiceConfig stub."""

    def __init__(self):
        self.engine = create_test_engine()
        self.model_manager = ModelManager(self.engine)
        self.inventory_config = (
            InventoryConfig(gcp_api_mocks.ORGANIZATION_ID, '', {}, '', {}))

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
                'group/c': {
                    'user/a':{},
                    'user/f':{},
                }
            },
        },
        'user/e': {},
    },
    'roles': {
        'role/a': ['permission/a', 'permission/b', 'permission/c',
                   'permission/d', 'permission/e'],
        'role/b': ['permission/a', 'permission/b', 'permission/c'],
        'role/c': ['permission/f', 'permission/g', 'permission/h'],
        'role/d': ['permission/f', 'permission/g', 'permission/i'],
        # Include legacy roles for project(owner|editor|viewer) expansion
        'roles/viewer': ['permission/a'],
        'roles/editor': ['permissions/a', 'permissions/b', 'permissions/c',
                         'permission/d', 'permission/e', 'permission/f',
                         'permission/g'],
        'roles/owner': ['permissions/a', 'permissions/b', 'permissions/c',
                        'permission/d', 'permission/e', 'permission/f',
                        'permission/g', 'permissions/j'],
    },
    'bindings': {
        'organization/org1': {
            'role/b': ['group/a'],
        },
        'project/project2': {
            'role/a': ['group/b'],
            'roles/viewer': ['user/e'],
        },
        'project/project1': {
            'roles/editor': ['user/b', 'group/b'],
            'roles/owner': ['group/c'],
        },
        'vm/instance-1': {
            'role/a': ['user/a'],
        },
        'bucket/bucket1': {
            'role/c': ['projecteditor/project1'],
            'role/d': ['projectowner/project1'],
        },
        'bucket/bucket2': {
            'role/c': ['projectviewer/project2'],
            'role/d': ['allauthenticatedusers'],
        },
    },
}


def create_tester():
    """Creates a model based test runner."""
    return ModelTestRunner(
        MODEL, TestServiceConfig(),
        [
            GrpcExplainerFactory,
            GrpcInventoryFactory,
            GrpcModellerFactory,
        ])

def expand_message(messages, type):
    """Get the access_details in the form of
       set([member resource permission ])
    """
    details = set()
    if type == "access_by_resource":
        for access in messages:
            for member in access.members:
                details.add(' '.join([member,
                                      access.resource,
                                      access.role]))
    elif type == "access_by_member":
        for access in messages:
            for resource in access.resources:
                details.add(' '.join([access.member,
                                      resource,
                                      access.role]))
    elif type == "access_by_both":
        for access in messages:
            details.add(' '.join([access.member,
                                  access.resource,
                                  access.permission]))
    elif type == "role_permission":
        for permissionsbyrole in messages:
            for permission in permissionsbyrole.permissions:
                details.add(' '.join([permissionsbyrole.role,
                                      permission]))
    else:
        raise Exception("type unrecognized")
    return details

class ExplainerTest(ForsetiTestCase):
    """Test based on declarative model."""

    def setUp(self):
        self.setup = create_tester()

    def test_list_resources(self):
        """Test list resources."""

        def test(client):
            """Test implementation with API client."""
            list_resources_reply = set(
                r.full_resource_name for r in client.explain.list_resources(''))
            self.assertEqual(list_resources_reply,
                             set([
                                 'organization/org1',
                                 'project/project2',
                                 'vm/instance-1',
                                 'bucket/bucket2',
                                 'project/project1',
                                 'bucket/bucket1'
                                 ]))
        self.setup.run(test)

    def test_list_members(self):
        """Test list members."""

        def test(client):
            """Test implementation with API client."""
            list_members_reply = set(m.member_name for m in client.explain.list_members(''))
            self.assertEqual(list_members_reply,
                             set([
                                 'allauthenticatedusers',
                                 'group/a',
                                 'group/b',
                                 'group/c',
                                 'projecteditor/project1',
                                 'projectowner/project1',
                                 'projectviewer/project2',
                                 'user/a',
                                 'user/b',
                                 'user/c',
                                 'user/d',
                                 'user/e',
                                 'user/f',
                                 ]))
        self.setup.run(test)

    def test_list_roles(self):
        """Test list roles."""

        def test(client):
            """Test implementation with API client."""
            list_roles_reply = set(r.role_name for r in client.explain.list_roles(''))
            self.assertEqual(list_roles_reply,
                             set([
                                 'role/a',
                                 'role/b',
                                 'role/c',
                                 'role/d',
                                 'roles/editor',
                                 'roles/owner',
                                 'roles/viewer'
                                 ]))
        self.setup.run(test)

    def test_get_iam_policy(self):
        """Test get_iam_policy."""

        def test(client):
            """Test implementation with API client."""
            get_iam_policy_reply = client.explain.get_iam_policy('project/project2')
            bindings_reply = {binding.role: set(binding.members)
                              for binding in get_iam_policy_reply.bindings}
            self.assertEqual(bindings_reply,
                             {'role/a': set(['group/b']),
                              'roles/viewer': set(['user/e'])})
        self.setup.run(test)

    def test_check_policy(self):
        """Test check policy."""

        def test(client):
            """Test implementation with API client."""
            self.assertTrue(client.explain.check_iam_policy(
                'vm/instance-1',
                'permission/c',
                'user/d').result)
            self.assertTrue(client.explain.check_iam_policy(
                'vm/instance-1',
                'permission/e',
                'user/d').result)
            self.assertTrue(client.explain.check_iam_policy(
                'vm/instance-1',
                'permission/e',
                'user/a').result)
            self.assertFalse(client.explain.check_iam_policy(
                'organization/org1',
                'permission/e',
                'user/a').result)
            self.assertFalse(client.explain.check_iam_policy(
                'project/project2',
                'permission/e',
                'user/c').result)
            self.assertFalse(client.explain.check_iam_policy(
                'vm/instance-1',
                'permission/e',
                'user/c').result)
            # Transitive for projecteditor/project1
            self.assertTrue(client.explain.check_iam_policy(
                'bucket/bucket1',
                'permission/h',
                'user/b').result)
            # Transitive for projectowner/project1
            self.assertTrue(client.explain.check_iam_policy(
                'bucket/bucket1',
                'permission/i',
                'user/f').result)
            # Transitive for projectviewer/project2
            self.assertTrue(client.explain.check_iam_policy(
                'bucket/bucket2',
                'permission/h',
                'user/e').result)
            # Transitive for allauthenticatedusers
            self.assertTrue(client.explain.check_iam_policy(
                'bucket/bucket2',
                'permission/i',
                'user/unknown').result)
        self.setup.run(test)

    def test_explain_denied(self):
        """Test explain_denied."""
        def test(client):
            """Test implementation with API client."""
            response = client.explain.explain_denied(
                member_name='user/d',
                resource_names=[
                    'bucket/bucket2'],
                permission_names=['permission/f', 'permission/i'])
            self.assertTrue(response, 'Expected to get a deny explanation')

            response = client.explain.explain_denied(
                member_name='user/e',
                resource_names=[
                    'bucket/bucket2'],
                permission_names=['permission/a'])
            self.assertTrue(response, 'Expected to get a deny explanation')
        self.setup.run(test)

    def test_explain_granted(self):
        """Test explain_granted."""
        def test(client):
            """Test implementation with API client."""
            response = client.explain.explain_granted(
                member_name='user/d',
                resource_name='bucket/bucket2',
                role='role/b')
            self.assertTrue(response, 'Expected to get a grant explanation')
        self.setup.run(test)

    def test_query_access_by_resources(self):
        """Test query_access_by_resources."""
        def test(client):
            """Test implementation with API client."""
            response = client.explain.query_access_by_resources(
                resource_name='project/project2',
                permission_names=['permission/a', 'permission/c'],
                expand_groups=True)
            access_details = expand_message(response, "access_by_resource")
            self.assertEqual(access_details,set([
                'group/a project/project2 role/b',
                'group/b project/project2 role/a',
                'group/b project/project2 role/b',
                'group/c project/project2 role/a',
                'group/c project/project2 role/b',
                'user/a project/project2 role/a',
                'user/a project/project2 role/b',
                'user/b project/project2 role/b',
                'user/c project/project2 role/b',
                'user/d project/project2 role/a',
                'user/d project/project2 role/b',
                'user/f project/project2 role/a',
                'user/f project/project2 role/b',
                ]))
        self.setup.run(test)

    def test_query_access_by_resource_special_members(self):
        """Test query_access_by_resources for special member expansion."""
        def test(client):
            """Test implementation with API client."""
            response = client.explain.query_access_by_resources(
                resource_name='bucket/bucket2',
                permission_names=['permission/h'],
                expand_groups=True)
            access_details = expand_message(response,
                                            "access_by_resource")
            self.assertEqual(access_details,set([
                'projectviewer/project2 bucket/bucket2 role/c',
                'user/e bucket/bucket2 role/c',
                ]))
        self.setup.run(test)

    def test_query_access_by_members(self):
        """Test query_access_by_members."""
        def test(client):
            """Test implementation with API client."""
            response = client.explain.query_access_by_members(
                'group/a',
                ['permission/a'],
                expand_resources=True)
            access_details = expand_message(response, "access_by_member")
            self.assertEqual(access_details,set([
                'group/a bucket/bucket1 role/b',
                'group/a bucket/bucket2 role/b',
                'group/a organization/org1 role/b',
                'group/a project/project1 role/b',
                'group/a project/project2 role/b',
                'group/a vm/instance-1 role/b',
                ]))
        self.setup.run(test)

    def test_query_access_by_permissions(self):
        """Test query_access_by_permissions."""
        def test(client):
            """Test implementation with API client."""
            response = client.explain.query_access_by_permissions(
                'role/a',
                '',
                expand_groups=True,
                expand_resources=True)
            access_details = expand_message(response, "access_by_resource")
            self.assertEqual(access_details,set([
                'group/b bucket/bucket2 role/a',
                'group/b project/project2 role/a',
                'group/b vm/instance-1 role/a',
                'user/a bucket/bucket2 role/a',
                'user/a project/project2 role/a',
                'user/a vm/instance-1 role/a',
                'user/d bucket/bucket2 role/a',
                'user/d project/project2 role/a',
                'user/d vm/instance-1 role/a',
                'user/f bucket/bucket2 role/a',
                'user/f project/project2 role/a',
                'user/f vm/instance-1 role/a',
                ]))
        self.setup.run(test)

    def test_query_access_by_permissions_special_members(self):
        """Test query_access_by_permissions with special member expansion."""
        def test(client):
            """Test implementation with API client."""
            response = client.explain.query_access_by_permissions(
                'role/d',
                '',
                expand_groups=True,
                expand_resources=True)
            access_details = expand_message(response, "access_by_resource")
            self.assertEqual(access_details,set([
                'allauthenticatedusers bucket/bucket2 role/d',
                'projectowner/project1 bucket/bucket1 role/d',
                'user/a bucket/bucket1 role/d',
                'user/f bucket/bucket1 role/d',
                ]))
        self.setup.run(test)

    def test_query_role_permissions(self):
        """Test query_role_permissions."""
        def test(client):
            """Test implementation with API client."""
            response = client.explain.query_permissions_by_roles(
                role_names=['role/a', 'role/b'])
            rp_pairs = expand_message(response.permissionsbyroles,
                                      "role_permission")
            self.assertEquals(rp_pairs, set([
                'role/a permission/a',
                'role/a permission/b',
                'role/a permission/c',
                'role/a permission/d',
                'role/a permission/e',
                'role/b permission/a',
                'role/b permission/b',
                'role/b permission/c',
                ]))
        self.setup.run(test)

    def test_model_delete_empty_handle(self):
        """Verify model delete with no handle returns FAIL status."""

        def test(client):
            """Test implementation with API client."""
            response = client.model.delete_model('')
            self.assertEqual(response.status,
                             model_pb2.DeleteModelReply.FAIL)

        self.setup.run(test)

if __name__ == '__main__':
    unittest.main()
