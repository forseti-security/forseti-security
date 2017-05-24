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

"""Test the IamPolicy."""

from tests.unittest_utils import ForsetiTestCase
from google.cloud.security.common.gcp_type.errors import InvalidIamPolicyError
from google.cloud.security.common.gcp_type.errors import InvalidIamPolicyBindingError
from google.cloud.security.common.gcp_type.errors import InvalidIamPolicyMemberError
from google.cloud.security.common.gcp_type.iam_policy import IamPolicy
from google.cloud.security.common.gcp_type.iam_policy import IamPolicyBinding
from google.cloud.security.common.gcp_type.iam_policy import IamPolicyMember


def _get_member_list(members):
    return [':'.join(filter((lambda x: x is not None),
                            [member.type, member.name]))
            for member in members]


class IamPolicyTest(ForsetiTestCase):
    """Test IAM Policy class."""

    def setUp(self):
        self.members = [
            'user:test-user@company.com',
            'group:test-group@googlegroups.com',
            'serviceAccount:test-sa@sub.gserviceaccount.com',
            'allUsers',
            'allAuthenticatedUsers',
            'user:*@company.com',
            'serviceAccount:*@*.gserviceaccount.com',
            'user:*'
        ]

        self.test_members = [
            'user:test-user@company.com',
            'serviceAccount:abc@def.gserviceaccount.com',
            'user:someone@somewhere.tld',
            'allUsers',
            'user:anything'
        ]

    # Test IamPolicyMember
    def test_member_create_from_is_correct(self):
        """Test that IamPolicyMember creation is correct."""
        iam_member1 = IamPolicyMember.create_from(self.members[0])
        self.assertEqual('user', iam_member1.type)
        self.assertEqual('test-user@company.com', iam_member1.name)
        self.assertEqual('^test\-user\@company\.com$',
                         iam_member1.name_pattern.pattern)

        iam_member2 = IamPolicyMember.create_from(self.members[3])
        self.assertEqual('allUsers', iam_member2.type)
        self.assertIsNone(iam_member2.name)
        self.assertIsNone(iam_member2.name_pattern)

    def test_member_match_works(self):
        """Test the member match against wildcard and non-wildcard members."""
        iam_policy_members = [
            IamPolicyMember.create_from(self.members[0]), # specific user
            IamPolicyMember.create_from(self.members[3]), # allUsers
            IamPolicyMember.create_from(self.members[5]), # *@company.com
            IamPolicyMember.create_from(self.members[6]), # *@*.gserviceaccount
            IamPolicyMember.create_from(self.members[7]), # user:*
        ]

        self.assertTrue(iam_policy_members[0].matches(self.test_members[0]))

        # test globs/allUsers
        self.assertTrue(iam_policy_members[1].matches(self.members[1]))
        self.assertTrue(iam_policy_members[1].matches(self.test_members[3]))
        self.assertTrue(iam_policy_members[2].matches(self.test_members[0]))
        self.assertTrue(iam_policy_members[3].matches(self.test_members[1]))
        self.assertTrue(iam_policy_members[4].matches(self.test_members[2]))
        self.assertTrue(iam_policy_members[4].matches(self.test_members[4]))

        # test non matches
        self.assertFalse(iam_policy_members[0].matches(
            'user:not-user@company.com'))
        self.assertFalse(iam_policy_members[2].matches(
            'user:anyone@not.company.com'))
        self.assertFalse(iam_policy_members[3].matches(
            'serviceAccount:someone@gserviceaccount.com'))
        self.assertFalse(iam_policy_members[3].matches(
            'serviceAccount:someone@.gserviceaccount.com'))


    def test_member_invalid_type_raises(self):
        """Test that invalid member type raises exception."""
        with self.assertRaises(InvalidIamPolicyMemberError):
            iam_member = IamPolicyMember('fake_type')

    # Test IamPolicyBinding
    def test_binding_create_from_is_correct(self):
        """Test that the IamPolicyBinding create is correct."""
        # test role, members, role name pattern
        binding = {
            'role': 'roles/viewer',
            'members': self.test_members
        }
        iam_binding = IamPolicyBinding.create_from(binding)
        self.assertEqual(binding['role'], iam_binding.role_name)
        self.assertEqual(binding['members'],
                         _get_member_list(iam_binding.members))
        self.assertEqual('^roles\/viewer$', iam_binding.role_pattern.pattern)

        # test roles glob
        binding2 = {
            'role': 'roles/*',
            'members': self.test_members
        }
        iam_binding2 = IamPolicyBinding.create_from(binding2)
        self.assertEqual('^roles\/.+$', iam_binding2.role_pattern.pattern)

    def test_binding_missing_role_raises(self):
        """Test that a binding with no role raises an exception."""
        with self.assertRaises(InvalidIamPolicyBindingError):
            IamPolicyBinding(None, ['*'])

    def test_binding_missing_members_raises(self):
        """Test that a binding with no members raises an exception."""
        with self.assertRaises(InvalidIamPolicyBindingError):
            IamPolicyBinding('roles/fake', [])

    # Test IamPolicy
    def test_policy_create_from_is_correct(self):
        """Test IamPolicy creation."""
        policy_json = {
            'bindings': [
                {
                    'role': 'roles/editor',
                    'members': ['user:abc@company.com']
                },

                {
                    'role': 'roles/viewer',
                    'members': ['user:def@company.com',
                                'group:xyz@somewhere.co']
                },
            ]
        }
        iam_policy = IamPolicy.create_from(policy_json)
        actual_roles = [b.role_name for b in iam_policy.bindings]
        actual_members = [_get_member_list(b.members)
                          for b in iam_policy.bindings]

        expected_roles = ['roles/editor', 'roles/viewer']
        expected_members = [['user:abc@company.com'],
                            ['user:def@company.com',
                             'group:xyz@somewhere.co']]

        self.assertEqual(expected_roles, actual_roles)
        self.assertEqual(expected_members, actual_members)

    def test_empty_policy_has_zero_length_bindings(self):
        """Test that an empty policy has no bindings."""
        empty_policy = IamPolicy()
        self.assertTrue(empty_policy.is_empty())
        self.assertEqual(0, len(empty_policy.bindings))


if __name__ == '__main__':
    unittest.main()
