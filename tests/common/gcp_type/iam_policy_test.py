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

"""Test the IamPolicy."""

import unittest

from tests.unittest_utils import ForsetiTestCase
from google.cloud.forseti.common.gcp_type.errors import InvalidIamAuditConfigError
from google.cloud.forseti.common.gcp_type.errors import InvalidIamPolicyBindingError
from google.cloud.forseti.common.gcp_type.errors import InvalidIamPolicyMemberError
from google.cloud.forseti.common.gcp_type.iam_policy import IamAuditConfig
from google.cloud.forseti.common.gcp_type.iam_policy import IamPolicy
from google.cloud.forseti.common.gcp_type.iam_policy import IamPolicyBinding
from google.cloud.forseti.common.gcp_type.iam_policy import IamPolicyMember


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
            'allAuthenticatedUsers',
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

        iam_member3 = IamPolicyMember.create_from(self.members[4])
        self.assertEqual('allAuthenticatedUsers', iam_member3.type)
        self.assertIsNone(iam_member3.name)
        self.assertIsNone(iam_member3.name_pattern)

    def test_member_match_works(self):
        """Test the member match against wildcard and non-wildcard members."""
        iam_policy_members = [
            IamPolicyMember.create_from(self.members[0]), # specific user
            IamPolicyMember.create_from(self.members[3]), # allUsers
            IamPolicyMember.create_from(self.members[5]), # *@company.com
            IamPolicyMember.create_from(self.members[6]), # *@*.gserviceaccount
            IamPolicyMember.create_from(self.members[7]), # user:*
            IamPolicyMember.create_from(self.members[4]) # allAuthenticatedUsers
        ]

        self.assertTrue(iam_policy_members[0].matches(self.test_members[0]))

        # test globs/allUsers
        self.assertTrue(iam_policy_members[1].matches(self.members[3]))
        self.assertTrue(iam_policy_members[1].matches(self.test_members[3]))
        self.assertTrue(iam_policy_members[2].matches(self.test_members[0]))
        self.assertTrue(iam_policy_members[3].matches(self.test_members[1]))
        self.assertTrue(iam_policy_members[4].matches(self.test_members[2]))
        self.assertTrue(iam_policy_members[4].matches(self.test_members[5]))
        self.assertTrue(iam_policy_members[5].matches(self.test_members[4]))

        # test non matches
        self.assertFalse(iam_policy_members[0].matches(
            'user:not-user@company.com'))
        self.assertFalse(iam_policy_members[2].matches(
            'user:anyone@not.company.com'))
        self.assertFalse(iam_policy_members[2].matches(
            'user:anyone@notmycompany.com'))
        self.assertFalse(iam_policy_members[2].matches(
            'user:anyone@mycompany.com.notmycompany.com'))
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

    def test_binding_merge_members_other_type_different_raises(self):
        """Test that merging raises exception if `other`is not of same type."""
        with self.assertRaises(InvalidIamPolicyBindingError):
            binding = {
                'role': 'roles/viewer',
                'members': [
                    'user:test-user@company.com',
                    'serviceAccount:abc@def.gserviceaccount.com',
                ]
            }
            iam_binding = IamPolicyBinding.create_from(binding)
            iam_binding.merge_members([1, 2, 4])

    def test_binding_merge_members_same_role_and_members(self):
        binding = {
            'role': 'roles/viewer',
            'members': [
                'user:test-user@company.com',
                'serviceAccount:abc@def.gserviceaccount.com',
            ]
        }
        iam_binding1 = IamPolicyBinding.create_from(binding)
        iam_binding2 = IamPolicyBinding.create_from(binding)
        iam_binding1.merge_members(iam_binding2)
        self.assertEqual(iam_binding1, iam_binding2)

    def test_binding_merge_members_same_role_different_members(self):
        binding1 = {
            'role': 'roles/viewer',
            'members': [
                'user:test-user@company.com',
                'serviceAccount:abc@def.gserviceaccount.com',
            ]
        }
        binding2 = {
            'role': 'roles/viewer',
            'members': [
                'user:xxx@company.com',
            ]
        }
        expected_binding = {
            'role': 'roles/viewer',
            'members': [
                'user:test-user@company.com',
                'serviceAccount:abc@def.gserviceaccount.com',
                'user:xxx@company.com',
            ]
        }
        iam_binding1 = IamPolicyBinding.create_from(binding1)
        iam_binding2 = IamPolicyBinding.create_from(binding2)
        iam_binding1.merge_members(iam_binding2)
        expected_binding = IamPolicyBinding.create_from(expected_binding)
        self.assertEqual(expected_binding, iam_binding1)

    def test_binding_merge_members_same_role_mixed_members(self):
        binding1 = {
            'role': 'roles/viewer',
            'members': [
                'user:test-user@company.com',
                'serviceAccount:abc@def.gserviceaccount.com',
            ]
        }
        binding2 = {
            'role': 'roles/viewer',
            'members': [
                'user:xxx@company.com',
                'serviceAccount:abc@def.gserviceaccount.com',
            ]
        }
        expected_binding = {
            'role': 'roles/viewer',
            'members': [
                'user:test-user@company.com',
                'serviceAccount:abc@def.gserviceaccount.com',
                'user:xxx@company.com',
            ]
        }
        iam_binding1 = IamPolicyBinding.create_from(binding1)
        iam_binding2 = IamPolicyBinding.create_from(binding2)
        iam_binding1.merge_members(iam_binding2)
        expected_binding = IamPolicyBinding.create_from(expected_binding)
        self.assertEqual(expected_binding, iam_binding1)

    def test_binding_merge_members_different_role(self):
        """Original binding remains same if other's role is different."""
        binding1 = {
            'role': 'roles/owner',
            'members': [
                'user:test-user@company.com',
                'serviceAccount:abc@def.gserviceaccount.com',
            ]
        }
        binding2 = {
            'role': 'roles/viewer',
            'members': [
                'user:xxx@company.com',
            ]
        }
        expected_binding = {
            'role': 'roles/owner',
            'members': [
                'user:test-user@company.com',
                'serviceAccount:abc@def.gserviceaccount.com',
            ]
        }
        iam_binding1 = IamPolicyBinding.create_from(binding1)
        iam_binding2 = IamPolicyBinding.create_from(binding2)
        iam_binding1.merge_members(iam_binding2)
        expected_binding = IamPolicyBinding.create_from(expected_binding)
        self.assertEqual(expected_binding, iam_binding1)

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
        actual_audit_configs = iam_policy.audit_configs

        expected_roles = ['roles/editor', 'roles/viewer']
        expected_members = [['user:abc@company.com'],
                            ['user:def@company.com',
                             'group:xyz@somewhere.co']]

        self.assertEqual(expected_roles, actual_roles)
        self.assertEqual(expected_members, actual_members)
        self.assertIsNone(actual_audit_configs)

    def test_policy_create_from_with_audit_configs(self):
        """Test IamPolicy creation with auditConfigs."""
        policy_json = {
            'bindings': [
                {
                    'role': 'roles/editor',
                    'members': ['user:abc@company.com']
                },
            ],
            'auditConfigs': [
                {
                    'service': 'allServices',
                    'auditLogConfigs': [
                        {
                            'logType': 'ADMIN_READ',
                        }
                    ]
                },
                {
                    'service': 'storage.googleapis.com',
                    'auditLogConfigs': [
                        {
                            'logType': 'DATA_READ',
                        },
                        {
                            'logType': 'DATA_WRITE',
                            'exemptedMembers': [
                                'user:user1@org.com',
                                'user:user2@org.com'
                            ]
                        }
                    ]
                }
            ]
        }
        iam_policy = IamPolicy.create_from(policy_json)
        actual_roles = [b.role_name for b in iam_policy.bindings]
        actual_members = [_get_member_list(b.members)
                          for b in iam_policy.bindings]
        actual_audit_configs = iam_policy.audit_configs.service_configs

        expected_roles = ['roles/editor']
        expected_members = [['user:abc@company.com']]
        expected_audit_configs = {
            'allServices': {
                'ADMIN_READ': set(),
            },
            'storage.googleapis.com': {
                'DATA_READ': set(),
                'DATA_WRITE': set(['user:user1@org.com', 'user:user2@org.com']),
            },
        }

        self.assertEqual(expected_roles, actual_roles)
        self.assertEqual(expected_members, actual_members)
        self.assertEqual(expected_audit_configs, actual_audit_configs)

    def test_empty_policy_has_zero_length_bindings(self):
        """Test that an empty policy has no bindings."""
        empty_policy = IamPolicy()
        self.assertTrue(empty_policy.is_empty())
        self.assertEqual(False, bool(empty_policy.bindings))

    def test_member_create_from_domain_is_correct(self):
        member = IamPolicyMember.create_from('domain:xyz.edu')
        self.assertEqual('domain', member.type)
        self.assertEqual('xyz.edu', member.name)
        self.assertEqual('^xyz\\.edu$', member.name_pattern.pattern)

    def test_is_matching_domain_success(self):
        member = IamPolicyMember.create_from('domain:xyz.edu')
        other = IamPolicyMember.create_from('user:u@xyz.edu')
        self.assertTrue(member._is_matching_domain(other))

    def test_is_matching_domain_fail_wrong_domain(self):
        member = IamPolicyMember.create_from('domain:xyz.edu')
        other = IamPolicyMember.create_from('user:u@abc.edu')
        self.assertFalse(member._is_matching_domain(other))

    def test_is_matching_domain_fail_wrong_type(self):
        member = IamPolicyMember.create_from('group:xyz.edu')
        other = IamPolicyMember.create_from('user:u@xyz.edu')
        self.assertFalse(member._is_matching_domain(other))

    def test_is_matching_domain_fail_invalid_email(self):
        member = IamPolicyMember.create_from('domain:xyz.edu')
        other = IamPolicyMember.create_from('user:u AT xyz DOT edu')
        self.assertFalse(member._is_matching_domain(other))

    # Test IamAuditConfig
    def test_audit_config_create_from_is_correct(self):
        audit_configs_json = [
            {
                'service': 'allServices',
                'auditLogConfigs': [
                    {
                        'logType': 'DATA_READ',
                    }
                ]
            },
            {
                'service': 'storage.googleapis.com',
                'auditLogConfigs': [
                    {
                        'logType': 'DATA_READ',
                    },
                    {
                        'logType': 'DATA_WRITE',
                        'exemptedMembers': [
                            'user:user1@org.com',
                            'user:user2@org.com'
                        ]
                    }
                ]
            }
        ]
        audit_config = IamAuditConfig.create_from(audit_configs_json)
        expected_service_configs = {
            'allServices': {
                'DATA_READ': set(),
            },
            'storage.googleapis.com': {
                'DATA_READ': set(),
                'DATA_WRITE': set(['user:user1@org.com', 'user:user2@org.com']),
            },
        }
        expected_audit_config = IamAuditConfig(expected_service_configs)

        self.assertEqual(expected_service_configs, audit_config.service_configs)
        self.assertEqual(expected_audit_config, audit_config)

    def test_audit_config_create_from_bad_config(self):
        # Log configs without a service service name.
        audit_configs_json = [
            {
                'auditLogConfigs': [
                    {
                        'logType': 'DATA_READ',
                    }
                ]
            },
        ]
        with self.assertRaises(InvalidIamAuditConfigError):
            audit_config = IamAuditConfig.create_from(audit_configs_json)

    def test_audit_config_merge_succeeds(self):
        configs1 = {
            'allServices': {
                'ADMIN_READ': set(['user:user1@org.com', 'user:user2@org.com']),
                'DATA_READ': set(),
            },
            'storage.googleapis.com': {
                'DATA_READ': set(),
                'DATA_WRITE': set(['user:user1@org.com', 'user:user2@org.com']),
            },
        }
        configs2 = {
            'allServices': {
                'ADMIN_READ': set(['user:user2@org.com', 'user:user3@org.com']),
                'DATA_WRITE': set(),
            },
            'cloudsql.googleapis.com': {
                'DATA_READ': set(),
                'DATA_WRITE': set(['user:user1@org.com', 'user:user2@org.com']),
            },
        }
        expected_configs = {
            'allServices': {
                'ADMIN_READ': set([
                    'user:user1@org.com',
                    'user:user2@org.com',
                    'user:user3@org.com'
                ]),
                'DATA_READ': set(),
                'DATA_WRITE': set(),
            },
            'cloudsql.googleapis.com': {
                'DATA_READ': set(),
                'DATA_WRITE': set(['user:user1@org.com', 'user:user2@org.com']),
            },
            'storage.googleapis.com': {
                'DATA_READ': set(),
                'DATA_WRITE': set(['user:user1@org.com', 'user:user2@org.com']),
            },
        }

        audit_config1 = IamAuditConfig(configs1)
        audit_config2 = IamAuditConfig(configs2)
        expected_audit_config = IamAuditConfig(expected_configs)

        audit_config1.merge_configs(audit_config2)

        # Modify audit_config2 to make sure merge used a deep copy.
        audit_config2.service_configs['cloudsql.googleapis.com'][
            'DATA_READ'].add('user:extra_user@org.com')

        self.assertEqual(expected_audit_config, audit_config1)


if __name__ == '__main__':
    unittest.main()
