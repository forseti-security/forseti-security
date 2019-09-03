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

"""Rules to use in the unit tests."""

# A whitelist for:
# * org 778899, on self and children
# * projects "my-project-1" and "my-project-2", on self
# No inheritance of rules
# Allow members of any role and pattern "user:*@company.com"
RULES1 = {
    'rules': [{
            'name': 'my rule',
            'mode': 'whitelist',
            'resource': [{
                    'type': 'organization',
                    'applies_to': 'self_and_children',
                    'resource_ids': ['778899']
                }, {
                    'type': 'project',
                    'applies_to': 'self',
                    'resource_ids': [
                        'my-project-1',
                        'my-project-2',
                    ]
                }],
            'inherit_from_parents': False,
            'bindings': [{
                    'role': 'roles/*',
                    'members': ['user:*@company.com']
                }]
        }]
}

# Whitelist, blacklist, and required list
#
# Whitelist
# * org 778899, on self and children
# * projects "my-project-1" and "my-project-2", on self
# No inheritance of rules
# "Allow members of any role and pattern `user:*@company.com`
# on these resources"
# 
# Blacklist
# * project "my-project-2", on self
# "Don't allow `user:baduser@company.com` with any roles on my-project-2"
#
# Required list
# * project "my-project-1", on self
# "Require `user:project_viewer@company.com` to have roles/viewer on
# my-project-1"
RULES2 = {
    'rules': [
        {
            'name': 'my rule',
            'mode': 'whitelist',
            'resource': [{
                    'type': 'organization',
                    'applies_to': 'self_and_children',
                    'resource_ids': ['778899']
                }, {
                    'type': 'project',
                    'applies_to': 'self',
                    'resource_ids': [
                        'my-project-1',
                        'my-project-2',
                    ]
                }],
            'inherit_from_parents': False,
            'bindings': [{
                    'role': 'roles/*',
                    'members': ['user:*@company.com']
                }]
        }, {
            'name': 'my other rule',
            'mode': 'blacklist',
            'resource': [{
                    'type': 'project',
                    'applies_to': 'self',
                    'resource_ids': ['my-project-2',]
                }],
            'inherit_from_parents': False,
            'bindings': [{
                    'role': 'roles/*',
                    'members': ['user:baduser@company.com']
                }]
        }, {
            'name': 'required rule',
            'mode': 'required',
            'resource': [{
                    'type': 'project',
                    'applies_to': 'self',
                    'resource_ids': [
                        'my-project-1',
                    ]
                }],
            'inherit_from_parents': False,
            'bindings': [{
                    'role': 'roles/viewer',
                    'members': ['user:project_viewer@company.com']
                }]
        }
    ]
}

# Same as RULES2, except:
# Blacklist
# * org 778899 on self and children
# "Block `user:baduser@company.com` from having any roles on the org"
# This is to see how the rule plays along with the whitelist rule, which
# allows user:*@company.com to have any role in the org.
RULES3 = {
    'rules': [
        {
            'name': 'my whitelist rule',
            'mode': 'whitelist',
            'resource': [{
                    'type': 'organization',
                    'applies_to': 'self_and_children',
                    'resource_ids': ['778899']
                }, {
                    'type': 'project',
                    'applies_to': 'self',
                    'resource_ids': [
                        'my-project-1',
                        'my-project-2',
                    ]
                }],
            'inherit_from_parents': False,
            'bindings': [{
                    'role': 'roles/*',
                    'members': ['user:*@company.com']
                }]
        }, {
            'name': 'my blacklist rule',
            'mode': 'blacklist',
            'resource': [{
                    'type': 'organization',
                    'applies_to': 'self_and_children',
                    'resource_ids': ['778899']
                }],
            'inherit_from_parents': False,
            'bindings': [{
                    'role': 'roles/*',
                    'members': ['user:baduser@company.com']
                }]
        }, {
            'name': 'my required rule',
            'mode': 'required',
            'resource': [{
                    'type': 'project',
                    'applies_to': 'self',
                    'resource_ids': ['my-project-1',]
                }],
            'inherit_from_parents': False,
            'bindings': [{
                    'role': 'roles/viewer',
                    'members': ['user:project_viewer@company.com']
                }]
        }
    ]
}

# Two separate whitelist rules:
# * org 778899, applies to self only
# * org 778899, applies to children only
# "Allow `user:owner@company.com` to have an owner role on the org, and
# allow `user:*@company.com` to have any role on the org's children."
RULES4 = {
    'rules': [
        {
            'name': 'org whitelist',
            'mode': 'whitelist',
            'resource': [{
                    'type': 'organization',
                    'applies_to': 'self',
                    'resource_ids': ['778899']
                }],
            'inherit_from_parents': False,
            'bindings': [{
                    'role': 'roles/owner',
                    'members': ['user:owner@company.com']
                }]
        }, {
            'name': 'project whitelist',
            'mode': 'whitelist',
            'resource': [{
                    'type': 'organization',
                    'applies_to': 'children',
                    'resource_ids': ['778899']
                }],
            'inherit_from_parents': False,
            'bindings': [{
                    'role': 'roles/*',
                    'members': ['user:*@company.com']
                }]
        },
    ]
}

# Blacklist/whitelist combination
# * org 778899 blacklist for self and children
#   "Don't allow `user:owner@company.com` to have roles/owner."
# * project my-project-1 for self
#   "Allow `user:*@company.com` to have any role in this project."
RULES5 = {
    'rules': [
        {
            'name': 'org blacklist',
            'mode': 'blacklist',
            'resource': [{
                    'type': 'organization',
                    'applies_to': 'self_and_children',
                    'resource_ids': ['778899']
                }],
            'bindings': [{
                    'role': 'roles/owner',
                    'members': ['user:owner@company.com']
                }]
        }, {
            'name': 'project whitelist',
            'mode': 'whitelist',
            'resource': [
                {
                    'type': 'project',
                    'applies_to': 'self',
                    'resource_ids': ['my-project-1']
                }],
            'inherit_from_parents': False,
            'bindings': [{
                    'role': 'roles/*',
                    'members': ['user:*@company.com']
                }]
        },
    ]
}

# Org children whitelist allows any roles/members for users @company.com
# Org children blacklist blocks owner@company.com.
RULES6 = {
    'rules': [
        {
            'name': 'org whitelist',
            'mode': 'whitelist',
            'resource': [{
                    'type': 'organization',
                    'applies_to': 'children',
                    'resource_ids': ['778899']
                }],
            'bindings': [{
                    'role': 'roles/*',
                    'members': ['user:*@company.com']
                }]
        }, {
            'name': 'project blacklist',
            'mode': 'blacklist',
            'resource': [{
                    'type': 'organization',
                    'applies_to': 'children',
                    'resource_ids': ['778899']
                }],
            'inherit_from_parents': False,
            'bindings': [{
                    'role': 'roles/owner',
                    'members': ['user:owner@company.com']
                }]
        },
    ]
}

# Org children blacklist blocks user@company.com with
# Project self whitelist allows *@company.com
RULES7 = {
    'rules': [
        {
            'name': 'org blacklist',
            'mode': 'blacklist',
            'resource': [{
                    'type': 'organization',
                    'applies_to': 'children',
                    'resource_ids': ['778899']
                }],
            'bindings': [{
                    'role': 'roles/*',
                    'members': ['user:user@company.com']
                }]
        }, {
            'name': 'project whitelist',
            'mode': 'whitelist',
            'resource': [{
                    'type': 'project',
                    'applies_to': 'self',
                    'resource_ids': ['my-project-1']
                }],
            'inherit_from_parents': False,
            'bindings': [{
                    'role': 'roles/owner',
                    'members': ['user:user@company.com']
                }]
        },
    ]
}

# A whitelist for:
# * Folder 1 (id=333)
# * projects "my-project-3"
# No inheritance of rules
# Allow members of any role and pattern "user:*@company.com"
FOLDER_RULES1 = {
    'rules': [{
            'name': 'folder rule 1',
            'mode': 'whitelist',
            'resource': [{
                    'type': 'organization',
                    'applies_to': 'self_and_children',
                    'resource_ids': ['778899']
                }, {
                    'type': 'project',
                    'applies_to': 'self',
                    'resource_ids': [
                        'my-project-3',
                    ]
                }],
            'inherit_from_parents': True,
            'bindings': [{
                    'role': 'roles/*',
                    'members': ['user:*@company.com']
                }]
        }]
}

# Simple whitelist to allow any users @ company.com to be present with
# any roles inside any organization.
RULES8 = {
    'rules': [
        {
            'name': 'org whitelist',
            'mode': 'whitelist',
            'resource': [{
                    'type': 'organization',
                    'applies_to': 'self_and_children',
                    'resource_ids': ['*']
                }],
            'bindings': [{
                    'role': 'roles/*',
                    'members': ['user:*@company.com']
                }]
        },
    ]
}

# Whitelist to allow *@company.com on all orgs and their descendents,
# plus allow my-project-1 to have *@contract-company.com.
RULES9 = {
    'rules': [
        {
            'name': 'org whitelist',
            'mode': 'whitelist',
            'resource': [{
                    'type': 'organization',
                    'applies_to': 'self_and_children',
                    'resource_ids': ['*']
                }],
            'bindings': [{
                    'role': 'roles/*',
                    'members': ['user:*@company.com']
                }]
        }, {
            'name': 'project whitelist',
            'mode': 'whitelist',
            'resource': [{
                    'type': 'project',
                    'applies_to': 'self',
                    'resource_ids': ['my-project-1']
                }],
            'inherit_from_parents': True,
            'bindings': [{
                    'role': 'roles/editor',
                    'members': ['user:*@contract-company.com']
                }]
        },
    ]
}

RULES10 = {
    'rules': [
        {
            'name': 'project required',
            'mode': 'required',
            'resource': [{
                    'type': 'project',
                    'applies_to': 'self',
                    'resource_ids': ['*']
                }],
            'inherit_from_parents': True, # this is kinda broken, keep it for now
            'bindings': [{
                    'role': 'roles/owner',
                    'members': ['user:*@company.com']
                }]
        },
    ]
}

# Requiring projects to have owners from a specific domain, for context see
# also https://github.com/GoogleCloudPlatform/forseti-security/issues/799
RULES11 = {
    'rules': [
        {
            'name': (
                'this rule uses domain in member of the IAM policy to '
                'stipulate that all owners must belong to my domain'),
            'mode': 'required',
            'resource': [{
                    'type': 'project',
                    'applies_to': 'self',
                    'resource_ids': ['*']
                }],
            'inherit_from_parents': True,
            'bindings': [{
                    'role': 'roles/owner',
                    'members': ['domain:xyz.edu']
                }]
        },
    ]
}

# Requiring projects to have owners from a specific domain, expressed as a
# wildcard user
RULES12 = {
    'rules': [
        {
            'name': (
                'this rule uses a wildcard user in member of the IAM policy '
                'to stipulate that all owners must belong to my domain'),
            'mode': 'required',
            'resource': [{
                    'type': 'project',
                    'applies_to': 'self',
                    'resource_ids': ['*']
                }],
            'inherit_from_parents': True,
            'bindings': [{
                    'role': 'roles/owner',
                    'members': ['user:*@xyz.edu']
                }]
        },
    ]
}

# Requiring buckets to have object owners from a specific domain, expressed as
# a wildcard user on bucket level
RULES13 = {
    'rules': [
        {
            'name': (
                'this rule uses a wildcard user in member of the IAM policy '
                'to stipulate that object viewers must belong to my domain'),
            'mode': 'required',
            'resource': [{
                    'type': 'bucket',
                    'applies_to': 'self',
                    'resource_ids': ['*']
                }],
            'inherit_from_parents': True,
            'bindings': [{
                    'role': 'roles/objectViewer',
                    'members': ['user:*@gcs.cloud']
                }]
        },
    ]
}

# Billing Account rules, whitelisting specific users for billing roles in the
# billing account, and blacklisting all user-level bindings for logging roles.
RULES14 = {
    'rules': [
        {
            'name': 'this rule whitelists specific users in billing roles',
            'mode': 'whitelist',
            'resource': [{
                    'type': 'billing_account',
                    'applies_to': 'self',
                    'resource_ids': ['000000-111111-222222']
                }],
            'inherit_from_parents': False,
            'bindings': [{
                    'role': 'roles/billing.*',
                    'members': [
                        'user:ceo@xyz.edu',
                        'user:cfo@xyz.edu',
                    ]
                }]
        },
        {
            'name': (
                'this rule blacklists groups in billing account logging roles'),
            'mode': 'blacklist',
            'resource': [{
                    'type': 'billing_account',
                    'applies_to': 'self',
                    'resource_ids': ['000000-111111-222222']
                }],
            'inherit_from_parents': False,
            'bindings': [{
                    'role': 'roles/logging.*',
                    'members': ['user:*'],
                }]
        },
    ]
}
