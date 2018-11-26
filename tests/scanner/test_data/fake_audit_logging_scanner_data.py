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
"""Fake Cloud Audit Logging data."""

from google.cloud.forseti.scanner.audit import audit_logging_rules_engine


# Audit logging configs are saved in IAM policies of organizations, folders and
# projects.
# Test data in the following heirarchy:
#             +-----------------------> proj_1
#             |
#             |
#     org_234 +-----> folder_56 +-----> proj_2
#             |
#             |
#             +-----------------------> proj_3 +-------> bucket_3_1
IAM_POLICY_RESOURCES = [
    # Organization 234.
    {
        'parent_type': 'organization',
        'parent_name': '234',
        'parent_full_name': 'organization/234/',
        'iam_policy': {
            'auditConfigs': [
                {
                    'service': 'allServices',
                    'auditLogConfigs': [
                        {
                            'logType': 'ADMIN_READ'
                        }
                    ]
                }
            ],
            'bindings': [
                {
                    'role': 'roles/owner',
                    'members': ['user:someone@company.com']
                }
            ],
            'etag': 'aBcDe+FgHiJ=',
        }
    },
    # Folder 56.
    {
        'parent_type': 'folder',
        'parent_name': '56',
        'parent_full_name': 'organization/234/folder/56/',
        'iam_policy': {
            'auditConfigs': [
                {
                    'service': 'allServices',
                    'auditLogConfigs': [
                        {
                            'logType': 'ADMIN_READ',
                            'exemptedMembers': [
                                'user:user1@org.com',
                                'user:user2@org.com',
                            ]
                        }
                    ]
                },
                {
                    'service': 'cloudsql.googleapis.com',
                    'auditLogConfigs': [
                        {
                            'logType': 'DATA_READ',
                        },
                        {
                            'logType': 'DATA_WRITE',
                        },
                    ]
                }
            ],
        }
    },
    # Project 1 (doesn't add any audit configs).
    {
        'parent_type': 'project',
        'parent_name': 'proj-1',
        'parent_full_name': 'organization/234/project/proj-1/',
        'iam_policy': {
            'bindings': [
                {
                    'role': 'roles/owner',
                    'members': ['user:someone_else@company.com']
                }
            ],
            'etag': 'b1234+FgHiJ=',
        }
    },
    # Project 2 (under Folder 56).
    {
        'parent_type': 'project',
        'parent_name': 'proj-2',
        'parent_full_name': 'organization/234/folder/56/project/proj-2/',
        'iam_policy': {
            'auditConfigs': [
                {
                    'service': 'allServices',
                    'auditLogConfigs': [
                        {
                            'logType': 'ADMIN_READ',
                            'exemptedMembers': [
                                'user:user2@org.com',
                                'user:user3@org.com',
                            ]
                        }
                    ]
                },
                {
                    'service': 'compute.googleapis.com',
                    'auditLogConfigs': [
                        {
                            'logType': 'DATA_READ',
                        },
                        {
                            'logType': 'DATA_WRITE',
                        },
                    ]
                }
            ],
        }
    },
    # Project 3.
    {
        'parent_type': 'project',
        'parent_name': 'proj-3',
        'parent_full_name': 'organization/234/project/proj-3/',
        'iam_policy': {
            'auditConfigs': [
                {
                    'service': 'allServices',
                    'auditLogConfigs': [
                        {
                            'logType': 'ADMIN_READ',
                        },
                        {
                            'logType': 'DATA_WRITE',
                        },
                    ]
                },
                {
                    'service': 'cloudsql.googleapis.com',
                    'auditLogConfigs': [
                        {
                            'logType': 'ADMIN_READ',
                            'exemptedMembers': [
                                'user:user1@org.com',
                            ]
                        },
                    ]
                }
            ],
        }
    },
    # Buckets have IAM policies, but no audit configs, so should be ignored.
    {
        'parent_type': 'bucket',
        'parent_name': 'bucket-3-1',
        'parent_full_name': 'organization/234/project/proj-1/bucket/bucket-3-1',
        'iam_policy': {
            'bindings': [
                {
                    'role': 'roles/editor',
                    'members': ['user:someone_else@company.com']
                }
            ],
        }
    },
]

RuleViolation = audit_logging_rules_engine.Rule.RuleViolation

AUDIT_LOGGING_VIOLATIONS = [
    RuleViolation(resource_type='project',
                  resource_id='proj-2',
                  full_name='organization/234/folder/56/project/proj-2/',
                  rule_name='Require ADMIN_READ on all services, user3 exempt.',
                  rule_index=0,
                  violation_type='AUDIT_LOGGING_VIOLATION',
                  service='allServices',
                  log_type='ADMIN_READ',
                  unexpected_exemptions=('user:user1@org.com',
                                         'user:user2@org.com'),
                  resource_data='proj-2-data',
                  resource_name='proj-2'),
    RuleViolation(resource_type='project',
                  resource_id='proj-3',
                  full_name='organization/234/project/proj-3/',
                  rule_name='Require all logs on the compute api.',
                  rule_index=1,
                  violation_type='AUDIT_LOGGING_VIOLATION',
                  service='compute.googleapis.com',
                  log_type='DATA_READ',
                  unexpected_exemptions=None,
                  resource_data='proj-3-data',
                  resource_name='proj-3'),
]

FLATTENED_AUDIT_LOGGING_VIOLATIONS = [
    {
        'resource_type': 'project',
        'resource_id': 'proj-2',
        'full_name': 'organization/234/folder/56/project/proj-2/',
        'rule_name': 'Require ADMIN_READ on all services, user3 exempt.',
        'rule_index': 0,
        'violation_type': 'AUDIT_LOGGING_VIOLATION',
        'violation_data': {
            'full_name': 'organization/234/folder/56/project/proj-2/',
            'service': 'allServices',
            'log_type': 'ADMIN_READ',
            'unexpected_exemptions': [
                'user:user1@org.com', 'user:user2@org.com']
        },
        'resource_data': 'proj-2-data',
    },
    {
        'resource_type': 'project',
        'resource_id': 'proj-3',
        'full_name': 'organization/234/project/proj-3/',
        'rule_name': 'Require all logs on the compute api.',
        'rule_index': 1,
        'violation_type': 'AUDIT_LOGGING_VIOLATION',
        'violation_data': {
            'full_name': 'organization/234/project/proj-3/',
            'service': 'compute.googleapis.com',
            'log_type': 'DATA_READ',
        },
        'resource_data': 'proj-3-data',
    }
]
