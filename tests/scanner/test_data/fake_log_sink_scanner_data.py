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
"""Fake Log Sink scanner data."""

from google.cloud.forseti.scanner.audit import log_sink_rules_engine


# Test Log Sink resources
LOG_SINK_RESOURCES = [
    {
        'parent': 'organization/234',
        'sink_name': 'org_sink_1',
    },
    {
        'parent': 'billing_account/ABCD-1234',
        'sink_name': 'billing_sink',
    },
    {
        'parent': 'folder/56',
        'sink_name': 'folder_sink',
    },
    # No sinks for proj-1.
    {
        'parent': 'project/proj-2',
        'sink_name': 'p2_sink_1',
    },
    {
        'parent': 'project/proj-2',
        'sink_name': 'p2_sink_2',
    },
    {
        'parent': 'project/proj-3',
        'sink_name': 'p3_sink',
    },
    {
        'parent': 'organization/234',
        'sink_name': 'org_sink_2',
    },
]

# Names of parent GCP resources by type.
GCP_RESOURCES = {
    'organization': ['organization/234/'],
    'billing_account': ['organization/234/billing_account/ABCD-1234/'],
    'folder': ['organization/234/folder/56/'],
    'project': [
        'organization/234/project/proj-1/',
        'organization/234/folder/56/project/proj-2/',
        'organization/234/project/proj-3/'
    ]
}

RuleViolation = log_sink_rules_engine.Rule.RuleViolation

LOG_SINK_VIOLATIONS = [
    RuleViolation(resource_type='project',
                  resource_id='proj-2',
                  resource_name='projects/proj-2',
                  full_name='projects/proj-2',
                  rule_name='Require a PubSub sink in all projects.',
                  rule_index=0,
                  violation_type='LOG_SINK_VIOLATION',
                  sink_destination='^pubsub\\.googleapis\\.com\\/.+?$',
                  sink_filter='^$',
                  sink_include_children='*',
                  resource_data=''),
    RuleViolation(resource_type='sink',
                  resource_id='audit_logs_to_bq',
                  resource_name='folders/56/sinks/audit_logs_to_bq',
                  full_name='folders/56/sinks/audit_logs_to_bq',
                  rule_name='Disallow folder sinks.',
                  rule_index=1,
                  violation_type='LOG_SINK_VIOLATION',
                  sink_destination=('bigquery.googleapis.com/projects/'
                                    'my-audit-logs/datasets/folder_logs'),
                  sink_filter='logName:"logs/cloudaudit.googleapis.com"',
                  sink_include_children=False,
                  resource_data='__SINK_1_DATA__'),
]

FLATTENED_LOG_SINK_VIOLATIONS = [
    {
        'resource_type': 'project',
        'resource_id': 'proj-2',
        'resource_name': 'projects/proj-2',
        'full_name': 'projects/proj-2',
        'rule_name': 'Require a PubSub sink in all projects.',
        'rule_index': 0,
        'violation_type': 'LOG_SINK_VIOLATION',
        'violation_data': {
            'full_name': 'projects/proj-2',
            'sink_destination': '^pubsub\\.googleapis\\.com\\/.+?$',
            'sink_filter': '^$',
            'sink_include_children': '*',
        },
        'resource_data': '',
    },
    {
        'resource_type': 'sink',
        'resource_id': 'audit_logs_to_bq',
        'resource_name': 'folders/56/sinks/audit_logs_to_bq',
        'full_name': 'folders/56/sinks/audit_logs_to_bq',
        'rule_name': 'Disallow folder sinks.',
        'rule_index': 1,
        'violation_type': 'LOG_SINK_VIOLATION',
        'violation_data': {
            'full_name': 'folders/56/sinks/audit_logs_to_bq',
            'sink_destination': ('bigquery.googleapis.com/projects/'
                                 'my-audit-logs/datasets/folder_logs'),
            'sink_filter': 'logName:"logs/cloudaudit.googleapis.com"',
            'sink_include_children': False,
        },
        'resource_data': '__SINK_1_DATA__',
    }
]
