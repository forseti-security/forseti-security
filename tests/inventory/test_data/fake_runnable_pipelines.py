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

"""Fake runnable pipelines."""

ALL_ENABLED = [
    'organizations',
    'folders',
    'projects',
    'bigquery_datasets',
    'buckets',
    'buckets_acl',
    'cloudsql',
    'firewall_rules',
    'forwarding_rules',
    'project_iam_policies',
    'groups',
    'group_members',
    'org_iam_policies',
]

ALL_DISABLED = []

ONE_RESOURCE_IS_ENABLED = [
    'organizations',
    'folders',
    'projects',
    'firewall_rules',
]

TWO_RESOURCES_ARE_ENABLED = [
    'organizations',
    'folders',
    'projects',
    'cloudsql',
    'firewall_rules',
]

THREE_RESOURCES_ARE_ENABLED_GROUP_MEMBERS = [
    'organizations',
    'folders',
    'projects',
    'cloudsql',
    'firewall_rules',
    'groups',
    'group_members',
]

THREE_RESOURCES_ARE_ENABLED_GROUPS = [
    'organizations',
    'folders',
    'projects',
    'cloudsql',
    'firewall_rules',
    'groups',
]

CORE_RESOURCES_ARE_ENABLED = [
    'organizations',
    'folders',
    'projects',
    'buckets',
    'buckets_acl',
    'firewall_rules',
    'forwarding_rules',
    'project_iam_policies',
    'groups',
    'group_members',
    'org_iam_policies',
]
