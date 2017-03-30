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

"""Transform data from one format to another."""

import json

from dateutil import parser

from google.cloud.security.common.util import log_util

LOGGER = log_util.get_logger(__name__)

MYSQL_DATETIME_FORMAT = '%Y-%m-%d %H:%M:%S'


def flatten_groups(groups):
    """Yield an iterator of flattened groups.

    Args:
        groups: An iterable of Admin SDK Directory API Groups.
        https://google-api-client-libraries.appspot.com/documentation/admin/directory_v1/python/latest/admin_directory_v1.groups.html#list

    Yields:
        An iterable of flattened groups as a per-group dictionary.
    """
    # Currently there is nothing to flatten.
    for group in groups:
        yield {'group_id': group.get('id'),
               'group_email': group.get('email')}

def flatten_projects(projects):
    """Yield an iterator of flattened projects.

    Args:
        projects: An iterable of resource manager project list response.
        https://cloud.google.com/resource-manager/reference/rest/v1/projects/list#response-body

    Yields:
        An iterable of flattened projects as a per-project dictionary.
    """
    for project in (project for d in projects \
                    for project in d.get('projects', [])):
        project_json = json.dumps(project)
        try:
            formatted_project_create_time = \
                parser.parse(project.get('createTime'))\
                    .strftime(MYSQL_DATETIME_FORMAT)
        except (TypeError, ValueError) as e:
            LOGGER.error('Unable to parse create_time from project: %s\n%s',
                         project.get('createTime', ''), e)
            formatted_project_create_time = '0000-00-00 00:00:00'

        yield {'project_number': project.get('projectNumber'),
               'project_id': project.get('projectId'),
               'project_name': project.get('name'),
               'lifecycle_state': project.get('lifecycleState'),
               'parent_type': project.get('parent', {}).get('type'),
               'parent_id': project.get('parent', {}).get('id'),
               'raw_project': project_json,
               'create_time': formatted_project_create_time}

def _parse_member_info(member):
    """Parse out the component info in the member string.

    Args:
        member: String of a member.  Example: user:foo@bar.com

    Returns:
        member_type: String of the member type.
        member_name: String of the name portion of the member.
        member_domain: String of the domain of the member.
    """
    member_type, email = member.split(":", 1)

    if '@' in email:
        member_name, member_domain = email.split('@', 1)
    else:
        # member is really something like domain:google.com
        member_name = ''
        member_domain = email

    return member_type, member_name, member_domain

def flatten_iam_policies(iam_policies_map):
    """Yield an iterator of flattened iam policies.

    Args:
        iam_policies_map: An iterable of iam policies as per-resource dict.
            Example: {'project_number': 11111,
                      'iam_policy': policy}
            https://cloud.google.com/resource-manager/reference/rest/Shared.Types/Policy

    Yields:
        An iterable of flattened iam policies, as a per-resource dict.
    """
    for iam_policy_map in iam_policies_map:
        iam_policy = iam_policy_map['iam_policy']
        bindings = iam_policy.get('bindings', [])
        for binding in bindings:
            members = binding.get('members', [])
            for member in members:
                member_type, member_name, member_domain = (
                    _parse_member_info(member))
                role = binding.get('role', '')
                if role.startswith('roles/'):
                    role = role.replace('roles/', '')
                if iam_policy_map.get('project_number'):
                    yield {'project_number': iam_policy_map['project_number'],
                           'role': role,
                           'member_type': member_type,
                           'member_name': member_name,
                           'member_domain': member_domain}
                else:
                    yield {'org_id': iam_policy_map['org_id'],
                           'role': role,
                           'member_type': member_type,
                           'member_name': member_name,
                           'member_domain': member_domain}
