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
"""Helper functions for handling IAM policies."""
# pylint: disable=too-many-locals

from google.cloud.forseti.common.util import logger

LOGGER = logger.get_logger(__name__)


def _split_member(member):
    """Splits an IAM member into type and optional value.

    Args:
        member (str): The IAM member to split.

    Returns:
        tuple: The member type and optionally member value.
    """
    # 'allUsers' and 'allAuthenticatedUsers' member do not contain ':' so they
    # need to be handled seperately.
    if ':' in member:
        return member.split(':', 1)
    return (member, None)


def convert_iam_to_bigquery_policy(iam_policy):
    """Converts an IAM policy to a bigquery Access Policy.

    The is used for backwards compatibility between data returned from live
    API and the data stored in CAI. Once the live API returns IAM policies
    instead, this can be deprecated.

    Args:
        iam_policy (dict): The BigQuery dataset IAM policy.

    Returns:
        list: A list of access policies.

        An example return value:

            [
                {'role': 'WRITER', 'specialGroup': 'projectWriters'},
                {'role': 'OWNER', 'specialGroup': 'projectOwners'},
                {'role': 'OWNER', 'userByEmail': 'user@domain.com'},
                {'role': 'READER', 'specialGroup': 'projectReaders'}
            ]
    """
    # Map of iam policy roles to bigquery access policy roles.
    iam_to_access_policy_role_map = {
        'roles/bigquery.dataEditor': 'WRITER',
        'roles/bigquery.dataOwner': 'OWNER',
        'roles/bigquery.dataViewer': 'READER'
    }
    # Map iam policy member type to bigquery access policy member type.
    # The value of the map is a tuple of access policy member type and access
    # policy member value pairs. If the member value is None, then the value
    # from the IAM policy binding is used.
    iam_to_access_policy_member_map = {
        'allAuthenticatedUsers': ('specialGroup', 'allAuthenticatedUsers'),
        'projectEditor': ('specialGroup', 'projectWriters'),
        'projectOwner': ('specialGroup', 'projectOwners'),
        'projectViewer': ('specialGroup', 'projectReaders'),
        'domain': ('domain', None),
        'group': ('groupByEmail', None),
        'user': ('userByEmail', None),
    }

    access_policies = []
    for binding in iam_policy.get('bindings', []):
        if binding.get('role', '') in iam_to_access_policy_role_map:
            role = iam_to_access_policy_role_map[binding['role']]
            for member in binding.get('members', []):
                member_type, member_value = _split_member(member)
                if member_type in iam_to_access_policy_member_map:
                    new_type, new_value = (
                        iam_to_access_policy_member_map[member_type])
                    if not new_value:
                        new_value = member_value
                    access_policies.append({'role': role, new_type: new_value})
    return access_policies


def convert_iam_to_bucket_acls(iam_policy, bucket, project_id, project_number):
    """Converts an IAM policy to Bucket Access Controls.

    The is used for backwards compatibility between data returned from live
    API and the data stored in CAI. Once acls are removed from cloud storage,
    this can be deprecated.

    Args:
        iam_policy (dict): The Storage Bucket IAM policy.
        bucket (str): The Storage Bucket name.
        project_id (str): The project id for the project the bucket is under.
        project_number (str): The project number for the project the bucket is
            under.

    Returns:
        list: A list of access policies.

        An example return value:

        [
          {
            "bucket": "my-bucket",
            "id": "my-bucket/project-owners-12345",
            "entity": "project-owners-12345",
            "projectTeam": {"projectNumber": "12345", "team": "owners"},
            "role": "OWNER"
          },
          {
            "bucket": "my-bucket",
            "id": "my-bucket/project-editors-12345",
            "entity": "project-editors-12345",
            "projectTeam": {"projectNumber": "12345", "team": "editors"},
            "role": "OWNER"
          },
          {
            "bucket": "my-bucket",
            "id": "my-bucket/project-viewers-12345",
            "entity": "project-viewers-12345",
            "projectTeam": {"projectNumber": "12345", "team": "viewers"},
            "role": "READER"
          },
          {
            "bucket": "my-bucket",
            "id": "my-bucket/domain-forseti.test",
            "domain": "forseti.test",
            "entity": "domain-forseti.test",
            "role": "READER"
          },
          {
            "bucket": "my-bucket",
            "id": "my-bucket/group-my-group@forseti.test",
            "email": "my-group@forseti.test",
            "entity": "group-my-group@forseti.test",
            "role": "WRITER"
          },
          {
            "bucket": "my-bucket",
            "id": "my-bucket/user-12345-compute@developer.gserviceaccount.com",
            "email": "12345-compute@developer.gserviceaccount.com",
            "entity": "user-12345-compute@developer.gserviceaccount.com",
            "role": "WRITER"
          },
          {
            "bucket": "my-bucket",
            "id": "my-bucket/allAuthenticatedUsers",
            "entity": "allAuthenticatedUsers",
            "role": "READER"
          },
          {
            "bucket": "my-bucket",
            "id": "my-bucket/allUsers",
            "entity": "allUsers",
            "role": "READER"
          }
        ]
    """
    # Map of iam policy roles to bucket access control roles.
    iam_to_access_policy_role_map = {
        'roles/storage.legacyBucketOwner': 'OWNER',
        'roles/storage.legacyBucketReader': 'READER',
        'roles/storage.legacyBucketWriter': 'WRITER',
    }
    # Map iam policy member type to bucket access control entity type.
    iam_to_entity_member_type_map = {
        'allAuthenticatedUsers': ('allAuthenticatedUsers', None),
        'allUsers': ('allUsers', None),
        'domain': ('domain', None),
        'group': ('group', None),
        'projectEditor': ('project-editors', 'editors'),
        'projectOwner': ('project-owners', 'owners'),
        'projectViewer': ('project-viewers', 'viewers'),
        'serviceAccount': ('user', None),
        'user': ('user', None),
    }

    access_policies = {}
    for binding in iam_policy.get('bindings', []):
        if binding.get('role', '') not in iam_to_access_policy_role_map:
            continue

        role = iam_to_access_policy_role_map[binding['role']]
        for member in binding.get('members', []):
            acl = {'bucket': bucket, 'role': role}
            member_type, member_value = _split_member(member)

            if member_type not in iam_to_entity_member_type_map:
                LOGGER.warn('unparsable member in binding: %s', member)
                continue

            (entity, team) = iam_to_entity_member_type_map[member_type]
            if team:
                if member_value == project_id:
                    member_value = project_number
                acl['entity'] = '-'.join([entity, member_value])
                acl['projectTeam'] = {'projectNumber': member_value,
                                      'team': team}
            else:
                if member_value:
                    entity = '-'.join([entity, member_value])
                    if '@' in member_value:
                        acl['email'] = member_value
                acl['entity'] = entity

            acl['id'] = '/'.join([bucket, acl['entity']])
            if acl['id'] in access_policies:
                other_acl = access_policies[acl['id']]
                # If existing acl is equal or higher permission,
                # then it takes precedence.
                if (other_acl['role'] == 'OWNER' or
                        (other_acl['role'] == 'WRITER' and role != 'OWNER') or
                        (other_acl['role'] == 'READER' and role == 'READER')):
                    continue

            access_policies[acl['id']] = acl

    return access_policies.values()
