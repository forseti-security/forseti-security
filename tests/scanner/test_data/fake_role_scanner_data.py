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
"""Fake Role scanner data."""

from builtins import object
import json
import collections


from google.cloud.forseti.common.gcp_type import role
from google.cloud.forseti.common.gcp_type import organization
from google.cloud.forseti.common.gcp_type import project
from google.cloud.forseti.scanner.audit import role_rules_engine as rre

ORGANIZATION = organization.Organization(
    '123456',
    display_name='Default Organization',
    full_name='organization/123456/',
    data='fake_org_data_123456',
)

PROJECT1 = project.Project(
    'def-project-1',
    project_number=11223344,
    display_name='default project 1',
    parent=ORGANIZATION,
    full_name='organization/123456/project/def-project-1/',
    data='fake_project_data_11223344',
)

PROJECT2 = project.Project(
    'def-project-2',
    project_number=55667788,
    display_name='default project 2',
    parent=ORGANIZATION,
    full_name='organization/123456/project/def-project-2/',
    data='fake_project_data_55667788',
)

PROJECT3 = project.Project(
    'def-project-3',
    project_number=12344321,
    display_name='default project 3',
    parent=ORGANIZATION,
    full_name='organization/123456/project/def-project-3/',
    data='fake_project_data_12344321',
)

class FakeRoleDataCreater(object):
    def __init__(self, name, permissions, parent):
        self._name = '%ss/%s/roles/%s'%(parent.type, parent.id, name)
        self.SetPermissions(permissions)
        self._parent = parent

    def SetPermissions(self, permissions):
        self._permissions = permissions

    def get_resource(self):
        data_dict = {'name': self._name, 'includedPermissions': self._permissions}

        data = json.dumps(data_dict)
        return role.Role(role_id=self._name,
                         parent=self._parent,
                         data=data)


FakeRoleDataInput = collections.namedtuple(
    'FakeRoleDataInput', ['name', 'permission', 'parent'])


def get_fake_role_resource(fake_role_data_input):
    """Create a fake Role object for test cases

    Args:
        fake_role_data_input (FakeRoleDataInput): arguments of the role.

    Returns:
        Role: A new Role.
    """
    data_creater = FakeRoleDataCreater(
        fake_role_data_input.name, fake_role_data_input.permission, fake_role_data_input.parent)

    return data_creater.get_resource()

def generate_violation(role, index, name):
    """Generate a violation.

    Args:
        role (Role): The role that triggers the violation.
    Returns:
        RuleViolation: The violation.
    """
    permissions = role.get_permissions()
    permissions_str = json.dumps(permissions)

    return rre.RuleViolation(
        resource_name=role.name,
        resource_id=role.id,
        resource_type=role.type,
        full_name=role.full_name,
        rule_name=name,
        rule_index=index,
        violation_type=rre.VIOLATION_TYPE,
        violation_data=permissions_str,
        resource_data=role.data,
    )
