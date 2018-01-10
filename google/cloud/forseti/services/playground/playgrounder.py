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

""" Playground API. """

from google.cloud.forseti.common.util import log_util

# TODO: The next editor must remove this disable and correct issues.
# pylint: disable=missing-type-doc,missing-return-type-doc,missing-return-doc
# pylint: disable=missing-param-doc

LOGGER = log_util.get_logger(__name__)

# pylint: disable=invalid-name,no-self-use
class Playgrounder(object):
    """Playground API implementation."""

    def __init__(self, config):
        self.config = config

    def SetIamPolicy(self, model_name, resource, policy):
        """Sets the IAM policy for the resource."""

        LOGGER.info("Setting IAM policy, resource = %s, policy = %s,"
                    " model_name = %s", resource, policy, model_name)
        model_manager = self.config.model_manager
        scoped_session, data_access = model_manager.get(model_name)
        with scoped_session as session:
            data_access.set_iam_policy(session, resource, policy)

    def GetIamPolicy(self, model_name, resource):
        """Gets the IAM policy for the resource."""

        LOGGER.debug("Retrieving IAM policy, model_name = %s, resource = %s",
                     model_name, resource)
        model_manager = self.config.model_manager
        scoped_session, data_access = model_manager.get(model_name)
        with scoped_session as session:
            return data_access.get_iam_policy(session, resource)

    def CheckIamPolicy(self, model_name, resource, permission, identity):
        """Checks access according to IAM policy for the resource."""

        LOGGER.debug("Checking IAM policy, model_name = %s, resource = %s,"
                     " permission = %s, identity = %s",
                     model_name, resource, permission, identity)
        model_manager = self.config.model_manager
        scoped_session, data_access = model_manager.get(model_name)
        with scoped_session as session:
            return data_access.check_iam_policy(
                session, resource, permission, identity)

    def AddGroupMember(self, model_name, member_type_name, parent_type_names):
        """Adds a member to the model."""

        LOGGER.info("Adding group member to model, model_name = %s,"
                    " member_type_name = %s, parent_type_names = %s",
                    model_name, member_type_name, parent_type_names)
        model_manager = self.config.model_manager
        scoped_session, data_access = model_manager.get(model_name)
        with scoped_session as session:
            return data_access.add_group_member(
                session, member_type_name, parent_type_names, denorm=True)

    def DelGroupMember(self, model_name, member_name, parent_name,
                       only_delete_relationship):
        """Deletes a member from the model."""

        LOGGER.info("Deleting group member from model, member_name = %s,"
                    " model_name = %s, parent_name = %s",
                    member_name, model_name, parent_name)
        model_manager = self.config.model_manager
        scoped_session, data_access = model_manager.get(model_name)
        with scoped_session as session:
            return data_access.del_group_member(
                session,
                member_name,
                parent_name,
                only_delete_relationship,
                denorm=True)

    def ListGroupMembers(self, model_name, member_name_prefix):
        """Lists a member from the model."""

        LOGGER.debug("Listing Group members, model_name = %s, "
                     "member_name_prefix = %s", model_name, member_name_prefix)
        model_manager = self.config.model_manager
        scoped_session, data_access = model_manager.get(model_name)
        with scoped_session as session:
            return data_access.list_group_members(session, member_name_prefix)

    def DelResource(self, model_name, resource_type_name):
        """Deletes a resource from the model."""

        LOGGER.info("Deleting resource from model, resource_type_name = %s, "
                    "model_name = %s", resource_type_name, model_name)
        model_manager = self.config.model_manager
        scoped_session, data_access = model_manager.get(model_name)
        LOGGER.debug("model_manager = %s, scoped_session = %s",
                     model_manager, scoped_session)
        with scoped_session as session:
            data_access.del_resource_by_name(session, resource_type_name)
            session.commit()

    def AddResource(self, model_name,
                    resource_type_name,
                    parent_type_name,
                    no_require_parent):
        """Adds a resource to the model."""

        LOGGER.info("Adding resource to model, resource_type_name = %s, "
                    "model_name = %s, parent_type_name = %s, "
                    "no_require_parent = %s", resource_type_name,
                    model_name, parent_type_name, no_require_parent)
        model_manager = self.config.model_manager
        scoped_session, data_access = model_manager.get(model_name)
        with scoped_session as session:
            data_access.add_resource_by_name(
                session,
                resource_type_name,
                parent_type_name,
                no_require_parent)
            session.commit()

    def ListResources(self, model_name, full_resource_name_prefix):
        """Lists resources by resource name prefix."""

        LOGGER.debug("Listing resources, model_name = %s,"
                     " full_resource_name_prefix = %s",
                     model_name, full_resource_name_prefix)
        model_manager = self.config.model_manager
        scoped_session, data_access = model_manager.get(model_name)
        with scoped_session as session:
            return data_access.list_resources_by_prefix(
                session, full_resource_name_prefix)

    def DelRole(self, model_name, role_name):
        """Deletes role from the model."""

        LOGGER.info("Deleting role from model, model_name = %s,"
                    " role_name = %s", model_name, role_name)
        model_manager = self.config.model_manager
        scoped_session, data_access = model_manager.get(model_name)
        with scoped_session as session:
            data_access.del_role_by_name(session, role_name)
            session.commit()

    def AddRole(self, model_name, role_name, permission_names):
        """Adds a role to the model."""

        LOGGER.info("Adding role to model, model_name = %s, "
                    "role_name = %s, permission_names = %s",
                    model_name, role_name, permission_names)
        model_manager = self.config.model_manager
        scoped_session, data_access = model_manager.get(model_name)
        with scoped_session as session:
            data_access.add_role_by_name(session, role_name, permission_names)
            session.commit()

    def ListRoles(self, model_name, role_name_prefix):
        """Lists the role in the model matching the prefix."""

        LOGGER.info("Listing roles, model_name = %s,"
                    " role_name_prefix = %s", model_name, role_name_prefix)
        model_manager = self.config.model_manager
        scoped_session, data_access = model_manager.get(model_name)
        with scoped_session as session:
            return data_access.list_roles_by_prefix(session, role_name_prefix)


if __name__ == "__main__":
    class DummyConfig(object):
        """Dummy configuration for testing."""

        def run_in_background(self, function):
            """Dummy implementation."""

            function()

    e = Playgrounder(config=DummyConfig())
