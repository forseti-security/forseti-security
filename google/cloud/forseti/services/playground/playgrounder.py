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

# TODO: The next editor must remove this disable and correct issues.
# pylint: disable=missing-type-doc,missing-return-type-doc,missing-return-doc
# pylint: disable=missing-param-doc
# pylint: disable=no-self-use
class Playgrounder(object):
    """Playground API implementation."""

    def __init__(self, config):
        self.config = config

    def set_iam_policy(self, model_name, resource, policy):
        """Sets the IAM policy for the resource."""

        model_manager = self.config.model_manager
        scoped_session, data_access = model_manager.get(model_name)
        with scoped_session as session:
            data_access.set_iam_policy(session, resource, policy)

    def get_iam_policy(self, model_name, resource):
        """Gets the IAM policy for the resource."""

        model_manager = self.config.model_manager
        scoped_session, data_access = model_manager.get(model_name)
        with scoped_session as session:
            return data_access.get_iam_policy(session, resource)

    def check_iam_policy(self, model_name, resource, permission, identity):
        """Checks access according to IAM policy for the resource."""

        model_manager = self.config.model_manager
        scoped_session, data_access = model_manager.get(model_name)
        with scoped_session as session:
            return data_access.check_iam_policy(
                session, resource, permission, identity)

    def add_group_member(self, model_name, member_type_name, parent_type_names):
        """Adds a member to the model."""

        model_manager = self.config.model_manager
        scoped_session, data_access = model_manager.get(model_name)
        with scoped_session as session:
            return data_access.add_group_member(
                session, member_type_name, parent_type_names, denorm=True)

    def delete_group_member(self, model_name, member_name, parent_name,
                            only_delete_relationship):
        """Deletes a member from the model."""

        model_manager = self.config.model_manager
        scoped_session, data_access = model_manager.get(model_name)
        with scoped_session as session:
            return data_access.del_group_member(
                session,
                member_name,
                parent_name,
                only_delete_relationship,
                denorm=True)

    def list_group_members(self, model_name, member_name_prefix):
        """Lists a member from the model."""

        model_manager = self.config.model_manager
        scoped_session, data_access = model_manager.get(model_name)
        with scoped_session as session:
            return data_access.list_group_members(session, member_name_prefix)

    def delete_resource(self, model_name, resource_type_name):
        """Deletes a member from the model."""

        model_manager = self.config.model_manager
        scoped_session, data_access = model_manager.get(model_name)
        with scoped_session as session:
            data_access.del_resource_by_name(session, resource_type_name)
            session.commit()

    def add_resource(self, model_name, resource_type_name, parent_type_name,
                     no_require_parent):
        """Adds a resource to the model."""

        model_manager = self.config.model_manager
        scoped_session, data_access = model_manager.get(model_name)
        with scoped_session as session:
            data_access.add_resource_by_name(
                session,
                resource_type_name,
                parent_type_name,
                no_require_parent)
            session.commit()

    def list_resources(self, model_name, full_resource_name_prefix):
        """Lists resources by resource name prefix."""

        model_manager = self.config.model_manager
        scoped_session, data_access = model_manager.get(model_name)
        with scoped_session as session:
            return data_access.list_resources_by_prefix(
                session, full_resource_name_prefix)

    def delete_role(self, model_name, role_name):
        """Deletes role from the model."""

        model_manager = self.config.model_manager
        scoped_session, data_access = model_manager.get(model_name)
        with scoped_session as session:
            data_access.del_role_by_name(session, role_name)
            session.commit()

    def add_role(self, model_name, role_name, permission_names):
        """Adds a role to the model."""

        model_manager = self.config.model_manager
        scoped_session, data_access = model_manager.get(model_name)
        with scoped_session as session:
            data_access.add_role_by_name(session, role_name, permission_names)
            session.commit()

    def list_roles(self, model_name, role_name_prefix):
        """Lists the role in the model matching the prefix."""

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
