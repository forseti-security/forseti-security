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

""" Gcs API. """

from google.cloud.security.iam import dao

# TODO: The next editor must remove this disable and correct issues.
# pylint: disable=missing-type-doc,missing-return-type-doc,missing-return-doc
# pylint: disable=missing-param-doc,missing-yield-doc
# pylint: disable=missing-yield-type-doc


# pylint: disable=invalid-name,no-self-use
class Gcs(object):
    """Implements the Gcs Explain API."""

    def __init__(self, config):
        self.config = config

    def GetAccessByResources(self, model_name, resource_name, permission_names,
                             expand_groups):
        """Returns members who have access to the given resource."""

        model_manager = self.config.model_manager
        scoped_session, data_access = model_manager.get(model_name)
        with scoped_session as session:
            mapping = data_access.query_access_by_resource(session,
                                                           resource_name,
                                                           permission_names,
                                                           expand_groups)
            return mapping

    def GetAccessByPermissions(self, model_name, role_name, permission_name,
                               expand_groups, expand_resources):
        """Returns access tuples satisfying the permission or role.

        Args:
            model_name (str): Model to operate on.
            role_name (str): Role name to query for.
            permission_name (str): Permission name to query for.
            expand_groups (bool): Whether to expand groups in policies.
            expand_resources (bool): Whether to expand resources.

        Yields:
            Generator for access tuples.
        """

        model_manager = self.config.model_manager
        scoped_session, data_access = model_manager.get(model_name)
        with scoped_session as session:
            for role, resource, members in (
                    data_access.query_access_by_permission(session,
                                                           role_name,
                                                           permission_name,
                                                           expand_groups,
                                                           expand_resources)):
                yield role, resource, members

    def GetAccessByMembers(self, model_name, member_name, permission_names,
                           expand_resources):
        """Returns access to resources for the provided member."""

        model_manager = self.config.model_manager
        scoped_session, data_access = model_manager.get(model_name)
        with scoped_session as session:
            for role, resources in data_access.query_access_by_member(
                    session, member_name, permission_names, expand_resources):
                yield role, resources

    def Denormalize(self, model_name):
        """Denormalizes a model."""

        model_manager = self.config.model_manager
        scoped_session, data_access = model_manager.get(model_name)
        with scoped_session as session:
            for tpl in data_access.denormalize(session):
                permission, resource, member = tpl
                yield permission, resource, member


if __name__ == "__main__":
    class DummyConfig(object):
        """Dummy configuration."""

        def __init__(self):
            engine = dao.create_engine('sqlite:////tmp/test.db')
            self.model_manager = dao.ModelManager(engine)

        def run_in_background(self, function):
            """Dummy implementation."""

            function()

    e = Gcs(config=DummyConfig())
    e.CreateModel("TEST", 'test')
