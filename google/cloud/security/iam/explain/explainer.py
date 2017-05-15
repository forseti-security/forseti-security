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

""" Explain API. """

from google.cloud.security.iam import dao
from google.cloud.security.iam.explain.importer import importer


# pylint: disable=C0103
# pylint: disable=R0201
# pylint: disable=E1101
class Explainer(object):
    """Implements the IAM Explain API."""
    def __init__(self, config):
        self.config = config

    def ExplainDenied(self, model_name, member, resources, permissions, roles):
        """Provides information on granting a member access to a resource."""
        model_manager = self.config.model_manager
        scoped_session, data_access = model_manager.get(model_name)
        with scoped_session as session:
            result = data_access.explain_denied(session,
                                                member,
                                                resources,
                                                permissions,
                                                roles)
            return result

    def ExplainGranted(self, model_name, member, resource, role, permission):
        """Provides information on why a member has access to a resource."""
        model_manager = self.config.model_manager
        scoped_session, data_access = model_manager.get(model_name)
        with scoped_session as session:
            result = data_access.explain_granted(session,
                                                 member,
                                                 resource,
                                                 role,
                                                 permission)
            return result

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

    def CreateModel(self, source):
        """Creates a model from the import source."""
        model_manager = self.config.model_manager
        model_name = model_manager.create()
        scoped_session, data_access = model_manager.get(model_name)
        with scoped_session as session:

            def doImport():
                """Import runnable."""
                importer_cls = importer.by_source(source)
                import_runner = importer_cls(
                    session, model_manager.model(model_name), data_access)
                import_runner.run()

            self.config.run_in_background(doImport)
            return model_name

    def GetAccessByMembers(self, model_name, member_name, permission_names,
                           expand_resources):
        """Returns access to resources for the provided member."""
        model_manager = self.config.model_manager
        scoped_session, data_access = model_manager.get(model_name)
        with scoped_session as session:
            for role, resources in data_access.query_access_by_member(
                    session, member_name, permission_names, expand_resources):
                yield role, resources

    def GetPermissionsByRoles(self, model_name, role_names, role_prefixes):
        """Returns the permissions associated with the specified roles."""
        model_manager = self.config.model_manager
        scoped_session, data_access = model_manager.get(model_name)
        with scoped_session as session:
            for result in data_access.query_permissions_by_roles(
                    session, role_names, role_prefixes):
                yield result

    def ListModel(self):
        """Lists all models."""
        model_manager = self.config.model_manager
        return model_manager.models()

    def DeleteModel(self, model_name):
        """Deletes a model."""
        model_manager = self.config.model_manager
        model_manager.delete(model_name)

    def Denormalize(self, model_name):
        """Denormalizes a model."""
        model_manager = self.config.model_manager
        scoped_session, data_access = model_manager.get(model_name)
        with scoped_session as session:
            for tpl in data_access.denormalize(session):
                permission, resource, member = tpl
                yield permission.name, resource.full_name, member.name


if __name__ == "__main__":
    class DummyConfig(object):
        """Dummy configuration."""
        def __init__(self):
            engine = dao.create_engine('sqlite:////tmp/test.db')
            self.model_manager = dao.ModelManager(engine)

        def run_in_background(self, function):
            """Dummy implementation."""
            function()

    e = Explainer(config=DummyConfig())
    e.CreateModel("TEST")
