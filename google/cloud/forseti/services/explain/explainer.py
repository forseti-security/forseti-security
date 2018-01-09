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

""" Explain API. """

from google.cloud.forseti.common.util import log_util

# TODO: The next editor must remove this disable and correct issues.
# pylint: disable=missing-type-doc,missing-return-type-doc,missing-return-doc
# pylint: disable=missing-param-doc,missing-yield-doc
# pylint: disable=missing-yield-type-doc,invalid-name

LOGGER = log_util.get_logger(__name__)

class Explainer(object):
    """Implements the IAM Explain API."""

    def __init__(self, config):
        if config is None:
            LOGGER.warn("config is None")
        self.config = config

    def ExplainDenied(self, model_name, member, resources, permissions, roles):
        """Provides information on granting a member access to a resource."""

        LOGGER.debug("Explaining how to grant access to a member, "
                     "model_name = %s, member = %s, resources = %s,"
                     " permissions = %s, roles = %s",
                     model_name, member, resources, permissions, roles)
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

        LOGGER.debug("Explaining why the member has access to a resource, "
                     "model_name = %s, member = %s, resource = %s,"
                     " permission = %s, role = %s",
                     model_name, member, resource, permission, role)
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

        LOGGER.debug("Retrieving members that have access to the resource, "
                     "model_name = %s, resource_name = %s,"
                     " permission_names = %s, expand_groups = %s",
                     model_name, resource_name,
                     permission_names, expand_groups)
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

        LOGGER.debug("Retrieving access tuples that satisfy the role or"
                     " permission: model_name = %s, role_name = %s, "
                     "permission_name = %s, expand_groups = %s, "
                     "expand_resources = %s", model_name, role_name,
                     permission_name, expand_groups, expand_resources)
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

        LOGGER.debug("Retrieving access to resources for a given member, "
                     "model_name = %s, member_name = %s, "
                     "permission_names = %s, expand_resources = %s",
                     model_name, member_name,
                     permission_names, expand_resources)
        model_manager = self.config.model_manager
        scoped_session, data_access = model_manager.get(model_name)
        with scoped_session as session:
            for role, resources in data_access.query_access_by_member(
                    session, member_name, permission_names, expand_resources):
                yield role, resources

    def GetPermissionsByRoles(self, model_name, role_names, role_prefixes):
        """Returns the permissions associated with the specified roles."""

        LOGGER.debug("Retrieving the permissions associated with the "
                     "specified roles, model_name = %s, role_names = %s, "
                     "role_prefixes = %s",
                     model_name, role_names, role_prefixes)
        model_manager = self.config.model_manager
        scoped_session, data_access = model_manager.get(model_name)
        with scoped_session as session:
            for result in data_access.query_permissions_by_roles(
                    session, role_names, role_prefixes):
                yield result

    def Denormalize(self, model_name):
        """Denormalizes a model."""

        LOGGER.debug("De-normalizing a model, model_name = %s", model_name)
        model_manager = self.config.model_manager
        scoped_session, data_access = model_manager.get(model_name)
        with scoped_session as session:
            for tpl in data_access.denormalize(session):
                permission, resource, member = tpl
                yield permission, resource, member
