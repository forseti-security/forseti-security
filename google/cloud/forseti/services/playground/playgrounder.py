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

import json

from google.cloud.forseti.common.util import logger

LOGGER = logger.get_logger(__name__)

# pylint: disable=no-self-use
class Playgrounder(object):
    """Playground API implementation."""

    def __init__(self, config):
        """Initialize

        Args:
            config (object): ServiceConfig in server
        """
        self.config = config

    def set_iam_policy(self, model_name, resource, policy):
        """Sets the IAM policy for the resource.

        Args:
            model_name (str): model handle to delete role
            resource (str): the resource the policy applies
            policy (json): the policy to set
        """

        LOGGER.info('Setting IAM policy, resource = %s, policy = %s,'
                    ' model_name = %s', resource, policy, model_name)
        model_manager = self.config.model_manager
        scoped_session, data_access = model_manager.get(model_name)
        with scoped_session as session:
            model_manager.add_description(model_name, json.dumps({
                'pristine':False
                }), session)
            data_access.set_iam_policy(session, resource, policy)

    def add_group_member(self, model_name, member_type_name, parent_type_names):
        """Adds a member to the model.

        Args:
            model_name (str): model handle to delete role
            member_type_name (str): member to add
            parent_type_names (list): parents of the member
        """

        LOGGER.info('Adding group member to model, model_name = %s,'
                    ' member_type_name = %s, parent_type_names = %s',
                    model_name, member_type_name, parent_type_names)
        model_manager = self.config.model_manager
        scoped_session, data_access = model_manager.get(model_name)
        with scoped_session as session:
            model_manager.add_description(model_name, json.dumps({
                'pristine':False
                }), session)
            data_access.add_group_member(
                session, member_type_name, parent_type_names, denorm=True)

    def delete_group_member(self, model_name, member_name, parent_name,
                            only_delete_relationship):
        """Deletes a member from the model.

        Args:
            model_name (str): model handle to delete role
            member_name (str): member to delete
            parent_name (str): parent of the relation to delete
            only_delete_relationship (bool): if only delete relationship
        """

        LOGGER.info('Deleting group member from model, member_name = %s,'
                    ' model_name = %s, parent_name = %s',
                    member_name, model_name, parent_name)
        model_manager = self.config.model_manager
        scoped_session, data_access = model_manager.get(model_name)
        with scoped_session as session:
            model_manager.add_description(
                model_name,
                json.dumps({'pristine':False}),
                session
            )
            return data_access.delete_group_member(
                session,
                member_name,
                parent_name,
                only_delete_relationship)

    def delete_role(self, model_name, role_name):
        """Deletes role from the model.

        Args:
            model_name (str): model handle to delete role
            role_name (str): name of the role to delete
        """

        LOGGER.info('Deleting role from model, model_name = %s,'
                    ' role_name = %s', model_name, role_name)
        model_manager = self.config.model_manager
        scoped_session, data_access = model_manager.get(model_name)
        with scoped_session as session:
            model_manager.add_description(model_name, json.dumps({
                'pristine':False
                }), session)
            data_access.delete_role_by_name(session, role_name)
            session.commit()

    def add_role(self, model_name, role_name, permission_names):
        """Adds a role to the model.

        Args:
            model_name (str): model handle to add the role
            role_name (str): name of the role to add
            permission_names (list): list of permissions to be added to the role
        """

        LOGGER.info('Adding role to model, model_name = %s, '
                    'role_name = %s, permission_names = %s',
                    model_name, role_name, permission_names)
        model_manager = self.config.model_manager
        scoped_session, data_access = model_manager.get(model_name)
        with scoped_session as session:
            model_manager.add_description(model_name, json.dumps({
                'pristine':False
                }), session)
            data_access.add_role_by_name(session, role_name, permission_names)
            session.commit()


if __name__ == '__main__':
    class DummyConfig(object):
        """Dummy configuration for testing."""

        def run_in_background(self, function):
            """Dummy implementation.

            Args:
                function (func): function to run in background
            """

            function()

    e = Playgrounder(config=DummyConfig())
