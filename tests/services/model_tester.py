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
"""Installing test models against a session."""

from collections import defaultdict
from google.cloud.forseti.services import utils


class ModelCreatorClient(object):
    """Model creator client."""

    def __init__(self, session, data_access):
        self.session = session
        self.data_access = data_access
        self.explain = self

    def add_resource(self, resource_type_name, parent_type_name, no_parent):
        return self.data_access.add_resource_by_name(self.session,
                                                     resource_type_name,
                                                     parent_type_name,
                                                     no_parent)

    def add_member(self, child, parents):
        return self.data_access.add_member(self.session, child, parents)

    def add_role(self, role_name, permissions):
        return self.data_access.add_role_by_name(self.session,
                                                 role_name,
                                                 permissions)

    def get_iam_policy(self, full_resource_name):
        policy_dict = self.data_access.get_iam_policy(
            self.session, utils.full_to_type_name(full_resource_name))

        class PolicyAccessor(dict):

            def __init__(self, *args, **kwargs):
                super(PolicyAccessor, self).__init__(*args, **kwargs)
                self.policy = self
                self.bindings = self['bindings'] if 'bindings' in self else []
                self.etag = self['etag'] if 'etag' in self else None

        return PolicyAccessor(policy_dict)

    def set_iam_policy(self, full_resource_name, policy):
        return self.data_access.set_iam_policy(
            self.session, utils.full_to_type_name(full_resource_name), policy,
            update_members=True)

    def expand_special_members(self):
        self.data_access.expand_special_members(self.session)

    def commit(self):
        self.session.commit()
        self.data_access.denorm_group_in_group(self.session)
        self.session.commit()


class ModelCreator(object):
    """Model creator."""

    def __init__(self, model, client):
        self._install_model(model, client)
        client.commit()

    def _install_model(self, model, client):
        self._install_resources(model['resources'], client)
        self._install_memberships(model['memberships'], client)
        self._install_roles(model['roles'], client)
        self._install_bindings(model['bindings'], client)

    def _recursive_install_resources(self, node, model, client, parent):
        """Install resources."""

        client.add_resource(node, parent, bool(not parent))
        for root, tree in model.iteritems():
            self._recursive_install_resources(root, tree, client, node)

    def _install_resources(self, model_view, client):
        """Install resources."""
        for root, tree in model_view.iteritems():
            self._recursive_install_resources(root, tree, client, '')

    def _recursive_invert_membership(self, node, model, parentship):
        if node not in parentship:
            parentship[node] = set()
        for child in model.iterkeys():
            parentship[child].add(node)
        for root, tree in model.iteritems():
            self._recursive_invert_membership(root, tree, parentship)
        return parentship

    def _cyclic(self, g):
        path = set()
        visited = set()

        def visit(vertex):
            if vertex in visited:
                return False
            visited.add(vertex)
            path.add(vertex)
            for neighbour in g.get(vertex, ()):
                if neighbour in path or visit(neighbour):
                    return True
            path.remove(vertex)
            return False

        return any(visit(v) for v in g)

    def _install_memberships(self, model_view, client):
        parent_relationship = defaultdict(set)
        for root, tree in model_view.iteritems():
            self._recursive_invert_membership(root, tree, parent_relationship)

        if self._cyclic(parent_relationship):
            raise Exception('Cyclic membership relation not supported!')

        installed_members = set()
        while len(parent_relationship) > 0:
            for child, parents in parent_relationship.iteritems():
                if parents.issubset(installed_members):
                    break

            installed_members.add(child)
            client.add_member(child, list(parents))
            parent_relationship.pop(child)

    def _install_roles(self, model_view, client):
        for role, permissions in model_view.iteritems():
            client.add_role(role, permissions)

    def _install_bindings(self, model_view, client):
        for resource_name, bindings in model_view.iteritems():
            reply = client.get_iam_policy(resource_name)
            if len(reply.policy.bindings) > 0:
                raise Exception('policy should have been empty')
            client.set_iam_policy(resource_name,
                                  {'bindings': bindings,
                                   'etag': reply.policy.etag})
        client.expand_special_members()
