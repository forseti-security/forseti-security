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

import grpc
from concurrent import futures
from collections import defaultdict

from google.cloud.forseti.services.client import ClientComposition


class ApiTestRunner(object):
    """Test runner for end-to-end API testing."""
    def __init__(self, service_config, service_factories, port=50058):
        super(ApiTestRunner, self).__init__()
        self.service_config = service_config
        self.service_factories = service_factories
        self.service_port = port

    def run(self, test_callback):
        """Test runner."""

        self.service_port += 1
        server = grpc.server(futures.ThreadPoolExecutor(1))
        server.add_insecure_port('[::]:{}'.format(self.service_port))
        for factory in self.service_factories:
            try:
                factory(self.service_config).create_and_register_service(server)
            except Exception:
                # This is a workaround for a gRPC bug
                # that triggers an assertion if the server is gc'd
                # without ever being started.
                server.start()
                server.stop(0)
                raise

        server.start()
        try:
            client = ClientComposition(
                endpoint='localhost:{}'.format(self.service_port))
            test_callback(client)
        finally:
            server.stop(0)


class ModelTestRunner(ApiTestRunner):
    """Test runner for testing on declarative models."""
    def __init__(self, model, *args, **kwargs):
        super(ModelTestRunner, self).__init__(*args, **kwargs)
        self.model = model

    def _install_model(self, model, client):
        """Installs the declarative model in the database."""
        self._install_resources(model['resources'], client.playground)
        self._install_memberships(model['memberships'], client.playground)
        self._install_roles(model['roles'], client.playground)
        self._install_bindings(model['bindings'], client.playground)

    def _recursive_install_resources(self, node, model, client, parent):
        """Install resources."""

        client.add_resource(node, parent, parent == '')
        for root, tree in model.iteritems():
            self._recursive_install_resources(root, tree, client, node)

    def _install_resources(self, model_view, client):
        """Install resources."""
        for root, tree in model_view.iteritems():
            self._recursive_install_resources(root, tree, client, '')

    def _recursive_invert_membership(self, node, model, parentship):
        """Invert declarative membership model mapping."""
        if node not in parentship:
            parentship[node] = set()
        for child in model.iterkeys():
            parentship[child].add(node)
        for root, tree in model.iteritems():
            self._recursive_invert_membership(root, tree, parentship)
        return parentship

    def _cyclic(self, graph):
        """Returns true if the graph is cyclic."""
        path = set()
        visited = set()

        def visit(vertex):
            """Visit each node."""
            if vertex in visited:
                return False
            visited.add(vertex)
            path.add(vertex)
            for neighbour in graph.get(vertex, ()):
                if neighbour in path or visit(neighbour):
                    return True
            path.remove(vertex)
            return False

        return any(visit(v) for v in graph)

    def _install_memberships(self, model_view, client):
        """Install membership relation."""
        parent_relationship = defaultdict(set)
        for root, tree in model_view.iteritems():
            self._recursive_invert_membership(root, tree, parent_relationship)

        if self._cyclic(parent_relationship):
            raise Exception("Cyclic membership relation not supported!")

        installed_members = set()
        while parent_relationship:
            for child, parents in parent_relationship.iteritems():
                if parents.issubset(installed_members):
                    installed_members.add(child)
                    client.add_member(child, list(parents))
                    parent_relationship.pop(child)
                    break

    def _install_roles(self, model_view, client):
        """Install roles."""
        for role, permissions in model_view.iteritems():
            client.add_role(role, permissions)

    def _install_bindings(self, model_view, client):
        """Install bindings."""
        for resource_name, bindings in model_view.iteritems():
            reply = client.get_iam_policy(resource_name)
            if reply.policy.bindings:
                raise Exception('policy should have been empty')
            client.set_iam_policy(
                resource_name,
                {'bindings': bindings, 'etag': reply.policy.etag})

    def _get_model_name_deterministic(self):
        """Create deterministic sequence of names for models."""
        try:
            self.counter += 1
        except AttributeError:
            self.counter = 0
        finally:
            return str(self.counter)

    def run(self, test_callback):
        def callback_wrapper(client):
            """Wrapping the client callback interface."""

            reply = client.new_model(
                source='EMPTY',
                name=self._get_model_name_deterministic())
            client.switch_model(reply.model.handle)
            self._install_model(self.model, client)
            test_callback(client)
        super(ModelTestRunner, self).run(callback_wrapper)
