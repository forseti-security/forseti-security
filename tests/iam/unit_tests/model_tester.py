
"""Installing test models against a session."""

from collections import defaultdict
from google.cloud.security.iam.utils import logcall

class ModelCreatorClient:
    def __init__(self, session, data_access):
        self.session = session
        self.data_access = data_access
        self.playground = self
        self.explain = self

    def add_resource(self, full_res_name, res_type, parent, no_parent):
        return self.data_access.add_resource_by_name(self.session, full_res_name, parent, no_parent)

    def add_member(self, child, parents):
        return self.data_access.add_member(self.session, child, parents)

    def add_role(self, role_name, permissions):
        return self.data_access.add_role_by_name(self.session, role_name, permissions)

    def get_iam_policy(self, full_resource_name):
        policy_dict = self.data_access.get_iam_policy(self.session, full_resource_name)
        class PolicyAccessor(dict):
            def __init__(self, *args, **kwargs):
                super(PolicyAccessor, self).__init__(*args, **kwargs)
                self.policy = self
                self.bindings = self['bindings'] if 'bindings' in self else []
                self.etag = self['etag'] if 'etag' in self else None
        return PolicyAccessor(policy_dict)

    def set_iam_policy(self, full_resource_name, policy):
        return self.data_access.set_iam_policy(self.session, full_resource_name, policy)

class ModelCreator:
    def __init__(self, model, client):
        self._install_model(model, client)

    def _install_model(self, model, client):
        resource_full_name_map = self._install_resources(model['resources'], client.playground)
        self._install_memberships(model['memberships'], client.playground)
        self._install_roles(model['roles'], client.playground)
        self._install_bindings(model['bindings'], client.playground, resource_full_name_map)

    def _recursive_install_resources(self, node, model, client, parent, resource_full_name_map):
        def full_resource_name(res_name, res_type, parent):
            if parent == '':
                return '{}/{}'.format(res_type,res_name)
            return '{}/{}/{}'.format(parent, res_type, res_name)

        res_type, res_name = node.split('/', 1)
        full_res_name = full_resource_name(res_name, res_type, parent)
        client.add_resource(full_res_name, res_type, parent, parent == '')
        resource_full_name_map[node] = full_res_name

        for root, tree in model.iteritems():
            self._recursive_install_resources(root, tree, client, full_res_name, resource_full_name_map)

    def _install_resources(self, model_view, client):
        resource_full_name_map = {}
        for root, tree in model_view.iteritems():
            self._recursive_install_resources(root, tree, client, '', resource_full_name_map)
        return resource_full_name_map

    def _recursive_invert_membership(self, node, model, parentship):
        for child in model.iterkeys():
            parentship[child].add(node)
            parentship[node]
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
            raise Exception("Cyclic membership relation not supported!")

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

    def _install_bindings(self, model_view, client, resource_full_name_map):
        for resource_name, bindings in model_view.iteritems():
            full_resource_name = resource_full_name_map[resource_name]
            reply = client.get_iam_policy(full_resource_name)
            if len(reply.policy.bindings) > 0:
                raise Exception('policy should have been empty')
            client.set_iam_policy(full_resource_name, {'bindings':bindings, 'etag':reply.policy.etag})
