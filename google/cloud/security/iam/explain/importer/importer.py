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

""" Importer implementations. """

# pylint: disable=too-many-lines, unused-argument,too-many-instance-attributes,no-self-use,not-callable

from collections import defaultdict
import csv
import json
from StringIO import StringIO
from time import time
import traceback

from google.cloud.security.iam.utils import get_sql_dialect
from google.cloud.security.common.data_access import forseti
from google.cloud.security.iam.explain.importer import roles as roledef
from google.cloud.security.iam.inventory.storage import Storage as Inventory


class ResourceCache(dict):
    """Resource cache."""
    def __setitem__(self, key, value):
        """Overriding to assert the keys does not exist previously.

            Args:
                key (object): Key into the dict.
                value (object): Value to set.

            Raises:
                Exception: If the key already exists in the dict.
        """

        if key in self:
            raise Exception('Key should not exist: {}'.format(key))
        super(ResourceCache, self).__setitem__(key, value)


class MemberCache(dict):
    """Member cache."""
    pass


class RoleCache(defaultdict):
    """Role cache."""

    def __init__(self):
        super(RoleCache, self).__init__(set)


class Member(object):
    """Member object."""

    def __init__(self, member_name):
        """Construct a member object.

        Args:
            member_name (str): name of the member in 'type/name' format.
        """
        self.type, self.name = member_name.split(':', 1)

    def get_type(self):
        """Returns the member type.

        Returns:
            str: type portion of the member.
        """

        return self.type

    def get_name(self):
        """Returns the member name.

        Returns:
            str: name portion of the member.
        """

        return self.name


class Binding(dict):
    """Binding object."""

    def get_role(self):
        """Returns the role from the binding.

        Returns:
            str: role of the binding
        """

        return self['role']

    def iter_members(self):
        """Iterate over members in the binding.
        Yields:
            Member: each member which is part of the binding.
        """

        members = self['members']
        i = 0
        while i < len(members):
            yield Member(members[i])
            i += 1


class Policy(dict):
    """Policy object."""

    def __init__(self, policy):
        """Create a Policy object from a json policy.

        Args:
            policy (object): object supporting get_policy to return json
                             formatted policy binding.
        """
        super(Policy, self).__init__(json.loads(policy.get_policy()))

    def iter_bindings(self):
        """Iterate over the policy bindings.

        Yields:
            Binding: to iterate over policy bindings.
        """

        bindings = self['bindings']
        i = 0
        while i < len(bindings):
            yield Binding(bindings[i])
            i += 1


class EmptyImporter(object):
    """Imports an empty model."""

    def __init__(self, session, model, dao, _, *args, **kwargs):
        """Create an EmptyImporter which creates an empty stub model.

        Args:
            session (object): Database session.
            model (str): Model name to create.
            dao (object): Data Access Object from dao.py.
            _ (object): Unused.
            *args (list): Unused.
            **kwargs (dict): Unused.
        """

        self.session = session
        self.model = model
        self.dao = dao

    def run(self):
        """Runs the import."""

        self.session.add(self.model)
        self.model.set_done()
        self.session.commit()


class TestImporter(object):
    """Importer for testing purposes. Imports a test scenario."""

    def __init__(self, session, model, dao, _, *args, **kwargs):
        """Create a TestImporter which creates a constant defined model.

        Args:
            session (object): Database session.
            model (str): Model name to create.
            dao (object): Data Access Object from dao.py.
            _ (object): Unused.
            *args (list): Unused args.
            **kwargs (dict): Unused kwargs.
        """
        self.session = session
        self.model = model
        self.dao = dao

    def run(self):
        """Runs the import."""

        project = self.dao.add_resource(self.session, 'project')
        instance = self.dao.add_resource(self.session, 'vm1', project)
        _ = self.dao.add_resource(self.session, 'db1', project)

        permission1 = self.dao.add_permission(
            self.session, 'cloudsql.table.read')
        permission2 = self.dao.add_permission(
            self.session, 'cloudsql.table.write')

        role1 = self.dao.add_role(self.session, 'sqlreader', [permission1])
        role2 = self.dao.add_role(
            self.session, 'sqlwriter', [
                permission1, permission2])

        group1 = self.dao.add_member(self.session, 'group1', 'group')
        group2 = self.dao.add_member(self.session, 'group2', 'group', [group1])

        _ = self.dao.add_member(self.session, 'felix', 'user', [group2])
        _ = self.dao.add_member(self.session, 'fooba', 'user', [group2])

        _ = self.dao.add_binding(self.session, instance, role1, [group1])
        _ = self.dao.add_binding(self.session, project, role2, [group2])
        self.session.commit()


def load_roles():
    """Load curated roles.

    Returns:
        defaultdict(set): Map from role name to set of containing permissions.
    """
    curated_roles = defaultdict(set)

    csv_content = roledef.CURATED_ROLES_CSV
    roles = csv.reader(csv_content.splitlines(),
                       delimiter=',',
                       quotechar='"')
    for entry in roles:
        role = entry[0]
        permission = entry[1]
        curated_roles[role].add(permission)
    return curated_roles


class InventoryImporter(object):
    """Imports data from Inventory."""

    def __init__(self,
                 session,
                 model,
                 dao,
                 service_config,
                 inventory_id,
                 *args,
                 **kwargs):
        """Create a Inventory importer which creates a model from the inventory.

        Args:
            session (object): Database session.
            model (str): Model name to create.
            dao (object): Data Access Object from dao.py
            service_config (ServiceConfig): Service configuration.
            inventory_id (int): Inventory id to import from
            *args (list): Unused.
            **kwargs (dict): Unused.
        """

        self.session = session
        self.model = model
        self.dao = dao
        self.service_config = service_config
        self.inventory_id = inventory_id
        self.session.add(self.model)

        self.role_cache = {}
        self.permission_cache = {}
        self.resource_cache = ResourceCache()
        self._membership_cache = []
        self.member_cache = {}
        self.member_cache_policies = {}

    def run(self):
        """Runs the import.

        Raises:
            NotImplementedError: If the importer encounters an unknown
                                 inventory type.
        """

        gcp_type_list = [
            'organization',
            'folder',
            'project',
            'role',
            'serviceaccount'
            ]

        gsuite_type_list = [
            'gsuite_group',
            'gsuite_user',
            ]

        member_type_list = [
            'gsuite_user_member',
            'gsuite_group_member',
            ]

        autoflush = self.session.autoflush
        try:
            self.session.autoflush = False
            item_counter = 0
            last_res_type = None
            with Inventory(self.session, self.inventory_id, True) as inventory:

                for resource in inventory.iter(gcp_type_list):
                    item_counter += 1
                    last_res_type = self._store_resource(resource,
                                                         last_res_type)
                self._store_resource(None, last_res_type)
                self.session.flush()

                for resource in inventory.iter(gsuite_type_list):
                    self._store_gsuite_principal(resource)
                self.session.flush()

                self._store_gsuite_membership_pre()
                for child, parent in inventory.iter(member_type_list,
                                                    with_parent=True):
                    self._store_gsuite_membership(parent, child)
                self._store_gsuite_membership_post()

                self.dao.denorm_group_in_group(self.session)

                self._store_iam_policy_pre()
                for resource in inventory.iter(gcp_type_list,
                                               require_iam_policy=True):
                    self._store_iam_policy(resource)
                self._store_iam_policy_post()

        except Exception:  # pylint: disable=broad-except
            buf = StringIO()
            traceback.print_exc(file=buf)
            buf.seek(0)
            message = buf.read()
            self.model.set_error(message)
        else:
            self.model.set_done(item_counter)
        finally:
            self.session.commit()
            self.session.autoflush = autoflush

    def _store_gsuite_principal(self, principal):
        """Store a gsuite principal such as a group, user or member.

        Args:
            principal (object): object to store.

        Raises:
            Exception: if the principal type is unknown.
        """

        gsuite_type = principal.get_type()
        data = principal.get_data()
        if gsuite_type == 'gsuite_user':
            member = 'user:{}'.format(data['primaryEmail'])
        elif gsuite_type == 'gsuite_group':
            member = 'group:{}'.format(data['email'])
        else:
            raise Exception('Unknown gsuite principal: {}'.format(gsuite_type))
        if member not in self.member_cache:
            m_type, name = member.split(':', 1)
            self.member_cache[member] = self.dao.TBL_MEMBER(
                name=member,
                type=m_type,
                member_name=name)

    def _store_gsuite_membership_pre(self):
        """Prepare storing gsuite memberships."""

        pass

    def _store_gsuite_membership_post(self):
        """Flush storing gsuite memberships."""

        # Store all members before we flush the memberships
        self.session.add_all(self.member_cache.values())
        self.session.flush()

        # session.execute automatically flushes
        if get_sql_dialect(self.session) == 'sqlite':
            # SQLite doesn't support bulk insert
            for item in self._membership_cache:
                stmt = self.dao.TBL_MEMBERSHIP.insert(
                    dict(group_name=item[0],
                         members_name=item[1]))
                self.session.execute(stmt)
        else:
            dicts = [dict(group_name=item[0], members_name=item[1])
                     for item in self._membership_cache]
            stmt = self.dao.TBL_MEMBERSHIP.insert(dicts)
            self.session.execute(stmt)

    def _store_gsuite_membership(self, parent, child):
        """Store a gsuite principal such as a group, user or member.

        Args:
            parent (object): parent part of membership.
            child (object): member item
        """

        def member_name(child):
            """Create the type:name representation for a non-group.

            Args:
                child (object): member to create representation from.

            Returns:
                str: type:name representation of the member.
            """
            data = child.get_data()
            return '{}:{}'.format(data['type'].lower(),
                                  data['email'])

        def group_name(parent):
            """Create the type:name representation for a group.

            Args:
                parent (object): group to create representation from.

            Returns:
                str: group:name representation of the group.
            """

            data = parent.get_data()
            return 'group:{}'.format(data['email'])

        # Gsuite group members don't have to be part
        # of this domain, so we might see them for
        # the first time here.
        member = member_name(child)
        if member not in self.member_cache:
            m_type, name = member.split(':', 1)
            self.member_cache[member] = self.dao.TBL_MEMBER(
                name=member,
                type=m_type,
                member_name=name)

        self._membership_cache.append(
            (group_name(parent), member))

    def _store_iam_policy_pre(self):
        """Executed before iam policies are inserted."""

        pass

    def _store_iam_policy_post(self):
        """Executed after iam policies are inserted."""

        # Store all members which are mentioned in policies
        # that were not previously in groups or gsuite users.
        self.session.add_all(self.member_cache_policies.values())
        self.session.flush()

    def _store_iam_policy(self, resource):
        """Store the iam policy of the resource.

        Args:
            resource (object): Object whose policy to store.

        Raises:
            KeyError: if member could not be found in any cache.
        """

        policy = resource.get_iam_policy()

        # TODO: Remove this once inventory test db is updated.
        if 'bindings' not in policy:
            policy = policy['iam_policy']
        bindings = policy['bindings']
        for binding in bindings:
            role = binding['role']
            if role not in self.role_cache:
                msg = 'Role reference in iam policy not found: {}'.format(role)
                self.model.add_warning(msg)
                continue
            for member in binding['members']:

                # We still might hit external users or groups
                # that we haven't seen in gsuite.
                if member not in self.member_cache and \
                   member not in self.member_cache_policies:
                    m_type, name = member.split(':', 1)
                    self.member_cache_policies[member] = self.dao.TBL_MEMBER(
                        name=member,
                        type=m_type,
                        member_name=name)
                    self.session.add(self.member_cache_policies[member])

            # Get all the member objects to reference
            # in the binding row
            db_members = []
            for member in binding['members']:
                if member not in self.member_cache:
                    if member not in self.member_cache_policies:
                        raise KeyError(member)
                    db_members.append(self.member_cache_policies[member])
                    continue
                db_members.append(self.member_cache[member])

            self.session.add(
                self.dao.TBL_BINDING(
                    resource_type_name=self._type_name(resource),
                    role_name=role,
                    members=db_members))

    def _store_resource(self, resource, last_res_type=None):
        """Store an inventory resource in the database.

        Args:
            resource (object): Resource object to convert from.
            last_res_type (str): Previsouly processed resource type
                                 used to spot transition between types
                                 to execute pre/handler/post accordingly.

        Returns:
            str: Resource type that was processed during the execution.
        """

        handlers = {
            'organization': (None,
                             self._convert_organization,
                             None),
            'folder': (None,
                       self._convert_folder,
                       None),
            'project': (None,
                        self._convert_project,
                        None),
            'role': (self._convert_role_pre,
                     self._convert_role,
                     self._convert_role_post),
            'serviceaccount': (None,
                               self._convert_serviceaccount,
                               None),
            None: (None, None, None),
            }

        res_type = resource.get_type() if resource else None
        if res_type not in handlers:
            self.model.add_warning('No handler for type "{}"'.format(res_type))

        if res_type != last_res_type:
            post = handlers[last_res_type][-1]
            if post:
                post()

            pre = handlers[res_type][0]
            if pre:
                pre()

        handler = handlers[res_type][1]
        if handler:
            handler(resource)
            return res_type
        return None

    def _convert_serviceaccount(self, service_account):
        """Convert a service account to a database object.

        Args:
            service_account (object): Service account to store.
        """

        data = service_account.get_data()
        parent, full_res_name, type_name = self._full_resource_name(
            service_account)
        self.session.add(
            self.dao.TBL_RESOURCE(
                full_name=full_res_name,
                type_name=type_name,
                name=service_account.get_key(),
                type=service_account.get_type(),
                display_name=data.get('displayName', ''),
                email=data.get('email', ''),
                parent=parent))

    def _convert_folder(self, folder):
        """Convert a folder to a database object.

        Args:
            folder (object): Folder to store.
        """

        data = folder.get_data()
        parent, full_res_name, type_name = self._full_resource_name(folder)
        resource = self.dao.TBL_RESOURCE(
            full_name=full_res_name,
            type_name=type_name,
            name=folder.get_key(),
            type=folder.get_type(),
            display_name=data.get('displayName', ''),
            parent=parent)
        self.session.add(resource)
        self._add_to_cache(folder, resource)

    def _convert_project(self, project):
        """Convert a project to a database object.

        Args:
            project (object): Project to store.
        """

        data = project.get_data()
        parent, full_res_name, type_name = self._full_resource_name(project)

        resource = self.dao.TBL_RESOURCE(
            full_name=full_res_name,
            type_name=type_name,
            name=project.get_key(),
            type=project.get_type(),
            display_name=data.get('name', ''),
            parent=parent)
        self.session.add(resource)
        self._add_to_cache(project, resource)

    def _convert_role_pre(self):
        """Executed before roles are handled. Prepares for bulk insert."""

        pass

    def _convert_role_post(self):
        """Executed after all roles were handled. Performs bulk insert."""

        self.session.add_all(self.permission_cache.values())
        self.session.add_all(self.role_cache.values())

    def _convert_role(self, role):
        """Convert a role to a database object.

        Args:
            role (object): Role to store.
        """

        data = role.get_data()
        is_custom = not data['name'].startswith('roles/')
        db_permissions = []
        if 'includedPermissions' not in data:
            self.model.add_warning(
                'Role missing permissions: {}'.format(
                    data.get('name', '<missing name>')))
        else:
            for perm_name in data['includedPermissions']:
                if perm_name not in self.permission_cache:
                    permission = self.dao.TBL_PERMISSION(
                        name=perm_name)
                    db_permissions.append(permission)
                    self.permission_cache[perm_name] = permission

        dbrole = self.dao.TBL_ROLE(
            name=data['name'],
            title=data.get('title', ''),
            stage=data.get('stage', ''),
            description=data.get('description', ''),
            custom=is_custom,
            permissions=db_permissions)
        self.role_cache[data['name']] = dbrole

        if is_custom:
            parent, full_res_name, type_name = self._full_resource_name(role)
            self.session.add(
                self.dao.TBL_RESOURCE(
                    full_name=full_res_name,
                    type_name=type_name,
                    name=role.get_key(),
                    type=role.get_type(),
                    display_name=data.get('title'),
                    parent=parent))

    def _convert_organization(self, organization):
        """Convert an organization a database object.

        Args:
            organization (object): Organization to store.
        """

        data = organization.get_data()
        type_name = self._type_name(organization)
        org = self.dao.TBL_RESOURCE(
            full_name=type_name,
            type_name=type_name,
            name=organization.get_key(),
            type=organization.get_type(),
            display_name=data.get('displayName', ''),
            parent=None)

        self._add_to_cache(organization, org)
        self.session.add(org)

    def _add_to_cache(self, resource, dbobj):
        """Add a resource to the cache for parent lookup.

        Args:
            resource (object): Resource to put in the cache.
            dbobj (object): Database object.
        """

        type_name = self._type_name(resource)
        self.resource_cache[type_name] = (dbobj, type_name)

    def _get_parent(self, resource):
        """Return the parent object for a resource from cache.

        Args:
            resource (object): Resource whose parent to look for.

        Returns:
            tuple: cached object and full resource name
        """

        return self.resource_cache[self._parent_type_name(resource)]

    def _type_name(self, resource):
        """Return the type/name for that resource.

        Args:
            resource (object): Resource to retrieve type/name for.

        Returns:
            str: type/name representation of the resource.
        """

        return '{}/{}'.format(
            resource.get_type(),
            resource.get_key())

    def _parent_type_name(self, resource):
        """Return the type/name for a resource's parent.

        Args:
            resource (object): Resource whose parent should be returned.

        Returns:
            str: type/name representation of the resource's parent.
        """

        return '{}/{}'.format(
            resource.get_parent_type(),
            resource.get_parent_key())

    def _full_resource_name(self, resource):
        """Returns the parent object, full resource name and type name.

        Args:
            resource (object): Resource whose full resource name and parent
            should be returned.

        Returns:
            str: full resource name for the provided resource.
        """

        type_name = self._type_name(resource)
        parent, full_res_name = self._get_parent(resource)
        full_resource_name = '{}/{}'.format(
            full_res_name,
            type_name)
        return parent, full_resource_name, type_name


class ForsetiImporter(object):
    """Imports data from Forseti."""

    def __init__(self, session, model, dao, service_config, *args, **kwargs):
        """Create a ForsetiImporter which creates a model from the Forseti DB.

        Args:
            session (object): Database session.
            model (str): Model name to create.
            dao (object): Data Access Object from dao.py.
            service_config (ServiceConfig): Service configuration.
            *args (list): Unused.
            **kwargs (dict): Unused.
        """
        self.session = session
        self.model = model
        self.forseti_importer = forseti.Importer(
            service_config.forseti_connect_string)
        self.resource_cache = ResourceCache()
        self.role_cache = RoleCache()
        self.dao = dao
        self.curated_roles = load_roles()

    def _convert_organization(self, forseti_org):
        """Creates a db object from a Forseti organization.

        Args:
            forseti_org (object): Forseti DB object for an organization.

        Returns:
            object: dao Resource() table object.
        """

        org_name = 'organization/{}'.format(forseti_org.org_id)
        org = self.dao.TBL_RESOURCE(
            full_name=org_name,
            type_name=org_name,
            name=forseti_org.org_id,
            type='organization',
            parent=None)
        self.resource_cache['organization'] = (org, org_name)
        self.resource_cache[org_name] = (org, org_name)
        return org

    def _convert_folder(self, forseti_folder):
        """Creates a db object from a Forseti folder.

        Args:
            forseti_folder (object): Forseti DB object for a folder.

        Returns:
            object: dao Resource() table object.
        """

        parent_type_name = '{}/{}'.format(
            forseti_folder.parent_type,
            forseti_folder.parent_id)

        obj, full_res_name = self.resource_cache[parent_type_name]

        full_folder_name = '{}/folder/{}'.format(
            full_res_name, forseti_folder.folder_id)

        folder_type_name = 'folder/{}'.format(
            forseti_folder.folder_id)

        folder = self.dao.TBL_RESOURCE(
            full_name=full_folder_name,
            type_name=folder_type_name,
            name=forseti_folder.folder_id,
            type='folder',
            parent=obj,
            display_name=forseti_folder.display_name,
            )

        self.resource_cache[folder.type_name] = folder, full_folder_name
        return self.session.merge(folder)

    def _convert_project(self, forseti_project):
        """Creates a db object from a Forseti project.

        Args:
            forseti_project (object): Forseti DB object for a project.

        Returns:
            object: dao Resource() table object.
        """

        parent_type_name = '{}/{}'.format(
            forseti_project.parent_type,
            forseti_project.parent_id)

        obj, full_res_name = self.resource_cache[parent_type_name]
        project_name = 'project/{}'.format(forseti_project.project_number)
        full_project_name = '{}/project/{}'.format(
            full_res_name, forseti_project.project_number)
        project = self.session.merge(
            self.dao.TBL_RESOURCE(
                full_name=full_project_name,
                type_name=project_name,
                name=forseti_project.project_number,
                type='project',
                display_name=forseti_project.project_name,
                parent=obj))
        self.resource_cache[project.type_name] = (project, full_project_name)
        self.resource_cache[forseti_project.project_id] = (
            project, full_project_name)
        return project

    def _convert_bucket(self, forseti_bucket):
        """Creates a db object from a Forseti bucket.

        Args:
            forseti_bucket (object): Forseti DB object for a bucket.

        Returns:
            object: dao Resource() table object.
        """

        bucket_name = 'bucket/{}'.format(forseti_bucket.bucket_id)
        project_name = 'project/{}'.format(forseti_bucket.project_number)
        parent, full_parent_name = self.resource_cache[project_name]
        full_bucket_name = '{}/{}'.format(full_parent_name, bucket_name)
        bucket = self.session.merge(
            self.dao.TBL_RESOURCE(
                full_name=full_bucket_name,
                type_name=bucket_name,
                name=forseti_bucket.bucket_id,
                type='bucket',
                parent=parent))
        return bucket

    def _convert_instance(self, forseti_instance):
        """Creates a db object from a Forseti gce instance.

        Args:
            forseti_instance (object): Forseti DB object for a gce instance.

        Returns:
            object: dao Resource() table object.
        """

        instance_name = 'instance/{}#{}'.format(
            forseti_instance.project_id,
            forseti_instance.name)
        parent, full_parent_name = self.resource_cache[
            forseti_instance.project_id]

        full_instance_name = '{}/{}'.format(full_parent_name, instance_name)
        instance = self.session.merge(
            self.dao.TBL_RESOURCE(
                full_name=full_instance_name,
                type_name=instance_name,
                name=forseti_instance.name,
                type='instance',
                parent=parent))
        return instance

    def _convert_instance_group(self, forseti_instance_group):
        """Creates a db object from a Forseti GCE instance group.

        Args:
            forseti_instance_group (object): Forseti DB object for a gce
            instance.

        Returns:
            object: dao Resource() table object.
        """

        instance_group_name = '{}#{}'.format(
            forseti_instance_group.project_id,
            forseti_instance_group.name)
        instance_group_type_name = 'instancegroup/{}'.format(
            instance_group_name)
        parent, full_parent_name = self.resource_cache[
            forseti_instance_group.project_id]

        full_instance_name = '{}/{}'.format(
            full_parent_name, instance_group_type_name)

        instance = self.session.merge(
            self.dao.TBL_RESOURCE(
                full_name=full_instance_name,
                type_name=instance_group_type_name,
                name=instance_group_name,
                type='instancegroup',
                parent=parent))
        return instance

    def _convert_bigquery_dataset(self, forseti_bigquery_dataset):
        """Creates a db object from a Forseti Bigquery dataset.

        Args:
            forseti_bigquery_dataset (object): Forseti DB object for a gce
            instance.

        Returns:
            object: dao Resource() table object.
        """
        bigquery_dataset_name = '{}#{}'.format(
            forseti_bigquery_dataset.project_id,
            forseti_bigquery_dataset.dataset_id)
        bigquery_dataset_type_name = 'bigquerydataset/{}'.format(
            bigquery_dataset_name)
        parent, full_parent_name = self.resource_cache[
            forseti_bigquery_dataset.project_id]

        full_instance_name = '{}/{}'.format(
            full_parent_name, bigquery_dataset_type_name)

        instance = self.session.merge(
            self.dao.TBL_RESOURCE(
                full_name=full_instance_name,
                type_name=bigquery_dataset_type_name,
                name=bigquery_dataset_name,
                type='bigquerydataset',
                parent=parent))
        return instance

    def _convert_backend_service(self, forseti_backend_service):
        """Creates a db object from a Forseti backend service.

        Args:
            forseti_backend_service (object): Forseti DB object for a gce
            backend service.

        Returns:
            object: dao Resource() table object.
        """

        backend_service_name = '{}#{}'.format(
            forseti_backend_service.project_id,
            forseti_backend_service.name)
        backend_service_type_name = 'backendservice/{}'.format(
            backend_service_name)
        parent, full_parent_name = self.resource_cache[
            forseti_backend_service.project_id]

        full_instance_name = '{}/{}'.format(
            full_parent_name, forseti_backend_service)

        instance = self.session.merge(
            self.dao.TBL_RESOURCE(
                full_name=full_instance_name,
                type_name=backend_service_type_name,
                name=backend_service_name,
                type='backendservice',
                parent=parent))
        return instance

    def _convert_cloudsqlinstance(self, forseti_cloudsqlinstance):
        """Creates a db sql instance from a Forseti sql instance.

        Args:
            forseti_cloudsqlinstance (object): Forseti DB object
                                               for a sql instance.

        Returns:
            object: dao Resource() table object.
        """

        sqlinst_name = 'cloudsqlinstance/{}'.format(
            forseti_cloudsqlinstance.name)
        project_name = 'project/{}'.format(
            forseti_cloudsqlinstance.project_number)
        parent, full_parent_name = self.resource_cache[project_name]
        full_sqlinst_name = '{}/{}'.format(full_parent_name, sqlinst_name)
        sqlinst = self.session.merge(
            self.dao.TBL_RESOURCE(
                full_name=full_sqlinst_name,
                type_name=sqlinst_name,
                name=forseti_cloudsqlinstance.name,
                type='cloudsqlinstance',
                parent=parent))
        return sqlinst

    def _convert_binding(self, res_type, res_id, binding):
        """Converts a policy binding into the respective db model.

        Args:
            res_type (str): Type of the bound resource
            res_id (str): Id of the bound resource
            binding (dict): role:members dictionary
        """
        members = []
        for member in binding.iter_members():
            members.append(self.session.merge(
                self.dao.TBL_MEMBER(
                    name='{}/{}'.format(member.get_type(),
                                        member.get_name()),
                    member_name=member.get_name(),
                    type=member.get_type())))

        try:
            role = (
                self.session.query(self.dao.TBL_ROLE)
                .filter(self.dao.TBL_ROLE.name == binding.get_role())
                .one())
        except Exception:  # pylint: disable=broad-except
            try:
                permission_names = self._get_permissions_for_role(
                    binding.get_role())
            except KeyError as err:
                self.model.add_warning(str(err))
                permission_names = []

            permissions = (
                [self.session.merge(self.dao.TBL_PERMISSION(name=p))
                 for p in permission_names])
            role = self.dao.TBL_ROLE(name=binding.get_role(),
                                     permissions=permissions)
            for permission in permissions:
                self.session.add(permission)
            self.session.add(role)

        res_type_name = '{}/{}'.format(res_type, res_id)
        resource = (
            self.session.query(self.dao.TBL_RESOURCE)
            .filter(self.dao.TBL_RESOURCE.type_name == res_type_name)
            .one())
        self.session.add(
            self.dao.TBL_BINDING(resource=resource,
                                 role=role,
                                 members=members))

    def _convert_policy(self, forseti_policy):
        """Creates a db object from a Forseti policy.

        Args:
            forseti_policy (object): Forseti DB object for a policy.
        """

        res_type, res_id = forseti_policy.get_resource_reference()
        policy = Policy(forseti_policy)
        for binding in policy.iter_bindings():
            self._convert_binding(res_type, res_id, binding)

    def _convert_membership(self, forseti_membership):
        """Creates a db membership from a Forseti membership.

        Args:
            forseti_membership (object): Forseti DB object for a membership.

        Returns:
            object: dao Membership() table object.
        """

        member, groups = forseti_membership

        groups = [self.session.merge(
            self.dao.TBL_MEMBER(name='group/{}'.format(group.group_email),
                                type='group',
                                member_name=group.group_email))
                  for group in groups]

        member_type = member.member_type.lower()
        member_name = member.member_email
        return self.session.merge(self.dao.TBL_MEMBER(
            name='{}/{}'.format(member_type, member_name),
            type=member_type,
            member_name=member_name,
            parents=groups))

    def _convert_group(self, forseti_group):
        """Creates a db group from a Forseti group.

        Args:
            forseti_group (object): Forseti DB object for a group.

        Returns:
            object: dao Member() table object.
        """

        return self.session.merge(
            self.dao.TBL_MEMBER(name='group/{}'.format(forseti_group),
                                type='group',
                                member_name=forseti_group))

    def _get_permissions_for_role(self, role_type_name):
        """Returns permissions defined for that role name.
        Args:
            role_type_name (str): role name in format roles/name to get
                                  the respective permissions for.
        Returns:
            set: Set of permissions containing the role.

        Raises:
            KeyError: If the role could not be found.
        """

        role_name = role_type_name.split('/', 1)[-1]
        if role_name not in self.curated_roles:
            warning = 'Permissions for role not found: {}'.format(role_name)
            raise KeyError(warning)
        return self.curated_roles[role_name]

    def run(self):
        """Runs the import.

        Raises:
            NotImplementedError: If the importer encounters an unknown
                                 inventory type.
        """

        try:
            self.session.add(self.model)
            self.model.set_inprogress()
            self.model.kick_watchdog()
            self.session.commit()

            actions = {
                'organizations': self._convert_organization,
                'folders': self._convert_folder,
                'projects': self._convert_project,
                'buckets': self._convert_bucket,
                'cloudsqlinstances': self._convert_cloudsqlinstance,
                'group': self._convert_group,
                'membership': self._convert_membership,
                'instances': self._convert_instance,
                'instancegroups': self._convert_instance_group,
                'bigquerydatasets': self._convert_bigquery_dataset,
                'backendservices': self._convert_backend_service,
                }

            item_counter = 0
            last_watchdog_kick = time()
            for res_type, obj in self.forseti_importer:
                item_counter += 1
                if res_type in actions:
                    self.session.add(actions[res_type](obj))
                elif res_type == 'policy':
                    self._convert_policy(obj)
                elif res_type == 'customer':
                    # TODO: investigate how we
                    # don't see this in the first place
                    pass
                else:
                    raise NotImplementedError(res_type)

                # kick watchdog about every ten seconds
                if time() - last_watchdog_kick > 10.0:
                    self.model.kick_watchdog()
                    last_watchdog_kick = time()
                    self.session.commit()

            self.dao.denorm_group_in_group(self.session)

        except Exception:  # pylint: disable=broad-except
            buf = StringIO()
            traceback.print_exc(file=buf)
            buf.seek(0)
            message = buf.read()
            self.model.set_error(message)
        else:
            self.model.set_done(item_counter)
        self.session.commit()


def by_source(source):
    """Helper to resolve client provided import sources.

    Args:
        source (str): Source to import from.

    Returns:
        Importer: Chosen by source.
    """

    return {
        'TEST': TestImporter,
        'FORSETI': ForsetiImporter,
        'INVENTORY': InventoryImporter,
        'EMPTY': EmptyImporter,
    }[source.upper()]
