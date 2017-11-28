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

""" Importer implementations. """

# pylint: disable=unused-argument,too-many-instance-attributes
# pylint: disable=no-self-use,not-callable

from StringIO import StringIO
import traceback

from google.cloud.forseti.services.utils import get_sql_dialect
from google.cloud.forseti.services.utils import to_full_resource_name
from google.cloud.forseti.services.utils import to_type_name
from google.cloud.forseti.services.inventory.storage import Storage as Inventory


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

        self.found_root = False

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
            'serviceaccount',
            'bucket',
            'dataset',
            'compute_project',
            'instancegroup',
            'instance',
            'firewall',
            'backendservice',
            'cloudsqlinstance'
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

                for resource in inventory.iter(['organization']):
                    self.found_root = True
                if not self.found_root:
                    raise Exception(
                        'Cannot import inventory without organization root')

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
                for policy in inventory.iter(gcp_type_list,
                                             fetch_iam_policy=True):
                    self._store_iam_policy(policy)
                self._store_iam_policy_post()

        except Exception:  # pylint: disable=broad-except
            buf = StringIO()
            traceback.print_exc(file=buf)
            buf.seek(0)
            message = buf.read()
            self.model.set_error(message)
        else:
            self.model.add_warning(inventory.index.warnings)
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
            member = 'user/{}'.format(data['primaryEmail'])
        elif gsuite_type == 'gsuite_group':
            member = 'group/{}'.format(data['email'])
        else:
            raise Exception('Unknown gsuite principal: {}'.format(gsuite_type))
        if member not in self.member_cache:
            m_type, name = member.split('/', 1)
            self.member_cache[member] = self.dao.TBL_MEMBER(
                name=member,
                type=m_type,
                member_name=name)

    def _store_gsuite_membership_pre(self):
        """Prepare storing gsuite memberships."""

        pass

    def _store_gsuite_membership_post(self):
        """Flush storing gsuite memberships."""

        if not self.member_cache:
            return

        # Store all members before we flush the memberships
        self.session.add_all(self.member_cache.values())
        self.session.flush()

        # session.execute automatically flushes
        if self._membership_cache:
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
            return '{}/{}'.format(data['type'].lower(),
                                  data['email'])

        def group_name(parent):
            """Create the type:name representation for a group.

            Args:
                parent (object): group to create representation from.

            Returns:
                str: group:name representation of the group.
            """

            data = parent.get_data()
            return 'group/{}'.format(data['email'])

        # Gsuite group members don't have to be part
        # of this domain, so we might see them for
        # the first time here.
        member = member_name(child)
        if member not in self.member_cache:
            m_type, name = member.split('/', 1)
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

    def _store_iam_policy(self, policy):
        """Store the iam policy of the resource.

        Args:
            policy (object): IAM policy to store.

        Raises:
            KeyError: if member could not be found in any cache.
        """

        bindings = policy.get_data()['bindings']
        for binding in bindings:
            role = binding['role']
            if role not in self.role_cache:
                msg = 'Role reference in iam policy not found: {}'.format(role)
                self.model.add_warning(msg)
                continue
            for member in binding['members']:
                member = member.replace(':', '/', 1)

                # We still might hit external users or groups
                # that we haven't seen in gsuite.
                if member not in self.member_cache and \
                   member not in self.member_cache_policies:
                    try:
                        # This is the default case, e.g. 'group/foobar'
                        m_type, name = member.split('/', 1)
                    except ValueError:
                        # Special groups like 'allUsers' done specify a type
                        m_type, name = member, member
                    self.member_cache_policies[member] = self.dao.TBL_MEMBER(
                        name=member,
                        type=m_type,
                        member_name=name)
                    self.session.add(self.member_cache_policies[member])

            # Get all the member objects to reference
            # in the binding row
            db_members = []
            for member in binding['members']:
                member = member.replace(':', '/', 1)
                if member not in self.member_cache:
                    if member not in self.member_cache_policies:
                        raise KeyError(member)
                    db_members.append(self.member_cache_policies[member])
                    continue
                db_members.append(self.member_cache[member])

            self.session.add(
                self.dao.TBL_BINDING(
                    resource_type_name=self._type_name(policy),
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
            'bucket': (None,
                       self._convert_bucket,
                       None),
            'object': (None,
                       self._convert_object,
                       None),
            'dataset': (None,
                        self._convert_dataset,
                        None),
            'compute_project': (None,
                        self._convert_computeproject,
                        None),
            'instancegroup': (None,
                              self._convert_instancegroup,
                              None),
            'instance': (None,
                         self._convert_instance,
                         None),
            'firewall': (None,
                         self._convert_firewall,
                         None),
            'backendservice': (None,
                               self._convert_backendservice,
                               None),
            'cloudsqlinstance': (None,
                                 self._convert_cloudsqlinstance,
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

    def _convert_bucket(self, bucket):
        """Convert a bucket to a database object.

        Args:
            bucket (object): Bucket to store.
        """

        data = bucket.get_data()
        parent, full_res_name, type_name = self._full_resource_name(
            bucket)
        self.session.add(
            self.dao.TBL_RESOURCE(
                full_name=full_res_name,
                type_name=type_name,
                name=bucket.get_key(),
                type=bucket.get_type(),
                display_name=data.get('displayName', ''),
                email=data.get('email', ''),
                data=bucket.get_data_raw(),
                parent=parent))

    def _convert_object(self, gcsobject):
        """Not Implemented

        Args:
            gcsobject (object): Object to store.
        """

    def _convert_dataset(self, dataset):
        """Convert a dataset to a database object.

        Args:
            dataset (object): Dataset to store.
        """
        data = dataset.get_data()
        parent, full_res_name, type_name = self._full_resource_name(
            dataset)
        self.session.add(
            self.dao.TBL_RESOURCE(
                full_name=full_res_name,
                type_name=type_name,
                name=dataset.get_key(),
                type=dataset.get_type(),
                display_name=data.get('displayName', ''),
                email=data.get('email', ''),
                data=dataset.get_data_raw(),
                parent=parent))

    def _convert_computeproject(self, computeproject):
        """Convert a computeproject to a database object.
        Args:
            computeproject (object): computeproject to store.
        """
        data = computeproject.get_data()
        parent, full_res_name, type_name = self._full_resource_name(
            computeproject)
        self.session.add(
            self.dao.TBL_RESOURCE(
                full_name=full_res_name,
                type_name=type_name,
                name=computeproject.get_key(),
                type=computeproject.get_type(),
                display_name=data.get('displayName', ''),
                email=data.get('email', ''),
                data=computeproject.get_data_raw(),
                parent=parent))

    def _convert_instancegroup(self, instancegroup):
        """Convert a instancegroup to a database object.

        Args:
            instancegroup (object): Instancegroup to store.
        """
        data = instancegroup.get_data()
        parent, full_res_name, type_name = self._full_resource_name(
            instancegroup)
        self.session.add(
            self.dao.TBL_RESOURCE(
                full_name=full_res_name,
                type_name=type_name,
                name=instancegroup.get_key(),
                type=instancegroup.get_type(),
                display_name=data.get('displayName', ''),
                email=data.get('email', ''),
                data=instancegroup.get_data_raw(),
                parent=parent))

    def _convert_instance(self, instance):
        """Convert a instance to a database object.

        Args:
            instance (object): Instance to store.
        """
        data = instance.get_data()
        parent, full_res_name, type_name = self._full_resource_name(
            instance)
        self.session.add(
            self.dao.TBL_RESOURCE(
                full_name=full_res_name,
                type_name=type_name,
                name=instance.get_key(),
                type=instance.get_type(),
                display_name=data.get('displayName', ''),
                email=data.get('email', ''),
                data=instance.get_data_raw(),
                parent=parent))

    def _convert_firewall(self, firewall):
        """Convert a firewall to a database object.

        Args:
            firewall (object): Firewall to store.
        """
        data = firewall.get_data()
        parent, full_res_name, type_name = self._full_resource_name(
            firewall)
        self.session.add(
            self.dao.TBL_RESOURCE(
                full_name=full_res_name,
                type_name=type_name,
                name=firewall.get_key(),
                type=firewall.get_type(),
                display_name=data.get('displayName', ''),
                email=data.get('email', ''),
                data=firewall.get_data_raw(),
                parent=parent))

    def _convert_backendservice(self, backendservice):
        """Convert a backendservice to a database object.

        Args:
            backendservice (object): Backendservice to store.
        """
        data = backendservice.get_data()
        parent, full_res_name, type_name = self._full_resource_name(
            backendservice)
        self.session.add(
            self.dao.TBL_RESOURCE(
                full_name=full_res_name,
                type_name=type_name,
                name=backendservice.get_key(),
                type=backendservice.get_type(),
                display_name=data.get('displayName', ''),
                email=data.get('email', ''),
                data=backendservice.get_data_raw(),
                parent=parent))

    def _convert_cloudsqlinstance(self, cloudsqlinstance):
        """Convert a cloudsqlinstance to a database object.

        Args:
            cloudsqlinstance (object): Cloudsql to store.
        """
        data = cloudsqlinstance.get_data()
        parent, full_res_name, type_name = self._full_resource_name(
            cloudsqlinstance)
        self.session.add(
            self.dao.TBL_RESOURCE(
                full_name=full_res_name,
                type_name=type_name,
                name=cloudsqlinstance.get_key(),
                type=cloudsqlinstance.get_type(),
                display_name=data.get('displayName', ''),
                email=data.get('email', ''),
                data=cloudsqlinstance.get_data_raw(),
                parent=parent))

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
                data=service_account.get_data_raw(),
                parent=parent))

    def _convert_folder(self, folder):
        """Convert a folder to a database object.

        Args:
            folder (object): Folder to store.
        """

        data = folder.get_data()
        if self._is_root(folder):
            parent, type_name = None, self._type_name(folder)
            full_res_name = type_name
        else:
            parent, full_res_name, type_name = self._full_resource_name(
                folder)
        resource = self.dao.TBL_RESOURCE(
            full_name=full_res_name,
            type_name=type_name,
            name=folder.get_key(),
            type=folder.get_type(),
            display_name=data.get('displayName', ''),
            data=folder.get_data_raw(),
            parent=parent)
        self.session.add(resource)
        self._add_to_cache(folder, resource)

    def _convert_project(self, project):
        """Convert a project to a database object.

        Args:
            project (object): Project to store.
        """

        data = project.get_data()
        if self._is_root(project):
            parent, type_name = None, self._type_name(project)
            full_res_name = type_name
        else:
            parent, full_res_name, type_name = self._full_resource_name(
                project)
        resource = self.dao.TBL_RESOURCE(
            full_name=full_res_name,
            type_name=type_name,
            name=project.get_key(),
            type=project.get_type(),
            display_name=data.get('name', ''),
            data=project.get_data_raw(),
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
                    self.permission_cache[perm_name] = permission
                db_permissions.append(self.permission_cache[perm_name])

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
                    data=role.get_data_raw(),
                    parent=parent))

    def _convert_organization(self, organization):
        """Convert an organization a database object.

        Args:
            organization (object): Organization to store.
        """

        # Under current assumptions, organization is always root
        self.found_root = True
        data = organization.get_data()
        type_name = self._type_name(organization)
        org = self.dao.TBL_RESOURCE(
            full_name=to_full_resource_name("", type_name),
            type_name=type_name,
            name=organization.get_key(),
            type=organization.get_type(),
            display_name=data.get('displayName', ''),
            data=organization.get_data_raw(),
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
        full_res_name = dbobj.full_name
        self.resource_cache[type_name] = (dbobj, full_res_name)

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

        return to_type_name(
            resource.get_type(),
            resource.get_key())

    def _parent_type_name(self, resource):
        """Return the type/name for a resource's parent.

        Args:
            resource (object): Resource whose parent should be returned.

        Returns:
            str: type/name representation of the resource's parent.
        """

        return to_type_name(
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
        full_resource_name = to_full_resource_name(full_res_name, type_name)
        return parent, full_resource_name, type_name

    def _is_root(self, resource):
        """Checks if the resource is an inventory root. Result is cached.

        Args:
            resource (object): Resource to check.

        Returns:
            bool: Whether the resource is root or not
        """
        if not self.found_root:
            is_root = \
                resource.get_type() == resource.get_parent_type() and \
                resource.get_key() == resource.get_parent_key()
            if is_root:
                self.found_root = True
            return is_root
        return False


def by_source(source):
    """Helper to resolve client provided import sources.

    Args:
        source (str): Source to import from.

    Returns:
        Importer: Chosen by source.
    """

    return {
        'INVENTORY': InventoryImporter,
        'EMPTY': EmptyImporter,
    }[source.upper()]
