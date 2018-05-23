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
# pylint: disable=no-self-use,not-callable,too-many-lines

from StringIO import StringIO
import traceback
import json

from google.cloud.forseti.common.util import logger
from google.cloud.forseti.services.utils import get_resource_id_from_type_name
from google.cloud.forseti.services.utils import get_sql_dialect
from google.cloud.forseti.services.utils import to_full_resource_name
from google.cloud.forseti.services.utils import to_type_name
from google.cloud.forseti.services.inventory.storage import Storage as Inventory


LOGGER = logger.get_logger(__name__)


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

    def __init__(self, session, readonly_session,
                 model, dao, _, *args, **kwargs):
        """Create an EmptyImporter which creates an empty stub model.

        Args:
            session (object): Database session.
            readonly_session (Session): Database session (read-only).
            model (str): Model name to create.
            dao (object): Data Access Object from dao.py.
            _ (object): Unused.
            *args (list): Unused.
            **kwargs (dict): Unused.
        """

        self.session = session
        self.readonly_session = readonly_session
        self.model = model
        self.dao = dao

    def run(self):
        """Runs the import."""

        self.session.add(self.model)
        self.model.add_description(
            json.dumps(
                {'source': 'empty', 'pristine': True}
            )
        )
        self.model.set_done()
        self.session.commit()


class InventoryImporter(object):
    """Imports data from Inventory."""

    def __init__(self,
                 session,
                 readonly_session,
                 model,
                 dao,
                 service_config,
                 inventory_index_id,
                 *args,
                 **kwargs):
        """Create a Inventory importer which creates a model from the inventory.

        Args:
            session (Session): Database session.
            readonly_session (Session): Database session (read-only).
            model (Model): Model object.
            dao (object): Data Access Object from dao.py
            service_config (ServiceConfig): Service configuration.
            inventory_index_id (int64): Inventory id to import from
            *args (list): Unused.
            **kwargs (dict): Unused.
        """

        self.readonly_session = readonly_session
        self.session = session
        self.model = model
        self.dao = dao
        self.service_config = service_config
        self.inventory_index_id = inventory_index_id
        self.session.add(self.model)

        self.role_cache = {}
        self.permission_cache = {}
        self.resource_cache = ResourceCache()
        self.membership_items = []
        self.membership_map = {} # Maps group_name to {member_name}
        self.member_cache = {}
        self.member_cache_policies = {}

        self.found_root = False

    # pylint: disable=too-many-statements
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
            'appengine_app',
            'appengine_service',
            'appengine_version',
            'appengine_instance',
            'serviceaccount',
            'serviceaccount_key',
            'bucket',
            'dataset',
            'compute_project',
            'image',
            'instancegroup',
            'instancegroupmanager',
            'instancetemplate',
            'instance',
            'firewall',
            'backendservice',
            'forwardingrule',
            'network',
            'subnetwork',
            'cloudsqlinstance',
            'kubernetes_cluster',
        ]

        gsuite_type_list = [
            'gsuite_group',
            'gsuite_user',
        ]

        member_type_list = [
            'gsuite_user_member',
            'gsuite_group_member',
        ]

        autocommit = self.session.autocommit
        autoflush = self.session.autoflush
        try:
            self.session.autocommit = False
            self.session.autoflush = True
            with Inventory(self.readonly_session, self.inventory_index_id,
                           True) as inventory:
                root = inventory.get_root()
                description = {
                    'source': 'inventory',
                    'source_info': {
                        'inventory_index_id': inventory.inventory_index.id},
                    'source_root': self._type_name(root),
                    'pristine': True,
                    'gsuite_enabled': inventory.type_exists(
                        ['gsuite_group', 'gsuite_user'])
                }
                LOGGER.debug('Model description: %s', description)
                self.model.add_description(json.dumps(description))

                if root.get_resource_type() in ['organization']:
                    LOGGER.debug('Root resource is organization: %s', root)
                    self.found_root = True
                if not self.found_root:
                    LOGGER.debug('Root resource is not organization: %s.', root)
                    raise Exception(
                        'Cannot import inventory without organization root')

                last_res_type = None
                item_counter = 0
                LOGGER.debug('Start storing resources into models.')
                for resource in inventory.iter(gcp_type_list):
                    item_counter += 1
                    last_res_type = self._store_resource(resource,
                                                         last_res_type)
                    if not item_counter % 1000:
                        # Flush database every 1000 resources
                        LOGGER.debug('Flushing model write session: %s',
                                     item_counter)
                        self.session.flush()

                self._store_resource(None, last_res_type)
                if item_counter % 1000:
                    # Additional rows added since last flush.
                    self.session.flush()
                LOGGER.debug('Finished storing resources into models.')

                item_counter += self.model_action_wrapper(
                    self.session,
                    inventory.iter(gcp_type_list,
                                   fetch_dataset_policy=True),
                    None,
                    self._convert_dataset_policy,
                    None,
                    1000
                )

                item_counter += self.model_action_wrapper(
                    self.session,
                    inventory.iter(gcp_type_list,
                                   fetch_service_config=True),
                    None,
                    self._convert_service_config,
                    None,
                    1000
                )

                self.model_action_wrapper(
                    self.session,
                    inventory.iter(gsuite_type_list),
                    None,
                    self._store_gsuite_principal,
                    None,
                    1000
                )

                self.model_action_wrapper(
                    self.session,
                    inventory.iter(gcp_type_list, fetch_enabled_apis=True),
                    None,
                    self._convert_enabled_apis,
                    None,
                    1000
                )

                self.model_action_wrapper(
                    self.session,
                    inventory.iter(member_type_list, with_parent=True),
                    self._store_gsuite_membership_pre,
                    self._store_gsuite_membership,
                    self._store_gsuite_membership_post,
                    1000
                )

                self.dao.denorm_group_in_group(self.session)

                self.model_action_wrapper(
                    self.session,
                    inventory.iter(gcp_type_list,
                                   fetch_iam_policy=True),
                    self._store_iam_policy_pre,
                    self._store_iam_policy,
                    self._store_iam_policy_post,
                    1000
                )
        except Exception:  # pylint: disable=broad-except
            buf = StringIO()
            traceback.print_exc(file=buf)
            buf.seek(0)
            message = buf.read()
            LOGGER.debug('Importer has an exception: %s', message)
            self.model.set_error(message)
        else:
            LOGGER.debug('Set model status.')
            self.model.add_warning(
                inventory.inventory_index.inventory_index_warnings)
            self.model.set_done(item_counter)
        finally:
            LOGGER.debug('Finished running importer.')
            self.session.commit()
            self.session.autocommit = autocommit
            self.session.autoflush = autoflush
    # pylint: enable=too-many-statements

    @staticmethod
    def model_action_wrapper(session,
                             inventory_iterable,
                             pre_action,
                             action,
                             post_action,
                             flush_count):
        """Model action wrapper. This is used to reduce code duplication.

        Args:
            session (Session): Database session.
            inventory_iterable (Iterable): Inventory iterable.
            pre_action (func): Action taken before iterating the
                inventory list.
            action (func): Action taken during the iteration of
                the inventory list.
            post_action (func): Action taken after iterating the
                inventory list.
            flush_count (int): Flush every flush_count times.

        Returns:
            int: Number of item iterated.
        """
        LOGGER.debug('Performing model action: %s', action)
        if pre_action:
            pre_action()

        idx = 0
        for idx, inventory_data in enumerate(inventory_iterable, start=1):
            if isinstance(inventory_data, tuple):
                action(*inventory_data)
            else:
                action(inventory_data)

            if not idx % flush_count:
                # Flush database every flush_count resources
                LOGGER.debug('Flushing write session: %s.', idx)
                session.flush()

        if post_action:
            post_action()

        if idx % flush_count:
            # Additional rows added since last flush.
            session.flush()

        return idx

    def _store_gsuite_principal(self, principal):
        """Store a gsuite principal such as a group, user or member.

        Args:
            principal (object): object to store.

        Raises:
            Exception: if the principal type is unknown.
        """

        gsuite_type = principal.get_resource_type()
        data = principal.get_resource_data()
        if gsuite_type == 'gsuite_user':
            member = 'user/{}'.format(data['primaryEmail'].lower())
        elif gsuite_type == 'gsuite_group':
            member = 'group/{}'.format(data['email'].lower())
        else:
            raise Exception('Unknown gsuite principal: {}'.format(gsuite_type))

        if member not in self.member_cache:
            m_type, name = member.split('/', 1)
            self.member_cache[member] = self.dao.TBL_MEMBER(
                name=member,
                type=m_type,
                member_name=name)
            self.session.add(self.member_cache[member])

    def _store_gsuite_membership_pre(self):
        """Prepare storing gsuite memberships."""

        pass

    def _store_gsuite_membership_post(self):
        """Flush storing gsuite memberships."""

        if not self.member_cache:
            return

        self.session.flush()

        # session.execute automatically flushes
        if self.membership_items:
            if get_sql_dialect(self.session) == 'sqlite':
                # SQLite doesn't support bulk insert
                for item in self.membership_items:
                    stmt = self.dao.TBL_MEMBERSHIP.insert(item)
                    self.session.execute(stmt)
            else:
                stmt = self.dao.TBL_MEMBERSHIP.insert(
                    self.membership_items)
                self.session.execute(stmt)

    def _store_gsuite_membership(self, child, parent):
        """Store a gsuite principal such as a group, user or member.

        Args:
            child (object): member item.
            parent (object): parent part of membership.
        """

        def member_name(child):
            """Create the type:name representation for a non-group.

            Args:
                child (object): member to create representation from.

            Returns:
                str: type:name representation of the member.
            """

            data = child.get_resource_data()
            return '{}/{}'.format(data['type'].lower(),
                                  data['email'].lower())

        def group_name(parent):
            """Create the type:name representation for a group.

            Args:
                parent (object): group to create representation from.

            Returns:
                str: group:name representation of the group.
            """

            data = parent.get_resource_data()
            return 'group/{}'.format(data['email'].lower())

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
            self.session.add(self.member_cache[member])

        parent_group = group_name(parent)

        if parent_group not in self.membership_map:
            self.membership_map[parent_group] = set()

        if member not in self.membership_map[parent_group]:
            self.membership_map[parent_group].add(member)
            self.membership_items.append(
                dict(group_name=group_name(parent), members_name=member))

    def _store_iam_policy_pre(self):
        """Executed before iam policies are inserted."""

        pass

    def _store_iam_policy_post(self):
        """Executed after iam policies are inserted."""

        # Store all members which are mentioned in policies
        # that were not previously in groups or gsuite users.
        self.session.flush()

    def _store_iam_policy(self, policy):
        """Store the iam policy of the resource.

        Args:
            policy (object): IAM policy to store.

        Raises:
            KeyError: if member could not be found in any cache.
        """

        bindings = policy.get_resource_data().get('bindings', [])
        policy_type_name = self._type_name(policy)
        for binding in bindings:
            role = binding['role']
            if role not in self.role_cache:
                msg = 'Role reference in iam policy not found: {}'.format(role)
                self.model.add_warning(msg)
                continue

            # binding['members'] can have duplicate ids
            members = set(binding['members'])
            db_members = set()
            for member in members:
                member = member.replace(':', '/', 1).lower()

                # We still might hit external users or groups
                # that we haven't seen in gsuite.
                if member in self.member_cache and member not in db_members:
                    db_members.add(self.member_cache[member])
                    continue

                if (member not in self.member_cache and
                        member not in self.member_cache_policies):
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
                db_members.add(self.member_cache_policies[member])

            binding_object = self.dao.TBL_BINDING(
                resource_type_name=policy_type_name,
                role_name=role,
                members=list(db_members))
            self.session.add(binding_object)
        self._convert_iam_policy(policy)

    def _store_resource(self, resource, last_res_type=None):
        """Store an inventory resource in the database.

        Args:
            resource (object): Resource object to convert from.
            last_res_type (str): Previously processed resource type used to
                spot transition between types to execute pre/handler/post
                accordingly.

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
            'appengine_app': (None,
                              self._convert_appengine_resource,
                              None),
            'appengine_service': (None,
                                  self._convert_appengine_resource,
                                  None),
            'appengine_version': (None,
                                  self._convert_appengine_resource,
                                  None),
            'appengine_instance': (None,
                                   self._convert_appengine_resource,
                                   None),
            'serviceaccount': (None,
                               self._convert_serviceaccount,
                               None),
            'serviceaccount_key': (None,
                                   self._convert_serviceaccount_key,
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
            'image': (None,
                      self._convert_image,
                      None),
            'instancegroup': (None,
                              self._convert_instancegroup,
                              None),
            'instancegroupmanager': (None,
                                     self._convert_instancegroupmanager,
                                     None),
            'instancetemplate': (None,
                                 self._convert_instancetemplate,
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
            'forwardingrule': (None,
                               self._convert_forwardingrule,
                               None),
            'network': (None,
                        self._convert_network,
                        None),
            'subnetwork': (None,
                           self._convert_subnetwork,
                           None),
            'cloudsqlinstance': (None,
                                 self._convert_cloudsqlinstance,
                                 None),
            'kubernetes_cluster': (None,
                                   self._convert_kubernetes_cluster,
                                   None),
            None: (None, None, None),
        }

        res_type = resource.get_resource_type() if resource else None
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

    def _convert_object(self, gcsobject):
        """Not Implemented

        Args:
            gcsobject (object): Object to store.
        """

    def _convert_appengine_resource(self, gae_resource):
        """Convert an AppEngine resource to a database object.

        Args:
            gae_resource (dict): An appengine resource to store.
        """
        data = gae_resource.get_resource_data()
        parent, full_res_name, type_name = self._full_resource_name(
            gae_resource)
        resource = self.dao.TBL_RESOURCE(
            full_name=full_res_name,
            type_name=type_name,
            name=gae_resource.get_resource_id(),
            type=gae_resource.get_resource_type(),
            display_name=data.get('name', ''),
            data=gae_resource.get_resource_data_raw(),
            parent=parent)

        self.session.add(resource)
        self._add_to_cache(resource, gae_resource.id)

    def _convert_bucket(self, bucket):
        """Convert a bucket to a database object.

        Args:
            bucket (object): Bucket to store.
        """
        data = bucket.get_resource_data()
        parent, full_res_name, type_name = self._full_resource_name(
            bucket)
        resource = self.dao.TBL_RESOURCE(
            full_name=full_res_name,
            type_name=type_name,
            name=bucket.get_resource_id(),
            type=bucket.get_resource_type(),
            display_name=data.get('displayName', ''),
            email=data.get('email', ''),
            data=bucket.get_resource_data_raw(),
            parent=parent)

        self.session.add(resource)
        self._add_to_cache(resource, bucket.id)

    def _convert_kubernetes_cluster(self, cluster):
        """Convert an AppEngine resource to a database object.

        Args:
            cluster (dict): A Kubernetes cluster resource to store.
        """
        data = cluster.get_resource_data()
        parent, full_res_name, type_name = self._full_resource_name(
            cluster)
        resource = self.dao.TBL_RESOURCE(
            full_name=full_res_name,
            type_name=type_name,
            name=cluster.get_resource_id(),
            type=cluster.get_resource_type(),
            display_name=data.get('name', ''),
            data=cluster.get_resource_data_raw(),
            parent=parent)

        self.session.add(resource)
        self._add_to_cache(resource, cluster.id)

    def _convert_service_config(self, service_config):
        """Convert Kubernetes Service Config to a database object.

        Args:
            service_config (dict): A Service Config resource to store.
        """
        parent, full_res_name = self._get_parent(service_config)
        sc_type_name = to_type_name(
            service_config.get_category(),
            parent.type_name)
        sc_res_name = to_full_resource_name(full_res_name, sc_type_name)
        resource = self.dao.TBL_RESOURCE(
            full_name=sc_res_name,
            type_name=sc_type_name,
            name=service_config.get_resource_id(),
            type=service_config.get_category(),
            data=service_config.get_resource_data_raw(),
            parent=parent)

        self.session.add(resource)
        self._add_to_cache(resource, service_config.id)

    def _convert_dataset(self, dataset):
        """Convert a dataset to a database object.

        Args:
            dataset (object): Dataset to store.
        """
        parent, full_res_name, type_name = self._full_resource_name(
            dataset)
        resource = self.dao.TBL_RESOURCE(
            full_name=full_res_name,
            type_name=type_name,
            name=dataset.get_resource_id(),
            type=dataset.get_resource_type(),
            data=dataset.get_resource_data_raw(),
            parent=parent)

        self.session.add(resource)
        self._add_to_cache(resource, dataset.id)

    def _convert_enabled_apis(self, enabled_apis):
        """Convert a description of enabled APIs to a database object.

        Args:
            enabled_apis (object): Enabled APIs description to store.
        """
        parent, full_res_name = self._get_parent(enabled_apis)
        apis_type_name = to_type_name(
            enabled_apis.get_category(),
            ':'.join(parent.type_name.split('/')))
        apis_res_name = to_full_resource_name(full_res_name, apis_type_name)
        resource = self.dao.TBL_RESOURCE(
            full_name=apis_res_name,
            type_name=apis_type_name,
            name=enabled_apis.get_resource_id(),
            type=enabled_apis.get_category(),
            data=enabled_apis.get_resource_data_raw(),
            parent=parent)

        self.session.add(resource)

    def _convert_dataset_policy(self, dataset_policy):
        """Convert a dataset policy to a database object.

        Args:
            dataset_policy (object): Dataset policy to store.
        """
        # TODO: Dataset policies should be integrated in the model, not stored
        # as a resource.
        parent, full_res_name = self._get_parent(dataset_policy)
        policy_type_name = to_type_name(
            dataset_policy.get_category(),
            parent.type_name)
        policy_res_name = to_full_resource_name(full_res_name, policy_type_name)
        resource = self.dao.TBL_RESOURCE(
            full_name=policy_res_name,
            type_name=policy_type_name,
            name=dataset_policy.get_resource_id(),
            type=dataset_policy.get_category(),
            data=dataset_policy.get_resource_data_raw(),
            parent=parent)

        self.session.add(resource)

    def _convert_computeproject(self, computeproject):
        """Convert a computeproject to a database object.

        Args:
            computeproject (object): computeproject to store.
        """
        data = computeproject.get_resource_data()
        parent, full_res_name, type_name = self._full_resource_name(
            computeproject)
        resource = self.dao.TBL_RESOURCE(
            full_name=full_res_name,
            type_name=type_name,
            name=computeproject.get_resource_id(),
            type=computeproject.get_resource_type(),
            display_name=data.get('displayName', ''),
            email=data.get('email', ''),
            data=computeproject.get_resource_data_raw(),
            parent=parent)

        self.session.add(resource)
        self._add_to_cache(resource, computeproject.id)

    def _convert_iam_policy(self, iam_policy):
        """Convert an IAM policy to a database object.

        Args:
            iam_policy (object): IAM policy to store.
        """
        _, full_res_name = self._get_parent(iam_policy)
        parent_type_name = self._type_name(iam_policy)
        iam_policy_type_name = to_type_name(
            iam_policy.get_category(),
            ':'.join(parent_type_name.split('/')))
        iam_policy_full_res_name = to_full_resource_name(
            full_res_name,
            iam_policy_type_name)
        resource = self.dao.TBL_RESOURCE(
            full_name=iam_policy_full_res_name,
            type_name=iam_policy_type_name,
            name=iam_policy.get_resource_id(),
            type=iam_policy.get_category(),
            data=iam_policy.get_resource_data_raw(),
            parent_type_name=parent_type_name)

        self.session.add(resource)

    def _convert_image(self, image):
        """Convert a image to a database object.

        Args:
            image (object): Image to store.
        """
        data = image.get_resource_data()
        parent, full_res_name, type_name = self._full_resource_name(
            image)
        resource = self.dao.TBL_RESOURCE(
            full_name=full_res_name,
            type_name=type_name,
            name=image.get_resource_id(),
            type=image.get_resource_type(),
            display_name=data.get('displayName', ''),
            email=data.get('email', ''),
            data=image.get_resource_data_raw(),
            parent=parent)

        self.session.add(resource)
        self._add_to_cache(resource, image.id)

    def _convert_instancegroup(self, instancegroup):
        """Convert a instancegroup to a database object.

        Args:
            instancegroup (object): Instancegroup to store.
        """
        data = instancegroup.get_resource_data()
        parent, full_res_name, type_name = self._full_resource_name(
            instancegroup)
        resource = self.dao.TBL_RESOURCE(
            full_name=full_res_name,
            type_name=type_name,
            name=instancegroup.get_resource_id(),
            type=instancegroup.get_resource_type(),
            display_name=data.get('displayName', ''),
            email=data.get('email', ''),
            data=instancegroup.get_resource_data_raw(),
            parent=parent)

        self.session.add(resource)
        self._add_to_cache(resource, instancegroup.id)

    def _convert_instancegroupmanager(self, instancegroupmanager):
        """Convert a instancegroupmanager to a database object.

        Args:
            instancegroupmanager (object): InstanceGroupManager to store.
        """
        data = instancegroupmanager.get_resource_data()
        parent, full_res_name, type_name = self._full_resource_name(
            instancegroupmanager)
        resource = self.dao.TBL_RESOURCE(
            full_name=full_res_name,
            type_name=type_name,
            name=instancegroupmanager.get_resource_id(),
            type=instancegroupmanager.get_resource_type(),
            display_name=data.get('displayName', ''),
            email=data.get('email', ''),
            data=instancegroupmanager.get_resource_data_raw(),
            parent=parent)

        self.session.add(resource)
        self._add_to_cache(resource, instancegroupmanager.id)

    def _convert_instancetemplate(self, instancetemplate):
        """Convert a instancetemplate to a database object.

        Args:
            instancetemplate (object): InstanceTemplate to store.
        """
        data = instancetemplate.get_resource_data()
        parent, full_res_name, type_name = self._full_resource_name(
            instancetemplate)
        resource = self.dao.TBL_RESOURCE(
            full_name=full_res_name,
            type_name=type_name,
            name=instancetemplate.get_resource_id(),
            type=instancetemplate.get_resource_type(),
            display_name=data.get('displayName', ''),
            email=data.get('email', ''),
            data=instancetemplate.get_resource_data_raw(),
            parent=parent)

        self.session.add(resource)
        self._add_to_cache(resource, instancetemplate.id)

    def _convert_instance(self, instance):
        """Convert a instance to a database object.

        Args:
            instance (object): Instance to store.
        """
        data = instance.get_resource_data()
        parent, full_res_name, type_name = self._full_resource_name(
            instance)
        resource = self.dao.TBL_RESOURCE(
            full_name=full_res_name,
            type_name=type_name,
            name=instance.get_resource_id(),
            type=instance.get_resource_type(),
            display_name=data.get('displayName', ''),
            email=data.get('email', ''),
            data=instance.get_resource_data_raw(),
            parent=parent)

        self.session.add(resource)
        self._add_to_cache(resource, instance.id)

    def _convert_firewall(self, firewall):
        """Convert a firewall to a database object.

        Args:
            firewall (object): Firewall to store.
        """
        data = firewall.get_resource_data()
        parent, full_res_name, type_name = self._full_resource_name(
            firewall)
        resource = self.dao.TBL_RESOURCE(
            full_name=full_res_name,
            type_name=type_name,
            name=firewall.get_resource_id(),
            type=firewall.get_resource_type(),
            display_name=data.get('displayName', ''),
            email=data.get('email', ''),
            data=firewall.get_resource_data_raw(),
            parent=parent)

        self.session.add(resource)
        self._add_to_cache(resource, firewall.id)

    def _convert_backendservice(self, backendservice):
        """Convert a backendservice to a database object.

        Args:
            backendservice (object): Backendservice to store.
        """
        data = backendservice.get_resource_data()
        parent, full_res_name, type_name = self._full_resource_name(
            backendservice)
        resource = self.dao.TBL_RESOURCE(
            full_name=full_res_name,
            type_name=type_name,
            name=backendservice.get_resource_id(),
            type=backendservice.get_resource_type(),
            display_name=data.get('displayName', ''),
            email=data.get('email', ''),
            data=backendservice.get_resource_data_raw(),
            parent=parent)

        self.session.add(resource)
        self._add_to_cache(resource, backendservice.id)

    def _convert_forwardingrule(self, forwardingrule):
        """Convert a forwarding rule to a database object.

        Args:
            forwardingrule (object): ForwardingRule to store.
        """
        data = forwardingrule.get_resource_data()
        parent, full_res_name, type_name = self._full_resource_name(
            forwardingrule)
        resource = self.dao.TBL_RESOURCE(
            full_name=full_res_name,
            type_name=type_name,
            name=forwardingrule.get_resource_id(),
            type=forwardingrule.get_resource_type(),
            display_name=data.get('displayName', ''),
            email=data.get('email', ''),
            data=forwardingrule.get_resource_data_raw(),
            parent=parent)

        self.session.add(resource)
        self._add_to_cache(resource, forwardingrule.id)

    def _convert_network(self, network):
        """Convert a network to a database object.

        Args:
            network (object): Network to store.
        """
        data = network.get_resource_data()
        parent, full_res_name, type_name = self._full_resource_name(
            network)
        resource = self.dao.TBL_RESOURCE(
            full_name=full_res_name,
            type_name=type_name,
            name=network.get_resource_id(),
            type=network.get_resource_type(),
            display_name=data.get('displayName', ''),
            email=data.get('email', ''),
            data=network.get_resource_data_raw(),
            parent=parent)

        self.session.add(resource)
        self._add_to_cache(resource, network.id)

    def _convert_subnetwork(self, subnetwork):
        """Convert a subnetwork to a database object.

        Args:
            subnetwork (object): Subnetwork to store.
        """
        data = subnetwork.get_resource_data()
        parent, full_res_name, type_name = self._full_resource_name(
            subnetwork)
        resource = self.dao.TBL_RESOURCE(
            full_name=full_res_name,
            type_name=type_name,
            name=subnetwork.get_resource_id(),
            type=subnetwork.get_resource_type(),
            display_name=data.get('displayName', ''),
            email=data.get('email', ''),
            data=subnetwork.get_resource_data_raw(),
            parent=parent)

        self.session.add(resource)
        self._add_to_cache(resource, subnetwork.id)

    def _convert_cloudsqlinstance(self, cloudsqlinstance):
        """Convert a cloudsqlinstance to a database object.

        Args:
            cloudsqlinstance (object): Cloudsql to store.
        """
        data = cloudsqlinstance.get_resource_data()
        parent, full_res_name, type_name = self._full_resource_name(
            cloudsqlinstance)
        parent_key = get_resource_id_from_type_name(parent.type_name)
        resource_identifier = '{}:{}'.format(parent_key,
                                             cloudsqlinstance.get_resource_id())
        type_name = to_type_name(cloudsqlinstance.get_resource_type(),
                                 resource_identifier)

        resource = self.dao.TBL_RESOURCE(
            full_name=full_res_name,
            type_name=type_name,
            name=cloudsqlinstance.get_resource_id(),
            type=cloudsqlinstance.get_resource_type(),
            display_name=data.get('displayName', ''),
            email=data.get('email', ''),
            data=cloudsqlinstance.get_resource_data_raw(),
            parent=parent)

        self.session.add(resource)
        self._add_to_cache(resource, cloudsqlinstance.id)

    def _convert_serviceaccount(self, service_account):
        """Convert a service account to a database object.

        Args:
            service_account (object): Service account to store.
        """
        data = service_account.get_resource_data()
        parent, full_res_name, type_name = self._full_resource_name(
            service_account)
        resource = self.dao.TBL_RESOURCE(
            full_name=full_res_name,
            type_name=type_name,
            name=service_account.get_resource_id(),
            type=service_account.get_resource_type(),
            display_name=data.get('displayName', ''),
            email=data.get('email', ''),
            data=service_account.get_resource_data_raw(),
            parent=parent)
        self.session.add(resource)
        self._add_to_cache(resource, service_account.id)

    def _convert_serviceaccount_key(self, service_account_key):
        """Convert a service account key to a database object.

        Args:
            service_account_key (object): Service account key to store.
        """

        data = service_account_key.get_resource_data()
        parent, full_res_name, type_name = self._full_resource_name(
            service_account_key)
        resource = self.dao.TBL_RESOURCE(
            full_name=full_res_name,
            type_name=type_name,
            name=service_account_key.get_resource_id(),
            type=service_account_key.get_resource_type(),
            display_name=data.get('displayName', ''),
            email=data.get('email', ''),
            data=service_account_key.get_resource_data_raw(),
            parent=parent)
        self.session.add(resource)

    def _convert_folder(self, folder):
        """Convert a folder to a database object.

        Args:
            folder (object): Folder to store.
        """

        data = folder.get_resource_data()
        if self._is_root(folder):
            parent, type_name = None, self._type_name(folder)
            full_res_name = type_name
        else:
            parent, full_res_name, type_name = self._full_resource_name(
                folder)
        resource = self.dao.TBL_RESOURCE(
            full_name=full_res_name,
            type_name=type_name,
            name=folder.get_resource_id(),
            type=folder.get_resource_type(),
            display_name=data.get('displayName', ''),
            data=folder.get_resource_data_raw(),
            parent=parent)
        self.session.add(resource)
        self._add_to_cache(resource, folder.id)

    def _convert_project(self, project):
        """Convert a project to a database object.

        Args:
            project (object): Project to store.
        """

        data = project.get_resource_data()
        if self._is_root(project):
            parent, type_name = None, self._type_name(project)
            full_res_name = type_name
        else:
            parent, full_res_name, type_name = self._full_resource_name(
                project)
        resource = self.dao.TBL_RESOURCE(
            full_name=full_res_name,
            type_name=type_name,
            name=project.get_resource_id(),
            type=project.get_resource_type(),
            display_name=data.get('name', ''),
            data=project.get_resource_data_raw(),
            parent=parent)
        self.session.add(resource)
        self._add_to_cache(resource, project.id)

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

        data = role.get_resource_data()
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

        if not self._is_role_unique(data['name']):
            return
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
            role_resource = self.dao.TBL_RESOURCE(
                full_name=full_res_name,
                type_name=type_name,
                name=role.get_resource_id(),
                type=role.get_resource_type(),
                display_name=data.get('title'),
                data=role.get_resource_data_raw(),
                parent=parent)

            self._add_to_cache(role_resource, role.id)
            self.session.add(role_resource)

    def _convert_organization(self, organization):
        """Convert an organization a database object.

        Args:
            organization (object): Organization to store.
        """

        # Under current assumptions, organization is always root
        self.found_root = True
        data = organization.get_resource_data()
        type_name = self._type_name(organization)
        org = self.dao.TBL_RESOURCE(
            full_name=to_full_resource_name('', type_name),
            type_name=type_name,
            name=organization.get_resource_id(),
            type=organization.get_resource_type(),
            display_name=data.get('displayName', ''),
            data=organization.get_resource_data_raw(),
            parent=None)

        self._add_to_cache(org, organization.id)
        self.session.add(org)

    def _is_role_unique(self, role_name):
        """Check to see if the session contains Role with
        primary key = role_name.

        Args:
            role_name (str): The role name (Primary key of the role table).

        Returns:
            bool: Whether or not session contains Role with
                primary key = role_name.
        """

        # one_or_none returns None if the query selects no rows.
        exists = role_name in self.role_cache

        if exists:
            LOGGER.warn('Duplicate role_name: %s', role_name)
            return False
        return True

    def _add_to_cache(self, resource, resource_id):
        """Add a resource to the cache for parent lookup.

        Args:
            resource (object): Resource to put in the cache.
            resource_id (int): The database key for the resource.
        """

        full_res_name = resource.full_name
        self.resource_cache[resource_id] = (resource, full_res_name)

    def _get_parent(self, resource):
        """Return the parent object for a resource from cache.

        Args:
            resource (object): Resource whose parent to look for.

        Returns:
            tuple: cached object and full resource name
        """

        parent_id = resource.get_parent_id()

        return self.resource_cache[parent_id]

    def _type_name(self, resource):
        """Return the type/name for that resource.

        Args:
            resource (object): Resource to retrieve type/name for.

        Returns:
            str: type/name representation of the resource.
        """
        return to_type_name(
            resource.get_resource_type(),
            resource.get_resource_id())

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
            is_root = not resource.get_parent_id()
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
