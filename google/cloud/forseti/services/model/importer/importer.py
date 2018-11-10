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
"""Importer implementations."""

# pylint: disable=too-many-instance-attributes

import json
from StringIO import StringIO
import traceback

from google.cloud.forseti.common.util import logger
from google.cloud.forseti.services.inventory.storage import Storage as Inventory
from google.cloud.forseti.services.utils import get_resource_id_from_type_name
from google.cloud.forseti.services.utils import get_sql_dialect
from google.cloud.forseti.services.utils import to_full_resource_name
from google.cloud.forseti.services.utils import to_type_name

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
        del args, kwargs  # Unused.

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
        del args, kwargs  # Unused.

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
        self.membership_map = {}  # Maps group_name to {member_name}
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
            'appengine_app',
            'appengine_service',
            'appengine_version',
            'appengine_instance',
            'backendservice',
            'billing_account',
            'bucket',
            'cloudsqlinstance',
            'compute_autoscaler',
            'compute_backendbucket',
            'compute_healthcheck',
            'compute_httphealthcheck',
            'compute_httpshealthcheck',
            'compute_license',
            'compute_project',
            'compute_router',
            'compute_sslcertificate',
            'compute_targethttpproxy',
            'compute_targethttpsproxy',
            'compute_targetinstance',
            'compute_targetpool',
            'compute_targetsslproxy',
            'compute_targettcpproxy',
            'compute_urlmap',
            'crm_org_policy',
            'dataset',
            'disk',
            'dns_managedzone',
            'dns_policy',
            'firewall',
            'forwardingrule',
            'image',
            'instance',
            'instancegroup',
            'instancegroupmanager',
            'instancetemplate',
            'kubernetes_cluster',
            'lien',
            'network',
            'pubsub_topic',
            'serviceaccount',
            'serviceaccount_key',
            'sink',
            'snapshot',
            'spanner_instance',
            'spanner_database',
            'subnetwork',
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
                else:
                    LOGGER.debug('Root resource is not organization: %s.', root)

                item_counter = 0
                LOGGER.debug('Start storing resources into models.')
                for resource in inventory.iter(gcp_type_list):
                    item_counter += 1
                    self._store_resource(resource)
                    if not item_counter % 1000:
                        # Flush database every 1000 resources
                        LOGGER.debug('Flushing model write session: %s',
                                     item_counter)
                        self.session.flush()

                if item_counter % 1000:
                    # Additional rows added since last flush.
                    self.session.flush()
                LOGGER.debug('Finished storing resources into models.')

                item_counter += self.model_action_wrapper(
                    self.session,
                    inventory.iter(['role']),
                    self._convert_role,
                    post_action=self._convert_role_post
                )

                item_counter += self.model_action_wrapper(
                    self.session,
                    inventory.iter(gcp_type_list,
                                   fetch_dataset_policy=True),
                    self._convert_dataset_policy
                )

                item_counter += self.model_action_wrapper(
                    self.session,
                    inventory.iter(gcp_type_list,
                                   fetch_service_config=True),
                    self._convert_service_config
                )

                self.model_action_wrapper(
                    self.session,
                    inventory.iter(gsuite_type_list),
                    self._store_gsuite_principal
                )

                self.model_action_wrapper(
                    self.session,
                    inventory.iter(gcp_type_list, fetch_enabled_apis=True),
                    self._convert_enabled_apis
                )

                self.model_action_wrapper(
                    self.session,
                    inventory.iter(member_type_list, with_parent=True),
                    self._store_gsuite_membership,
                    post_action=self._store_gsuite_membership_post
                )

                self.dao.denorm_group_in_group(self.session)

                self.model_action_wrapper(
                    self.session,
                    inventory.iter(gcp_type_list,
                                   fetch_iam_policy=True),
                    self._store_iam_policy
                )
        except Exception as e:  # pylint: disable=broad-except
            LOGGER.exception(e)
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
                             action,
                             post_action=None,
                             flush_count=1000):
        """Model action wrapper. This is used to reduce code duplication.

        Args:
            session (Session): Database session.
            inventory_iterable (Iterable): Inventory iterable.
            action (func): Action taken during the iteration of
                the inventory list.
            post_action (func): Action taken after iterating the
                inventory list.
            flush_count (int): Flush every flush_count times.

        Returns:
            int: Number of item iterated.
        """
        LOGGER.debug('Performing model action: %s', action)

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

        if idx % flush_count:
            # Additional rows added since last flush.
            session.flush()

        if post_action:
            post_action()

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

    def _store_resource(self, resource):
        """Store an inventory resource in the database.

        Args:
            resource (object): Resource object to convert from.
        """
        handlers = {
            'appengine_app': self._convert_gae_resource,
            'appengine_instance': self._convert_gae_instance_resource,
            'appengine_service': self._convert_gae_resource,
            'appengine_version': self._convert_gae_resource,
            'backendservice': self._convert_computeengine_resource,
            'billing_account': self._convert_billing_account,
            'bucket': self._convert_bucket,
            'cloudsqlinstance': self._convert_cloudsqlinstance,
            'compute_autoscaler': self._convert_computeengine_resource,
            'compute_backendbucket': self._convert_computeengine_resource,
            'compute_healthcheck': self._convert_computeengine_resource,
            'compute_httphealthcheck': self._convert_computeengine_resource,
            'compute_httpshealthcheck': self._convert_computeengine_resource,
            'compute_license': self._convert_computeengine_resource,
            'compute_project': self._convert_computeengine_resource,
            'compute_router': self._convert_computeengine_resource,
            'compute_sslcertificate': self._convert_computeengine_resource,
            'compute_targethttpproxy': self._convert_computeengine_resource,
            'compute_targethttpsproxy': self._convert_computeengine_resource,
            'compute_targetinstance': self._convert_computeengine_resource,
            'compute_targetpool': self._convert_computeengine_resource,
            'compute_targetsslproxy': self._convert_computeengine_resource,
            'compute_targettcpproxy': self._convert_computeengine_resource,
            'compute_urlmap': self._convert_computeengine_resource,
            'crm_org_policy': self._convert_crm_org_policy,
            'dataset': self._convert_dataset,
            'disk': self._convert_computeengine_resource,
            'dns_managedzone': self._convert_clouddns_resource,
            'dns_policy': self._convert_clouddns_resource,
            'firewall': self._convert_computeengine_resource,
            'folder': self._convert_folder,
            'forwardingrule': self._convert_computeengine_resource,
            'image': self._convert_computeengine_resource,
            'instance': self._convert_computeengine_resource,
            'instancegroup': self._convert_computeengine_resource,
            'instancegroupmanager': self._convert_computeengine_resource,
            'instancetemplate': self._convert_computeengine_resource,
            'kubernetes_cluster': self._convert_kubernetes_cluster,
            'lien': self._convert_lien,
            'network': self._convert_computeengine_resource,
            'organization': self._convert_organization,
            'project': self._convert_project,
            'pubsub_topic': self._convert_pubsub_topic,
            'serviceaccount': self._convert_serviceaccount,
            'serviceaccount_key': self._convert_serviceaccount_key,
            'sink': self._convert_sink,
            'snapshot': self._convert_computeengine_resource,
            'spanner_database': self._convert_spanner_db_resource,
            'spanner_instance': self._convert_spanner_resource,
            'subnetwork': self._convert_computeengine_resource,
            None: None,
        }

        res_type = resource.get_resource_type() if resource else None
        handler = handlers.get(res_type)
        if handler:
            handler(resource)
        else:
            self.model.add_warning('No handler for type "{}"'.format(res_type))

    def _convert_resource(self, resource, cached=False, display_key='name',
                          email_key='email'):
        """Convert resource to a database object.

        Args:
            resource (dict): A resource to store.
            cached (bool): Set to true for resources that have child resources
                or policies associated with them.
            display_key (str): The key in the resource dictionary to lookup to
                get the display name for the resource.
            email_key (str): The key in the resource dictionary to lookup to get
                the email associated with the resource.
        """
        data = resource.get_resource_data()
        if self._is_root(resource):
            parent, type_name = None, self._type_name(resource)
            full_res_name = to_full_resource_name('', type_name)
        else:
            parent, full_res_name, type_name = self._full_resource_name(
                resource)
        row = self.dao.TBL_RESOURCE(
            full_name=full_res_name,
            type_name=type_name,
            name=resource.get_resource_id(),
            type=resource.get_resource_type(),
            display_name=data.get(display_key, ''),
            email=data.get(email_key, ''),
            data=resource.get_resource_data_raw(),
            parent=parent)

        self.session.add(row)
        if cached:
            self._add_to_cache(row, resource.id)

    def _convert_billing_account(self, billing_account):
        """Convert a billing account to a database object.

        Args:
            billing_account (object): billing account to store.
        """
        self._convert_resource(billing_account, cached=True,
                               display_key='displayName')

    def _convert_bucket(self, bucket):
        """Convert a bucket to a database object.

        Args:
            bucket (object): Bucket to store.
        """
        self._convert_resource(bucket, cached=True)

    def _convert_clouddns_resource(self, resource):
        """Convert a CloudDNS resource to a database object.

        Args:
            resource (dict): A resource to store.
        """
        self._convert_resource(resource, cached=False)

    def _convert_computeengine_resource(self, resource):
        """Convert an AppEngine resource to a database object.

        Args:
            resource (dict): An appengine resource to store.
        """
        self._convert_resource(resource, cached=False)

    def _convert_crm_org_policy(self, org_policy):
        """Convert an org policy to a database object.

        Args:
            org_policy (object): org policy to store.
        """
        self._convert_resource(org_policy, cached=False,
                               display_key='constraint')

    def _convert_dataset(self, dataset):
        """Convert a dataset to a database object.

        Args:
            dataset (object): Dataset to store.
        """
        self._convert_resource(dataset, cached=True)

    def _convert_folder(self, folder):
        """Convert a folder to a database object.

        Args:
            folder (object): Folder to store.
        """
        self._convert_resource(folder, cached=True, display_key='displayName')

    def _convert_gae_instance_resource(self, resource):
        """Convert an AppEngine Instance resource to a database object.

        Args:
            resource (dict): A resource to store.
        """
        self._convert_resource(resource, cached=False)

    def _convert_gae_resource(self, resource):
        """Convert an AppEngine resource to a database object.

        Args:
            resource (dict): A resource to store.
        """
        self._convert_resource(resource, cached=True)

    def _convert_kubernetes_cluster(self, cluster):
        """Convert an AppEngine resource to a database object.

        Args:
            cluster (dict): A Kubernetes cluster resource to store.
        """
        self._convert_resource(cluster, cached=True)

    def _convert_lien(self, lien):
        """Convert a lien to a database object.

        Args:
            lien (object): Lien to store.
        """
        self._convert_resource(lien, cached=True)

    def _convert_organization(self, organization):
        """Convert an organization a database object.

        Args:
            organization (object): Organization to store.
        """
        self._convert_resource(organization, cached=True,
                               display_key='displayName')

    def _convert_pubsub_topic(self, topic):
        """Convert a PubSub Topic to a database object.

        Args:
            topic (object): Pubsub Topic to store.
        """
        self._convert_resource(topic, cached=True)

    def _convert_project(self, project):
        """Convert a project to a database object.

        Args:
            project (object): Project to store.
        """
        self._convert_resource(project, cached=True)

    def _convert_serviceaccount(self, service_account):
        """Convert a service account to a database object.

        Args:
            service_account (object): Service account to store.
        """
        self._convert_resource(service_account, cached=True,
                               display_key='displayName', email_key='email')

    def _convert_serviceaccount_key(self, service_account_key):
        """Convert a service account key to a database object.

        Args:
            service_account_key (object): Service account key to store.
        """
        self._convert_resource(service_account_key, cached=False)

    def _convert_sink(self, sink):
        """Convert a log sink to a database object.

        Args:
            sink (object): Sink to store.
        """
        self._convert_resource(sink, cached=False, email_key='writerIdentity')

    def _convert_spanner_db_resource(self, resource):
        """Convert a Spanner Database resource to a database object.

        Args:
            resource (dict): A resource to store.
        """
        self._convert_resource(resource, cached=False)

    def _convert_spanner_resource(self, resource):
        """Convert a Spanner Instance resource to a database object.

        Args:
            resource (dict): A resource to store.
        """
        self._convert_resource(resource, cached=True, display_key='displayName')

    # The following methods require more complex logic than _convert_resource
    # provides.
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
            dataset_policy.get_resource_id())
        policy_res_name = to_full_resource_name(full_res_name, policy_type_name)
        resource = self.dao.TBL_RESOURCE(
            full_name=policy_res_name,
            type_name=policy_type_name,
            name=dataset_policy.get_resource_id(),
            type=dataset_policy.get_category(),
            data=dataset_policy.get_resource_data_raw(),
            parent=parent)

        self.session.add(resource)

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

    def _convert_role_post(self):
        """Executed after all roles were handled. Performs bulk insert."""

        self.session.add_all(self.permission_cache.values())
        self.session.add_all(self.role_cache.values())

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

    def _add_to_cache(self, resource, resource_id):
        """Add a resource to the cache for parent lookup.

        Args:
            resource (object): Resource to put in the cache.
            resource_id (int): The database key for the resource.
        """

        full_res_name = resource.full_name
        self.resource_cache[resource_id] = (resource, full_res_name)

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

    def _get_parent(self, resource):
        """Return the parent object for a resource from cache.

        Args:
            resource (object): Resource whose parent to look for.

        Returns:
            tuple: cached object and full resource name
        """
        parent_id = resource.get_parent_id()
        return self.resource_cache[parent_id]

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

    @staticmethod
    def _type_name(resource):
        """Return the type/name for that resource.

        This is a simple wrapper for the to_type_name function.

        Args:
            resource (object): Resource to retrieve type/name for.

        Returns:
            str: type/name representation of the resource.
        """
        return to_type_name(
            resource.get_resource_type(),
            resource.get_resource_id())


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
