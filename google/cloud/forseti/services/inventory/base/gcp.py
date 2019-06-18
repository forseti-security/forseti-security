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
"""GCP API client fassade."""

# pylint: disable=invalid-name,too-many-lines
# pylint: disable=too-many-public-methods,too-many-instance-attributes

from builtins import object
import abc

from future.utils import with_metaclass
from google.cloud.forseti.common.gcp_api import admin_directory
from google.cloud.forseti.common.gcp_api import appengine
from google.cloud.forseti.common.gcp_api import bigquery
from google.cloud.forseti.common.gcp_api import cloud_resource_manager
from google.cloud.forseti.common.gcp_api import cloudbilling
from google.cloud.forseti.common.gcp_api import cloudsql
from google.cloud.forseti.common.gcp_api import compute
from google.cloud.forseti.common.gcp_api import container
from google.cloud.forseti.common.gcp_api import groups_settings
from google.cloud.forseti.common.gcp_api import iam
from google.cloud.forseti.common.gcp_api import servicemanagement
from google.cloud.forseti.common.gcp_api import stackdriver_logging
from google.cloud.forseti.common.gcp_api import storage


class AssetMetadata(object):
    """Asset Metadata."""
    def __init__(self, cai_name='', cai_type=''):
        """Init.
        Args:
            cai_name (str): CAI resource name.
            cai_type (str): CAI resource type.
        """
        self.cai_name = cai_name
        self.cai_type = cai_type

    def __eq__(self, other):
        """Equals.

        Args:
            other (AssetMetadata): other asset metadata.

        Returns:
            bool: if two asset metadata are the same.
        """
        return (self.cai_name == other.cai_name and
                self.cai_type == other.cai_type)

    def __repr__(self):
        """Repr.

        Returns:
            str: repr.
        """
        return 'cai_name: {}, cai_type: {}'.format(
            self.cai_name, self.cai_type)


class ResourceNotSupported(Exception):
    """Exception raised for resources not supported by the API client."""


class ApiClient(with_metaclass(abc.ABCMeta, object)):
    """The gcp api client interface"""

    @abc.abstractmethod
    def fetch_bigquery_dataset_policy(self, project_id,
                                      project_number, dataset_id):
        """Dataset policy Iterator for a dataset from gcp API call.

        Args:
            project_id (str): id of the project to query.
            project_number (str): number of the project to query.
            dataset_id (str): id of the dataset to query.
        """

    @abc.abstractmethod
    def fetch_bigquery_iam_policy(self, project_id, project_number, dataset_id):
        """Gets IAM policy of a bigquery dataset from gcp API call.

        Args:
            project_id (str): id of the project to query.
            project_number (str): number of the project to query.
            dataset_id (str): id of the dataset to query.
        """

    @abc.abstractmethod
    def iter_bigquery_datasets(self, project_number):
        """Iterate Datasets from GCP API.

        Args:
            project_number (str): number of the project to query.
        """

    @abc.abstractmethod
    def iter_bigquery_tables(self, dataset_reference):
        """Iterate Tables from GCP API.

        Args:
            dataset_reference (dict): The project and dataset ID to get
                                      bigquery tables.
        """

    @abc.abstractmethod
    def fetch_billing_account_iam_policy(self, account_id):
        """Gets IAM policy of a Billing Account from GCP API.

        Args:
            account_id (str): id of the billing account to get policy.
        """

    @abc.abstractmethod
    def fetch_billing_project_info(self, project_number):
        """Project Billing Info from gcp API call.

        Args:
            project_number (str): number of the project to query.
        """

    @abc.abstractmethod
    def iter_billing_accounts(self):
        """Iterate visible Billing Accounts in an organization from GCP API."""

    @abc.abstractmethod
    def iter_cloudsql_instances(self, project_id, project_number):
        """Iterate Cloud sql instances from GCP API.

        Args:
            project_id (str): id of the project to query.
            project_number (str): number of the project to query.
        """

    @abc.abstractmethod
    def is_compute_api_enabled(self, project_number):
        """Verifies the Compute API is enabled on a project.

        Args:
            project_number (str): number of the project to query.
        """

    @abc.abstractmethod
    def fetch_compute_ig_instances(self, project_number, instance_group_name,
                                   region=None, zone=None):
        """Get the instances for an instance group from GCP API.

        One and only one of zone (for zonal instance groups) and region
        (for regional instance groups) must be specified.

        Args:
            project_number (str): number of the project to query.
            instance_group_name (str): The instance group's name.
            region (str): The regional instance group's region.
            zone (str): The zonal instance group's zone.
        """

    @abc.abstractmethod
    def fetch_compute_project(self, project_number):
        """Fetch compute project data from GCP API.

        Args:
            project_number (str): number of the project to query.
        """

    @abc.abstractmethod
    def iter_compute_autoscalers(self, project_number):
        """Iterate Autoscalers from GCP API.

        Args:
            project_number (str): number of the project to query.
        """

    @abc.abstractmethod
    def iter_compute_backendbuckets(self, project_number):
        """Iterate Backend buckets from GCP API.

        Args:
            project_number (str): number of the project to query.
        """

    @abc.abstractmethod
    def iter_compute_backendservices(self, project_number):
        """Iterate Backend services from GCP API.

        Args:
            project_number (str): number of the project to query.
        """

    @abc.abstractmethod
    def iter_compute_disks(self, project_number):
        """Iterate Compute Engine disks from GCP API.

        Args:
            project_number (str): number of the project to query.
        """

    @abc.abstractmethod
    def iter_compute_firewalls(self, project_number):
        """Iterate Compute Engine Firewalls from GCP API.

        Args:
            project_number (str): number of the project to query.
        """

    @abc.abstractmethod
    def iter_compute_forwardingrules(self, project_number):
        """Iterate Forwarding Rules from GCP API.

        Args:
            project_number (str): number of the project to query.
        """

    @abc.abstractmethod
    def iter_compute_healthchecks(self, project_number):
        """Iterate Health checks from GCP API.

        Args:
            project_number (str): number of the project to query.
        """

    @abc.abstractmethod
    def iter_compute_httphealthchecks(self, project_number):
        """Iterate HTTP Health checks from GCP API.

        Args:
            project_number (str): number of the project to query.
        """

    @abc.abstractmethod
    def iter_compute_httpshealthchecks(self, project_number):
        """Iterate HTTPS Health checks from GCP API.

        Args:
            project_number (str): number of the project to query.
        """

    @abc.abstractmethod
    def iter_compute_ig_managers(self, project_number):
        """Iterate Instance Group Manager from GCP API.

        Args:
            project_number (str): number of the project to query.
        """

    @abc.abstractmethod
    def iter_compute_images(self, project_number):
        """Iterate Images from GCP API.

        Args:
            project_number (str): number of the project to query.
        """

    @abc.abstractmethod
    def iter_compute_instancegroups(self, project_number):
        """Iterate Compute Engine groups from GCP API.

        Args:
            project_number (str): number of the project to query.
        """

    @abc.abstractmethod
    def iter_compute_instances(self, project_number):
        """Iterate compute engine instance from GCP API.

        Args:
            project_number (str): number of the project to query.
        """

    @abc.abstractmethod
    def iter_compute_instancetemplates(self, project_number):
        """Iterate Instance Templates from GCP API.

        Args:
            project_number (str): number of the project to query.
        """

    @abc.abstractmethod
    def iter_compute_licenses(self, project_number):
        """Iterate Licenses from GCP API.

        Args:
            project_number (str): number of the project to query.
        """

    @abc.abstractmethod
    def iter_compute_networks(self, project_number):
        """Iterate Networks from GCP API.

        Args:
            project_number (str): number of the project to query.
        """

    @abc.abstractmethod
    def iter_compute_project(self, project_number):
        """Iterate Project from GCP API.

        Will only ever return up to 1 result. Ensures compatibility with other
        resource iterators.

        Args:
            project_number (str): number of the project to query.
        """

    @abc.abstractmethod
    def iter_compute_routers(self, project_number):
        """Iterate Compute Engine routers from GCP API.

        Args:
            project_number (str): number of the project to query.
        """

    @abc.abstractmethod
    def iter_compute_snapshots(self, project_number):
        """Iterate Compute Engine snapshots from GCP API.

        Args:
            project_number (str): number of the project to query.
        """

    @abc.abstractmethod
    def iter_compute_sslcertificates(self, project_number):
        """Iterate SSL Certificates from GCP API.

        Args:
            project_number (str): number of the project to query.
        """

    @abc.abstractmethod
    def iter_compute_subnetworks(self, project_number):
        """Iterate Subnetworks from GCP API.

        Args:
            project_number (str): number of the project to query.
        """

    @abc.abstractmethod
    def iter_compute_targethttpproxies(self, project_number):
        """Iterate Target HTTP proxies from GCP API.

        Args:
            project_number (str): number of the project to query.
        """

    @abc.abstractmethod
    def iter_compute_targethttpsproxies(self, project_number):
        """Iterate Target HTTPS proxies from GCP API.

        Args:
            project_number (str): number of the project to query.
        """

    @abc.abstractmethod
    def iter_compute_targetinstances(self, project_number):
        """Iterate Target Instances from GCP API.

        Args:
            project_number (str): number of the project to query.
        """

    @abc.abstractmethod
    def iter_compute_targetpools(self, project_number):
        """Iterate Target Pools from GCP API.

        Args:
            project_number (str): number of the project to query.
        """

    @abc.abstractmethod
    def iter_compute_targetsslproxies(self, project_number):
        """Iterate Target SSL proxies from GCP API.

        Args:
            project_number (str): number of the project to query.
        """

    @abc.abstractmethod
    def iter_compute_targettcpproxies(self, project_number):
        """Iterate Target TCP proxies from GCP API.

        Args:
            project_number (str): number of the project to query.
        """

    @abc.abstractmethod
    def iter_compute_targetvpngateways(self, project_number):
        """Iterate Target VPN Gateways from GCP API.

        Args:
            project_number (str): number of the project to query.
        """

    @abc.abstractmethod
    def iter_compute_urlmaps(self, project_number):
        """Iterate URL maps from GCP API.

        Args:
            project_number (str): number of the project to query.
        """

    @abc.abstractmethod
    def iter_compute_vpntunnels(self, project_number):
        """Iterate VPN tunnels from GCP API.

        Args:
            project_number (str): number of the project to query.
        """

    @abc.abstractmethod
    def fetch_container_serviceconfig(self, project_id, zone=None,
                                      location=None):
        """Fetch Kubernetes Engine per zone service config from GCP API.

        Args:
            project_id (str): id of the project to query.
            zone (str): zone of the Kubernetes Engine.
            location (str): location of the Kubernetes Engine.
        """

    @abc.abstractmethod
    def iter_container_clusters(self, project_number):
        """Iterate Kubernetes Engine Cluster from GCP API.

        Args:
            project_number (str): number of the project to query.
        """

    @abc.abstractmethod
    def fetch_crm_folder(self, folder_id):
        """Fetch Folder data from GCP API.

        Args:
            folder_id (str): id of the folder to query.
        """

    @abc.abstractmethod
    def fetch_crm_folder_iam_policy(self, folder_id):
        """Folder IAM policy in a folder from gcp API call.

        Args:
            folder_id (str): id of the folder to get policy.
        """

    @abc.abstractmethod
    def fetch_crm_organization(self, org_id):
        """Fetch Organization data from GCP API.

        Args:
            org_id (str): id of the organization to get.
        """

    @abc.abstractmethod
    def fetch_crm_organization_iam_policy(self, org_id):
        """Organization IAM policy from gcp API call.

        Args:
            org_id (str): id of the organization to get policy.
        """

    @abc.abstractmethod
    def fetch_crm_project(self, project_number):
        """Fetch Project data from GCP API.

        Args:
            project_number (str): number of the project to query.
        """

    @abc.abstractmethod
    def fetch_crm_project_iam_policy(self, project_number):
        """Project IAM policy from gcp API call.

        Args:
            project_number (str): number of the project to query.
        """

    @abc.abstractmethod
    def iter_crm_folder_org_policies(self, folder_id):
        """Folder organization policies from gcp API call.

        Args:
            folder_id (str): id of the folder to get policy.
        """

    @abc.abstractmethod
    def iter_crm_folders(self, parent_id):
        """Iterate Folders from GCP API.

        Args:
            parent_id (str): id of the parent of the folder.
        """

    @abc.abstractmethod
    def iter_crm_organization_org_policies(self, org_id):
        """Organization organization policies from gcp API call.

        Args:
            org_id (str): id of the organization to get policy.
        """

    @abc.abstractmethod
    def iter_crm_project_liens(self, project_number):
        """Iterate Liens from GCP API.

        Args:
            project_number (str): number of the parent project of the lien.
        """

    @abc.abstractmethod
    def iter_crm_project_org_policies(self, project_number):
        """Project organization policies from gcp API call.

        Args:
            project_number (str): number of the parent project of the policy.
        """

    @abc.abstractmethod
    def iter_crm_projects(self, parent_type, parent_id):
        """Iterate Projects from GCP API.

        Args:
            parent_type (str): type of the parent, "folder" or "organization".
            parent_id (str): id of the parent of the folder.
        """

    @abc.abstractmethod
    def fetch_dataproc_cluster_iam_policy(self, cluster):
        """Fetch Dataproc Cluster IAM Policy from GCP API.

        Args:
            cluster (str): The Dataproc cluster to query, must be in the format
                projects/{PROJECT_ID}/regions/{REGION}/clusters/{CLUSTER_NAME}
        """

    @abc.abstractmethod
    def iter_dataproc_clusters(self, project_id, region=None):
        """Iterate Dataproc clusters from GCP API.

        Args:
            project_id (str): id of the project to query.
            region (str): The region to query. Not required when using Cloud
                Asset API.
        """

    @abc.abstractmethod
    def iter_dns_managedzones(self, project_number):
        """Iterate CloudDNS Managed Zones from GCP API.

        Args:
            project_number (str): number of the parent project.
        """

    @abc.abstractmethod
    def iter_dns_policies(self, project_number):
        """Iterate CloudDNS Policies from GCP API.

        Args:
            project_number (str): number of the parent project of the policy.
        """

    @abc.abstractmethod
    def fetch_gae_app(self, project_id):
        """Fetch the AppEngine App.

        Args:
            project_id (str): id of the project to query.
        """

    @abc.abstractmethod
    def iter_gae_instances(self, project_id, service_id, version_id):
        """Iterate gae instances from GCP API.

        Args:
            project_id (str): id of the project to query.
            service_id (str): id of the appengine service.
            version_id (str): id of the appengine version.
        """

    @abc.abstractmethod
    def iter_gae_services(self, project_id):
        """Iterate gae services from GCP API.

        Args:
            project_id (str): id of the project to query.
        """

    @abc.abstractmethod
    def iter_gae_versions(self, project_id, service_id):
        """Iterate gae versions from GCP API.

        Args:
            project_id (str): id of the project to query.
            service_id (str): id of the appengine service.
        """

    @abc.abstractmethod
    def iter_gsuite_group_members(self, group_key):
        """Iterate Gsuite group members from GCP API.

        Args:
            group_key (str): key of the group to get.
        """

    @abc.abstractmethod
    def fetch_gsuite_groups_settings(self, group_email):
        """Fetch Gsuite groups settings from GCP API.

        Args:
            group_email (str): Gsuite group email.
        """

    @abc.abstractmethod
    def iter_gsuite_groups(self, gsuite_id):
        """Iterate Gsuite groups from GCP API.

        Args:
            gsuite_id (str): Gsuite id.
        """

    @abc.abstractmethod
    def iter_gsuite_users(self, gsuite_id):
        """Iterate Gsuite users from GCP API.

        Args:
            gsuite_id (str): Gsuite id.
        """

    @abc.abstractmethod
    def fetch_iam_serviceaccount_iam_policy(self, name, unique_id):
        """Service Account IAM policy from gcp API call.

        Args:
            name (str): The service account name to query, must be in the format
                projects/{PROJECT_ID}/serviceAccounts/{SERVICE_ACCOUNT_EMAIL}
            unique_id (str): The unique id of the service account.
        """

    @abc.abstractmethod
    def iter_iam_curated_roles(self):
        """Iterate Curated roles in an organization from GCP API.
        """

    @abc.abstractmethod
    def iter_iam_organization_roles(self, org_id):
        """Iterate Organization roles from GCP API.

        Args:
            org_id (str): id of the organization to get.
        """

    @abc.abstractmethod
    def iter_iam_project_roles(self, project_id, project_number):
        """Iterate Project roles in a project from GCP API.

        Args:
            project_id (str): id of the project to query.
            project_number (str): number of the project to query.
        """

    @abc.abstractmethod
    def iter_iam_serviceaccount_exported_keys(self, name):
        """Iterate Service Account User Managed Keys from GCP API.

        Args:
            name (str): name of the service account.
        """

    @abc.abstractmethod
    def iter_iam_serviceaccounts(self, project_id, project_number):
        """Iterate Service Accounts in a project from GCP API.

        Args:
            project_id (str): id of the project to query.
            project_number (str): number of the project to query.
        """

    @abc.abstractmethod
    def fetch_kms_cryptokey_iam_policy(self, cryptokey):
        """Fetch KMS Cryptokey IAM Policy from GCP API.

        Args:
            cryptokey (str): The KMS cryptokey to query, must be in the format
                projects/{PROJECT_ID}/locations/{LOCATION}/keyRings/{RING_NAME}/
                cryptoKeys/{CRYPTOKEY_NAME}
        """

    @abc.abstractmethod
    def fetch_kms_keyring_iam_policy(self, keyring):
        """Fetch KMS Keyring IAM Policy from GCP API.

        Args:
            keyring (str): The KMS keyring to query, must be in the format
                projects/{PROJECT_ID}/locations/{LOCATION}/keyRings/{RING_NAME}
        """

    @abc.abstractmethod
    def iter_kms_cryptokeys(self, parent):
        """Iterate KMS Cryptokeys in a keyring from GCP API.

        Args:
            parent (str): The KMS keyring to query, must be in the format
                projects/{PROJECT_ID}/locations/{LOCATION}/keyRings/{RING_NAME}
        """

    @abc.abstractmethod
    def iter_kms_cryptokeyversions(self, parent):
        """Iterate KMS Cryptokey Versions from GCP API.

        Args:
            parent (str): The KMS keyring to query, must be in the format
                projects/{PROJECT_ID}/locations/{LOCATION}/keyRings/{RING_NAME}/
                cryptoKeys/{CRYPTOKEY_NAME}
        """

    @abc.abstractmethod
    def iter_kms_keyrings(self, project_id, location=None):
        """Iterate KMS Keyrings in a project from GCP API.

        Args:
            project_id (str): id of the project to query.
            location (str): The location to query. Not required when
                using Cloud Asset API.
        """

    @abc.abstractmethod
    def fetch_pubsub_subscription_iam_policy(self, name):
        """PubSub Subscription IAM policy from gcp API call.

        Args:
            name (str): The pubsub topic to query, must be in the format
               projects/{PROJECT_ID}/subscriptions/{SUBSCRIPTION_NAME}
        """

    @abc.abstractmethod
    def fetch_pubsub_topic_iam_policy(self, name):
        """PubSub Topic IAM policy from gcp API call.

        Args:
            name (str): The pubsub topic to query, must be in the format
                projects/{PROJECT_ID}/topics/{TOPIC_NAME}
        """

    @abc.abstractmethod
    def iter_pubsub_subscriptions(self, project_id, project_number):
        """Iterate PubSub subscriptions from GCP API.

        Args:
            project_id (str): id of the project to query.
            project_number (str): number of the project to query.
        """

    @abc.abstractmethod
    def iter_pubsub_topics(self, project_id, project_number):
        """Iterate PubSub topics from GCP API.

        Args:
            project_id (str): id of the project to query.
            project_number (str): number of the project to query.
        """

    @abc.abstractmethod
    def fetch_services_enabled_apis(self, project_number):
        """Project enabled API services from gcp API call.

        Args:
            project_number (str): number of the project to query.
        """

    @abc.abstractmethod
    def iter_spanner_instances(self, project_number):
        """Iterate Spanner Instances from GCP API.

        Args:
            project_number (str): number of the project to query.
        """

    @abc.abstractmethod
    def iter_spanner_databases(self, parent):
        """Iterate Spanner Databases from GCP API.

        Args:
            parent (str): parent spanner instance to query.
        """

    @abc.abstractmethod
    def iter_stackdriver_billing_account_sinks(self, acct_id):
        """Iterate Billing Account logging sinks from GCP API.

        Args:
            acct_id (str): id of the billing account to query.
        """

    @abc.abstractmethod
    def iter_stackdriver_folder_sinks(self, folder_id):
        """Iterate Folder logging sinks from GCP API.

        Args:
            folder_id (str): id of the folder to query.
        """

    @abc.abstractmethod
    def iter_stackdriver_organization_sinks(self, org_id):
        """Iterate Organization logging sinks from GCP API.

        Args:
            org_id (str): id of the organization to query.
        """

    @abc.abstractmethod
    def iter_stackdriver_project_sinks(self, project_number):
        """Iterate Project logging sinks from GCP API.

        Args:
            project_number (str): number of the project to query.
        """

    @abc.abstractmethod
    def fetch_storage_bucket_acls(self, bucket_id, project_id, project_number):
        """Bucket Access Controls from GCP API.

        Args:
            bucket_id (str): id of the bucket to query.
            project_id (str): id of the project to query.
            project_number (str): number of the project to query.
        """

    @abc.abstractmethod
    def fetch_storage_bucket_iam_policy(self, bucket_id):
        """Bucket IAM policy Iterator from gcp API call.

        Args:
            bucket_id (str): id of the bucket to query.
        """

    @abc.abstractmethod
    def fetch_storage_object_iam_policy(self, bucket_name, object_name):
        """Object IAM policy Iterator for an object from gcp API call.

        Args:
            bucket_name (str): name of the bucket.
            object_name (str): name of the object.
        """

    @abc.abstractmethod
    def iter_storage_buckets(self, project_number):
        """Iterate Buckets from GCP API.

        Args:
            project_number (str): number of the project to query.
        """

    @abc.abstractmethod
    def iter_storage_objects(self, bucket_id):
        """Iterate Objects from GCP API.

        Args:
            bucket_id (str): id of the bucket to get.
        """


def create_lazy(attribute, factory):
    """Create attributes right before they are needed.

    Args:
        attribute (str): Attribute name to check/create.
        factory (function): Factory to create object.

    Returns:
        function: Decorator.
    """
    def f_wrapper(func):
        """Create decorator.

        Args:
            func (function): Function to wrap.

        Returns:
            function: Decorator.
        """

        def wrapper(*args, **kwargs):
            """Decorator implementation.

            Args:
                *args (list): Original func arguments.
                **kwargs (dict): Original func arguments.

            Returns:
                object: Result produced by the wrapped func.
            """
            this = args[0]
            if not hasattr(this, attribute) or not getattr(this, attribute):
                setattr(this, attribute, factory(this))
            return func(*args, **kwargs)
        return wrapper
    return f_wrapper


def is_api_disabled(config, api_name):
    """Check if api_name is disabled in the config.

    Args:
        config (dict): GCP API client configuration.
        api_name (str): The name of the GCP api to check.

    Returns:
        bool: True if the API is disabled in the configuration, else False.
    """
    return config.get(api_name, {}).get('disable_polling', False)


class ApiClientImpl(ApiClient):
    """The gcp api client Implementation"""

    def __init__(self, config):
        """Initialize.

        Args:
            config (dict): GCP API client configuration.
        """
        self.ad = None
        self.appengine = None
        self.bigquery = None
        self.crm = None
        self.cloudbilling = None
        self.cloudsql = None
        self.compute = None
        self.container = None
        self.iam = None
        self.servicemanagement = None
        self.stackdriver_logging = None
        self.storage = None

        self.config = config

    def _create_ad(self):
        """Create admin directory API client.

        Returns:
            object: Client.

        Raises:
            ResourceNotSupported: Raised if polling is disabled for this API in
                the GCP API client configuration.
        """
        if is_api_disabled(self.config, admin_directory.API_NAME):
            raise ResourceNotSupported('Admin API disabled by server '
                                       'configuration.')
        return admin_directory.AdminDirectoryClient(self.config)

    def _create_groups_settings(self):
        """Create gsuite groups settings API client.

        Returns:
            object: Client.

        Raises:
            ResourceNotSupported: Raised if polling is disabled for this API in
                the GCP API client configuration.
        """
        if is_api_disabled(self.config, groups_settings.API_NAME):
            raise ResourceNotSupported('Groups Settings API disabled by server '
                                       'configuration.')
        return groups_settings.GroupsSettingsClient(self.config)

    def _create_appengine(self):
        """Create AppEngine API client.

        Returns:
            object: Client.

        Raises:
            ResourceNotSupported: Raised if polling is disabled for this API in
                the GCP API client configuration.
        """
        if is_api_disabled(self.config, appengine.API_NAME):
            raise ResourceNotSupported('AppEngine API disabled by server '
                                       'configuration.')
        return appengine.AppEngineClient(self.config)

    def _create_bq(self):
        """Create bigquery API client.

        Returns:
            object: Client.

        Raises:
            ResourceNotSupported: Raised if polling is disabled for this API in
                the GCP API client configuration.
        """
        if is_api_disabled(self.config, bigquery.API_NAME):
            raise ResourceNotSupported('Bigquery API disabled by server '
                                       'configuration.')
        return bigquery.BigQueryClient(self.config)

    def _create_crm(self):
        """Create resource manager API client.

        Returns:
            object: Client.

        Raises:
            ResourceNotSupported: Raised if polling is disabled for this API in
                the GCP API client configuration.
        """
        if is_api_disabled(self.config, cloud_resource_manager.API_NAME):
            raise ResourceNotSupported('Resource Manager API disabled by '
                                       'server configuration.')
        return cloud_resource_manager.CloudResourceManagerClient(self.config)

    def _create_cloudbilling(self):
        """Create cloud billing API client.

        Returns:
            object: Client.

        Raises:
            ResourceNotSupported: Raised if polling is disabled for this API in
                the GCP API client configuration.
        """
        if is_api_disabled(self.config, cloudbilling.API_NAME):
            raise ResourceNotSupported('Cloud Billing API disabled by server '
                                       'configuration.')
        return cloudbilling.CloudBillingClient(self.config)

    def _create_cloudsql(self):
        """Create cloud sql API client.

        Returns:
            object: Client.

        Raises:
            ResourceNotSupported: Raised if polling is disabled for this API in
                the GCP API client configuration.
        """
        if is_api_disabled(self.config, cloudsql.API_NAME):
            raise ResourceNotSupported('CloudSQL Admin API disabled by server '
                                       'configuration.')
        return cloudsql.CloudsqlClient(self.config)

    def _create_compute(self):
        """Create compute API client.

        Returns:
            object: Client.

        Raises:
            ResourceNotSupported: Raised if polling is disabled for this API in
                the GCP API client configuration.
        """
        if is_api_disabled(self.config, compute.API_NAME):
            raise ResourceNotSupported('Compute Engine API disabled by server '
                                       'configuration.')
        return compute.ComputeClient(self.config)

    def _create_container(self):
        """Create Kubernetes Engine API client.

        Returns:
            object: Client.

        Raises:
            ResourceNotSupported: Raised if polling is disabled for this API in
                the GCP API client configuration.
        """
        if is_api_disabled(self.config, container.API_NAME):
            raise ResourceNotSupported('Kubernetes Engine API disabled by '
                                       'server configuration.')
        return container.ContainerClient(self.config)

    def _create_iam(self):
        """Create IAM API client.

        Returns:
            object: Client.

        Raises:
            ResourceNotSupported: Raised if polling is disabled for this API in
                the GCP API client configuration.
        """
        if is_api_disabled(self.config, iam.API_NAME):
            raise ResourceNotSupported('IAM API disabled by server '
                                       'configuration.')
        return iam.IAMClient(self.config)

    def _create_servicemanagement(self):
        """Create servicemanagement API client.

        Returns:
            object: Client.

        Raises:
            ResourceNotSupported: Raised if polling is disabled for this API in
                the GCP API client configuration.
        """
        if is_api_disabled(self.config, servicemanagement.API_NAME):
            raise ResourceNotSupported('Service Management API disabled by '
                                       'server configuration.')
        return servicemanagement.ServiceManagementClient(self.config)

    def _create_stackdriver_logging(self):
        """Create stackdriver_logging API client.

        Returns:
            object: Client.

        Raises:
            ResourceNotSupported: Raised if polling is disabled for this API in
                the GCP API client configuration.
        """
        if is_api_disabled(self.config, stackdriver_logging.API_NAME):
            raise ResourceNotSupported('Stackdriver Logging API disabled by '
                                       'server configuration.')
        return stackdriver_logging.StackdriverLoggingClient(self.config)

    def _create_storage(self):
        """Create storage API client.

        Returns:
            object: Client.

        Raises:
            ResourceNotSupported: Raised if polling is disabled for this API in
                the GCP API client configuration.
        """
        if is_api_disabled(self.config, storage.API_NAME):
            raise ResourceNotSupported('Storage API disabled by server '
                                       'configuration.')
        return storage.StorageClient(self.config)

    @create_lazy('bigquery', _create_bq)
    def fetch_bigquery_dataset_policy(self, project_id,
                                      project_number, dataset_id):
        """Dataset policy Iterator for a dataset from gcp API call.

        Args:
            project_id (str): id of the project to query.
            project_number (str): number of the project to query.
            dataset_id (str): id of the dataset to query.

        Returns:
            Tuple[dict, AssetMetadata]: Dataset Policy and asset
                metadata that defaults to None for all GCP clients.
        """
        del project_id

        return self.bigquery.get_dataset_access(
            project_number, dataset_id), None

    def fetch_bigquery_iam_policy(self, project_id, project_number, dataset_id):
        """Gets IAM policy of a bigquery dataset from gcp API call.

        Args:
            project_id (str): id of the project to query.
            project_number (str): number of the project to query.
            dataset_id (str): id of the dataset to query.

        Raises:
            ResourceNotSupported: Raised for all calls using this class.
        """
        raise ResourceNotSupported('Bigquery Dataset IAM policy is not '
                                   'supported by this API client')

    @create_lazy('bigquery', _create_bq)
    def iter_bigquery_datasets(self, project_number):
        """Iterate Datasets from GCP API.

        Args:
            project_number (str): number of the project to query.

        Yields:
            Tuple[dict, AssetMetadata]: Generator of datasets and asset
                metadata that defaults to None for all GCP clients.
        """
        for dataset in self.bigquery.get_datasets_for_projectid(project_number):
            yield dataset, None

    @create_lazy('bigquery', _create_bq)
    def iter_bigquery_tables(self, dataset_reference):
        """Iterate Tables from GCP API.

        Args:
            dataset_reference (dict): The project and dataset ID to get
                                      bigquery tables.

        Yields:
            Tuple[dict, AssetMetadata]: Generator of tables and asset
                metadata that defaults to None for all GCP clients.
        """
        for table in self.bigquery.get_tables(dataset_reference['projectId'],
                                              dataset_reference['datasetId']):
            yield table, None

    @create_lazy('cloudbilling', _create_cloudbilling)
    def fetch_billing_account_iam_policy(self, account_id):
        """Gets IAM policy of a Billing Account from GCP API.

        Args:
            account_id (str): id of the billing account to get policy.

        Returns:
            Tuple[dict, AssetMetadata]: Billing Account IAM policy and asset
                metadata that defaults to None for all GCP clients.
        """
        return (
            self.cloudbilling.get_billing_acct_iam_policies(account_id), None)

    @create_lazy('cloudbilling', _create_cloudbilling)
    def fetch_billing_project_info(self, project_number):
        """Project Billing Info from gcp API call.

        Args:
            project_number (str): number of the project to query.

        Returns:
            Tuple[dict, AssetMetadata]: Project Billing Info resource and asset
                metadata that defaults to None for all GCP clients.
        """
        return self.cloudbilling.get_billing_info(project_number), None

    @create_lazy('cloudbilling', _create_cloudbilling)
    def iter_billing_accounts(self):
        """Iterate visible Billing Accounts in an organization from GCP API.

        Yields:
            Tuple[dict, AssetMetadata]: Generator of billing accounts and asset
                metadata that defaults to None for all GCP clients.
        """
        for account in self.cloudbilling.get_billing_accounts():
            yield account, None

    @create_lazy('cloudsql', _create_cloudsql)
    def iter_cloudsql_instances(self, project_id, project_number):
        """Iterate Cloud sql instances from GCP API.

        Args:
            project_id (str): id of the project to query.
            project_number (str): number of the project to query.

        Yields:
            Tuple[dict, AssetMetadata]: Generator of cloudsql instance and
                asset metadata that defaults to None for all GCP clients.
        """
        del project_id  # Not used by the API client
        for item in self.cloudsql.get_instances(project_number):
            yield item, None

    @create_lazy('compute', _create_compute)
    def is_compute_api_enabled(self, project_number):
        """Verifies the Compute API is enabled on a project.

        Args:
            project_number (str): number of the project to query.

        Returns:
            bool: True if API is enabled, else False.
        """
        return self.compute.is_api_enabled(project_number)

    @create_lazy('compute', _create_compute)
    def fetch_compute_ig_instances(self, project_number, instance_group_name,
                                   region=None, zone=None):
        """Get the instances for an instance group from GCP API.

        One and only one of zone (for zonal instance groups) and region
        (for regional instance groups) must be specified.

        Args:
            project_number (str): number of the project to query.
            instance_group_name (str): The instance group's name.
            region (str): The regional instance group's region.
            zone (str): The zonal instance group's zone.

        Returns:
            Tuple[list, AssetMetadata]: instance URLs for this instance group
                and asset metadata that defaults to None for all GCP clients.
        """
        return self.compute.get_instance_group_instances(project_number,
                                                         instance_group_name,
                                                         region,
                                                         zone), None

    @create_lazy('compute', _create_compute)
    def fetch_compute_project(self, project_number):
        """Fetch compute project data from GCP API.

        Args:
            project_number (str): number of the project to query.

        Returns:
            Tuple[dict, AssetMetadata]: Compute project metadata resource and
                asset metadata that defaults to None for all GCP clients.
        """
        return self.compute.get_project(project_number), None

    def iter_compute_autoscalers(self, project_number):
        """Iterate Autoscalers from GCP API.

        Args:
            project_number (str): number of the project to query.

        Raises:
            ResourceNotSupported: Raised for all calls using this class.
        """
        raise ResourceNotSupported('Compute Autoscalers are not supported by '
                                   'this API client')

    def iter_compute_backendbuckets(self, project_number):
        """Iterate Backend buckets from GCP API.

        Args:
            project_number (str): number of the project to query.

        Raises:
            ResourceNotSupported: Raised for all calls using this class.
        """
        raise ResourceNotSupported('Compute BackendBuckets are not supported '
                                   'by this API client')

    @create_lazy('compute', _create_compute)
    def iter_compute_backendservices(self, project_number):
        """Iterate Backend services from GCP API.

        Args:
            project_number (str): number of the project to query.

        Yields:
            Tuple[dict, AssetMetadata]: Generator of backend service and
                asset metadata that defaults to None for all GCP clients.
        """
        for backendservice in self.compute.get_backend_services(project_number):
            yield backendservice, None

    @create_lazy('compute', _create_compute)
    def iter_compute_disks(self, project_number):
        """Iterate Compute Engine disks from GCP API.

        Args:
            project_number (str): number of the project to query.

        Yields:
            Tuple[dict, AssetMetadata]: Generator of compute disk and
                asset metadata that defaults to None for all GCP clients.
        """
        for disk in self.compute.get_disks(project_number):
            yield disk, None

    @create_lazy('compute', _create_compute)
    def iter_compute_firewalls(self, project_number):
        """Iterate Compute Engine Firewalls from GCP API.

        Args:
            project_number (str): number of the project to query.

        Yields:
            Tuple[dict, AssetMetadata]: Generator of Compute Engine Firewall
                and asset metadata that defaults to None for all GCP clients.
        """
        for rule in self.compute.get_firewall_rules(project_number):
            yield rule, None

    @create_lazy('compute', _create_compute)
    def iter_compute_forwardingrules(self, project_number):
        """Iterate Forwarding Rules from GCP API.

        Args:
            project_number (str): number of the project to query.

        Yields:
            Tuple[dict, AssetMetadata]: Generator of forwarding rule resources
                and asset metadata that defaults to None for all GCP clients.
        """
        for forwardingrule in self.compute.get_forwarding_rules(project_number):
            yield forwardingrule, None

    def iter_compute_healthchecks(self, project_number):
        """Iterate Health checks from GCP API.

        Args:
            project_number (str): number of the project to query.

        Raises:
            ResourceNotSupported: Raised for all calls using this class.
        """
        raise ResourceNotSupported('Compute HealthChecks are not supported by '
                                   'this API client')

    def iter_compute_httphealthchecks(self, project_number):
        """Iterate HTTP Health checks from GCP API.

        Args:
            project_number (str): number of the project to query.

        Raises:
            ResourceNotSupported: Raised for all calls using this class.
        """
        raise ResourceNotSupported('Compute HttpHealthChecks are not supported '
                                   'by this API client')

    def iter_compute_httpshealthchecks(self, project_number):
        """Iterate HTTPS Health checks from GCP API.

        Args:
            project_number (str): number of the project to query.

        Raises:
            ResourceNotSupported: Raised for all calls using this class.
        """
        raise ResourceNotSupported('Compute HttpsHealthChecks are not '
                                   'supported by this API client')

    @create_lazy('compute', _create_compute)
    def iter_compute_ig_managers(self, project_number):
        """Iterate Instance Group Manager from GCP API.

        Args:
            project_number (str): number of the project to query.

        Yields:
            Tuple[dict, AssetMetadata]: Generator of instance group manager
                resources and asset metadata that defaults to None for
                all GCP clients.
        """
        for igmanager in self.compute.get_instance_group_managers(
                project_number):
            yield igmanager, None

    @create_lazy('compute', _create_compute)
    def iter_compute_images(self, project_number):
        """Iterate Images from GCP API.

        Args:
            project_number (str): number of the project to query.

        Yields:
            Tuple[dict, AssetMetadata]: Generator of image resources resources
                and asset metadata that defaults to None for all GCP clients.
        """
        for image in self.compute.get_images(project_number):
            yield image, None

    @create_lazy('compute', _create_compute)
    def iter_compute_instancegroups(self, project_number):
        """Iterate Compute Engine groups from GCP API.

        Args:
            project_number (str): number of the project to query.

        Yields:
            Tuple[dict, AssetMetadata]: Generator of Compute Instance group
                and asset metadata that defaults to None for all GCP clients.
        """
        for instancegroup in self.compute.get_instance_groups(
                project_number, include_instance_urls=False):
            yield instancegroup, None

    @create_lazy('compute', _create_compute)
    def iter_compute_instances(self, project_number):
        """Iterate compute engine instance from GCP API.

        Args:
            project_number (str): number of the project to query.

        Yields:
            Tuple[dict, AssetMetadata]: Generator of Compute Engine Instance
                and asset metadata that defaults to None for all GCP clients.
        """
        for instance in self.compute.get_instances(project_number):
            yield instance, None

    @create_lazy('compute', _create_compute)
    def iter_compute_instancetemplates(self, project_number):
        """Iterate Instance Templates from GCP API.

        Args:
            project_number (str): number of the project to query.

        Yields:
            Tuple[dict, AssetMetadata]: Generator of instance template
                resources and asset metadata that defaults to None
                for all GCP clients.
        """
        for instancetemplate in self.compute.get_instance_templates(
                project_number):
            yield instancetemplate, None

    def iter_compute_licenses(self, project_number):
        """Iterate Licenses from GCP API.

        Args:
            project_number (str): number of the project to query.

        Raises:
            ResourceNotSupported: Raised for all calls using this class.
        """
        raise ResourceNotSupported('Compute Licenses are not supported by '
                                   'this API client')

    @create_lazy('compute', _create_compute)
    def iter_compute_networks(self, project_number):
        """Iterate Networks from GCP API.

        Args:
            project_number (str): number of the project to query.

        Yields:
            Tuple[dict, AssetMetadata]: Generator of network resources
                and asset metadata that defaults to None for all GCP clients.
        """
        for network in self.compute.get_networks(project_number):
            yield network, None

    def iter_compute_project(self, project_number):
        """Iterate Project from GCP API.

        Will only ever return up to 1 result. Ensures compatibility with other
        resource iterators.

        Args:
            project_number (str): number of the project to query.

        Yields:
            Tuple[dict, AssetMetadata]: Generator of compute project resources
                and asset metadata that defaults to None for all GCP clients.
        """
        yield self.fetch_compute_project(project_number)

    def iter_compute_routers(self, project_number):
        """Iterate Compute Engine routers from GCP API.

        Args:
            project_number (str): number of the project to query.

        Raises:
            ResourceNotSupported: Raised for all calls using this class.
        """
        raise ResourceNotSupported('Compute Routers are not supported '
                                   'by this API client')

    @create_lazy('compute', _create_compute)
    def iter_compute_snapshots(self, project_number):
        """Iterate Compute Engine snapshots from GCP API.

        Args:
            project_number (str): number of the project to query.

        Yields:
            Tuple[dict, AssetMetadata]: Generator of Compute Snapshots
                and asset metadata that defaults to None for all GCP clients.
        """
        for snapshot in self.compute.get_snapshots(project_number):
            yield snapshot, None

    def iter_compute_sslcertificates(self, project_number):
        """Iterate SSL Certificates from GCP API.

        Args:
            project_number (str): number of the project to query.

        Raises:
            ResourceNotSupported: Raised for all calls using this class.
        """
        raise ResourceNotSupported('Compute SslCertificates are not supported '
                                   'by this API client')

    @create_lazy('compute', _create_compute)
    def iter_compute_subnetworks(self, project_number):
        """Iterate Subnetworks from GCP API.

        Args:
            project_number (str): number of the project to query.

        Yields:
            Tuple[dict, AssetMetadata]: Generator of subnetwork resources
                and asset metadata that defaults to None for all GCP clients.
        """
        for subnetwork in self.compute.get_subnetworks(project_number):
            yield subnetwork, None

    def iter_compute_targethttpproxies(self, project_number):
        """Iterate Target HTTP proxies from GCP API.

        Args:
            project_number (str): number of the project to query.

        Raises:
            ResourceNotSupported: Raised for all calls using this class.
        """
        raise ResourceNotSupported('Compute TargetHttpProxies are not '
                                   'supported by this API client')

    def iter_compute_targethttpsproxies(self, project_number):
        """Iterate Target HTTPS proxies from GCP API.

        Args:
            project_number (str): number of the project to query.

        Raises:
            ResourceNotSupported: Raised for all calls using this class.
        """
        raise ResourceNotSupported('Compute TargetHttpsProxies are not '
                                   'supported by this API client')

    def iter_compute_targetinstances(self, project_number):
        """Iterate Target Instances from GCP API.

        Args:
            project_number (str): number of the project to query.

        Raises:
            ResourceNotSupported: Raised for all calls using this class.
        """
        raise ResourceNotSupported('Compute TargetInstances are not '
                                   'supported by this API client')

    def iter_compute_targetpools(self, project_number):
        """Iterate Target Pools from GCP API.

        Args:
            project_number (str): number of the project to query.

        Raises:
            ResourceNotSupported: Raised for all calls using this class.
        """
        raise ResourceNotSupported('Compute TargetPools are not '
                                   'supported by this API client')

    def iter_compute_targetsslproxies(self, project_number):
        """Iterate Target SSL proxies from GCP API.

        Args:
            project_number (str): number of the project to query.

        Raises:
            ResourceNotSupported: Raised for all calls using this class.
        """
        raise ResourceNotSupported('Compute TargetSslProxies are not '
                                   'supported by this API client')

    def iter_compute_targettcpproxies(self, project_number):
        """Iterate Target TCP proxies from GCP API.

        Args:
            project_number (str): number of the project to query.

        Raises:
            ResourceNotSupported: Raised for all calls using this class.
        """
        raise ResourceNotSupported('Compute TargetTcpProxies are not '
                                   'supported by this API client')

    def iter_compute_targetvpngateways(self, project_number):
        """Iterate Target VPN Gateways from GCP API.

        Args:
            project_number (str): number of the project to query.

        Raises:
            ResourceNotSupported: Raised for all calls using this class.
        """
        raise ResourceNotSupported('Compute TargetVpnGateways are not '
                                   'supported by this API client')

    def iter_compute_urlmaps(self, project_number):
        """Iterate URL maps from GCP API.

        Args:
            project_number (str): number of the project to query.

        Raises:
            ResourceNotSupported: Raised for all calls using this class.
        """
        raise ResourceNotSupported('Compute UrlMaps are not supported by this '
                                   'API client')

    def iter_compute_vpntunnels(self, project_number):
        """Iterate VPN tunnels from GCP API.

        Args:
            project_number (str): number of the project to query.

        Raises:
            ResourceNotSupported: Raised for all calls using this class.
        """
        raise ResourceNotSupported('Compute VpnTunnels are not supported by '
                                   'this API client')

    @create_lazy('container', _create_container)
    def fetch_container_serviceconfig(self, project_id, zone=None,
                                      location=None):
        """Fetch Kubernetes Engine per zone service config from GCP API.

        Args:
            project_id (str): id of the project to query.
            zone (str): zone of the Kubernetes Engine.
            location (str): location of the Kubernetes Engine.

        Returns:
            Tuple[dict, AssetMetadata]: Generator of Kubernetes Engine Cluster
                resources and asset metadata that defaults to None for all
                GCP clients.
        """
        return self.container.get_serverconfig(project_id, zone=zone,
                                               location=location), None

    @create_lazy('container', _create_container)
    def iter_container_clusters(self, project_number):
        """Iterate Kubernetes Engine Cluster from GCP API.

        Args:
            project_number (str): number of the project to query.

        Yields:
            Tuple[dict, AssetMetadata]: Generator of Kubernetes Engine Cluster
                resources and asset metadata that defaults to None for all
                GCP clients.
        """
        for cluster in self.container.get_clusters(project_number):

            # Don't store the master auth data in the database.
            if 'masterAuth' in cluster:
                cluster['masterAuth'] = {
                    k: '[redacted]'
                    for k in list(cluster['masterAuth'].keys())}

            yield cluster, None

    @create_lazy('crm', _create_crm)
    def fetch_crm_folder(self, folder_id):
        """Fetch Folder data from GCP API.

        Args:
            folder_id (str): id of the folder to query.

        Returns:
            Tuple[dict, AssetMetadata]: Folder resource and asset
                metadata that defaults to None for all GCP clients.
        """
        return self.crm.get_folder(folder_id), None

    @create_lazy('crm', _create_crm)
    def fetch_crm_folder_iam_policy(self, folder_id):
        """Folder IAM policy in a folder from gcp API call.

        Args:
            folder_id (str): id of the folder to get policy.

        Returns:
            Tuple[dict, AssetMetadata]: Folder IAM policy and asset
                metadata that defaults to None for all GCP clients.
        """
        return self.crm.get_folder_iam_policies(folder_id), None

    @create_lazy('crm', _create_crm)
    def fetch_crm_organization(self, org_id):
        """Fetch Organization data from GCP API.

        Args:
            org_id (str): id of the organization to get.

        Returns:
            Tuple[dict, AssetMetadata]: Organization resource and asset
                metadata that defaults to None for all GCP clients.
        """
        return self.crm.get_organization(org_id), None

    @create_lazy('crm', _create_crm)
    def fetch_crm_organization_iam_policy(self, org_id):
        """Organization IAM policy from gcp API call.

        Args:
            org_id (str): id of the organization to get policy.

        Returns:
           Tuple[dict, AssetMetadata]: Organization IAM policy and asset
                metadata that defaults to None for all GCP clients.
        """
        return self.crm.get_org_iam_policies(org_id), None

    @create_lazy('crm', _create_crm)
    def fetch_crm_project(self, project_number):
        """Fetch Project data from GCP API.

        Args:
            project_number (str): number of the project to query.

        Returns:
            Tuple[dict, AssetMetadata]: Project resource and asset
                metadata that defaults to None for all GCP clients.
        """
        return self.crm.get_project(project_number), None

    @create_lazy('crm', _create_crm)
    def fetch_crm_project_iam_policy(self, project_number):
        """Project IAM policy from gcp API call.

        Args:
            project_number (str): number of the project to query.

        Returns:
            Tuple[dict, AssetMetadata]: Project IAM policy and asset
                metadata that defaults to None for all GCP clients.
        """
        return self.crm.get_project_iam_policies(project_number), None

    @create_lazy('crm', _create_crm)
    def iter_crm_folder_org_policies(self, folder_id):
        """Folder organization policies from gcp API call.

        Args:
            folder_id (str): id of the folder to get policy.

        Yields:
            Tuple[dict, AssetMetadata]: Generator of org policies and asset
                metadata that defaults to None for all GCP clients.
        """
        for org_policy in self.crm.get_folder_org_policies(folder_id):
            yield org_policy, None

    @create_lazy('crm', _create_crm)
    def iter_crm_folders(self, parent_id):
        """Iterate Folders from GCP API.

        Args:
            parent_id (str): id of the parent of the folder.

        Yields:
            Tuple[dict, AssetMetadata]: Generator of folders and asset
                metadata that defaults to None for all GCP clients.
        """
        for folder in self.crm.get_folders(parent_id):
            yield folder, None

    @create_lazy('crm', _create_crm)
    def iter_crm_organization_org_policies(self, org_id):
        """Organization organization policies from gcp API call.

        Args:
            org_id (str): id of the organization to get policy.

        Yields:
            Tuple[dict, AssetMetadata]: Generator of org policies and asset
                metadata that defaults to None for all GCP clients.
        """
        for org_policy in self.crm.get_org_org_policies(org_id):
            yield org_policy, None

    @create_lazy('crm', _create_crm)
    def iter_crm_project_liens(self, project_number):
        """Iterate Liens from GCP API.

        Args:
            project_number (str): number of the parent project of the lien.

        Yields:
            Tuple[dict, AssetMetadata]: Generator of liens and asset
                metadata that defaults to None for all GCP clients.
        """
        for lien in self.crm.get_project_liens(project_number):
            yield lien, None

    @create_lazy('crm', _create_crm)
    def iter_crm_project_org_policies(self, project_number):
        """Project organization policies from gcp API call.

        Args:
            project_number (str): number of the parent project of the policy.

        Yields:
            Tuple[dict, AssetMetadata]: Generator of org policies and asset
                metadata that defaults to None for all GCP clients.
        """
        for org_policy in self.crm.get_project_org_policies(project_number):
            yield org_policy, None

    @create_lazy('crm', _create_crm)
    def iter_crm_projects(self, parent_type, parent_id):
        """Iterate Projects from GCP API.

        Args:
            parent_type (str): type of the parent, "folder" or "organization".
            parent_id (str): id of the parent of the folder.

        Yields:
            Tuple[dict, AssetMetadata]: Generator of projects and asset
                metadata that defaults to None for all GCP clients.
        """
        for page in self.crm.get_projects(parent_id=parent_id,
                                          parent_type=parent_type):
            for project in page.get('projects', []):
                yield project, None

    def fetch_dataproc_cluster_iam_policy(self, cluster):
        """Fetch Dataproc Cluster IAM Policy from GCP API.

        Args:
            cluster (str): The Dataproc cluster to query, must be in the format
                projects/{PROJECT_ID}/regions/{REGION}/clusters/{CLUSTER_NAME}

        Raises:
            ResourceNotSupported: Raised for all calls using this class.
        """
        raise ResourceNotSupported('Cloud Dataproc Clusters are not supported '
                                   'by this API client')

    def iter_dataproc_clusters(self, project_id, region=None):
        """Iterate Dataproc clusters from GCP API.

        Args:
            project_id (str): id of the project to query.
            region (str): The region to query. Not required when using Cloud
                Asset API.

        Raises:
            ResourceNotSupported: Raised for all calls using this class.
        """
        raise ResourceNotSupported('Cloud Dataproc Clusters are not supported '
                                   'by this API client')

    def iter_dns_managedzones(self, project_number):
        """Iterate CloudDNS Managed Zones from GCP API.

        Args:
            project_number (str): number of the parent project.

        Raises:
            ResourceNotSupported: Raised for all calls using this class.
        """
        raise ResourceNotSupported('Cloud DNS Managed Zones are not supported '
                                   'by this API client')

    def iter_dns_policies(self, project_number):
        """Iterate CloudDNS Policies from GCP API.

        Args:
            project_number (str): number of the parent project of the policy.

        Raises:
            ResourceNotSupported: Raised for all calls using this class.
        """
        raise ResourceNotSupported('Cloud DNS Policies are not supported by '
                                   'this API client')

    @create_lazy('appengine', _create_appengine)
    def fetch_gae_app(self, project_id):
        """Fetch the AppEngine App.

        Args:
            project_id (str): id of the project to query.

        Returns:
            Tuple[dict, AssetMetadata]: AppEngine App resource and asset
                metadata that defaults to None for all GCP clients.
        """
        return self.appengine.get_app(project_id), None

    @create_lazy('appengine', _create_appengine)
    def iter_gae_instances(self, project_id, service_id, version_id):
        """Iterate gae instances from GCP API.

        Args:
            project_id (str): id of the project to query.
            service_id (str): id of the appengine service.
            version_id (str): version id of the appengine.

        Yields:
            Tuple[dict, AssetMetadata]:Generator of AppEngine Instance
                resources and asset metadata that defaults to None for
                all GCP clients.
        """
        for instance in self.appengine.list_instances(
                project_id, service_id, version_id):
            yield instance, None

    @create_lazy('appengine', _create_appengine)
    def iter_gae_services(self, project_id):
        """Iterate gae services from GCP API.

        Args:
            project_id (str): id of the project to query.

        Yields:
            Tuple[dict, AssetMetadata]: Generator of AppEngine Service
                resources and asset metadata that defaults to None for
                all GCP clients.
        """
        for service in self.appengine.list_services(project_id):
            yield service, None

    @create_lazy('appengine', _create_appengine)
    def iter_gae_versions(self, project_id, service_id):
        """Iterate gae versions from GCP API.

        Args:
            project_id (str): id of the project to query.
            service_id (str): id of the appengine service.

        Yields:
            Tuple[dict, AssetMetadata]: Generator of AppEngine Version
                resources and asset metadata that defaults to None for
                all GCP clients.
        """
        for version in self.appengine.list_versions(project_id, service_id):
            yield version, None

    @create_lazy('ad', _create_ad)
    def iter_gsuite_group_members(self, group_key):
        """Iterate Gsuite group members from GCP API.

        Args:
            group_key (str): key of the group to get.

        Yields:
            Tuple[dict, AssetMetadata]: Generator of group_member
                and asset metadata that defaults to None for
                all GCP clients.
        """
        for member in self.ad.get_group_members(group_key):
            yield member, None

    @create_lazy('ad', _create_ad)
    def iter_gsuite_groups(self, gsuite_id):
        """Iterate Gsuite groups from GCP API.

        Args:
            gsuite_id (str): Gsuite id.

        Yields:
            Tuple[dict, AssetMetadata]: Generator of groups
                and asset metadata that defaults to None for
                all GCP clients.
        """
        result = self.ad.get_groups(gsuite_id)
        for group in result:
            yield group, None

    @create_lazy('groups_settings', _create_groups_settings)
    def fetch_gsuite_groups_settings(self, group_email):
        """Retrieve Gsuite groups settings from GCP API.

        Args:
            group_email (str): Gsuite group email.

        Returns:
            dict: Dictionary of groups settings.
        """
        # pylint:disable=no-member
        return self.groups_settings.get_groups_settings(group_email)

    @create_lazy('ad', _create_ad)
    def iter_gsuite_users(self, gsuite_id):
        """Iterate Gsuite users from GCP API.

        Args:
            gsuite_id (str): Gsuite id.

        Yields:
            Tuple[dict, AssetMetadata]: Generator of users
                and asset metadata that defaults to None for
                all GCP clients.
        """
        for user in self.ad.get_users(gsuite_id):
            yield user, None

    @create_lazy('iam', _create_iam)
    def fetch_iam_serviceaccount_iam_policy(self, name, unique_id):
        """Service Account IAM policy from gcp API call.

        Args:
            name (str): The service account name to query, must be in the format
                projects/{PROJECT_ID}/serviceAccounts/{SERVICE_ACCOUNT_EMAIL}
            unique_id (str): The unique id of the service account.

        Returns:
            Tuple[dict, AssetMetadata]: Service Account IAM policy and asset
                metadata that defaults to None for all GCP clients.
        """
        del unique_id  # Used by CAI, not the API.
        return self.iam.get_service_account_iam_policy(name), None

    @create_lazy('iam', _create_iam)
    def iter_iam_curated_roles(self):
        """Iterate Curated roles in an organization from GCP API.

        Yields:
            Tuple[dict, AssetMetadata]:Generator of curated roles and asset
                metadata that defaults to None for all GCP clients.
        """
        for role in self.iam.get_curated_roles():
            yield role, None

    @create_lazy('iam', _create_iam)
    def iter_iam_organization_roles(self, org_id):
        """Iterate Organization roles from GCP API.

        Args:
            org_id (str): id of the organization to get.

        Yields:
            Tuple[dict, AssetMetadata]:Generator of organization roles and
                asset metadata that defaults to None for all GCP clients.
        """
        for role in self.iam.get_organization_roles(org_id):
            yield role, None

    @create_lazy('iam', _create_iam)
    def iter_iam_project_roles(self, project_id, project_number):
        """Iterate Project roles in a project from GCP API.

        Args:
            project_id (str): id of the project to query.
            project_number (str): number of the project to query.

        Yields:
            Tuple[dict, AssetMetadata]:Generator of project roles and
                asset metadata that defaults to None for all GCP clients.
        """
        del project_number  # Used by CAI, not the API.
        for role in self.iam.get_project_roles(project_id):
            yield role, None

    @create_lazy('iam', _create_iam)
    def iter_iam_serviceaccount_exported_keys(self, name):
        """Iterate Service Account User Managed Keys from GCP API.

        Args:
            name (str): name of the service account.

        Yields:
            Tuple[dict, AssetMetadata]: Generator of service account user
                managed (exported) keys and asset metadata that defaults to
                None for all GCP clients.
        """
        for key in self.iam.get_service_account_keys(
                name, key_type=iam.IAMClient.USER_MANAGED):
            yield key, None

    @create_lazy('iam', _create_iam)
    def iter_iam_serviceaccounts(self, project_id, project_number):
        """Iterate Service Accounts in a project from GCP API.

        Args:
            project_id (str): id of the project to query.
            project_number (str): number of the project to query.

        Yields:
            Tuple[dict, AssetMetadata]: Generator of service account and
                asset metadata that defaults to None for all GCP clients.
        """
        del project_number  # Used by CAI, not the API.
        for serviceaccount in self.iam.get_service_accounts(project_id):
            yield serviceaccount, None

    def fetch_kms_cryptokey_iam_policy(self, cryptokey):
        """Fetch KMS Cryptokey IAM Policy from GCP API.

        Args:
            cryptokey (str): The KMS cryptokey to query, must be in the format
                projects/{PROJECT_ID}/locations/{LOCATION}/keyRings/{RING_NAME}/
                cryptoKeys/{CRYPTOKEY_NAME}

        Raises:
            ResourceNotSupported: Raised for all calls using this class.
        """
        raise ResourceNotSupported('Key Management Service is not supported by '
                                   'this API client')

    def fetch_kms_keyring_iam_policy(self, keyring):
        """Fetch KMS Keyring IAM Policy from GCP API.

        Args:
            keyring (str): The KMS keyring to query, must be in the format
                projects/{PROJECT_ID}/locations/{LOCATION}/keyRings/{RING_NAME}

        Raises:
            ResourceNotSupported: Raised for all calls using this class.
        """
        raise ResourceNotSupported('Key Management Service is not supported by '
                                   'this API client')

    def iter_kms_cryptokeys(self, parent):
        """Iterate KMS Cryptokeys in a keyring from GCP API.

        Args:
            parent (str): The KMS keyring to query, must be in the format
                projects/{PROJECT_ID}/locations/{LOCATION}/keyRings/{RING_NAME}

        Raises:
            ResourceNotSupported: Raised for all calls using this class.
        """
        raise ResourceNotSupported('Key Management Service is not supported by '
                                   'this API client')

    def iter_kms_cryptokeyversions(self, parent):
        """Iterate KMS Cryptokey Versions from GCP API.

        Args:
            parent (str): The KMS keyring to query, must be in the format
                projects/{PROJECT_ID}/locations/{LOCATION}/keyRings/{RING_NAME}/
                cryptoKeys/{CRYPTOKEY_NAME}

        Raises:
            ResourceNotSupported: Raised for all calls using this class.
        """
        raise ResourceNotSupported('Key Management Service is not supported by '
                                   'this API client')

    def iter_kms_keyrings(self, project_id, location=None):
        """Iterate KMS Keyrings in a project from GCP API.

        Args:
            project_id (str): id of the project to query.
            location (str): The location to query. Not required when
                using Cloud Asset API.

        Raises:
            ResourceNotSupported: Raised for all calls using this class.
        """
        raise ResourceNotSupported('Key Management Service is not supported by '
                                   'this API client')

    def iter_kubernetes_nodes(self, project_id, zone, cluster):
        """Iterate k8s nodes in an organization from GCP API.
         Args:
            project_id (str): id of the project to query.
            zone (str): The zone the cluster is in.
            cluster (str): The cluster name.
         Raises:
            ResourceNotSupported: Raised for all calls using this class.
        """
        raise ResourceNotSupported('Kubernetes resources are not supported '
                                   'by this API client')

    def iter_kubernetes_pods(self, project_id, zone, cluster, namespace):
        """Iterate k8s pods in an organization from GCP API.
         Args:
            project_id (str): id of the project to query.
            zone (str): The zone the cluster is in.
            cluster (str): The cluster name.
            namespace (str): The namespace name.
         Raises:
            ResourceNotSupported: Raised for all calls using this class.
        """
        raise ResourceNotSupported('Kubernetes resources are not supported '
                                   'by this API client')

    def iter_kubernetes_namespaces(self, project_id, zone, cluster):
        """Iterate k8s namespaces in an organization from GCP API.
         Args:
            project_id (str): id of the project to query.
            zone (str): The zone the cluster is in.
            cluster (str): The cluster name.
         Raises:
            ResourceNotSupported: Raised for all calls using this class.
        """
        raise ResourceNotSupported('Kubernetes resources are not supported '
                                   'by this API client')

    def iter_kubernetes_roles(self, project_id, zone, cluster, namespace):
        """Iterate k8s roles in an organization from GCP API.
         Args:
            project_id (str): id of the project to query.
            zone (str): The zone the cluster is in.
            cluster (str): The cluster name.
            namespace (str): The namespace name.
         Raises:
            ResourceNotSupported: Raised for all calls using this class.
        """
        raise ResourceNotSupported('Kubernetes resources are not supported '
                                   'by this API client')

    def iter_kubernetes_rolebindings(self, project_id, zone, cluster, namespace):
        """Iterate k8s role bindings in an organization from GCP API.
         Args:
            project_id (str): id of the project to query.
            zone (str): The zone the cluster is in.
            cluster (str): The cluster name.
            namespace (str): The namespace name.
         Raises:
            ResourceNotSupported: Raised for all calls using this class.
        """
        raise ResourceNotSupported('Kubernetes resources are not supported '
                                   'by this API client')

    def iter_kubernetes_clusterroles(self, project_id, zone, cluster):
        """Iterate k8s cluster roles in an organization from GCP API.
         Args:
            project_id (str): id of the project to query.
            zone (str): The zone the cluster is in.
            cluster (str): The cluster name
         Raises:
            ResourceNotSupported: Raised for all calls using this class.
        """
        raise ResourceNotSupported('Kubernetes resources are not supported '
                                   'by this API client')

    def iter_kubernetes_clusterrolebindings(self, project_id, zone, cluster):
        """Iterate k8s cluster role bindings in an organization from GCP API.
           data.
         Args:
            project_id (str): id of the project to query.
            zone (str): The zone the cluster is in.
            cluster (str): The cluster name
         Raises:
            ResourceNotSupported: Raised for all calls using this class.
        """
        raise ResourceNotSupported('Kubernetes resources are not supported '
                                   'by this API client')

    def fetch_pubsub_subscription_iam_policy(self, name):
        """PubSub Subscription IAM policy from gcp API call.

        Args:
            name (str): The pubsub topic to query, must be in the format
               projects/{PROJECT_ID}/subscriptions/{SUBSCRIPTION_NAME}

        Raises:
            ResourceNotSupported: Raised for all calls using this class.
        """
        raise ResourceNotSupported('PubSub Subscriptions are not supported by '
                                   'this API client')

    def fetch_pubsub_topic_iam_policy(self, name):
        """PubSub Topic IAM policy from gcp API call.

        Args:
            name (str): The pubsub topic to query, must be in the format
                projects/{PROJECT_ID}/topics/{TOPIC_NAME}

        Raises:
            ResourceNotSupported: Raised for all calls using this class.
        """
        raise ResourceNotSupported('PubSub Topics are not supported by this '
                                   'API client')

    def iter_pubsub_subscriptions(self, project_id, project_number):
        """Iterate PubSub subscriptions from GCP API.

        Args:
            project_id (str): id of the project to query.
            project_number (str): number of the project to query.

        Raises:
            ResourceNotSupported: Raised for all calls using this class.
        """
        raise ResourceNotSupported('PubSub Subscriptions are not supported by '
                                   'this API client')

    def iter_pubsub_topics(self, project_id, project_number):
        """Iterate PubSub topics from GCP API.

        Args:
            project_id (str): id of the project to query.
            project_number (str): number of the project to query.

        Raises:
            ResourceNotSupported: Raised for all calls using this class.
        """
        raise ResourceNotSupported('PubSub Topics are not supported by this '
                                   'API client')

    @create_lazy('servicemanagement', _create_servicemanagement)
    def fetch_services_enabled_apis(self, project_number):
        """Project enabled API services from gcp API call.

        Args:
            project_number (str): number of the project to query.

        Returns:
            Tuple[list, AssetMetadata]:A list of ManagedService resource dicts
                and asset metadata that defaults to None for all GCP clients.
        """
        return self.servicemanagement.get_enabled_apis(project_number), None

    def iter_spanner_instances(self, project_number):
        """Iterate Spanner Instances from GCP API.

        Args:
            project_number (str): number of the project to query.

        Raises:
            ResourceNotSupported: Raised for all calls using this class.
        """
        raise ResourceNotSupported('Spanner Instances are not supported by '
                                   'this API client')

    def iter_spanner_databases(self, parent):
        """Iterate Spanner Databases from GCP API.

        Args:
            parent (str): parent spanner instance to query.

        Raises:
            ResourceNotSupported: Raised for all calls using this class.
        """
        raise ResourceNotSupported('Spanner Databases are not supported by '
                                   'this API client')

    @create_lazy('stackdriver_logging', _create_stackdriver_logging)
    def iter_stackdriver_billing_account_sinks(self, acct_id):
        """Iterate Billing Account logging sinks from GCP API.

        Args:
            acct_id (str): id of the billing account to query.

        Yields:
            Tuple[dict, AssetMetadata]:Generator of billing account logging
                sinks and asset metadata that defaults to None for all
                GCP clients.
        """
        for sink in self.stackdriver_logging.get_billing_account_sinks(acct_id):
            yield sink, None

    @create_lazy('stackdriver_logging', _create_stackdriver_logging)
    def iter_stackdriver_folder_sinks(self, folder_id):
        """Iterate Folder logging sinks from GCP API.

        Args:
            folder_id (str): id of the folder to query.

        Yields:
            Tuple[dict, AssetMetadata]:Generator of folder logging
                sinks and asset metadata that defaults to None for all
                GCP clients.
        """
        for sink in self.stackdriver_logging.get_folder_sinks(folder_id):
            yield sink, None

    @create_lazy('stackdriver_logging', _create_stackdriver_logging)
    def iter_stackdriver_organization_sinks(self, org_id):
        """Iterate Organization logging sinks from GCP API.

        Args:
            org_id (str): id of the organization to query.

        Yields:
            Tuple[dict, AssetMetadata]:Generator of organization logging
                sinks and asset metadata that defaults to None for all
                GCP clients.
        """
        for sink in self.stackdriver_logging.get_organization_sinks(org_id):
            yield sink, None

    @create_lazy('stackdriver_logging', _create_stackdriver_logging)
    def iter_stackdriver_project_sinks(self, project_number):
        """Iterate Project logging sinks from GCP API.

        Args:
            project_number (str): number of the project to query.

        Yields:
            Tuple[dict, AssetMetadata]:Generator of project logging
                sinks and asset metadata that defaults to None for all
                GCP clients.
        """
        for sink in self.stackdriver_logging.get_project_sinks(project_number):
            yield sink, None

    @create_lazy('storage', _create_storage)
    def fetch_storage_bucket_acls(self, bucket_id, project_id, project_number):
        """Bucket Access Controls from GCP API.

        Args:
            bucket_id (str): id of the bucket to query.
            project_id (str): id of the project to query.
            project_number (str): number of the project to query.

        Returns:
            Tuple[list, AssetMetadata]: Bucket Access Controls
                and asset metadata that defaults to None for all
                GCP clients.
        """
        del project_id, project_number
        return self.storage.get_bucket_acls(bucket_id), None

    @create_lazy('storage', _create_storage)
    def fetch_storage_bucket_iam_policy(self, bucket_id):
        """Bucket IAM policy Iterator from gcp API call.

        Args:
            bucket_id (str): id of the bucket to query.

        Returns:
            Tuple[dict, AssetMetadata]: Bucket IAM policy
                and asset metadata that defaults to None for all
                GCP clients.
        """
        return self.storage.get_bucket_iam_policy(bucket_id), None

    @create_lazy('storage', _create_storage)
    def fetch_storage_object_iam_policy(self, bucket_name, object_name):
        """Object IAM policy Iterator for an object from gcp API call.

        Args:
            bucket_name (str): name of the bucket.
            object_name (str): name of the object.

        Returns:
            Tuple[dict, AssetMetadata]: Object IAM policy
                and asset metadata that defaults to None for all
                GCP clients.
        """
        return self.storage.get_storage_object_iam_policy(bucket_name,
                                                          object_name), None

    @create_lazy('storage', _create_storage)
    def iter_storage_buckets(self, project_number):
        """Iterate Buckets from GCP API.

        Args:
            project_number (str): number of the project to query.

        Yields:
            Tuple[dict, AssetMetadata]: Generator of buckets
                and asset metadata that defaults to None for all
                GCP clients.
        """
        for bucket in self.storage.get_buckets(project_number):
            yield bucket, None

    @create_lazy('storage', _create_storage)
    def iter_storage_objects(self, bucket_id):
        """Iterate Objects from GCP API.

        Args:
            bucket_id (str): id of the bucket to get.

        Yields:
            Tuple[dict, AssetMetadata]: Generator of objects
                and asset metadata that defaults to None for all
                GCP clients.
        """
        for gcs_object in self.storage.get_objects(bucket_name=bucket_id):
            yield gcs_object, None
