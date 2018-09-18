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

# pylint: disable=invalid-name,arguments-differ
# pylint: disable=too-many-public-methods,too-many-instance-attributes

from google.cloud.forseti.common.gcp_api import admin_directory
from google.cloud.forseti.common.gcp_api import appengine
from google.cloud.forseti.common.gcp_api import bigquery
from google.cloud.forseti.common.gcp_api import cloud_resource_manager
from google.cloud.forseti.common.gcp_api import cloudbilling
from google.cloud.forseti.common.gcp_api import cloudsql
from google.cloud.forseti.common.gcp_api import compute
from google.cloud.forseti.common.gcp_api import container
from google.cloud.forseti.common.gcp_api import iam
from google.cloud.forseti.common.gcp_api import servicemanagement
from google.cloud.forseti.common.gcp_api import stackdriver_logging
from google.cloud.forseti.common.gcp_api import storage


class ApiClient(object):
    """The gcp api client interface"""
    def fetch_organization(self, orgid):
        """Not Implemented.

        Args:
            orgid (str): id of the organization to get

        Raises:
            NotImplementedError: Because not implemented.
        """
        raise NotImplementedError()

    def iter_projects(self, orgid):
        """Not Implemented.

        Args:
            orgid (str): id of the organization to get

        Raises:
            NotImplementedError: Because not implemented.
        """
        raise NotImplementedError()

    def iter_folders(self, orgid):
        """Not Implemented.

        Args:
            orgid (str): id of the organization to get

        Raises:
            NotImplementedError: Because not implemented.
        """
        raise NotImplementedError()

    def iter_buckets(self, projectid):
        """Not Implemented.

        Args:
            projectid (str): id of the project to query

        Raises:
            NotImplementedError: Because not implemented.
        """
        raise NotImplementedError()

    def iter_objects(self, bucket_id):
        """Not Implemented.

        Args:
            bucket_id (str): id of the bucket to get

        Raises:
            NotImplementedError: Because not implemented.
        """
        raise NotImplementedError()

    def get_organization_iam_policy(self, orgid):
        """Not Implemented.

        Args:
            orgid (str): id of the organization to get

        Raises:
            NotImplementedError: Because not implemented.
        """
        raise NotImplementedError()

    def get_project_iam_policy(self, projectid):
        """Not Implemented.

        Args:
            projectid (str): id of the project to query

        Raises:
            NotImplementedError: Because not implemented.
        """
        raise NotImplementedError()


def create_lazy(attribute, factory):
    """Create attributes right before they are needed.

    Args:
        attribute (str): Attribute name to check/create
        factory (function): Factory to create object

    Returns:
        function: Decorator
    """
    def f_wrapper(func):
        """Create decorator

        Args:
            func (function): Function to wrap.

        Returns:
            function: Decorator
        """

        def wrapper(*args, **kwargs):
            """Decorator implementation

            Args:
                *args (list): Original func arguments
                **kwargs (dict): Original func arguments

            Returns:
                object: Result produced by the wrapped func
            """
            this = args[0]
            if not hasattr(this, attribute) or not getattr(this, attribute):
                setattr(this, attribute, factory(this))
            return func(*args, **kwargs)
        return wrapper
    return f_wrapper


class ApiClientImpl(ApiClient):
    """The gcp api client Implementation"""
    def __init__(self, config):
        """Initialize

        Args:
            config (dict): GCP API client configuration
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
        self.cached_folders = None
        self.cached_projects = None

    def _create_ad(self):
        """Create admin directory API client

        Returns:
            object: Client
        """
        return admin_directory.AdminDirectoryClient(self.config)

    def _create_appengine(self):
        """Create AppEngine API client

        Returns:
            object: Client
        """
        return appengine.AppEngineClient(self.config)

    def _create_bq(self):
        """Create bigquery API client
        Returns:

            object: Client
        """
        return bigquery.BigQueryClient(self.config)

    def _create_crm(self):
        """Create resource manager API client

        Returns:
            object: Client
        """
        return cloud_resource_manager.CloudResourceManagerClient(self.config)

    def _create_cloudbilling(self):
        """Create cloud billing API client

        Returns:
            object: Client
        """
        return cloudbilling.CloudBillingClient(self.config)

    def _create_cloudsql(self):
        """Create cloud sql API client

        Returns:
            object: Client
        """
        return cloudsql.CloudsqlClient(self.config)

    def _create_compute(self):
        """Create compute API client

        Returns:
            object: Client
        """
        return compute.ComputeClient(self.config)

    def _create_container(self):
        """Create Kubernetes Engine API client

        Returns:
            object: Client
        """
        return container.ContainerClient(self.config)

    def _create_iam(self):
        """Create IAM API client

        Returns:
            object: Client
        """
        return iam.IAMClient(self.config)

    def _create_servicemanagement(self):
        """Create servicemanagement API client

        Returns:
            object: Client
        """
        return servicemanagement.ServiceManagementClient(self.config)

    def _create_stackdriver_logging(self):
        """Create stackdriver_logging API client

        Returns:
            object: Client
        """
        return stackdriver_logging.StackdriverLoggingClient(self.config)

    def _create_storage(self):
        """Create storage API client

        Returns:
            object: Client
        """
        return storage.StorageClient(self.config)

    @create_lazy('ad', _create_ad)
    def iter_users(self, gsuite_id):
        """Iterate Gsuite users from GCP API.

        Args:
            gsuite_id (str): Gsuite id

        Yields:
            dict: Generator of user
        """
        for user in self.ad.get_users(gsuite_id):
            yield user

    @create_lazy('ad', _create_ad)
    def iter_groups(self, gsuite_id):
        """Iterate Gsuite groups from GCP API.

        Args:
            gsuite_id (str): Gsuite id

        Yields:
            dict: Generator of groups
        """
        result = self.ad.get_groups(gsuite_id)
        for group in result:
            yield group

    @create_lazy('ad', _create_ad)
    def iter_group_members(self, group_key):
        """Iterate Gsuite group members from GCP API.

        Args:
            group_key (str): key of the group to get

        Yields:
            dict: Generator of group_member
        """
        for member in self.ad.get_group_members(group_key):
            yield member

    @create_lazy('crm', _create_crm)
    def fetch_organization(self, orgid):
        """Fetch Organization data from GCP API.

        Args:
            orgid (str): id of the organization to get

        Returns:
            dict: Generator of organization
        """
        return self.crm.get_organization(orgid)

    @create_lazy('crm', _create_crm)
    def fetch_folder(self, folderid):
        """Fetch Folder data from GCP API.

        Args:
            folderid (str): id of the folder to query

        Returns:
            dict: Generator of folder
        """
        return self.crm.get_folder(folderid)

    @create_lazy('crm', _create_crm)
    def fetch_project(self, projectid):
        """Fetch Project data from GCP API.

        Args:
            projectid (str): id of the project to query

        Returns:
            dict: Generator of project
        """
        return self.crm.get_project(projectid)

    @create_lazy('crm', _create_crm)
    def iter_projects(self, parent_type, parent_id):
        """Iterate Projects from GCP API.

        Args:
            parent_type (str): type of the parent, "folder" or "organization"
            parent_id (str): id of the parent of the folder

        Yields:
            dict: Generator of projects
        """
        for page in self.crm.get_projects(parent_id=parent_id,
                                          parent_type=parent_type):
            for project in page.get('projects', []):
                yield project

    @create_lazy('crm', _create_crm)
    def iter_folders(self, parent_id):
        """Iterate Folders from GCP API.

        Args:
            parent_id (str): id of the parent of the folder

        Yields:
            dict: Generator of folders
        """
        for folder in self.crm.get_folders(parent_id):
            yield folder

    @create_lazy('crm', _create_crm)
    def iter_project_liens(self, project_id):
        """Iterate Liens from GCP API.

        Args:
            project_id (str): id of the parent project of the lien.

        Yields:
            dict: Generator of liens
        """
        for lien in self.crm.get_project_liens(project_id):
            yield lien

    @create_lazy('appengine', _create_appengine)
    def fetch_gae_app(self, projectid):
        """Fetch the AppEngine App.

        Args:
            projectid (str): id of the project to query

        Returns:
            dict: AppEngine App resource.
        """
        return self.appengine.get_app(projectid)

    @create_lazy('appengine', _create_appengine)
    def iter_gae_services(self, projectid):
        """Iterate gae services from GCP API.

        Args:
            projectid (str): id of the project to query

        Yields:
            dict: Generator of AppEngine Service resources.
        """
        for service in self.appengine.list_services(projectid):
            yield service

    @create_lazy('appengine', _create_appengine)
    def iter_gae_versions(self, projectid, serviceid):
        """Iterate gae versions from GCP API.

        Args:
            projectid (str): id of the project to query
            serviceid (str): id of the appengine service

        Yields:
            dict: Generator of AppEngine Version resources.
        """
        for version in self.appengine.list_versions(projectid, serviceid):
            yield version

    @create_lazy('appengine', _create_appengine)
    def iter_gae_instances(self, projectid, serviceid, versionid):
        """Iterate gae instances from GCP API.

        Args:
            projectid (str): id of the project to query
            serviceid (str): id of the appengine service
            versionid (str): version id of the appengine

        Yields:
            dict: Generator of AppEngine Instance resources.
        """
        for instance in self.appengine.list_instances(
                projectid, serviceid, versionid):
            yield instance

    @create_lazy('container', _create_container)
    def iter_container_clusters(self, projectid):
        """Iterate Kubernetes Engine Cluster from GCP API.

        Args:
            projectid (str): id of the project to query

        Yields:
            dict: Generator of Kubernetes Engine Cluster resources.
        """
        for cluster in self.container.get_clusters(projectid):

            # Don't store the master auth data in the database.
            if 'masterAuth' in cluster:
                cluster['masterAuth'] = {
                    k: '[redacted]'
                    for k in cluster['masterAuth'].keys()}

            yield cluster

    @create_lazy('container', _create_container)
    def fetch_container_serviceconfig(self, projectid, zone=None,
                                      location=None):
        """Fetch Kubernetes Engine per zone service config from GCP API.

        Args:
            projectid (str): id of the project to query
            zone (str): zone of the Kubernetes Engine
            location (str): location of the Kubernetes Engine

        Returns:
            dict: Generator of Kubernetes Engine Cluster resources.
        """
        return self.container.get_serverconfig(projectid, zone=zone,
                                               location=location)

    @create_lazy('storage', _create_storage)
    def iter_buckets(self, projectid):
        """Iterate Buckets from GCP API.

        Args:
            projectid (str): id of the project to query

        Yields:
            dict: Generator of buckets
        """
        for bucket in self.storage.get_buckets(projectid):
            yield bucket

    @create_lazy('storage', _create_storage)
    def iter_objects(self, bucket_id):
        """Iterate Objects from GCP API.

        Args:
            bucket_id (str): id of the bucket to get

        Yields:
            dict: Generator of objects
        """
        for object_ in self.storage.get_objects(bucket_name=bucket_id):
            yield object_

    @create_lazy('bigquery', _create_bq)
    def iter_datasets(self, projectid):
        """Iterate Datasets from GCP API.

        Args:
            projectid (str): id of the project to query

        Yields:
            dict: Generator of datasets
        """
        for dataset in self.bigquery.get_datasets_for_projectid(projectid):
            yield dataset

    @create_lazy('cloudsql', _create_cloudsql)
    def iter_cloudsqlinstances(self, projectid):
        """Iterate Cloud sql instances from GCP API.

        Args:
            projectid (str): id of the project to query

        Yields:
            dict: Generator of cloudsql instance
        """
        for item in self.cloudsql.get_instances(projectid):
            yield item

    @create_lazy('compute', _create_compute)
    def is_compute_api_enabled(self, projectid):
        """Verifies the Compute API is enabled on a project.

        Args:
            projectid (str): id of the project to query

        Returns:
            bool: True if API is enabled, else False.
        """
        return self.compute.is_api_enabled(projectid)

    @create_lazy('compute', _create_compute)
    def fetch_compute_project(self, projectid):
        """Fetch compute project data from GCP API.

        Args:
            projectid (str): id of the project to query

        Returns:
            dict: Compute project metadata resource.
        """
        return self.compute.get_project(projectid)

    @create_lazy('compute', _create_compute)
    def iter_computeinstances(self, projectid):
        """Iterate compute engine instance from GCP API.

        Args:
            projectid (str): id of the project to query

        Yields:
            dict: Generator of Compute Engine Instance
        """
        for instance in self.compute.get_instances(projectid):
            yield instance

    @create_lazy('compute', _create_compute)
    def iter_computefirewalls(self, projectid):
        """Iterate Compute Engine Firewalls from GCP API.

        Args:
            projectid (str): id of the project to query

        Yields:
            dict: Generator of Compute Engine Firewall
        """
        for rule in self.compute.get_firewall_rules(projectid):
            yield rule

    @create_lazy('compute', _create_compute)
    def iter_computeinstancegroups(self, projectid):
        """Iterate Compute Engine groups from GCP API.

        Args:
            projectid (str): id of the project to query

        Yields:
            dict: Generator of Compute Instance group
        """
        for instancegroup in self.compute.get_instance_groups(projectid):
            yield instancegroup

    @create_lazy('compute', _create_compute)
    def iter_computedisks(self, projectid):
        """Iterate Compute Engine disks from GCP API.

        Args:
            projectid (str): id of the project to query

        Yields:
            dict: Generator of Compute Disk
        """
        for disk in self.compute.get_disks(projectid):
            yield disk

    @create_lazy('compute', _create_compute)
    def iter_backendservices(self, projectid):
        """Iterate Backend services from GCP API.

        Args:
            projectid (str): id of the project to query

        Yields:
            dict: Generator of backend service
        """
        for backendservice in self.compute.get_backend_services(projectid):
            yield backendservice

    @create_lazy('compute', _create_compute)
    def iter_forwardingrules(self, projectid):
        """Iterate Forwarding Rules from GCP API.

        Args:
            projectid (str): id of the project to query

        Yields:
            dict: Generator of forwarding rule resources
        """
        for forwardingrule in self.compute.get_forwarding_rules(projectid):
            yield forwardingrule

    @create_lazy('compute', _create_compute)
    def iter_images(self, projectid):
        """Iterate Images from GCP API.

        Args:
            projectid (str): id of the project to query

        Yields:
            dict: Generator of image resources
        """
        for image in self.compute.get_images(projectid):
            yield image

    @create_lazy('compute', _create_compute)
    def iter_ig_managers(self, projectid):
        """Iterate Instance Group Manager from GCP API.

        Args:
            projectid (str): id of the project to query

        Yields:
            dict: Generator of instance group manager resources
        """
        for igmanager in self.compute.get_instance_group_managers(projectid):
            yield igmanager

    @create_lazy('compute', _create_compute)
    def iter_instancetemplates(self, projectid):
        """Iterate Instance Templates from GCP API.

        Args:
            projectid (str): id of the project to query

        Yields:
            dict: Generator of instance template resources
        """
        for instancetemplate in self.compute.get_instance_templates(projectid):
            yield instancetemplate

    @create_lazy('compute', _create_compute)
    def iter_networks(self, projectid):
        """Iterate Networks from GCP API.

        Args:
            projectid (str): id of the project to query

        Yields:
            dict: Generator of network resources
        """
        for network in self.compute.get_networks(projectid):
            yield network

    @create_lazy('compute', _create_compute)
    def iter_snapshots(self, projectid):
        """Iterate Compute Engine snapshots from GCP API.

        Args:
            projectid (str): id of the project to query

        Yields:
            dict: Generator of Compute Snapshots
        """
        for snapshot in self.compute.get_snapshots(projectid):
            yield snapshot

    @create_lazy('compute', _create_compute)
    def iter_subnetworks(self, projectid):
        """Iterate Subnetworks from GCP API.

        Args:
            projectid (str): id of the project to query

        Yields:
            dict: Generator of subnetwork resources
        """
        for subnetwork in self.compute.get_subnetworks(projectid):
            yield subnetwork

    @create_lazy('iam', _create_iam)
    def iter_serviceaccounts(self, projectid):
        """Iterate Service Accounts in a project from GCP API.

        Args:
            projectid (str): id of the project to query

        Yields:
            dict: Generator of service account
        """
        for serviceaccount in self.iam.get_service_accounts(projectid):
            yield serviceaccount

    @create_lazy('iam', _create_iam)
    def iter_serviceaccount_exported_keys(self, name):
        """Iterate Service Account User Managed Keys from GCP API.

        Args:
            name (str): name of the service account

        Yields:
            dict: Generator of service account user managed (exported) keys
        """
        for key in self.iam.get_service_account_keys(
                name, key_type=iam.IAMClient.USER_MANAGED):
            yield key

    @create_lazy('iam', _create_iam)
    def iter_project_roles(self, projectid):
        """Iterate Project roles in a project from GCP API.

        Args:
            projectid (str): id of the project to query

        Yields:
            dict: Generator of project roles
        """
        for role in self.iam.get_project_roles(projectid):
            yield role

    @create_lazy('iam', _create_iam)
    def iter_organization_roles(self, orgid):
        """Iterate Organization roles from GCP API.

        Args:
            orgid (str): id of the organization to get

        Yields:
            dict: Generator of organization role
        """
        for role in self.iam.get_organization_roles(orgid):
            yield role

    @create_lazy('iam', _create_iam)
    def iter_curated_roles(self):
        """Iterate Curated roles in an organization from GCP API.

        Yields:
            dict: Generator of curated roles
        """
        for role in self.iam.get_curated_roles():
            yield role

    @create_lazy('crm', _create_crm)
    def get_folder_iam_policy(self, folderid):
        """Folder IAM policy in a folder from gcp API call

        Args:
            folderid (str): id of the folder to get policy

        Returns:
            dict: Folder IAM policy
        """
        return self.crm.get_folder_iam_policies(folderid)

    @create_lazy('crm', _create_crm)
    def get_organization_iam_policy(self, orgid):
        """Organization IAM policy from gcp API call

        Args:
            orgid (str): id of the organization to get policy

        Returns:
            dict: Organization IAM policy
        """
        return self.crm.get_org_iam_policies(orgid)

    @create_lazy('crm', _create_crm)
    def get_project_iam_policy(self, projectid):
        """Project IAM policy from gcp API call

        Args:
            projectid (str): id of the project to query

        Returns:
            dict: Project IAM Policy
        """
        return self.crm.get_project_iam_policies(projectid)

    @create_lazy('iam', _create_iam)
    def get_serviceaccount_iam_policy(self, name):
        """Service Account IAM policy from gcp API call.

        Args:
            name (str): The service account name to query, must be in the format
                projects/{PROJECT_ID}/serviceAccounts/{SERVICE_ACCOUNT_EMAIL}

        Returns:
            dict: Service Account IAM policy.
        """
        return self.iam.get_service_account_iam_policy(name)

    @create_lazy('storage', _create_storage)
    def get_bucket_iam_policy(self, bucketid):
        """Bucket IAM policy Iterator from gcp API call

        Args:
            bucketid (str): id of the bucket to query

        Returns:
            dict: Bucket IAM policy
        """
        return self.storage.get_bucket_iam_policy(bucketid)

    @create_lazy('storage', _create_storage)
    def get_object_iam_policy(self, bucket_name, object_name):
        """Object IAM policy Iterator for an object from gcp API call

        Args:
            bucket_name (str): name of the bucket
            object_name (str): name of the object

        Returns:
            dict: Object IAM policy
        """
        return self.storage.get_object_iam_policy(bucket_name, object_name)

    @create_lazy('bigquery', _create_bq)
    def get_dataset_dataset_policy(self, projectid, datasetid):
        """Dataset policy Iterator for a dataset from gcp API call

        Args:
            projectid (str): id of the project to query
            datasetid (str): id of the dataset to query

        Returns:
            dict: Dataset Policy
        """
        return self.bigquery.get_dataset_access(projectid, datasetid)

    @create_lazy('cloudbilling', _create_cloudbilling)
    def get_project_billing_info(self, projectid):
        """Project Billing Info from gcp API call

        Args:
            projectid (str): id of the project to query

        Returns:
            dict: Project Billing Info resource.
        """
        return self.cloudbilling.get_billing_info(projectid)

    @create_lazy('cloudbilling', _create_cloudbilling)
    def iter_billing_accounts(self):
        """Iterate visible Billing Accounts in an organization from GCP API.

        Yields:
            dict: Generator of billing accounts.
        """
        for account in self.cloudbilling.get_billing_accounts():
            yield account

    @create_lazy('cloudbilling', _create_cloudbilling)
    def get_billing_account_iam_policy(self, accountid):
        """Gets IAM policy of a Billing Account from GCP API.

        Args:
            accountid (str): id of the billing account to get policy.

        Returns:
            dict: Billing Account IAM policy
        """
        return self.cloudbilling.get_billing_acct_iam_policies(accountid)

    @create_lazy('servicemanagement', _create_servicemanagement)
    def get_enabled_apis(self, projectid):
        """Project enabled API services from gcp API call.

        Args:
            projectid (str): id of the project to query

        Returns:
            list: A list of ManagedService resource dicts.
        """
        return self.servicemanagement.get_enabled_apis(projectid)

    @create_lazy('stackdriver_logging', _create_stackdriver_logging)
    def iter_organization_sinks(self, orgid):
        """Iterate Organization logging sinks from GCP API.

        Args:
            orgid (str): id of the organization to query

        Yields:
            dict: Generator of organization logging sinks
        """
        for sink in self.stackdriver_logging.get_organization_sinks(orgid):
            yield sink

    @create_lazy('stackdriver_logging', _create_stackdriver_logging)
    def iter_folder_sinks(self, folderid):
        """Iterate Folder logging sinks from GCP API.

        Args:
            folderid (str): id of the folder to query

        Yields:
            dict: Generator of folder logging sinks
        """
        for sink in self.stackdriver_logging.get_folder_sinks(folderid):
            yield sink

    @create_lazy('stackdriver_logging', _create_stackdriver_logging)
    def iter_billing_account_sinks(self, acctid):
        """Iterate Billing Account logging sinks from GCP API.

        Args:
            acctid (str): id of the billing account to query

        Yields:
            dict: Generator of billing account logging sinks
        """
        for sink in self.stackdriver_logging.get_billing_account_sinks(acctid):
            yield sink

    @create_lazy('stackdriver_logging', _create_stackdriver_logging)
    def iter_project_sinks(self, projectid):
        """Iterate Project logging sinks from GCP API.

        Args:
            projectid (str): id of the project to query

        Yields:
            dict: Generator of project logging sinks
        """
        for sink in self.stackdriver_logging.get_project_sinks(projectid):
            yield sink
