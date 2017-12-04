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

""" GCP API client fassade."""

# TODO: The next editor must remove this disable and correct issues.
# pylint: disable=missing-type-doc
# pylint: disable=missing-param-doc,invalid-name,too-many-instance-attributes
# pylint: disable=too-many-public-methods,arguments-differ

from google.cloud.forseti.common.gcp_api import admin_directory
from google.cloud.forseti.common.gcp_api import bigquery
from google.cloud.forseti.common.gcp_api import cloud_resource_manager
from google.cloud.forseti.common.gcp_api import cloudsql
from google.cloud.forseti.common.gcp_api import compute
from google.cloud.forseti.common.gcp_api import iam
from google.cloud.forseti.common.gcp_api import storage


class ApiClient(object):
    """The gcp api client interface"""
    def fetch_organization(self, orgid):
        """Not Implemented.

        Raises:
            NotImplementedError: Because not implemented.
        """
        raise NotImplementedError()

    def iter_projects(self, orgid):
        """Not Implemented.

        Raises:
            NotImplementedError: Because not implemented.
        """
        raise NotImplementedError()

    def iter_folders(self, orgid):
        """Not Implemented.

        Raises:
            NotImplementedError: Because not implemented.
        """
        raise NotImplementedError()

    def iter_buckets(self, projectid):
        """Not Implemented.

        Raises:
            NotImplementedError: Because not implemented.
        """
        raise NotImplementedError()

    def iter_objects(self, bucket_id):
        """Not Implemented.

        Raises:
            NotImplementedError: Because not implemented.
        """
        raise NotImplementedError()

    def get_organization_iam_policy(self, orgid):
        """Not Implemented.

        Raises:
            NotImplementedError: Because not implemented.
        """
        raise NotImplementedError()

    def get_project_iam_policy(self, projectid):
        """Not Implemented.

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
    def f_wrapper(function):
        """Create decorator

        Args:
            function (function): Function to wrap.

        Returns:
            function: Decorator
        """

        def wrapper(*args, **kwargs):
            """Decorator implementation

            Args:
                *args (list): Original function arguments
                **kwargs (dict): Original function arguments

            Returns:
                object: Result produced by the wrapped function
            """
            this = args[0]
            if not hasattr(this, attribute) or not getattr(this, attribute):
                setattr(this, attribute, factory(this))
            return function(*args, **kwargs)
        return wrapper
    return f_wrapper


class ApiClientImpl(ApiClient):
    """The gcp api client Implementation"""
    def __init__(self, config):
        self.ad = None
        self.bigquery = None
        self.crm = None
        self.cloudsql = None
        self.compute = None
        self.iam = None
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

    def _create_iam(self):
        """Create IAM API client
        Returns:
            object: Client
        """
        return iam.IAMClient(self.config)

    def _create_storage(self):
        """Create storage API client
        Returns:
            object: Client
        """
        return storage.StorageClient(self.config)

    @create_lazy('ad', _create_ad)
    def iter_users(self, gsuite_id):
        """Gsuite user Iterator from gcp API call

        Yields:
            dict: Generator of user
        """
        for user in self.ad.get_users(gsuite_id):
            yield user

    @create_lazy('ad', _create_ad)
    def iter_groups(self, gsuite_id):
        """Gsuite group Iterator from gcp API call

        Yields:
            dict: Generator of groups
        """
        result = self.ad.get_groups(gsuite_id)
        for group in result:
            yield group

    @create_lazy('ad', _create_ad)
    def iter_group_members(self, group_key):
        """Gsuite group_memeber Iterator from gcp API call

        Yields:
            dict: Generator of group_member
        """
        for member in self.ad.get_group_members(group_key):
            yield member

    @create_lazy('crm', _create_crm)
    def fetch_organization(self, orgid):
        """Organization data from gcp API call

        Returns:
            dict: Generator of organization
        """
        return self.crm.get_organization(orgid)

    @create_lazy('crm', _create_crm)
    def fetch_folder(self, folderid):
        """Folder data from gcp API call

        Returns:
            dict: Generator of folder
        """
        return self.crm.get_folder(folderid)

    @create_lazy('crm', _create_crm)
    def fetch_project(self, projectid):
        """Project data from gcp API call

        Returns:
            dict: Generator of project
        """
        return self.crm.get_project(projectid)

    @create_lazy('crm', _create_crm)
    def iter_projects(self, parent_type, parent_id):
        """Project Iterator from gcp API call

        Yields:
            dict: Generator of projects
        """
        for page in self.crm.get_projects(parent_id=parent_id,
                                          parent_type=parent_type):
            for project in page.get('projects', []):
                yield project

    @create_lazy('crm', _create_crm)
    def iter_folders(self, parent_id):
        """Folder Iterator from gcp API call

        Yields:
            dict: Generator of folders
        """
        for folder in self.crm.get_folders(parent_id):
            yield folder

    @create_lazy('storage', _create_storage)
    def iter_buckets(self, projectid):
        """Bucket Iterator from gcp API call

        Yields:
            dict: Generator of buckets
        """
        for bucket in self.storage.get_buckets(projectid):
            yield bucket

    @create_lazy('storage', _create_storage)
    def iter_objects(self, bucket_id):
        """Object Iterator from gcp API call

        Yields:
            dict: Generator of objects
        """
        for object_ in self.storage.get_objects(bucket_name=bucket_id):
            yield object_

    @create_lazy('bigquery', _create_bq)
    def iter_datasets(self, projectid):
        """Dataset Iterator from gcp API call

        Yields:
            dict: Generator of datasets
        """
        for dataset in self.bigquery.get_datasets_for_projectid(projectid):
            yield dataset

    @create_lazy('cloudsql', _create_cloudsql)
    def iter_cloudsqlinstances(self, projectid):
        """Cloudsqlinstance Iterator from gcp API call

        Yields:
            dict: Generator of cloudsql instance
        """
        for item in self.cloudsql.get_instances(projectid):
            yield item

    @create_lazy('compute', _create_compute)
    def is_compute_api_enabled(self, projectid):
        """Verifies the Compute API is enabled on a project.

        Returns:
            bool: True if API is enabled, else False.
        """
        return self.compute.is_api_enabled(projectid)

    @create_lazy('compute', _create_compute)
    def fetch_compute_project(self, projectid):
        """Compute project data from gcp API call.

        Returns:
            dict: Compute project metadata resource.
        """
        return self.compute.get_project(projectid)

    @create_lazy('compute', _create_compute)
    def iter_computeinstances(self, projectid):
        """Compute Engine Instance Iterator from gcp API call

        Yields:
            dict: Generator of Compute Engine Instance
        """
        for instance in self.compute.get_instances(projectid):
            yield instance

    @create_lazy('compute', _create_compute)
    def iter_computefirewalls(self, projectid):
        """Compute Engine Firewall Iterator from gcp API call

        Yields:
            dict: Generator of Compute Engine Firewall
        """
        for rule in self.compute.get_firewall_rules(projectid):
            yield rule

    @create_lazy('compute', _create_compute)
    def iter_computeinstancegroups(self, projectid):
        """Compute Engine group Iterator from gcp API call

        Yields:
            dict: Generator of Compute Instance group
        """
        for instancegroup in self.compute.get_instance_groups(projectid):
            yield instancegroup

    @create_lazy('compute', _create_compute)
    def iter_backendservices(self, projectid):
        """Backend service Iterator from gcp API call

        Yields:
            dict: Generator of backend service
        """
        for backendservice in self.compute.get_backend_services(projectid):
            yield backendservice

    @create_lazy('compute', _create_compute)
    def iter_forwardingrules(self, projectid):
        """Forwarding Rule Iterator from gcp API call

        Yields:
            dict: Generator of forwarding rule resources
        """
        for forwardingrule in self.compute.get_forwarding_rules(projectid):
            yield forwardingrule

    @create_lazy('compute', _create_compute)
    def iter_ig_managers(self, projectid):
        """Instance Group Manager Iterator from gcp API call

        Yields:
            dict: Generator of instance group manager resources
        """
        for igmanager in self.compute.get_instance_group_managers(projectid):
            yield igmanager

    @create_lazy('compute', _create_compute)
    def iter_instancetemplates(self, projectid):
        """Instance Template Iterator from gcp API call

        Yields:
            dict: Generator of instance template resources
        """
        for instancetemplate in self.compute.get_instance_templates(projectid):
            yield instancetemplate

    @create_lazy('compute', _create_compute)
    def iter_networks(self, projectid):
        """Network Iterator from gcp API call

        Yields:
            dict: Generator of network resources
        """
        for network in self.compute.get_networks(projectid):
            yield network

    @create_lazy('compute', _create_compute)
    def iter_subnetworks(self, projectid):
        """Subnetwork Iterator from gcp API call

        Yields:
            dict: Generator of subnetwork resources
        """
        for subnetwork in self.compute.get_subnetworks(projectid):
            yield subnetwork

    @create_lazy('iam', _create_iam)
    def iter_serviceaccounts(self, projectid):
        """Service Account Iterator in a project from gcp API call

        Yields:
            dict: Generator of service account
        """
        for serviceaccount in self.iam.get_service_accounts(projectid):
            yield serviceaccount

    @create_lazy('iam', _create_iam)
    def iter_project_roles(self, projectid):
        """Project role Iterator in a project from gcp API call

        Yields:
            dict: Generator of project roles
        """
        for role in self.iam.get_project_roles(projectid):
            yield role

    @create_lazy('iam', _create_iam)
    def iter_organization_roles(self, orgid):
        """Organization role Iterator from gcp API call

        Yields:
            dict: Generator of organization role
        """
        for role in self.iam.get_organization_roles(orgid):
            yield role

    @create_lazy('iam', _create_iam)
    def iter_curated_roles(self):
        """Curated role Iterator in an organization from gcp API call

        Yields:
            dict: Generator of curated roles
        """
        for role in self.iam.get_curated_roles():
            yield role

    @create_lazy('crm', _create_crm)
    def get_folder_iam_policy(self, folderid):
        """Folder IAM policy in a folder from gcp API call

        Returns:
            dict: Folder IAM policy
        """
        return self.crm.get_folder_iam_policies(folderid)

    @create_lazy('crm', _create_crm)
    def get_organization_iam_policy(self, orgid):
        """Organization IAM policy from gcp API call

        Returns:
            dict: Organization IAM policy
        """
        return self.crm.get_org_iam_policies(orgid)

    @create_lazy('crm', _create_crm)
    def get_project_iam_policy(self, projectid):
        """Project IAM policy from gcp API call

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
    def get_bucket_gcs_policy(self, bucketid):
        """Bucket GCS policy from gcp API call

        Returns:
            dict: Bucket GCS policy
        """
        return self.storage.get_bucket_acls(bucketid)

    @create_lazy('storage', _create_storage)
    def get_bucket_iam_policy(self, bucketid):
        """Bucket IAM policy Iterator from gcp API call

        Returns:
            dict: Bucket IAM policy
        """
        return self.storage.get_bucket_iam_policy(bucketid)

    @create_lazy('storage', _create_storage)
    def get_object_gcs_policy(self, bucket_name, object_name):
        """Object GCS policy for an object from gcp API call

        Returns:
            dict: Object GCS policy
        """
        return self.storage.get_object_acls(bucket_name, object_name)

    @create_lazy('storage', _create_storage)
    def get_object_iam_policy(self, bucket_name, object_name):
        """Object IAM policy Iterator for an object from gcp API call

        Returns:
            dict: Object IAM policy
        """
        return self.storage.get_object_iam_policy(bucket_name, object_name)

    @create_lazy('bigquery', _create_bq)
    def get_dataset_dataset_policy(self, projectid, datasetid):
        """Dataset policy Iterator for a dataset from gcp API call

        Returns:
            dict: Dataset Policy
        """
        return self.bigquery.get_dataset_access(projectid, datasetid)
