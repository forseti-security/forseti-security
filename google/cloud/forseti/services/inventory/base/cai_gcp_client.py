# Copyright 2018 The Forseti Security Authors. All rights reserved.
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

"""Cloud Asset and GCP API hybrid client fassade."""
import threading

from google.cloud.forseti.services import db
from google.cloud.forseti.services.inventory.base import gcp
from google.cloud.forseti.services.inventory.storage import CaiDataAccess
from google.cloud.forseti.services.inventory.storage import ContentTypes

LOCAL_THREAD = threading.local()


# pylint: disable=too-many-public-methods
class CaiApiClientImpl(gcp.ApiClientImpl):
    """The gcp api client Implementation"""

    def __init__(self, config, engine):
        """Initialize.

        Args:
            config (dict): GCP API client configuration.
            engine (object): Database engine to operate on.
        """
        super(CaiApiClientImpl, self).__init__(config)
        self.dao = CaiDataAccess()
        self.engine = engine
        self._local = LOCAL_THREAD

    @property
    def session(self):
        """Return a thread local CAI read only session object.

        Returns:
            object: A thread local Session.
        """
        if hasattr(self._local, 'cai_session'):
            return self._local.cai_session

        self._local.cai_session = db.create_readonly_session(engine=self.engine)
        return self._local.cai_session

    def iter_compute_backendservices(self, project_number):
        """Iterate Backend services from Cloud Asset data.

        Args:
            project_number (str): id of the project to query.

        Yields:
            dict: Generator of backend service.
        """
        resources = self.dao.iter_cai_assets(
            ContentTypes.resource,
            'google.compute.BackendService',
            '//cloudresourcemanager.googleapis.com/projects/{}'.format(
                project_number),
            self.session)
        for backendservice in resources:
            yield backendservice

    def iter_compute_disks(self, project_number):
        """Iterate Compute Engine disks from Cloud Asset data.

        Args:
            project_number (str): id of the project to query.

        Yields:
            dict: Generator of Compute Disk.
        """
        resources = self.dao.iter_cai_assets(
            ContentTypes.resource,
            'google.compute.Disk',
            '//cloudresourcemanager.googleapis.com/projects/{}'.format(
                project_number),
            self.session)
        for disk in resources:
            yield disk

    def iter_compute_firewalls(self, project_number):
        """Iterate Compute Engine Firewalls from Cloud Asset data.

        Args:
            project_number (str): id of the project to query.

        Yields:
            dict: Generator of Compute Engine Firewall.
        """
        resources = self.dao.iter_cai_assets(
            ContentTypes.resource,
            'google.compute.Firewall',
            '//cloudresourcemanager.googleapis.com/projects/{}'.format(
                project_number),
            self.session)
        for rule in resources:
            yield rule

    def iter_compute_images(self, project_number):
        """Iterate Images from Cloud Asset data.

        Args:
            project_number (str): id of the project to query.

        Yields:
            dict: Generator of image resources.
        """
        resources = self.dao.iter_cai_assets(
            ContentTypes.resource,
            'google.compute.Image',
            '//cloudresourcemanager.googleapis.com/projects/{}'.format(
                project_number),
            self.session)
        for image in resources:
            yield image

    # Use live API because CAI does not yet have all instance groups.
    # def iter_compute_instancegroups(self, project_number):

    def iter_compute_instances(self, project_number):
        """Iterate compute engine instance from Cloud Asset data.

        Args:
            project_number (str): id of the project to query.

        Yields:
            dict: Generator of Compute Engine Instance resources.
        """
        resources = self.dao.iter_cai_assets(
            ContentTypes.resource,
            'google.compute.Instance',
            '//cloudresourcemanager.googleapis.com/projects/{}'.format(
                project_number),
            self.session)
        for instance in resources:
            yield instance

    def iter_compute_instancetemplates(self, project_number):
        """Iterate Instance Templates from Cloud Asset data.

        Args:
            project_number (str): id of the project to query.

        Yields:
            dict: Generator of instance template resources.
        """
        resources = self.dao.iter_cai_assets(
            ContentTypes.resource,
            'google.compute.InstanceTemplate',
            '//cloudresourcemanager.googleapis.com/projects/{}'.format(
                project_number),
            self.session)
        for instancetemplate in resources:
            yield instancetemplate

    def iter_compute_networks(self, project_number):
        """Iterate Networks from Cloud Asset data.

        Args:
            project_number (str): id of the project to query.

        Yields:
            dict: Generator of network resources.
        """
        resources = self.dao.iter_cai_assets(
            ContentTypes.resource,
            'google.compute.Network',
            '//cloudresourcemanager.googleapis.com/projects/{}'.format(
                project_number),
            self.session)
        for network in resources:
            yield network

    def iter_compute_snapshots(self, project_number):
        """Iterate Compute Engine snapshots from Cloud Asset data.

        Args:
            project_number (str): id of the project to query.

        Yields:
            dict: Generator of Compute Snapshots.
        """
        resources = self.dao.iter_cai_assets(
            ContentTypes.resource,
            'google.compute.Snapshot',
            '//cloudresourcemanager.googleapis.com/projects/{}'.format(
                project_number),
            self.session)
        for snapshot in resources:
            yield snapshot

    def iter_compute_subnetworks(self, project_number):
        """Iterate Subnetworks from Cloud Asset data.

        Args:
            project_number (str): id of the project to query.

        Yields:
            dict: Generator of subnetwork resources.
        """
        resources = self.dao.iter_cai_assets(
            ContentTypes.resource,
            'google.compute.Subnetwork',
            '//cloudresourcemanager.googleapis.com/projects/{}'.format(
                project_number),
            self.session)
        for subnetwork in resources:
            yield subnetwork

    def fetch_crm_folder(self, folder_id):
        """Fetch Folder data from Cloud Asset data.

        Args:
            folder_id (str): id of the folder to query.

        Returns:
            dict: Folder resource.
        """
        resource = self.dao.fetch_cai_asset(
            ContentTypes.resource,
            'google.cloud.resourcemanager.Folder',
            '//cloudresourcemanager.googleapis.com/{}'.format(folder_id),
            self.session)
        if resource:
            return resource
        # Fall back to live API if the data isn't in the CAI cache.
        return super(CaiApiClientImpl, self).fetch_crm_folder(folder_id)

    def fetch_crm_folder_iam_policy(self, folder_id):
        """Folder IAM policy in a folder from Cloud Asset data.

        Args:
            folder_id (str): id of the folder to get policy.

        Returns:
            dict: Folder IAM policy.
        """
        resource = self.dao.fetch_cai_asset(
            ContentTypes.iam_policy,
            'google.cloud.resourcemanager.Folder',
            '//cloudresourcemanager.googleapis.com/{}'.format(folder_id),
            self.session)
        if resource:
            return resource
        # Fall back to live API if the data isn't in the CAI cache.
        return super(CaiApiClientImpl, self).fetch_crm_folder_iam_policy(
            folder_id)

    def fetch_crm_organization(self, org_id):
        """Fetch Organization data from Cloud Asset data.

        Args:
            org_id (str): id of the organization to get.

        Returns:
            dict: Organization resource.
        """
        resource = self.dao.fetch_cai_asset(
            ContentTypes.resource,
            'google.cloud.resourcemanager.Organization',
            '//cloudresourcemanager.googleapis.com/{}'.format(org_id),
            self.session)
        if resource:
            return resource
        # Fall back to live API if the data isn't in the CAI cache.
        return super(CaiApiClientImpl, self).fetch_crm_organization(org_id)

    def fetch_crm_organization_iam_policy(self, org_id):
        """Organization IAM policy from Cloud Asset data.

        Args:
            org_id (str): id of the organization to get policy.

        Returns:
            dict: Organization IAM policy.
        """
        resource = self.dao.fetch_cai_asset(
            ContentTypes.iam_policy,
            'google.cloud.resourcemanager.Organization',
            '//cloudresourcemanager.googleapis.com/{}'.format(org_id),
            self.session)
        if resource:
            return resource
        # Fall back to live API if the data isn't in the CAI cache.
        return super(CaiApiClientImpl, self).fetch_crm_organization_iam_policy(
            org_id)

    def fetch_crm_project(self, project_number):
        """Fetch Project data from Cloud Asset data.

        Args:
            project_number (str): id of the project to query.

        Returns:
            dict: Project resource.
        """
        resource = self.dao.fetch_cai_asset(
            ContentTypes.resource,
            'google.cloud.resourcemanager.Project',
            '//cloudresourcemanager.googleapis.com/projects/{}'.format(
                project_number),
            self.session)
        if resource:
            return resource
        # Fall back to live API if the data isn't in the CAI cache.
        return super(CaiApiClientImpl, self).fetch_crm_project(project_number)

    def fetch_crm_project_iam_policy(self, project_number):
        """Project IAM policy from Cloud Asset data.

        Args:
            project_number (str): id of the project to query.

        Returns:
            dict: Project IAM Policy.
        """
        resource = self.dao.fetch_cai_asset(
            ContentTypes.iam_policy,
            'google.cloud.resourcemanager.Project',
            '//cloudresourcemanager.googleapis.com/projects/{}'.format(
                project_number),
            self.session)
        if resource:
            return resource
        # Fall back to live API if the data isn't in the CAI cache.
        return super(CaiApiClientImpl, self).fetch_crm_project_iam_policy(
            project_number)

    def iter_crm_folders(self, parent_id):
        """Iterate Folders from Cloud Asset data.

        Args:
            parent_id (str): id of the parent of the folder

        Yields:
            dict: Generator of folders
        """
        resources = self.dao.iter_cai_assets(
            ContentTypes.resource,
            'google.cloud.resourcemanager.Folder',
            '//cloudresourcemanager.googleapis.com/{}'.format(parent_id),
            self.session)
        for folder in resources:
            yield folder

    def iter_crm_projects(self, parent_type, parent_id):
        """Iterate Projects from Cloud Asset data.

        Args:
            parent_type (str): type of the parent, "folder" or "organization".
            parent_id (str): id of the parent of the folder.

        Yields:
            dict: Generator of Project resources
        """
        resources = self.dao.iter_cai_assets(
            ContentTypes.resource,
            'google.cloud.resourcemanager.Project',
            '//cloudresourcemanager.googleapis.com/{}s/{}'.format(parent_type,
                                                                  parent_id),
            self.session)
        for project in resources:
            yield project

    def fetch_gae_app(self, project_id):
        """Fetch the AppEngine App from Cloud Asset data.

        Args:
            project_id (str): id of the project to query

        Returns:
            dict: AppEngine App resource.
        """
        resource = self.dao.fetch_cai_asset(
            ContentTypes.resource,
            'google.appengine.Application',
            '//appengine.googleapis.com/apps/{}'.format(project_id),
            self.session)
        return resource

    def iter_gae_services(self, project_id):
        """Iterate gae services from Cloud Asset data.

        Args:
            project_id (str): id of the project to query

        Yields:
            dict: Generator of AppEngine Service resources.
        """
        resources = self.dao.iter_cai_assets(
            ContentTypes.resource,
            'google.appengine.Service',
            '//appengine.googleapis.com/apps/{}'.format(project_id),
            self.session)
        for service in resources:
            yield service

    def iter_gae_versions(self, project_id, service_id):
        """Iterate gae versions from Cloud Asset data.

        Args:
            project_id (str): id of the project to query
            service_id (str): id of the appengine service

        Yields:
            dict: Generator of AppEngine Version resources.
        """
        resources = self.dao.iter_cai_assets(
            ContentTypes.resource,
            'google.appengine.Version',
            '//appengine.googleapis.com/apps/{}/services/{}'.format(project_id,
                                                                    service_id),
            self.session)
        for version in resources:
            yield version

    def fetch_storage_bucket_iam_policy(self, bucket_id):
        """Bucket IAM policy Iterator from Cloud Asset data.

        Args:
            bucket_id (str): id of the bucket to query

        Returns:
            dict: Bucket IAM policy
        """
        resource = self.dao.fetch_cai_asset(
            ContentTypes.iam_policy,
            'google.cloud.storage.Bucket',
            '//storage.googleapis.com/{}'.format(bucket_id),
            self.session)
        if resource:
            return resource
        # Fall back to live API if the data isn't in the CAI cache.
        return super(CaiApiClientImpl, self).fetch_storage_bucket_iam_policy(
            bucket_id)

    # Use live API because CAI does not yet have bucket ACLs.
    # def iter_storage_buckets(self, project_number):
