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
import os
import threading

from google.cloud.forseti.services import db
from google.cloud.forseti.services.inventory.base import gcp
from google.cloud.forseti.services.inventory.storage import CaiDataAccess
from google.cloud.forseti.services.inventory.storage import ContentTypes

LOCAL_THREAD = threading.local()


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

    def fetch_organization(self, orgid):
        """Fetch Organization data from Cloud Asset data.

        Args:
            orgid (str): id of the organization to get.

        Returns:
            dict: Organization resource.
        """
        resource = self.dao.fetch_cai_asset(
            ContentTypes.resource,
            'google.cloud.resourcemanager.Organization',
            '//cloudresourcemanager.googleapis.com/{}'.format(orgid),
            self.session)
        if resource:
            return resource
        # Fall back to live API if the data isn't in the CAI cache.
        return super(CaiApiClientImpl, self).fetch_organization(orgid)

    def fetch_folder(self, folderid):
        """Fetch Folder data from Cloud Asset data.

        Args:
            folderid (str): id of the folder to query.

        Returns:
            dict: Folder resource.
        """
        resource = self.dao.fetch_cai_asset(
            ContentTypes.resource,
            'google.cloud.resourcemanager.Folder',
            '//cloudresourcemanager.googleapis.com/{}'.format(folderid),
            self.session)
        if resource:
            return resource
        # Fall back to live API if the data isn't in the CAI cache.
        return super(CaiApiClientImpl, self).fetch_folder(folderid)

    def fetch_project(self, projectid):
        """Fetch Project data from Cloud Asset data.

        Args:
            projectid (str): id of the project to query.

        Returns:
            dict: Project resource.
        """
        resource = self.dao.fetch_cai_asset(
            ContentTypes.resource,
            'google.cloud.resourcemanager.Project',
            '//cloudresourcemanager.googleapis.com/projects/{}'.format(
                projectid),
            self.session)
        if resource:
            return resource
        # Fall back to live API if the data isn't in the CAI cache.
        return super(CaiApiClientImpl, self).fetch_project(projectid)

    def iter_projects(self, parent_type, parent_id):
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

    def iter_folders(self, parent_id):
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

    def get_folder_iam_policy(self, folderid):
        """Folder IAM policy in a folder from Cloud Asset data.

        Args:
            folderid (str): id of the folder to get policy.

        Returns:
            dict: Folder IAM policy.
        """
        resource = self.dao.fetch_cai_asset(
            ContentTypes.iam_policy,
            'google.cloud.resourcemanager.Folder',
            '//cloudresourcemanager.googleapis.com/{}'.format(folderid),
            self.session)
        if resource:
            return resource
        # Fall back to live API if the data isn't in the CAI cache.
        return super(CaiApiClientImpl, self).get_folder_iam_policy(folderid)

    def get_organization_iam_policy(self, orgid):
        """Organization IAM policy from Cloud Asset data.

        Args:
            orgid (str): id of the organization to get policy.

        Returns:
            dict: Organization IAM policy.
        """
        resource = self.dao.fetch_cai_asset(
            ContentTypes.iam_policy,
            'google.cloud.resourcemanager.Organization',
            '//cloudresourcemanager.googleapis.com/{}'.format(orgid),
            self.session)
        if resource:
            return resource
        # Fall back to live API if the data isn't in the CAI cache.
        return super(CaiApiClientImpl, self).get_organization_iam_policy(orgid)

    def get_project_iam_policy(self, projectid):
        """Project IAM policy from Cloud Asset data.

        Args:
            projectid (str): id of the project to query.

        Returns:
            dict: Project IAM Policy.
        """
        resource = self.dao.fetch_cai_asset(
            ContentTypes.iam_policy,
            'google.cloud.resourcemanager.Project',
            '//cloudresourcemanager.googleapis.com/projects/{}'.format(
                projectid),
            self.session)
        if resource:
            return resource
        # Fall back to live API if the data isn't in the CAI cache.
        return super(CaiApiClientImpl, self).get_project_iam_policy(projectid)

    def fetch_gae_app(self, projectid):
        """Fetch the AppEngine App from Cloud Asset data.

        Args:
            projectid (str): id of the project to query

        Returns:
            dict: AppEngine App resource.
        """
        resource = self.dao.fetch_cai_asset(
            ContentTypes.resource,
            'google.appengine.Application',
            '//appengine.googleapis.com/apps/{}'.format(projectid),
            self.session)
        return resource

    def iter_gae_services(self, projectid):
        """Iterate gae services from Cloud Asset data.

        Args:
            projectid (str): id of the project to query

        Yields:
            dict: Generator of AppEngine Service resources.
        """
        resources = self.dao.iter_cai_assets(
            ContentTypes.resource,
            'google.appengine.Service',
            '//appengine.googleapis.com/apps/{}'.format(projectid),
            self.session)
        for service in resources:
            yield service

    def iter_gae_versions(self, projectid, serviceid):
        """Iterate gae versions from Cloud Asset data.

        Args:
            projectid (str): id of the project to query
            serviceid (str): id of the appengine service

        Yields:
            dict: Generator of AppEngine Version resources.
        """
        resources = self.dao.iter_cai_assets(
            ContentTypes.resource,
            'google.appengine.Service',
            '//appengine.googleapis.com/apps/{}/services/{}'.format(projectid,
                                                                    serviceid),
            self.session)
        for version in resources:
            yield version

    def iter_buckets(self, projectid):
        """Iterate Buckets from Cloud Asset data.

        Args:
            projectid (str): id of the project to query

        Yields:
            dict: Generator of Bucket resources
        """
        # Fall back to live API because CAI does not yet have bucket ACLs.
        return super(CaiApiClientImpl, self).iter_buckets(projectid)

    def get_bucket_iam_policy(self, bucketid):
        """Bucket IAM policy Iterator from Cloud Asset data.

        Args:
            bucketid (str): id of the bucket to query

        Returns:
            dict: Bucket IAM policy
        """
        resource = self.dao.fetch_cai_asset(
            ContentTypes.iam_policy,
            'google.cloud.storage.Bucket',
            '//storage.googleapis.com/{}'.format(bucketid),
            self.session)
        if resource:
            return resource
        # Fall back to live API if the data isn't in the CAI cache.
        return super(CaiApiClientImpl, self).get_bucket_iam_policy(bucketid)

    def iter_computeinstances(self, projectid):
        """Iterate compute engine instance from Cloud Asset data.

        Args:
            projectid (str): id of the project to query.

        Yields:
            dict: Generator of Compute Engine Instance resources.
        """
        resources = self.dao.iter_cai_assets(
            ContentTypes.resource,
            'google.compute.Instance',
            '//cloudresourcemanager.googleapis.com/projects/{}'.format(
                projectid),
            self.session)
        for instance in resources:
            yield instance

    def iter_computefirewalls(self, projectid):
        """Iterate Compute Engine Firewalls from Cloud Asset data.

        Args:
            projectid (str): id of the project to query.

        Yields:
            dict: Generator of Compute Engine Firewall.
        """
        resources = self.dao.iter_cai_assets(
            ContentTypes.resource,
            'google.compute.Firewall',
            '//cloudresourcemanager.googleapis.com/projects/{}'.format(
                projectid),
            self.session)
        for rule in resources:
            yield rule

    @create_lazy('compute', _create_compute)
    def iter_computeinstancegroups(self, projectid):
        """Iterate Compute Engine groups from Cloud Asset data.

        Args:
            projectid (str): id of the project to query.

        Yields:
            dict: Generator of Compute Instance group.
        """
        resources = self.dao.iter_cai_assets(
            ContentTypes.resource,
            'google.compute.InstanceGroup',
            '//cloudresourcemanager.googleapis.com/projects/{}'.format(
                projectid),
            self.session)
        for instancegroup in resources:
            # Instance group instances not included in CAI data, add from API.
            instancegroup['instance_urls'] = (
                self.compute.get_instance_group_instances(
                    projectid,
                    instancegroup.get('name'),
                    # Turn zone and region URLs into a names
                    zone=os.path.basename(instancegroup.get('zone', '')),
                    region=os.path.basename(instancegroup.get('region', ''))))
            yield instancegroup

    def iter_computedisks(self, projectid):
        """Iterate Compute Engine disks from Cloud Asset data.

        Args:
            projectid (str): id of the project to query.

        Yields:
            dict: Generator of Compute Disk.
        """
        resources = self.dao.iter_cai_assets(
            ContentTypes.resource,
            'google.compute.Disk',
            '//cloudresourcemanager.googleapis.com/projects/{}'.format(
                projectid),
            self.session)
        for disk in resources:
            yield disk

    def iter_backendservices(self, projectid):
        """Iterate Backend services from Cloud Asset data.

        Args:
            projectid (str): id of the project to query.

        Yields:
            dict: Generator of backend service.
        """
        resources = self.dao.iter_cai_assets(
            ContentTypes.resource,
            'google.compute.BackendService',
            '//cloudresourcemanager.googleapis.com/projects/{}'.format(
                projectid),
            self.session)
        for backendservice in resources:
            yield backendservice

    def iter_forwardingrules(self, projectid):
        """Iterate Forwarding Rules from Cloud Asset data.

        Args:
            projectid (str): id of the project to query.

        Yields:
            dict: Generator of forwarding rule resources.
        """
        # Fall back to live API because CAI does not yet have forwarding rules.
        return super(CaiApiClientImpl, self).iter_forwardingrules(projectid)

    def iter_images(self, projectid):
        """Iterate Images from Cloud Asset data.

        Args:
            projectid (str): id of the project to query.

        Yields:
            dict: Generator of image resources.
        """
        resources = self.dao.iter_cai_assets(
            ContentTypes.resource,
            'google.compute.Image',
            '//cloudresourcemanager.googleapis.com/projects/{}'.format(
                projectid),
            self.session)
        for image in resources:
            yield image

    def iter_ig_managers(self, projectid):
        """Iterate Instance Group Manager from Cloud Asset data.

        Args:
            projectid (str): id of the project to query.

        Yields:
            dict: Generator of instance group manager resources.
        """
        # Fall back to live API because CAI does not yet have IG Managers.
        return super(CaiApiClientImpl, self).iter_ig_managers(projectid)

    def iter_instancetemplates(self, projectid):
        """Iterate Instance Templates from Cloud Asset data.

        Args:
            projectid (str): id of the project to query.

        Yields:
            dict: Generator of instance template resources.
        """
        resources = self.dao.iter_cai_assets(
            ContentTypes.resource,
            'google.compute.InstanceTemplate',
            '//cloudresourcemanager.googleapis.com/projects/{}'.format(
                projectid),
            self.session)
        for instancetemplate in resources:
            yield instancetemplate

    def iter_networks(self, projectid):
        """Iterate Networks from Cloud Asset data.

        Args:
            projectid (str): id of the project to query.

        Yields:
            dict: Generator of network resources.
        """
        resources = self.dao.iter_cai_assets(
            ContentTypes.resource,
            'google.compute.Network',
            '//cloudresourcemanager.googleapis.com/projects/{}'.format(
                projectid),
            self.session)
        for network in resources:
            yield network

    def iter_snapshots(self, projectid):
        """Iterate Compute Engine snapshots from Cloud Asset data.

        Args:
            projectid (str): id of the project to query.

        Yields:
            dict: Generator of Compute Snapshots.
        """
        resources = self.dao.iter_cai_assets(
            ContentTypes.resource,
            'google.compute.Snapshot',
            '//cloudresourcemanager.googleapis.com/projects/{}'.format(
                projectid),
            self.session)
        for snapshot in resources:
            yield snapshot

    def iter_subnetworks(self, projectid):
        """Iterate Subnetworks from Cloud Asset data.

        Args:
            projectid (str): id of the project to query.

        Yields:
            dict: Generator of subnetwork resources.
        """
        resources = self.dao.iter_cai_assets(
            ContentTypes.resource,
            'google.compute.Subnetwork',
            '//cloudresourcemanager.googleapis.com/projects/{}'.format(
                projectid),
            self.session)
        for subnetwork in resources:
            yield subnetwork
