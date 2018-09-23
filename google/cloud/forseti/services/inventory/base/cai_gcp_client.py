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
