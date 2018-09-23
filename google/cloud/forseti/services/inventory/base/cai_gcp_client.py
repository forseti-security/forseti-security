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

from google.cloud.forseti.services.inventory.base import gcp
from google.cloud.forseti.services.inventory.storage import ContentTypes


# pylint: disable=bad-indentation
class CaiApiClientImpl(gcp.ApiClientImpl):
    """The gcp api client Implementation"""

    def __init__(self, config, storage):
        """Initialize.

        Args:
            config (dict): GCP API client configuration.
            storage (Storage): The inventory storage DAO class.
        """
        super(CaiApiClientImpl, self).__init__(config)
        self.dao = storage

    def fetch_organization(self, orgid):
        """Fetch Organization data from Cloud Asset data.

        Args:
            orgid (str): id of the organization to get.

        Returns:
            dict: Organization resource.
        """
        resource = self.dao.fetch_cai_asset(
            ContentTypes.resource,
            'google.cloud.resourcemanager.Organization'
            '//cloudresourcemanager.googleapis.com/{}'.format(orgid))
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
            'google.cloud.resourcemanager.Folder'
            '//cloudresourcemanager.googleapis.com/{}'.format(folderid))
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
                projectid))
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
                                                                  parent_id))
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
            '//cloudresourcemanager.googleapis.com/{}'.format(parent_id))
        for folder in resources:
            yield folder
