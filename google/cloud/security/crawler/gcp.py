# Copyright 2017 Google Inc.
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

""" Crawler implementation. """

from google.cloud.security.common.gcp_api import admin_directory
from google.cloud.security.common.gcp_api import appengine
from google.cloud.security.common.gcp_api import bigquery
from google.cloud.security.common.gcp_api import cloud_resource_manager
from google.cloud.security.common.gcp_api import cloudsql
from google.cloud.security.common.gcp_api import compute
from google.cloud.security.common.gcp_api import errors
from google.cloud.security.common.gcp_api import storage


class ApiClient(object):
    def fetch_organization(self, orgid):
        raise NotImplementedError()

    def iter_projects(self, orgid):
        raise NotImplementedError()

    def iter_folders(self, orgid):
        raise NotImplementedError()

    def iter_buckets(self, projectid):
        raise NotImplementedError()

    def iter_objects(self, bucket_id):
        raise NotImplementedError()

    def get_organization_iam_policy(self, orgid):
        raise NotImplementedError()

    def get_project_iam_policy(self, projectid):
        raise NotImplementedError()


class ApiClientImpl(ApiClient):

    def __init__(self, config):
        self.ad = admin_directory.AdminDirectoryClient(config)
        self.appengine = appengine.AppEngineClient(config)
        self.bigquery = bigquery.BigQueryClient(config)
        self.crm = cloud_resource_manager.CloudResourceManagerClient(config)
        self.cloudsql = cloudsql.CloudsqlClient(config)
        self.compute = compute.ComputeClient(config)
        self.storage = storage.StorageClient(config)

    def fetch_organization(self, orgid):
        return self.crm.get_organization(orgid)

    def iter_projects(self, orgid):
        for page in self.crm.get_projects(orgid):
            for project in page['projects']:
                yield project

    def iter_folders(self, orgid):
        return self.crm.get_folders(orgid)

    def iter_buckets(self, projectid):
        response = self.storage.get_buckets(projectid)
        if 'items' not in response:
            return
            yield

        for bucket in response['items']:
            yield bucket

    def iter_datasets(self, projectid):
        return self.bigquery.get_datasets_for_projectid(projectid)

    def iter_appengineapps(self, projectid):
        return
        yield

    def iter_cloudsqlinstances(self, projectid):
        result = self.cloudsql.get_instances(projectid)
        if 'items' not in result:
            return
            yield
        for item in result['items']:
            yield item

    def iter_computeinstances(self, projectid):
        result = self.compute.get_instances(projectid)
        for instance in result:
            yield instance

    def iter_computefirewalls(self, projectid):
        result = self.compute.get_firewall_rules(projectid)
        for rule in result:
            yield rule

    def get_organization_iam_policy(self, orgid):
        return self.crm.get_org_iam_policies(orgid, orgid)

    def get_project_iam_policy(self, projectid):
        return self.crm.get_project_iam_policies(projectid, projectid)

    def get_bucket_iam_policy(self, bucketid):
        return None

    def get_bucket_gcs_policy(self, bucketid):
        return self.storage.get_bucket_acls(bucketid)

    def get_dataset_dataset_policy(self, projectid, datasetid):
        return self.bigquery.get_dataset_access(projectid, datasetid)
