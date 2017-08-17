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

""" GCP API client fassade. """

from google.cloud.security.common.gcp_api2 import admin_directory
from google.cloud.security.common.gcp_api2 import appengine
from google.cloud.security.common.gcp_api2 import bigquery
from google.cloud.security.common.gcp_api2 import cloud_resource_manager
from google.cloud.security.common.gcp_api2 import cloudsql
from google.cloud.security.common.gcp_api2 import compute
from google.cloud.security.common.gcp_api2 import iam
from google.cloud.security.common.gcp_api2 import storage


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
        self.iam = iam.IAMClient(config)
        self.storage = storage.StorageClient(config)

    def iter_users(self, gsuite_id):
        for user in self.ad.get_users(gsuite_id):
            yield user

    def iter_groups(self, gsuite_id):
        result = self.ad.get_groups(gsuite_id)
        for group in result:
            yield group

    def iter_group_members(self, group_key):
        for member in self.ad.get_group_members(group_key):
            yield member

    def fetch_organization(self, orgid):
        return self.crm.get_organization(orgid)

    def iter_projects(self, orgid):
        for page in self.crm.get_projects(orgid):
            for project in page['projects']:
                yield project

    def iter_folders(self, orgid):
        for response in self.crm.get_folders(orgid):
            if 'folders' not in response:
                return
                yield
            for folder in response['folders']:
                yield folder

    def iter_buckets(self, projectid):
        response = self.storage.get_buckets(projectid)
        if 'items' not in response:
            return
            yield

        for bucket in response['items']:
            yield bucket

    def iter_objects(self, bucket_id):
        for object in self.storage.get_objects(bucket_name=bucket_id):
            yield object

    def iter_datasets(self, projectid):
        response = self.bigquery.get_datasets_for_projectid(projectid)
        for dataset in response:
            yield dataset

    def iter_appengineapps(self, projectid):
        response = self.appengine.get_app(projectid)
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

    def iter_computeinstancegroups(self, projectid):
        result = self.compute.get_instance_groups(projectid)
        for instancegroup in result:
            yield instancegroup

    def iter_backendservices(self, projectid):
        result = self.compute.get_backend_services(projectid)
        for backendservice in result:
            yield backendservice

    def iter_serviceaccounts(self, projectid):
        for serviceaccount in self.iam.get_serviceaccounts(projectid):
            yield serviceaccount

    def iter_project_roles(self, projectid):
        for role in self.iam.get_project_roles(projectid):
            yield role

    def iter_organization_roles(self, orgid):
        for role in self.iam.get_organization_roles(orgid):
            yield role

    def iter_curated_roles(self, orgid):
        for role in self.iam.get_curated_roles(orgid):
            yield role

    def get_folder_iam_policy(self, folderid):
        return self.crm.get_folder_iam_policies(folderid)

    def get_organization_iam_policy(self, orgid):
        return self.crm.get_org_iam_policies(orgid, orgid)

    def get_project_iam_policy(self, projectid):
        return self.crm.get_project_iam_policies(projectid, projectid)

    def get_bucket_gcs_policy(self, bucketid):
        result = self.storage.get_bucket_acls(bucketid)
        if 'items' not in result:
            return []
        return result['items']

    def get_bucket_iam_policy(self, bucketid):
        return self.storage.get_bucket_iam_policy(bucketid)

    def get_object_gcs_policy(self, bucket_name, object_name):
        result = self.storage.get_object_acls(bucket_name, object_name)
        if 'items' not in result:
            return []
        return result['items']

    def get_object_iam_policy(self, bucket_name, object_name):
        return self.storage.get_object_iam_policy(bucket_name, object_name)

    def get_dataset_dataset_policy(self, projectid, datasetid):
        return self.bigquery.get_dataset_access(projectid, datasetid)
