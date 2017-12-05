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

"""Mock responses to GCP API calls, for testing."""

import contextlib
from googleapiclient import errors
import httplib2
import mock
from tests.services.inventory.test_data import mock_gcp_results as results
from google.cloud.forseti.common.gcp_api import errors as api_errors

MODULE_PATH = 'google.cloud.forseti.common.gcp_api.'

ORGANIZATION_ID = results.ORGANIZATION_ID


# pylint: disable=bad-indentation
@contextlib.contextmanager
def mock_gcp():
    """Mock the GCP API client libraries to return fake data."""
    ad_patcher = _mock_admin_directory()
    appengine_patcher = _mock_appengine()
    bq_patcher = _mock_bigquery()
    cloudsql_patcher = _mock_cloudsql()
    crm_patcher = _mock_crm()
    gce_patcher = _mock_gce()
    gcs_patcher = _mock_gcs()
    iam_patcher = _mock_iam()
    try:
        yield
    finally:
        ad_patcher.stop()
        appengine_patcher.stop()
        bq_patcher.stop()
        cloudsql_patcher.stop()
        crm_patcher.stop()
        gce_patcher.stop()
        gcs_patcher.stop()
        iam_patcher.stop()


def _mock_admin_directory():
    """Mock admin directory client."""

    def _mock_ad_get_users(gsuite_id):
        return results.AD_GET_USERS[gsuite_id]

    def _mock_ad_get_groups(gsuite_id):
        return results.AD_GET_GROUPS[gsuite_id]

    def _mock_ad_get_group_members(group_key):
        return results.AD_GET_GROUP_MEMBERS[group_key]

    ad_patcher = mock.patch(
        MODULE_PATH + 'admin_directory.AdminDirectoryClient', spec=True)
    mock_ad = ad_patcher.start().return_value
    mock_ad.get_users.side_effect = _mock_ad_get_users
    mock_ad.get_groups.side_effect = _mock_ad_get_groups
    mock_ad.get_group_members.side_effect = _mock_ad_get_group_members

    return ad_patcher


def _mock_appengine():
    """Mock appengine client."""

    def _mock_gae_get_app(projectid):
        if projectid in results.GAE_GET_APP:
            return results.GAE_GET_APP[projectid]
        return {}

    def _mock_gae_list_services(projectid):
        if projectid in results.GAE_GET_SERVICES:
            return results.GAE_GET_SERVICES[projectid]
        return []

    def _mock_gae_list_versions(projectid, serviceid):
        if projectid in results.GAE_GET_VERSIONS:
            if serviceid in results.GAE_GET_VERSIONS[projectid]:
                return results.GAE_GET_VERSIONS[projectid][serviceid]
        return []

    def _mock_gae_list_instances(projectid, serviceid, versionid):
        if projectid in results.GAE_GET_INSTANCES:
            gae_project = results.GAE_GET_INSTANCES[projectid]
            if serviceid in gae_project:
                if versionid in gae_project[serviceid]:
                    return gae_project[serviceid][versionid]
        return []

    appengine_patcher = mock.patch(
        MODULE_PATH + 'appengine.AppEngineClient', spec=True)
    mock_gae = appengine_patcher.start().return_value

    mock_gae.get_app.side_effect = _mock_gae_get_app
    mock_gae.list_services.side_effect = _mock_gae_list_services
    mock_gae.list_versions.side_effect = _mock_gae_list_versions
    mock_gae.list_instances.side_effect = _mock_gae_list_instances

    return appengine_patcher


def _mock_bigquery():
    """Mock bigquery client."""

    def _mock_bq_get_datasets_for_projectid(projectid):
        return results.BQ_GET_DATASETS_FOR_PROJECTID[projectid]

    def _mock_bq_get_dataset_access(projectid, datasetid):
        return results.BQ_GET_DATASET_ACCESS[projectid][datasetid]

    bq_patcher = mock.patch(
        MODULE_PATH + 'bigquery.BigQueryClient', spec=True)
    mock_bq = bq_patcher.start().return_value
    mock_bq.get_datasets_for_projectid = _mock_bq_get_datasets_for_projectid
    mock_bq.get_dataset_access = _mock_bq_get_dataset_access

    return bq_patcher


def _mock_cloudsql():
    """Mock CloudSQL client."""
    def _mock_sql_get_instances(projectid):
        if projectid in results.SQL_GET_INSTANCES:
            return results.SQL_GET_INSTANCES[projectid]
        return []

    sql_patcher = mock.patch(
        MODULE_PATH + 'cloudsql.CloudsqlClient', spec=True)
    mock_sql = sql_patcher.start().return_value
    mock_sql.get_instances.side_effect = _mock_sql_get_instances

    return sql_patcher


def _mock_crm():
    """Mock crm client."""

    def _mock_crm_get_organization(orgid):
        return results.CRM_GET_ORGANIZATION[orgid]

    def _mock_crm_get_folder(folderid):
        return results.CRM_GET_FOLDER[folderid]

    def _mock_crm_get_folders(parentid):
        return results.CRM_GET_FOLDERS[parentid]

    def _mock_crm_get_project(projectid):
        return results.CRM_GET_PROJECT[projectid]

    def _mock_crm_get_projects(parent_type, parent_id):
        return results.CRM_GET_PROJECTS[parent_type][parent_id]

    def _mock_crm_get_iam_policies(folderid):
        return results.CRM_GET_IAM_POLICIES[folderid]

    crm_patcher = mock.patch(
        MODULE_PATH + 'cloud_resource_manager.CloudResourceManagerClient',
        spec=True)
    mock_crm = crm_patcher.start().return_value
    mock_crm.get_organization.side_effect = _mock_crm_get_organization
    mock_crm.get_folder.side_effect = _mock_crm_get_folder
    mock_crm.get_folders.side_effect = _mock_crm_get_folders
    mock_crm.get_project.side_effect = _mock_crm_get_project
    mock_crm.get_projects.side_effect = _mock_crm_get_projects
    mock_crm.get_org_iam_policies.side_effect = _mock_crm_get_iam_policies
    mock_crm.get_folder_iam_policies.side_effect = _mock_crm_get_iam_policies
    mock_crm.get_project_iam_policies.side_effect = _mock_crm_get_iam_policies

    return crm_patcher


def _mock_gce():
    """Mock compute client."""

    def _mock_gce_is_api_enabled(projectid):
        return projectid in results.GCE_GET_PROJECT

    def _mock_gce_get_project(projectid):
        if projectid in results.GCE_GET_PROJECT:
            return results.GCE_GET_PROJECT[projectid]
        response = httplib2.Response(
            {'status': '403', 'content-type': 'application/json'})
        content = results.GCE_API_NOT_ENABLED_TEMPLATE.format(id=projectid)
        error_403 = errors.HttpError(response, content)
        raise api_errors.ApiNotEnabledError('Access Not Configured.', error_403)

    def _mock_gce_get_instances(projectid):
        return results.GCE_GET_INSTANCES[projectid]

    def _mock_gce_get_firewall_rules(projectid):
        return results.GCE_GET_FIREWALLS[projectid]

    def _mock_gce_get_instance_groups(projectid):
        if projectid in results.GCE_GET_INSTANCE_GROUPS:
            return results.GCE_GET_INSTANCE_GROUPS[projectid]
        return []

    def _mock_gce_get_instance_group_managers(projectid):
        if projectid in results.GCE_GET_INSTANCE_GROUP_MANAGERS:
            return results.GCE_GET_INSTANCE_GROUP_MANAGERS[projectid]
        return []

    def _mock_gce_get_instance_templates(projectid):
        if projectid in results.GCE_GET_INSTANCE_TEMPLATES:
            return results.GCE_GET_INSTANCE_TEMPLATES[projectid]
        return []

    def _mock_gce_get_backend_services(projectid):
        if projectid in results.GCE_GET_BACKEND_SERVICES:
            return results.GCE_GET_BACKEND_SERVICES[projectid]
        return []

    def _mock_gce_get_forwarding_rules(projectid):
        if projectid in results.GCE_GET_FORWARDING_RULES:
            return results.GCE_GET_FORWARDING_RULES[projectid]
        return []

    def _mock_gce_get_networks(projectid):
        if projectid in results.GCE_GET_NETWORKS:
            return results.GCE_GET_NETWORKS[projectid]
        return []

    def _mock_gce_get_subnetworks(projectid):
        if projectid in results.GCE_GET_SUBNETWORKS:
            return results.GCE_GET_SUBNETWORKS[projectid]
        return []

    gce_patcher = mock.patch(
        MODULE_PATH + 'compute.ComputeClient', spec=True)
    mock_gce = gce_patcher.start().return_value
    mock_gce.is_api_enabled.side_effect = _mock_gce_is_api_enabled
    mock_gce.get_project.side_effect = _mock_gce_get_project
    mock_gce.get_instances.side_effect = _mock_gce_get_instances
    mock_gce.get_firewall_rules.side_effect = _mock_gce_get_firewall_rules
    mock_gce.get_instance_groups.side_effect = _mock_gce_get_instance_groups
    mock_gce.get_instance_group_managers.side_effect = (
        _mock_gce_get_instance_group_managers)
    mock_gce.get_instance_templates.side_effect = (
        _mock_gce_get_instance_templates)
    mock_gce.get_backend_services.side_effect = _mock_gce_get_backend_services
    mock_gce.get_forwarding_rules.side_effect = _mock_gce_get_forwarding_rules
    mock_gce.get_networks.side_effect = _mock_gce_get_networks
    mock_gce.get_subnetworks.side_effect = _mock_gce_get_subnetworks

    return gce_patcher


def _mock_gcs():
    """Mock storage client."""
    def _mock_gcs_get_buckets(projectid):
        if projectid in results.GCS_GET_BUCKETS:
            return results.GCS_GET_BUCKETS[projectid]
        return []

    def _mock_gcs_get_objects(bucket_name):
        if bucket_name in results.GCS_GET_OBJECTS:
            return results.GCS_GET_OBJECTS[bucket_name]
        return []

    def _mock_gcs_get_bucket_acls(bucketid):
        return results.GCS_GET_BUCKET_ACLS[bucketid]

    def _mock_gcs_get_bucket_iam(bucketid):
        return results.GCS_GET_BUCKET_IAM[bucketid]

    def _mock_gcs_get_object_acls(bucket_name, object_name):
        if (bucket_name in results.GCS_GET_OBJECT_ACLS and
                object_name in results.GCS_GET_OBJECT_ACLS[bucket_name]):
            return results.GCS_GET_OBJECT_ACLS[bucket_name][object_name]
        return []

    def _mock_gcs_get_object_iam(bucket_name, object_name):
        if (bucket_name in results.GCS_GET_OBJECT_IAM and
                object_name in results.GCS_GET_OBJECT_IAM[bucket_name]):
            return results.GCS_GET_OBJECT_IAM[bucket_name][object_name]
        return {}

    gcs_patcher = mock.patch(
        MODULE_PATH + 'storage.StorageClient', spec=True)
    mock_gcs = gcs_patcher.start().return_value
    mock_gcs.get_buckets.side_effect = _mock_gcs_get_buckets
    mock_gcs.get_objects.side_effect = _mock_gcs_get_objects
    mock_gcs.get_bucket_acls.side_effect = _mock_gcs_get_bucket_acls
    mock_gcs.get_bucket_iam_policy.side_effect = _mock_gcs_get_bucket_iam
    mock_gcs.get_object_acls.side_effect = _mock_gcs_get_object_acls
    mock_gcs.get_object_iam_policy.side_effect = _mock_gcs_get_object_iam

    return gcs_patcher


def _mock_iam():
    """Mock IAM client."""
    def _mock_iam_get_service_accounts(projectid):
        if projectid in results.IAM_GET_SERVICEACCOUNTS:
            return results.IAM_GET_SERVICEACCOUNTS[projectid]
        return []

    def _mock_iam_get_project_roles(projectid):
        if projectid in results.IAM_GET_PROJECT_ROLES:
            return results.IAM_GET_PROJECT_ROLES[projectid]
        return []

    def _mock_iam_get_org_roles(orgid):
        if orgid in results.IAM_GET_ORG_ROLES:
            return results.IAM_GET_ORG_ROLES[orgid]
        return []

    def _mock_iam_get_curated_roles():
        return results.IAM_GET_CURATED_ROLES

    def _mock_iam_get_service_account_iam_policy(name):
        return results.IAM_GET_SERVICEACCOUNT_IAM_POLICY[name]

    def _mock_iam_get_service_account_keys(name, key_type):
        del key_type
        if name in results.IAM_GET_SERVICEACCOUNT_KEYS:
            return results.IAM_GET_SERVICEACCOUNT_KEYS[name]
        return []

    iam_patcher = mock.patch(
        MODULE_PATH + 'iam.IAMClient', spec=True)
    mock_iam = iam_patcher.start().return_value
    mock_iam.get_service_accounts.side_effect = _mock_iam_get_service_accounts
    mock_iam.get_project_roles.side_effect = _mock_iam_get_project_roles
    mock_iam.get_organization_roles.side_effect = _mock_iam_get_org_roles
    mock_iam.get_curated_roles.side_effect = _mock_iam_get_curated_roles
    mock_iam.get_service_account_iam_policy.side_effect = (
        _mock_iam_get_service_account_iam_policy)
    mock_iam.get_service_account_keys.side_effect = (
        _mock_iam_get_service_account_keys)

    return iam_patcher
