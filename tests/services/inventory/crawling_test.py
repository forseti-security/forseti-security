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
"""Unit Tests: Inventory crawler for Forseti Server."""

import copy
import os
import time
import unittest
import unittest.mock as mock
from tests.services.inventory import gcp_api_mocks
from tests.services.util.mock import MockServerConfig
from tests import unittest_utils
from google.cloud.forseti.common.util import logger
from google.cloud.forseti.services.base.config import InventoryConfig
from google.cloud.forseti.services.inventory.base.progress import Progresser
from google.cloud.forseti.services.inventory.base.storage import Memory as MemoryStorage
from google.cloud.forseti.services.inventory.crawler import run_crawler

LOGGER = logger.get_logger(__name__)

TEST_RESOURCE_DIR_PATH = os.path.join(
    os.path.dirname(__file__), 'test_data')

GCP_API_RESOURCES = {
    'appengine_app': {'resource': 2},
    'appengine_instance': {'resource': 3},
    'appengine_service': {'resource': 1},
    'appengine_version': {'resource': 1},
    'backendservice': {'resource': 1},
    'billing_account': {'resource': 2, 'iam_policy': 2},
    'bucket': {'gcs_policy': 2, 'iam_policy': 2, 'resource': 2},
    'cloudsqlinstance': {'resource': 1},
    'compute_project': {'resource': 2},
    'crm_org_policy': {'resource': 5},
    'dataset': {'dataset_policy': 1, 'iam_policy': 1, 'resource': 1},
    'disk': {'resource': 4},
    'firewall': {'resource': 7},
    'folder': {'iam_policy': 3, 'resource': 3},
    'forwardingrule': {'resource': 1},
    'gsuite_group': {'resource': 4},
    'gsuite_groups_settings': {'resource': 4},
    'gsuite_group_member': {'resource': 1},
    'gsuite_user': {'resource': 4},
    'gsuite_user_member': {'resource': 3},
    'image': {'resource': 2},
    'instance': {'resource': 4},
    'instancegroup': {'resource': 2},
    'instancegroupmanager': {'resource': 2},
    'instancetemplate': {'resource': 2},
    'kubernetes_cluster': {'resource': 1, 'service_config': 1},
    'lien': {'resource': 1},
    'network': {'resource': 2},
    'organization': {'iam_policy': 1, 'resource': 1},
    'project': {'billing_info': 4, 'enabled_apis': 4, 'iam_policy': 4,
                'resource': 4},
    'role': {'resource': 20},
    'serviceaccount': {'iam_policy': 2, 'resource': 2},
    'sink': {'resource': 7},
    'snapshot': {'resource': 3},
    'subnetwork': {'resource': 24},
}


class FakeServerConfig(MockServerConfig):
    """Fake server config."""

    def __init__(self, engine):
        """Initialize."""
        self.engine = engine

    def get_engine(self):
        """Get engine."""
        return self.engine


class NullProgresser(Progresser):
    """No-op progresser to suppress output."""

    def __init__(self):
        super(NullProgresser, self).__init__()
        self.errors = 0
        self.inventory_index_id = int(time.time())
        self.objects = 0
        self.warnings = 0

    def on_new_object(self, resource):
        self.objects += 1

    def on_warning(self, warning):
        LOGGER.error("Progressor Warning: %s", warning)
        self.warnings += 1

    def on_error(self, error):
        LOGGER.exception("Progressor Error: %s", error)
        self.errors += 1

    def get_summary(self):
        pass


class CrawlerBase(unittest_utils.ForsetiTestCase):
    """Base class for Crawler tests."""

    def setUp(self):
        """Setup method."""
        self.maxDiff = None
        unittest_utils.ForsetiTestCase.setUp(self)

    def tearDown(self):
        """Tear down method."""

        unittest_utils.ForsetiTestCase.tearDown(self)

    def _get_resource_counts_from_storage(self, storage):
        result_counts = {}
        for item in list(storage.mem.values()):
            item_type = item.type()
            item_counts = result_counts.setdefault(
                item_type, {'resource': 0})
            item_counts['resource'] += 1
            if item.get_iam_policy():
                item_counts.setdefault('iam_policy', 0)
                item_counts['iam_policy'] += 1
            if item.get_gcs_policy():
                item_counts.setdefault('gcs_policy', 0)
                item_counts['gcs_policy'] += 1
            if item.get_dataset_policy():
                item_counts.setdefault('dataset_policy', 0)
                item_counts['dataset_policy'] += 1
            if item.get_billing_info():
                item_counts.setdefault('billing_info', 0)
                item_counts['billing_info'] += 1
            if item.get_enabled_apis():
                item_counts.setdefault('enabled_apis', 0)
                item_counts['enabled_apis'] += 1
            if item.get_kubernetes_service_config():
                item_counts.setdefault('service_config', 0)
                item_counts['service_config'] += 1

        return result_counts

    def _run_crawler(self, config, has_org_access=True):
        """Runs the crawler with a specific InventoryConfig.

        Args:
            config (InventoryConfig): The configuration to test.
            has_org_access (bool): True if crawler has access to the org
                resource.
            client (object): An API Client implementation, used for CAI testing.

        Returns:
            dict: the resource counts returned by the crawler.
        """
        with MemoryStorage() as storage:
            progresser = NullProgresser()
            with gcp_api_mocks.mock_gcp(has_org_access=has_org_access):
                run_crawler(storage,
                            progresser,
                            config,
                            parallel=True)

            self.assertEqual(0,
                             progresser.errors,
                             'No errors should have occurred')

            return self._get_resource_counts_from_storage(storage)


class CrawlerTest(CrawlerBase):
    """Test inventory storage."""

    def test_crawling_to_memory_storage(self):
        """Crawl mock environment, test that there are items in storage."""
        config = InventoryConfig(
            gcp_api_mocks.ORGANIZATION_ID,
            '',
            {},
            '',
            {})
        config.set_service_config(FakeServerConfig('mock_engine'))

        result_counts = self._run_crawler(config)

        expected_counts = GCP_API_RESOURCES

        self.assertEqual(expected_counts, result_counts)

    def test_crawling_to_memory_storage_exclude_all_folders_and_projects(self):
        """Crawl mock environment, test that all the folders are excluded."""
        config = InventoryConfig(
            gcp_api_mocks.ORGANIZATION_ID,
            '',
            {},
            '',
            {},
            excluded_resources=['folders/1031', 'folders/1032',
                                'projects/project1', 'projects/project2'])
        config.set_service_config(FakeServerConfig('mock_engine'))

        result_counts = self._run_crawler(config)

        expected_counts = {
            'billing_account': {'iam_policy': 2, 'resource': 2},
            'crm_org_policy': {'resource': 2},
            'gsuite_group': {'resource': 4},
            'gsuite_group_member': {'resource': 1},
            'gsuite_groups_settings': {'resource': 4},
            'gsuite_user': {'resource': 4},
            'gsuite_user_member': {'resource': 3},
            'organization': {'iam_policy': 1, 'resource': 1},
            'role': {'resource': 19},
            'sink': {'resource': 2}
        }

        self.assertEqual(expected_counts, result_counts)

    def test_crawling_to_memory_storage_exclude_all_folders_and_projects_using_projectNumber(self):
        """Crawl mock environment, test that all the folders are excluded."""
        config = InventoryConfig(
            gcp_api_mocks.ORGANIZATION_ID,
            '',
            {},
            '',
            {},
            excluded_resources=['folders/1031', 'folders/1032',
                                'projects/1041', 'projects/1042'])
        config.set_service_config(FakeServerConfig('mock_engine'))

        result_counts = self._run_crawler(config)

        expected_counts = {
            'billing_account': {'iam_policy': 2, 'resource': 2},
            'crm_org_policy': {'resource': 2},
            'gsuite_group': {'resource': 4},
            'gsuite_group_member': {'resource': 1},
            'gsuite_groups_settings': {'resource': 4},
            'gsuite_user': {'resource': 4},
            'gsuite_user_member': {'resource': 3},
            'organization': {'iam_policy': 1, 'resource': 1},
            'role': {'resource': 19},
            'sink': {'resource': 2}
        }

        self.assertEqual(expected_counts, result_counts)

    def test_crawling_from_folder(self):
        """Crawl from folder, verify expected resources crawled."""
        config = InventoryConfig(
            'folders/1032',
            '',
            {},
            '',
            {})
        config.set_service_config(FakeServerConfig('mock_engine'))

        result_counts = self._run_crawler(config)

        expected_counts = {
            'appengine_app': {'resource': 1},
            'appengine_instance': {'resource': 3},
            'appengine_service': {'resource': 1},
            'appengine_version': {'resource': 1},
            'bucket': {'gcs_policy': 1, 'iam_policy': 1, 'resource': 1},
            'folder': {'iam_policy': 2, 'resource': 2},
            'project': {'billing_info': 1, 'enabled_apis': 1, 'iam_policy': 1,
                        'resource': 1},
            'role': {'resource': 1},
            'sink': {'resource': 1},
        }

        self.assertEqual(expected_counts, result_counts)

    def test_crawling_from_folder_exclude_project(self):
        """Crawl from folder, and skip one project, verify
        expected resources crawled."""
        config = InventoryConfig(
            'folders/1032',
            '',
            {},
            '',
            {},
            excluded_resources=['projects/project4'])
        config.set_service_config(FakeServerConfig('mock_engine'))

        result_counts = self._run_crawler(config)

        expected_counts = {
            'folder': {'iam_policy': 2, 'resource': 2},
            'sink': {'resource': 1},
        }

        self.assertEqual(expected_counts, result_counts)

    def test_crawling_from_folder_exclude_project_using_projectNumber(self):
        """Crawl from folder, and skip one project, verify
        expected resources crawled."""
        config = InventoryConfig(
            'folders/1032',
            '',
            {},
            '',
            {},
            excluded_resources=['projects/1044'])
        config.set_service_config(FakeServerConfig('mock_engine'))

        result_counts = self._run_crawler(config)

        expected_counts = {
            'folder': {'iam_policy': 2, 'resource': 2},
            'sink': {'resource': 1},
        }

        self.assertEqual(expected_counts, result_counts)

    def test_crawling_from_folder_exclude_folder(self):
        """Crawl from folder, and skip one folder, verify
        expected resources crawled."""
        config = InventoryConfig(
            'folders/1032',
            '',
            {},
            '',
            {},
            excluded_resources=['folders/1033'])
        config.set_service_config(FakeServerConfig('mock_engine'))

        result_counts = self._run_crawler(config)

        expected_counts = {
            'folder': {'iam_policy': 1, 'resource': 1},
            'sink': {'resource': 1},
        }

        self.assertEqual(expected_counts, result_counts)

    def test_crawling_from_project(self):
        """Crawl from project, verify expected resources crawled."""
        config = InventoryConfig(
            'projects/1041',
            '',
            {},
            '',
            {})
        config.set_service_config(FakeServerConfig('mock_engine'))

        result_counts = self._run_crawler(config)

        expected_counts = {
            'backendservice': {'resource': 1},
            'compute_project': {'resource': 1},
            'crm_org_policy': {'resource': 1},
            'disk': {'resource': 3},
            'firewall': {'resource': 3},
            'forwardingrule': {'resource': 1},
            'instance': {'resource': 3},
            'instancegroup': {'resource': 2},
            'instancegroupmanager': {'resource': 2},
            'instancetemplate': {'resource': 2},
            'kubernetes_cluster': {'resource': 1, 'service_config': 1},
            'lien': {'resource': 1},
            'network': {'resource': 1},
            'project': {'billing_info': 1, 'enabled_apis': 1, 'iam_policy': 1,
                        'resource': 1},
            'serviceaccount': {'iam_policy': 1, 'resource': 1},
            'sink': {'resource': 2},
            'snapshot': {'resource': 2},
            'subnetwork': {'resource': 12},
        }

        self.assertEqual(expected_counts, result_counts)

    def test_crawling_from_composite_root(self):
        """Crawl from composite_root with folder and project."""
        config = InventoryConfig(
            None,
            '',
            {},
            '',
            {},
            ['folders/1032', 'projects/1041'])
        config.set_service_config(FakeServerConfig('mock_engine'))

        result_counts = self._run_crawler(config)

        expected_counts = {
            'appengine_app': {'resource': 1},
            'appengine_instance': {'resource': 3},
            'appengine_service': {'resource': 1},
            'appengine_version': {'resource': 1},
            'backendservice': {'resource': 1},
            'bucket': {'gcs_policy': 1, 'iam_policy': 1, 'resource': 1},
            'composite_root': {'resource': 1},
            'compute_project': {'resource': 1},
            'crm_org_policy': {'resource': 1},
            'disk': {'resource': 3},
            'firewall': {'resource': 3},
            'folder': {'iam_policy': 2, 'resource': 2},
            'forwardingrule': {'resource': 1},
            'instance': {'resource': 3},
            'instancegroup': {'resource': 2},
            'instancegroupmanager': {'resource': 2},
            'instancetemplate': {'resource': 2},
            'kubernetes_cluster': {'resource': 1, 'service_config': 1},
            'lien': {'resource': 1},
            'network': {'resource': 1},
            'project': {'billing_info': 2, 'enabled_apis': 2, 'iam_policy': 2,
                        'resource': 2},
            'role': {'resource': 1},
            'serviceaccount': {'iam_policy': 1, 'resource': 1},
            'sink': {'resource': 3},
            'snapshot': {'resource': 2},
            'subnetwork': {'resource': 12},
        }

        self.assertEqual(expected_counts, result_counts)

    def test_crawling_no_org_access(self):
        """Crawl with no access to organization, only child projects."""
        config = InventoryConfig(
            gcp_api_mocks.ORGANIZATION_ID,
            '',
            {},
            '',
            {})
        config.set_service_config(FakeServerConfig('mock_engine'))

        result_counts = self._run_crawler(config, has_org_access=False)

        # The crawl should be the same as test_crawling_to_memory_storage, but
        # without organization iam_policy, org_policy (needs Org access) or
        # gsuite_* resources (needs directoryCustomerId from Organization).
        expected_counts = copy.deepcopy(GCP_API_RESOURCES)
        expected_counts['organization'].pop('iam_policy')
        expected_counts['crm_org_policy']['resource'] -= 2
        expected_counts.pop('gsuite_group')
        expected_counts.pop('gsuite_groups_settings')
        expected_counts.pop('gsuite_group_member')
        expected_counts.pop('gsuite_user')
        expected_counts.pop('gsuite_user_member')

        self.assertEqual(expected_counts, result_counts)

    def test_crawling_with_apis_disabled(self):
        """Crawl with the appengine and cloudsql APIs disabled."""
        config = InventoryConfig(
            gcp_api_mocks.ORGANIZATION_ID,
            '',
            {
                'appengine': {'disable_polling': True},
                'sqladmin': {'disable_polling': True},
            },
            '',
            {})
        config.set_service_config(FakeServerConfig('mock_engine'))

        result_counts = self._run_crawler(config, has_org_access=True)

        # The crawl should be the same as test_crawling_to_memory_storage, but
        # without appengine and cloudsql resources.
        expected_counts = copy.deepcopy(GCP_API_RESOURCES)
        expected_counts.pop('appengine_app')
        expected_counts.pop('appengine_instance')
        expected_counts.pop('appengine_service')
        expected_counts.pop('appengine_version')
        expected_counts.pop('cloudsqlinstance')

        self.assertEqual(expected_counts, result_counts)


class CloudAssetCrawlerTest(CrawlerBase):
    """Test CloudAsset integration with crawler."""

    def setUp(self):
        """Setup method."""
        CrawlerBase.setUp(self)
        self.inventory_config = InventoryConfig(gcp_api_mocks.ORGANIZATION_ID,
                                                '',
                                                {},
                                                0,
                                                {'enabled': True,
                                                 'gcs_path': 'gs://test-bucket'}
                                               )
        self.inventory_config.set_service_config(
            FakeServerConfig('mock_engine'))

        self.maxDiff = None

    def _run_crawler(self, config):
        """Runs the crawler with a specific InventoryConfig.

        Args:
            config (InventoryConfig): The configuration to test.

        Returns:
            dict: the resource counts returned by the crawler.
        """
        # Mock download to return correct test data file
        def _fake_download(full_bucket_path, output_file):
            if 'resource' in full_bucket_path:
                fake_file = os.path.join(TEST_RESOURCE_DIR_PATH,
                                         'mock_cai_resources.dump')
            elif 'iam_policy' in full_bucket_path:
                fake_file = os.path.join(TEST_RESOURCE_DIR_PATH,
                                         'mock_cai_iam_policies.dump')
            elif 'org_policy' in full_bucket_path:
                fake_file = os.path.join(TEST_RESOURCE_DIR_PATH,
                                         'mock_cai_org_policies.dump')
            elif 'access_policy' in full_bucket_path:
                fake_file = os.path.join(TEST_RESOURCE_DIR_PATH,
                                         'mock_cai_access_policies.dump')
            with open(fake_file, 'rb') as f:
                output_file.write(f.read())

        with MemoryStorage() as storage:
            progresser = NullProgresser()
            with gcp_api_mocks.mock_gcp() as gcp_mocks:
                gcp_mocks.mock_storage.download.side_effect = _fake_download
                run_crawler(storage,
                            progresser,
                            config,
                            parallel=True)

            self.assertEqual(0,
                             progresser.errors,
                             'No errors should have occurred')
            return self._get_resource_counts_from_storage(storage)

    def tearDown(self):
        """tearDown."""
        CrawlerBase.tearDown(self)
        mock.patch.stopall()

    def test_cai_crawl_to_memory(self):
        """Crawl mock environment, test that there are items in storage."""
        result_counts = self._run_crawler(self.inventory_config)

        expected_counts = copy.deepcopy(GCP_API_RESOURCES)
        expected_counts.update({
            'backendservice': {'resource': 2},
            'bigquery_table': {'resource': 1},
            'bigtable_cluster': {'resource': 1},
            'bigtable_instance': {'resource': 1},
            'bigtable_table': {'resource': 1},
            'cloudsqlinstance': {'resource': 2},
            'compute_address': {'resource': 2},
            'compute_autoscaler': {'resource': 1},
            'compute_backendbucket': {'resource': 1},
            'compute_healthcheck': {'resource': 1},
            'compute_httphealthcheck': {'resource': 1},
            'compute_httpshealthcheck': {'resource': 1},
            'compute_interconnect': {'resource': 1},
            'compute_interconnect_attachment': {'resource': 1},
            'compute_license': {'resource': 1},
            'compute_router': {'resource': 1},
            'compute_securitypolicy': {'resource': 1},
            'compute_sslcertificate': {'resource': 1},
            'compute_targethttpproxy': {'resource': 1},
            'compute_targethttpsproxy': {'resource': 1},
            'compute_targetinstance': {'resource': 1},
            'compute_targetpool': {'resource': 1},
            'compute_targetsslproxy': {'resource': 1},
            'compute_targettcpproxy': {'resource': 1},
            'compute_targetvpngateway': {'resource': 1},
            'compute_urlmap': {'resource': 1},
            'compute_vpntunnel': {'resource': 1},
            'crm_access_level': {'resource': 3},
            'crm_access_policy': {'resource': 2},
            'crm_org_policy': {'resource': 3},
            'crm_service_perimeter': {'resource': 2},
            'dataproc_cluster': {'resource': 2, 'iam_policy': 1},
            'dataset': {'dataset_policy': 2, 'iam_policy': 2, 'resource': 3},
            'disk': {'resource': 5},
            'dns_managedzone': {'resource': 1},
            'dns_policy': {'resource': 1},
            'forwardingrule': {'resource': 2},
            'kms_cryptokey': {'iam_policy': 1, 'resource': 1},
            'kms_cryptokeyversion': {'resource': 1},
            'kms_keyring': {'iam_policy': 1, 'resource': 1},
            'kubernetes_cluster': {'resource': 1, 'service_config': 1},
            'kubernetes_clusterrole': {'resource': 1},
            'kubernetes_clusterrolebinding':
                {'resource': 1},
            'kubernetes_namespace': {'resource': 1},
            'kubernetes_node': {'resource': 1},
            'kubernetes_pod': {'resource': 1},
            'kubernetes_role': {'resource': 1},
            'kubernetes_rolebinding': {'resource': 1},
            'pubsub_subscription': {'iam_policy': 1, 'resource': 1},
            'pubsub_topic': {'iam_policy': 1, 'resource': 1},
            'serviceaccount': {'iam_policy': 2, 'resource': 3},
            'serviceaccount_key': {'resource': 1},
            'spanner_database': {'resource': 1},
            'spanner_instance': {'resource': 1},
        })

        self.assertEqual(expected_counts, result_counts)

    def test_crawl_cai_api_polling_disabled(self):
        """Validate using only CAI and no API polling works."""
        self.inventory_config.api_quota_configs = {
            'admin': {'disable_polling': True},
            'appengine': {'disable_polling': True},
            'bigquery': {'disable_polling': True},
            'cloudbilling': {'disable_polling': True},
            'compute': {'disable_polling': True},
            'container': {'disable_polling': True},
            'crm': {'disable_polling': True},
            'iam': {'disable_polling': True},
            'logging': {'disable_polling': True},
            'servicemanagement': {'disable_polling': True},
            'serviceusage': {'disable_polling': True},
            'sqladmin': {'disable_polling': True},
            'storage': {'disable_polling': True},
        }
        result_counts = self._run_crawler(self.inventory_config)
        # Any resource not included in Cloud Asset export will not be in the
        # inventory.
        expected_counts = {
            'appengine_app': {'resource': 2},
            'appengine_service': {'resource': 1},
            'appengine_version': {'resource': 1},
            'backendservice': {'resource': 2},
            'bigtable_cluster': {'resource': 1},
            'bigtable_instance': {'resource': 1},
            'bigtable_table': {'resource': 1},
            'billing_account': {'iam_policy': 2, 'resource': 2},
            'bigquery_table': {'resource': 1},
            'bucket': {'gcs_policy': 2, 'iam_policy': 2, 'resource': 2},
            'cloudsqlinstance': {'resource': 2},
            'compute_address': {'resource': 2},
            'compute_autoscaler': {'resource': 1},
            'compute_backendbucket': {'resource': 1},
            'compute_healthcheck': {'resource': 1},
            'compute_httphealthcheck': {'resource': 1},
            'compute_httpshealthcheck': {'resource': 1},
            'compute_interconnect': {'resource': 1},
            'compute_interconnect_attachment': {'resource': 1},
            'compute_license': {'resource': 1},
            'compute_project': {'resource': 2},
            'compute_router': {'resource': 1},
            'compute_securitypolicy': {'resource': 1},
            'compute_sslcertificate': {'resource': 1},
            'compute_targethttpproxy': {'resource': 1},
            'compute_targethttpsproxy': {'resource': 1},
            'compute_targetinstance': {'resource': 1},
            'compute_targetpool': {'resource': 1},
            'compute_targetsslproxy': {'resource': 1},
            'compute_targettcpproxy': {'resource': 1},
            'compute_targetvpngateway': {'resource': 1},
            'compute_urlmap': {'resource': 1},
            'compute_vpntunnel': {'resource': 1},
            'crm_access_level': {'resource': 3},
            'crm_access_policy': {'resource': 2},
            'crm_org_policy': {'resource': 3},
            'crm_service_perimeter': {'resource': 2},
            'dataproc_cluster': {'resource': 2, 'iam_policy': 1},
            'dataset': {'dataset_policy': 2, 'iam_policy': 2, 'resource': 3},
            'disk': {'resource': 5},
            'dns_managedzone': {'resource': 1},
            'dns_policy': {'resource': 1},
            'firewall': {'resource': 7},
            'folder': {'iam_policy': 3, 'resource': 3},
            'forwardingrule': {'resource': 2},
            'image': {'resource': 2},
            'instance': {'resource': 4},
            'instancegroup': {'resource': 2},
            'instancegroupmanager': {'resource': 2},
            'instancetemplate': {'resource': 2},
            'kms_cryptokey': {'iam_policy': 1, 'resource': 1},
            'kms_cryptokeyversion': {'resource': 1},
            'kms_keyring': {'iam_policy': 1, 'resource': 1},
            'kubernetes_cluster': {'resource': 1},
            'kubernetes_clusterrole': {'resource': 1},
            'kubernetes_clusterrolebinding':
                {'resource': 1},
            'kubernetes_namespace': {'resource': 1},
            'kubernetes_node': {'resource': 1},
            'kubernetes_pod': {'resource': 1},
            'kubernetes_role': {'resource': 1},
            'kubernetes_rolebinding': {'resource': 1},
            'network': {'resource': 2},
            'organization': {'iam_policy': 1, 'resource': 1},
            'project': {'iam_policy': 4, 'resource': 4},
            'pubsub_subscription': {'iam_policy': 1, 'resource': 1},
            'pubsub_topic': {'iam_policy': 1, 'resource': 1},
            'role': {'resource': 2},
            'serviceaccount': {'iam_policy': 2, 'resource': 3},
            'serviceaccount_key': {'resource': 1},
            'snapshot': {'resource': 3},
            'spanner_database': {'resource': 1},
            'spanner_instance': {'resource': 1},
            'subnetwork': {'resource': 24}}
        self.assertEqual(expected_counts, result_counts)

    def test_crawl_cai_data_with_asset_types(self):
        """Validate including asset_types in the CAI inventory config works."""
        asset_types = ['cloudresourcemanager.googleapis.com/Folder',
                       'cloudresourcemanager.googleapis.com/Organization',
                       'cloudresourcemanager.googleapis.com/Project']
        inventory_config = InventoryConfig(gcp_api_mocks.ORGANIZATION_ID,
                                           '',
                                           {},
                                           0,
                                           {'enabled': True,
                                            'gcs_path': 'gs://test-bucket',
                                            'asset_types': asset_types}
                                          )
        inventory_config.set_service_config(FakeServerConfig('fake_engine'))

        # Create subsets of the mock resource dumps that only contain the
        # filtered asset types
        filtered_assets = []
        with open(os.path.join(TEST_RESOURCE_DIR_PATH,
                               'mock_cai_resources.dump'), 'r') as f:
            for line in f:
                if any('"%s"' % asset_type in line
                       for asset_type in asset_types):
                    filtered_assets.append(line)

        filtered_assets = ''.join(filtered_assets)

        filtered_iam = []
        with open(os.path.join(TEST_RESOURCE_DIR_PATH,
                               'mock_cai_iam_policies.dump'), 'r') as f:
            for line in f:
                if any('"%s"' % asset_type in line
                       for asset_type in asset_types):
                    filtered_iam.append(line)

        filtered_iam = ''.join(filtered_iam)

        filtered_org = []
        with open(os.path.join(TEST_RESOURCE_DIR_PATH,
                               'mock_cai_org_policies.dump'), 'r') as f:
            for line in f:
                if any('"%s"' % asset_type in line
                       for asset_type in asset_types):
                    filtered_org.append(line)

        filtered_org = ''.join(filtered_org)

        filtered_access = []
        with open(os.path.join(TEST_RESOURCE_DIR_PATH,
                               'mock_cai_access_policies.dump'), 'r') as f:
            for line in f:
                if any('"%s"' % asset_type in line
                       for asset_type in asset_types):
                    filtered_access.append(line)

        filtered_access = ''.join(filtered_access)

        with unittest_utils.create_temp_file(filtered_assets) as resources:
            with unittest_utils.create_temp_file(filtered_iam) as iam_policies:
                with unittest_utils.create_temp_file(
                        filtered_org) as org_policies:
                    with unittest_utils.create_temp_file(
                            filtered_access) as access_policies:
                        # Mock download to return correct test data file
                        def _fake_download(full_bucket_path, output_file):
                            if 'resource' in full_bucket_path:
                                fake_file = resources
                            elif 'iam_policy' in full_bucket_path:
                                fake_file = iam_policies
                            elif 'org_policy' in full_bucket_path:
                                fake_file = org_policies
                            elif 'access_policy' in full_bucket_path:
                                fake_file = access_policies
                            with open(fake_file, 'rb') as f:
                                output_file.write(f.read())

                        with MemoryStorage() as storage:
                            progresser = NullProgresser()
                            with gcp_api_mocks.mock_gcp() as gcp_mocks:
                                gcp_mocks.mock_storage.download.side_effect = (
                                    _fake_download)
                                run_crawler(storage,
                                            progresser,
                                            inventory_config)

                                # Validate export_assets called with asset_types
                                expected_calls = [
                                    mock.call(gcp_api_mocks.ORGANIZATION_ID,
                                              output_config=mock.ANY,
                                              content_type='RESOURCE',
                                              asset_types=asset_types,
                                              blocking=mock.ANY,
                                              timeout=mock.ANY),
                                    mock.call(gcp_api_mocks.ORGANIZATION_ID,
                                              output_config=mock.ANY,
                                              content_type='IAM_POLICY',
                                              asset_types=asset_types,
                                              blocking=mock.ANY,
                                              timeout=mock.ANY),
                                    mock.call(gcp_api_mocks.ORGANIZATION_ID,
                                              output_config=mock.ANY,
                                              content_type='ORG_POLICY',
                                              asset_types=asset_types,
                                              blocking=mock.ANY,
                                              timeout=mock.ANY),
                                    mock.call(gcp_api_mocks.ORGANIZATION_ID,
                                              output_config=mock.ANY,
                                              content_type='ACCESS_POLICY',
                                              asset_types=asset_types,
                                              blocking=mock.ANY,
                                              timeout=mock.ANY)]
                                (gcp_mocks.mock_cloudasset.export_assets
                                .assert_has_calls(expected_calls, any_order=True))

                        self.assertEqual(0,
                                         progresser.errors,
                                         'No errors should have occurred')

                        result_counts = self._get_resource_counts_from_storage(
                            storage)

        expected_counts = {
            'crm_access_level': {'resource': 3},
            'crm_access_policy': {'resource': 2},
            'crm_org_policy': {'resource': 3},
            'crm_service_perimeter': {'resource': 2},
            'folder': {'iam_policy': 3, 'resource': 3},
            'gsuite_group': {'resource': 4},
            'gsuite_group_member': {'resource': 1},
            'gsuite_groups_settings': {'resource': 4},
            'gsuite_user': {'resource': 4},
            'gsuite_user_member': {'resource': 3},
            'lien': {'resource': 1},
            'organization': {'iam_policy': 1, 'resource': 1},
            'project': {'billing_info': 4, 'enabled_apis': 4, 'iam_policy': 4,
                        'resource': 4},
            'role': {'resource': 18},
            'sink': {'resource': 6},
        }

        self.assertEqual(expected_counts, result_counts)


if __name__ == '__main__':
    unittest.main()
