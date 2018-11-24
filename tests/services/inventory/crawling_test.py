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

import os
import unittest
import mock
from sqlalchemy.orm import sessionmaker
from tests.services.inventory import gcp_api_mocks
from tests.services.util.db import create_test_engine_with_file
from tests.services.util.mock import MockServerConfig
from tests import unittest_utils
from google.cloud.forseti.common.util import file_loader
from google.cloud.forseti.common.util import logger
from google.cloud.forseti.services.base.config import InventoryConfig
from google.cloud.forseti.services.inventory.storage import initialize
from google.cloud.forseti.services.inventory.base.progress import Progresser
from google.cloud.forseti.services.inventory.base.storage import Memory as MemoryStorage
from google.cloud.forseti.services.inventory.crawler import run_crawler

LOGGER = logger.get_logger(__name__)

TEST_RESOURCE_DIR_PATH = os.path.join(
    os.path.dirname(__file__), 'test_data')


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


class CrawlerTest(unittest_utils.ForsetiTestCase):
    """Test inventory storage."""

    def setUp(self):
        """Setup method."""
        self.maxDiff = None
        unittest_utils.ForsetiTestCase.setUp(self)

    def tearDown(self):
        """Tear down method."""

        unittest_utils.ForsetiTestCase.tearDown(self)

    def _get_resource_counts_from_storage(self, storage):
        result_counts = {}
        for item in storage.mem.values():
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

    def test_crawling_to_memory_storage(self):
        """Crawl mock environment, test that there are items in storage."""

        config = InventoryConfig(
            gcp_api_mocks.ORGANIZATION_ID,
            '',
            {},
            '',
            {})
        config.set_service_config(FakeServerConfig('mock_engine'))

        with MemoryStorage() as storage:
            progresser = NullProgresser()
            with gcp_api_mocks.mock_gcp():
                run_crawler(storage,
                            progresser,
                            config,
                            parallel=True)

            self.assertEqual(0,
                             progresser.errors,
                             'No errors should have occurred')

            result_counts = self._get_resource_counts_from_storage(storage)

        expected_counts = {
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
            'dataset': {'dataset_policy': 1, 'resource': 1},
            'disk': {'resource': 4},
            'firewall': {'resource': 7},
            'folder': {'iam_policy': 3, 'resource': 3},
            'forwardingrule': {'resource': 1},
            'gsuite_group': {'resource': 4},
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
            'role': {'resource': 5},
            'serviceaccount': {'iam_policy': 2, 'resource': 2},
            'serviceaccount_key': {'resource': 1},
            'sink': {'resource': 7},
            'snapshot': {'resource': 3},
            'subnetwork': {'resource': 24},
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

        with MemoryStorage() as storage:
            progresser = NullProgresser()
            with gcp_api_mocks.mock_gcp():
                run_crawler(storage,
                            progresser,
                            config,
                            parallel=False)

            self.assertEqual(0,
                             progresser.errors,
                             'No errors should have occurred')

            result_counts = self._get_resource_counts_from_storage(storage)

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

    def test_crawling_from_project(self):
        """Crawl from project, verify expected resources crawled."""

        config = InventoryConfig(
            'projects/1041',
            '',
            {},
            '',
            {})
        config.set_service_config(FakeServerConfig('mock_engine'))

        with MemoryStorage() as storage:
            progresser = NullProgresser()
            with gcp_api_mocks.mock_gcp():
                run_crawler(storage,
                            progresser,
                            config,
                            parallel=False)

            self.assertEqual(0,
                             progresser.errors,
                             'No errors should have occurred')


            result_counts = self._get_resource_counts_from_storage(storage)

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
            'serviceaccount_key': {'resource': 1},
            'sink': {'resource': 2},
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

        with MemoryStorage() as storage:
            progresser = NullProgresser()
            with gcp_api_mocks.mock_gcp(has_org_access=False):
                run_crawler(storage,
                            progresser,
                            config,
                            parallel=True)

            self.assertEqual(0,
                             progresser.errors,
                             'No errors should have occurred')

            result_counts = self._get_resource_counts_from_storage(storage)

        # The crawl should be the same as test_crawling_to_memory_storage, but
        # without organization iam_policy, org_policy (needs Org access) or
        # gsuite_* resources (needs directoryCustomerId from Organization).
        expected_counts = {
            'appengine_app': {'resource': 2},
            'appengine_instance': {'resource': 3},
            'appengine_service': {'resource': 1},
            'appengine_version': {'resource': 1},
            'backendservice': {'resource': 1},
            'billing_account': {'resource': 2, 'iam_policy': 2},
            'bucket': {'gcs_policy': 2, 'iam_policy': 2, 'resource': 2},
            'cloudsqlinstance': {'resource': 1},
            'compute_project': {'resource': 2},
            'crm_org_policy': {'resource': 3},
            'dataset': {'dataset_policy': 1, 'resource': 1},
            'disk': {'resource': 4},
            'firewall': {'resource': 7},
            'folder': {'iam_policy': 3, 'resource': 3},
            'forwardingrule': {'resource': 1},
            'image': {'resource': 2},
            'instance': {'resource': 4},
            'instancegroup': {'resource': 2},
            'instancegroupmanager': {'resource': 2},
            'instancetemplate': {'resource': 2},
            'kubernetes_cluster': {'resource': 1, 'service_config': 1},
            'lien': {'resource': 1},
            'network': {'resource': 2},
            'organization': {'resource': 1},
            'project': {'billing_info': 4, 'enabled_apis': 4, 'iam_policy': 4,
                        'resource': 4},
            'role': {'resource': 5},
            'serviceaccount': {'iam_policy': 2, 'resource': 2},
            'serviceaccount_key': {'resource': 1},
            'sink': {'resource': 7},
            'snapshot': {'resource': 3},
            'subnetwork': {'resource': 24},
        }

        self.assertEqual(expected_counts, result_counts)


class CloudAssetCrawlerTest(CrawlerTest):
    """Test CloudAsset integration with crawler."""

    def setUp(self):
        """Setup method."""
        CrawlerTest.setUp(self)
        self.engine, self.dbfile = create_test_engine_with_file()
        session_maker = sessionmaker()
        self.session = session_maker(bind=self.engine)
        initialize(self.engine)
        self.inventory_config = InventoryConfig(gcp_api_mocks.ORGANIZATION_ID,
                                                '',
                                                {},
                                                0,
                                                {'enabled': True,
                                                 'gcs_path': 'gs://test-bucket'}
                                               )
        self.inventory_config.set_service_config(FakeServerConfig(self.engine))

        # Ensure test data doesn't get deleted
        self.mock_unlink = mock.patch.object(
            os, 'unlink', autospec=True).start()
        self.mock_copy_file_from_gcs = mock.patch.object(
            file_loader,
            'copy_file_from_gcs',
            autospec=True).start()
        self.maxDiff = None

        # Mock copy_file_from_gcs to return correct test data file
        def _copy_file_from_gcs(file_path, *args, **kwargs):
            """Fake copy_file_from_gcs."""
            del args, kwargs
            if 'resource' in file_path:
                return os.path.join(TEST_RESOURCE_DIR_PATH,
                                    'mock_cai_resources.dump')
            elif 'iam_policy' in file_path:
                return os.path.join(TEST_RESOURCE_DIR_PATH,
                                    'mock_cai_iam_policies.dump')

        self.mock_copy_file_from_gcs.side_effect = _copy_file_from_gcs

    def tearDown(self):
        """tearDown."""
        CrawlerTest.tearDown(self)
        mock.patch.stopall()

        # Stop mocks before unlinking the database file.
        os.unlink(self.dbfile)

    def test_cai_crawl_to_memory(self):
        """Crawl mock environment, test that there are items in storage."""
        with MemoryStorage(session=self.session) as storage:
            progresser = NullProgresser()
            with gcp_api_mocks.mock_gcp():
                run_crawler(storage,
                            progresser,
                            self.inventory_config,
                            parallel=True)

            self.assertEqual(0,
                             progresser.errors,
                             'No errors should have occurred')

            result_counts = self._get_resource_counts_from_storage(storage)

        expected_counts = {
            'appengine_app': {'resource': 2},
            'appengine_instance': {'resource': 3},
            'appengine_service': {'resource': 1},
            'appengine_version': {'resource': 1},
            'backendservice': {'resource': 1},
            'billing_account': {'resource': 2, 'iam_policy': 2},
            'bucket': {'gcs_policy': 2, 'iam_policy': 2, 'resource': 2},
            'cloudsqlinstance': {'resource': 1},
            'compute_autoscaler': {'resource': 1},
            'compute_backendbucket': {'resource': 1},
            'compute_healthcheck': {'resource': 1},
            'compute_httphealthcheck': {'resource': 1},
            'compute_httpshealthcheck': {'resource': 1},
            'compute_license': {'resource': 1},
            'compute_project': {'resource': 2},
            'compute_router': {'resource': 1},
            'compute_sslcertificate': {'resource': 1},
            'compute_targethttpproxy': {'resource': 1},
            'compute_targethttpsproxy': {'resource': 1},
            'compute_targetinstance': {'resource': 1},
            'compute_targetpool': {'resource': 1},
            'compute_targetsslproxy': {'resource': 1},
            'compute_targettcpproxy': {'resource': 1},
            'compute_urlmap': {'resource': 1},
            'crm_org_policy': {'resource': 5},
            'dataset': {'dataset_policy': 2, 'resource': 2},
            'disk': {'resource': 4},
            'dns_managedzone': {'resource': 1},
            'dns_policy': {'resource': 1},
            'firewall': {'resource': 7},
            'folder': {'iam_policy': 3, 'resource': 3},
            'forwardingrule': {'resource': 1},
            'gsuite_group': {'resource': 4},
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
            'pubsub_topic': {'iam_policy': 1, 'resource': 1},
            'role': {'resource': 5},
            'serviceaccount': {'iam_policy': 2, 'resource': 2},
            'serviceaccount_key': {'resource': 1},
            'sink': {'resource': 7},
            'snapshot': {'resource': 3},
            'spanner_database': {'resource': 1},
            'spanner_instance': {'resource': 1},
            'subnetwork': {'resource': 24},
        }

        self.assertEqual(expected_counts, result_counts)

    def test_crawl_cai_data_with_asset_types(self):
        """Validate including asset_types in the CAI inventory config works."""
        asset_types = ['google.cloud.resourcemanager.Folder',
                       'google.cloud.resourcemanager.Organization',
                       'google.cloud.resourcemanager.Project']
        inventory_config = InventoryConfig(gcp_api_mocks.ORGANIZATION_ID,
                                           '',
                                           {},
                                           0,
                                           {'enabled': True,
                                            'gcs_path': 'gs://test-bucket',
                                            'asset_types': asset_types}
                                          )
        inventory_config.set_service_config(FakeServerConfig(self.engine))

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

        with unittest_utils.create_temp_file(filtered_assets) as resources:
            with unittest_utils.create_temp_file(filtered_iam) as iam_policies:
                def _copy_file_from_gcs(file_path, *args, **kwargs):
                    """Fake copy_file_from_gcs."""
                    del args, kwargs
                    if 'resource' in file_path:
                        return resources
                    elif 'iam_policy' in file_path:
                        return iam_policies
                self.mock_copy_file_from_gcs.side_effect = _copy_file_from_gcs
                with MemoryStorage(session=self.session) as storage:
                    progresser = NullProgresser()
                    with gcp_api_mocks.mock_gcp() as gcp_mocks:
                        run_crawler(storage,
                                    progresser,
                                    inventory_config)

                        # Validate export_assets called with asset_types
                        expected_calls = [
                            mock.call(gcp_api_mocks.ORGANIZATION_ID,
                                      mock.ANY,
                                      content_type='RESOURCE',
                                      asset_types=asset_types,
                                      blocking=mock.ANY,
                                      timeout=mock.ANY),
                            mock.call(gcp_api_mocks.ORGANIZATION_ID,
                                      mock.ANY,
                                      content_type='IAM_POLICY',
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
            'bucket': {'gcs_policy': 2, 'iam_policy': 2, 'resource': 2},
            'cloudsqlinstance': {'resource': 1},
            'compute_project': {'resource': 2},
            'crm_org_policy': {'resource': 5},
            'folder': {'iam_policy': 3, 'resource': 3},
            'gsuite_group': {'resource': 4},
            'gsuite_group_member': {'resource': 1},
            'gsuite_user': {'resource': 4},
            'gsuite_user_member': {'resource': 3},
            'kubernetes_cluster': {'resource': 1, 'service_config': 1},
            'lien': {'resource': 1},
            'organization': {'iam_policy': 1, 'resource': 1},
            'project': {'billing_info': 4, 'enabled_apis': 4, 'iam_policy': 4,
                        'resource': 4},
            'role': {'resource': 3},
            'sink': {'resource': 6},
        }

        self.assertEqual(expected_counts, result_counts)

if __name__ == '__main__':
    unittest.main()
