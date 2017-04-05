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

"""Tests the base pipeline."""


from google.apputils import basetest
import mock

# pylint: disable=line-too-long
from google.cloud.security.common.data_access import dao
from google.cloud.security.common.data_access import errors as data_access_errors
from google.cloud.security.common.gcp_api import cloud_resource_manager as crm
from google.cloud.security.common.gcp_api import errors as api_errors
from google.cloud.security.common.util import parser
from google.cloud.security.common.util.log_util import LogUtil
from google.cloud.security.inventory import errors as inventory_errors
from google.cloud.security.inventory.pipelines import load_projects_pipeline
from tests.inventory.pipelines.test_data import fake_configs
from tests.inventory.pipelines.test_data import fake_projects
# pylint: enable=line-too-long


class BasePipelineTest(basetest.TestCase):
    """Tests for the base pipeline.
    
    Because base pipeline is an abstract class, there is no way to instantiate
    it for testing directly.  So, will test it by a pipeline that implements it.
    """

    def setUp(self):
        """Set up."""

        self.cycle_timestamp = '20001225T120000Z'
        self.configs = fake_configs.FAKE_CONFIGS
        self.mock_crm = mock.create_autospec(crm.CloudResourceManagerClient)
        self.mock_dao = mock.create_autospec(dao.Dao)
        self.mock_parser = mock.create_autospec(parser)
        self.pipeline = (
            load_projects_pipeline.LoadProjectsPipeline(
                self.cycle_timestamp,
                self.configs,
                self.mock_crm,
                self.mock_dao))

    def test_data_are_loaded(self):
        """Test that data are loaded."""

        resource_name = 'foo_resource'
        self.pipeline._load(resource_name,
                            fake_projects.EXPECTED_LOADABLE_PROJECTS)

        self.pipeline.dao.load_data.assert_called_once_with(
            resource_name,
            self.pipeline.cycle_timestamp,
            fake_projects.EXPECTED_LOADABLE_PROJECTS)       

    def test_load_errors_are_handled(self):
        """Test that errors are handled when loading."""

        self.pipeline.dao.load_data.side_effect = (
            data_access_errors.MySQLError('error error', mock.MagicMock()))

        with self.assertRaises(inventory_errors.LoadDataPipelineError):
            self.pipeline._load(self.pipeline.RESOURCE_NAME,
                                fake_projects.EXPECTED_LOADABLE_PROJECTS)

    def test_get_loaded_count(self):
        """Test the loaded count is gotten."""

        self.pipeline.dao.select_record_count.return_value = 55555

        self.pipeline._get_loaded_count()
        self.assertEquals(55555, self.pipeline.count)

    def test_error_is_handled_in_get_loaded_count(self):
        """Test error from get_loaded_count is handled."""

        self.pipeline.logger = mock.create_autospec(
            LogUtil).setup_logging('foo')
        self.pipeline.dao.select_record_count.side_effect = (
            data_access_errors.MySQLError('11111', '22222'))

        self.pipeline._get_loaded_count()
        self.assertEquals(1, self.pipeline.logger.error.call_count)
        self.assertIsNone(self.pipeline.count)
