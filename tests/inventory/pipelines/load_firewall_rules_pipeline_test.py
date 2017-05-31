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

"""Tests the load_firewall_rules_pipeline."""

from tests.unittest_utils import ForsetiTestCase
import mock

# pylint: disable=line-too-long
from google.cloud.security.common.data_access import project_dao
from google.cloud.security.common.gcp_api import compute
from google.cloud.security.inventory.pipelines import load_firewall_rules_pipeline
from tests.inventory.pipelines.test_data import fake_configs
from tests.inventory.pipelines.test_data import fake_firewall_rules
# pylint: enable=line-too-long


class LoadFirewallRulesTest(ForsetiTestCase):
    """Tests for the load firewall rules pipeline."""

    def setUp(self):
        """Set up."""
        self.cycle_timestamp = '20001225T120000Z'
        self.configs = fake_configs.FAKE_CONFIGS
        self.mock_compute_client = mock.create_autospec(compute.ComputeClient)
        self.mock_dao = mock.create_autospec(project_dao.ProjectDao)
        self.pipeline = (
            load_firewall_rules_pipeline.LoadFirewallRulesPipeline(
                self.cycle_timestamp,
                self.configs,
                self.mock_compute_client,
                self.mock_dao))

    def test_can_transform_firewall_rules(self):
        """Test the firewall rules map can be transformed."""

        loadable_firewall_rules = self.pipeline._transform(
            fake_firewall_rules.EXPECTED_FIREWALL_RULES_MAP)

        counter = 0
        for loadable_firewall_rule in loadable_firewall_rules:
            self.assertDictEqual(
                fake_firewall_rules.EXPECTED_LOADABLE_FIREWALL_RULES[counter],
                loadable_firewall_rule)
            counter +=1

    def test_can_retrieve_firewall_rules_from_gcp(self):
        self.pipeline.dao.get_projects.return_value = [
            mock.MagicMock(id='foo11111'), mock.MagicMock(id='foo22222')]

        self.pipeline.api_client.get_firewall_rules.side_effect = (
        fake_firewall_rules.FAKE_FIREWALL_RULES)

        firewall_rules_map = self.pipeline._retrieve()

        self.assertDictEqual(
            fake_firewall_rules.EXPECTED_FIREWALL_RULES_MAP_SHORT,
            firewall_rules_map)

    @mock.patch.object(
        load_firewall_rules_pipeline.LoadFirewallRulesPipeline,
        '_get_loaded_count')
    @mock.patch.object(
        load_firewall_rules_pipeline.LoadFirewallRulesPipeline,
        '_load')
    @mock.patch.object(
        load_firewall_rules_pipeline.LoadFirewallRulesPipeline,
        '_transform')
    @mock.patch.object(
        load_firewall_rules_pipeline.LoadFirewallRulesPipeline,
        '_retrieve')
    def test_subroutines_are_called_by_run(self, mock_retrieve, mock_transform,
            mock_load, mock_get_loaded_count):
        """Test that the subroutines are called by run."""

        self.pipeline.run()

        mock_retrieve.assert_called_once
        mock_transform.assert_called_once
        mock_load.assert_called_once
        mock_get_loaded_count.assert_called_once
