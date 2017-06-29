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

"""Scanner for the Forwarding Rules rules engine."""
from google.cloud.security.common.util import log_util
from google.cloud.security.common.data_access import forwarding_rules_dao
from google.cloud.security.common.gcp_type.resource import ResourceType
from google.cloud.security.scanner.scanners import base_scanner

LOGGER = log_util.get_logger(__name__)


class ForwardingRuleScanner(base_scanner.BaseScanner):
    """Pipeline for forwarding rules from dao"""
    def __init__(self, global_configs, snapshot_timestamp):
        """Initialization.

        Args:
            global_configs (dict): Global configurations.
            snapshot_timestamp (str): The snapshot timestamp
        Returns:

        """
        super(ForwardingRuleScanner, self).__init__(
            global_configs,
            snapshot_timestamp)
        self.snapshot_timestamp = snapshot_timestamp


    def run(self):
        """Runs the data collection for forwarding rules

        Returns:
            tuple: Returns a tuple of lists. The first one is a list of
                forwarding rules. The second one is a dictionary of resource
                counts per items in the first list
        """
        forwarding_rules = forwarding_rules_dao \
            .ForwardingRulesDao(self.global_configs) \
            .get_forwarding_rules(self.snapshot_timestamp)
        resource_counts = {
            ResourceType.FORWARDING_RULE: len(forwarding_rules),
        }
        return [forwarding_rules], resource_counts

    # pylint: disable=arguments-differ
    def find_violations(self, forwarding_rules, rules_engine):
        """Find violations in forwarding rules.

        Args:
            forwarding_rules(list): Forwarding rule to find violations in
            rules_engine(ForwardingRuleRulesEngine): The rules engine to run.

         Returns:
            list: A list of forwarding rule violations
        """
        all_violations = []
        LOGGER.info('Finding Forwading Rule violations...')

        for forwarding_rule in list(forwarding_rules):
            LOGGER.debug('%s', forwarding_rule)
            violations = rules_engine.find_policy_violations(
                forwarding_rule)
            LOGGER.debug(violations)
            if violations is not None:
                all_violations.append(violations)
        return all_violations
