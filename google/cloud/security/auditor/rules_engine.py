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

"""Auditor Rules Engine.

Reads and parses the rule configuration, then applies the configurations to
their specified rules for evaluation.
"""

import argparse as ap

# dummy import to force building the namespace package to find
# stuff in google.cloud.security.
# Otherwise, we get the following error:
# "ImportError: No module named cloud.security.common.util"
# See https://github.com/google/protobuf/issues/1296#issuecomment-264265761
# import google.protobuf

from google.cloud.security.auditor import rules_config_validator
from google.cloud.security.auditor.rules import rule as generic_rule
from google.cloud.security.common.gcp_type import project


class RulesEngine(object):
    """RulesEngine class."""

    def __init__(self, rules_config_path):
        """Initialize.

        Args:
            rules_config_path (str): The rules configuration path.
        """
        self.rules = []
        self.rules_config_path = rules_config_path

    def setup(self):
        """Set up the RulesEngine."""
        valid_config = self.validate_config()
        print valid_config
        for rule in valid_config.get('rules', []):
            self.rules.append(generic_rule.Rule.create_rule(rule))

    def validate_config(self):
        """Validate the rules config.

        Returns:
            dict: The parsed, valid config.
        """
        return rules_config_validator.RulesConfigValidator.validate(
            self.rules_config_path)

    def evaluate_rules(self, resource):
        """Evaluate rules for this resource.

        Args:
            resource (GcpResource): A GcpResource.

        Returns:
            list: A list of RuleResults.
        """
        results = []
        print self.rules
        for rule in self.rules:
            result = rule.audit(resource)
            if not result:
                continue
            results.append(result)
        print results

        return results


class Error(Exception):
    """Base Error class."""


def main():
    """Main."""
    parser = ap.ArgumentParser()
    parser.add_argument('--rules-path', required=True)
    parsed_args = parser.parse_args()

    rules_engine = RulesEngine(parsed_args.rules_path)
    rules_engine.setup()

    proj1 = project.Project('proj1', 1111)
    rules_engine.evaluate_rules(proj1)


if __name__ == '__main__':
    main()
