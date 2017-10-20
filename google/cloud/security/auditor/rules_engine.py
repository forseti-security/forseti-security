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
import os
import sys

from collections import namedtuple
# dummy import to force the PYTHONPATH to work and not complain about
# the "ImportError: No module named cloud.security.common.util"
from google.protobuf.json_format import MessageToJson

from google.cloud.security.common.util import config_validator


RULES_SCHEMA_PATH = os.path.abspath(
    os.path.join(
        os.path.dirname(__file__),
        'schema',
        'rules.json'))


class Error(Exception):
    """Base Error class."""


class InvalidRulesConfigError(Error):
    """InvalidRulesConfigError."""


class RulesEngine(object):
    """RulesEngine class."""

    def __init__(self, rules_config_path):
        self.valid_rules = []
        self.rules_config_path = rules_config_path

    def setup(self):
        self.validate_config()
        self.rules = self.parse_config()

    def parse_config(self):
        return []

    def validate_config(self):
        """Validate the rules config.

        Raises:
            InvalidRulesConfigError: When the rules config is invalid.
        """
        try:
            config_validator.validate(self.rules_config_path, RULES_SCHEMA_PATH)
        except (config_validator.ConfigLoadError,
                config_validator.InvalidConfigError,
                config_validator.InvalidSchemaError) as err:
            raise InvalidRulesConfigError(err)

    def _check_unique_rule_ids(self):
        return True

    def evaluate_rules(self, resource):
        for rule in self.valid_rules:
            result = rule.audit(resource)
        return []


"""The result of rule evaluation.

Args:
    rule_id (str): The rule id.
    resource (Resource): The GCP Resource.
    result (boolean): True if the rule condition is met, otherwise False.
    metadata (dict): Additional data related to the Resource and
        rule evaluation.
"""
RuleResult = namedtuple('RuleResult',
                        ['rule_id', 'resource', 'result', 'metadata'])

def main(args):
    parser = ap.ArgumentParser()
    parser.add_argument('--rules-path', required=True)
    parsed_args = parser.parse_args()

    rules_engine = RulesEngine(parsed_args.rules_path)
    rules_engine.validate_config()


if __name__ == '__main__':
    main(sys.argv[1:])
