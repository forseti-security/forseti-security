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

"""Rules configuration validator."""

import argparse as ap
import itertools
import os
import sys

from collections import defaultdict
from collections import namedtuple

# dummy import to force building the namespace package to find
# stuff in google.cloud.security.
# Otherwise, we get the 
# "ImportError: No module named cloud.security.common.util"
# See https://github.com/google/protobuf/issues/1296#issuecomment-264265761
import google.protobuf

from google.cloud.security.common.util import config_validator
from google.cloud.security.auditor import condition_parser


RULES_SCHEMA_PATH = os.path.abspath(
    os.path.join(
        os.path.dirname(__file__),
        'schema',
        'rules.json'))

class RulesConfigValidator(object):
    """RulesEngine class."""

    @staticmethod
    def validate(rules_config_path):
        """Validate the rules config.

        Args:
            rules_config_path (str): The rules configuration path.

        Returns:
            dict: The parsed, valid config.

        Raises:
            InvalidRulesConfigError: When the rules config is invalid.
        """
        # Validate against the JSON schema.
        try:
            config = config_validator.validate(
                rules_config_path, RULES_SCHEMA_PATH)
        except (config_validator.ConfigLoadError,
                config_validator.InvalidConfigError,
                config_validator.InvalidSchemaError) as err:
            schema_errors.append(err)

        # All the rule ids found in the config
        #   rule_id => # of rule_ids found in config
        rule_ids = defaultdict(int)

        # Differences between config variables and resource variables:
        # [tuple(rule_id, outstanding_config_vars, outstanding_res_vars), ...]
        outstanding_vars = []

        # Invalid rule conditions
        # [(rule_id, expanded_condition), ...]
        invalid_conditions = []

        for rule in config.get('rules', []):
            rule_id = rule['rule_id']

            # Keep track rule id occurrences.
            rule_ids[rule_id] += 1

            rule_config = rule.get('configurations')
            if not rule_config:
                continue

            config_vars = set(rule_config.get('variables', []))
            config_resources = rule_config.get('resources', {})

            # Check that all configuration['variables'] are present in
            # configuration['resources'] variables.
            resource_vars = set(config_resources.get('variables', {}).keys())
            unused_config_vars = config_vars - resource_vars
            unused_resource_vars = resource_vars - config_vars
            if unused_config_vars or unused_resource_vars:
                outstanding_vars.append(
                    (rule_id, unused_config_vars, unused_resource_vars))

            # Check that conditional statement parses.
            config_condition = ' and '.join(rule_config.get('condition', ''))
            # TODO: don't evaluate, just parse the condition for correctness
            cp = condition_parser.ConditionParser(config_vars)

        errors_iter = itertools.chain(
            # Schema errors
            schema_errors,

            # Errors for dupliate rule ids
            [InvalidRulesDuplicateError(rule_id)
                for rule_id in rule_ids
                if rule_ids[rule_id] > 1]),

            # Outstanding variables
            [],

            # Invalid conditions
            []
            )

        if errors:
            raise InvalidRulesConfigError(errors)


class Error(Exception):
    """Base Error class."""


class InvalidRulesConfigError(Error):
    """InvalidRulesConfigError."""

    CUSTOM_ERROR_MSG = (
        'Rules configuration failed to validate:\n'
        '{0}')

    def __init__(self, errors):
        """Init.

        Args:
            errors (list): The list of Errors.
        """
        super(InvalidRulesConfigError, self).__init__(
            self.CUSTOM_ERROR_MSG.format('\n'.join(errors)))


class InvalidRulesDuplicateIdError(Error):
    """InvalidRulesDuplicateIdError."""

    CUSTOM_ERROR_MSG = 'Duplicate rule id: {0}\n{1}'

    def __init__(self, rule_id, e):
        """Init.

        Args:
            rule_id (str): The rule id.
            e (Error): The Error.
        """
        super(InvalidRulesDuplicateIdError, self).__init__(
            self.CUSTOM_ERROR_MSG.format(rule_id, e))


def main(args):
    parser = ap.ArgumentParser()
    parser.add_argument('--rules-path', required=True)
    parsed_args = parser.parse_args()

    RulesConfigValidator.validate(parsed_args.rules_path)


if __name__ == '__main__':
    main(sys.argv[1:])
