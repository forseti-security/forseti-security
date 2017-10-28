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

import pyparsing

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
    """RulesConfigValidator class.

    Contains the most basic validation that should be done on all rule
    configurations.
    """
    # TODO: how to handle validation of rule configurations where a
    # certain resource requires a certain property that's not
    # included in the schema?

    @staticmethod
    def validate(rules_config_path):
        """Validate the rules config.

        Rule configuration validation:

        1. Rule configuration should validate against a json schema.
        2. Rule ids should be unique.
        3. Configuration variables should all matched to each
           resource's variables.
        4. Configuration condition statement should parse without error.

        TODO:
        1. Each rule.type is a valid module.
        2. Each resource.type is a valid module.

        Args:
            rules_config_path (str): The rules configuration path.

        Returns:
            dict: The parsed, valid config.

        Raises:
            InvalidRulesConfigError: When the rules config is invalid.
        """
        # Validate rules against the rules config schema.
        config, schema_errors = RulesConfigValidator._validate_schema(
            rules_config_path)

        # All the rule ids found in the config
        #   rule_id => # of rule_ids found in config
        rule_ids = defaultdict(int)

        # Differences between config variables and resource variables:
        # [tuple(rule_id, outstanding_config_vars, outstanding_res_vars), ...]
        unmatched_vars = []

        # Invalid rule conditions
        # [(rule_id, expanded_condition), ...]
        invalid_conditions = []

        for rule in config.get('rules', []):
            rule_id = rule['id']

            # Keep track rule id occurrences.
            rule_ids[rule_id] += 1

            rule_config = rule.get('configuration')
            if not rule_config:
                continue

            config_vars = set(rule_config.get('variables', []))
            config_resources = rule_config.get('resources', {})

            unmatched_vars = RulesConfigValidator._check_unmatched_config_vars(
                rule_id, config_vars, config_resources)

            invalid_conditions = RulesConfigValidator._check_invalid_conditions(
                rule_id, config_vars, rule_config.get('condition', ''))

        errors_iter = itertools.chain(
            # Schema errors
            schema_errors,

            # Errors for dupliate rule ids
            [DuplicateRuleIdError(rule_id)
                for rule_id in rule_ids
                if rule_ids[rule_id] > 1],

            # Outstanding variables
            [UnmatchedVariablesError(
                rule_id, resource_type, unmatched_cfg_vars, unmatched_res_vars)
                for (rule_id, resource_type,
                        unmatched_cfg_vars, unmatched_res_vars)
                in unmatched_vars],

            # Invalid conditions
            [ConditionParseError(rule_id, config_condition, pe)
                for (rule_id, config_condition, pe) in invalid_conditions]
            )

        errors = [str(err) for err in errors_iter]
        if errors:
            raise InvalidRulesConfigError(errors)

    @staticmethod
    def _validate_schema(rules_config_path):
        """Validate the rules configuration against the rules schema.

        Args:
            rules_config_path (str): The path to the rules configuration.

        Returns:
            dict: The config that gets successfully parsed/validated.
            list: A list of schema errors.
        """
        schema_errors = []
        config = {}
        try:
            config = config_validator.validate(
                rules_config_path, RULES_SCHEMA_PATH)
        except (config_validator.ConfigLoadError,
                config_validator.InvalidConfigError,
                config_validator.InvalidSchemaError) as err:
            schema_errors.append(err)

        return config, schema_errors

    @staticmethod
    def _check_unmatched_config_vars(
        rule_id, config_vars, config_resources):
        """Check that configuration variables are found in resource variables.

        Check that all configuration['variables'] are present in
        configuration['resources'] variables.

        Args:
            rule_id (str): The rule id.
            config_vars (set): The set of rule configuration variables.
            config_resources (list): The rule configuration resources.

        Returns:
            list: A list of tuples of 
                (rule_id, resource_type,
                 unmatched_config_vars, unmatched_resource_vars)
        """
        unmatched_vars = []
        for resource in config_resources:
            # {'resources': [
            #   {'variables': [
            #     {'key': 'value'},
            #    ...], ...}, ...], ...}
            resource_vars = set([
                res_var
                for var_map in resource.get('variables', [])
                for res_var in var_map.keys()])

            unmatched_config_vars = config_vars - resource_vars
            unmatched_resource_vars = resource_vars - config_vars
            if unmatched_config_vars or unmatched_resource_vars:
                unmatched_vars.append(
                    (rule_id,
                     resource.get('type'),
                     unmatched_config_vars,
                     unmatched_resource_vars))
        return unmatched_vars

    @staticmethod
    def _check_invalid_conditions(rule_id, config_vars, rule_config_conditions):
        """Check that conditional statement parses.

        Args:
            rule_id (str): The rule id.
            config_vars (set): The configuration variables.
            rule_config_conditions (list): The rule configuration conditions.

        Returns:
            list: The list of tuples 
                (rule_id, config_condition, ParseException)
                corresponding to the invalid configuration conditions.
        """
        invalid_conditions = []
        config_condition = ' and '.join(rule_config_conditions)
        cp = condition_parser.ConditionParser(
            {v: 1 for v in config_vars})

        try:
            cp.eval_filter(config_condition)
        except pyparsing.ParseException as pe:
            invalid_conditions.append((rule_id, config_condition, pe))

        return invalid_conditions


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
            self.CUSTOM_ERROR_MSG.format('\n--------------\n'.join(errors)))


class DuplicateRuleIdError(Error):
    """DuplicateRuleIdError."""

    CUSTOM_ERROR_MSG = 'Found duplicate rule id: {0}'

    def __init__(self, rule_id):
        """Init.

        Args:
            rule_id (str): The rule id.
        """
        super(DuplicateRuleIdError, self).__init__(
            self.CUSTOM_ERROR_MSG.format(rule_id))
        self.rule_id = rule_id


class UnmatchedVariablesError(Error):
    """UnmatchedVariablesError."""

    CUSTOM_ERROR_MSG = ('Unmatched config variables: '
                        'rule_id={0}, resource_type={1}\n'
                        'Unmatched config_vars={2}\n'
                        'Unmatched resource_vars={3}')

    def __init__(self,
                 rule_id,
                 resource_type,
                 unmatched_config_vars,
                 unmatched_resource_vars):
        """Init.

        Args:
            rule_id (str): The rule id.
            resource_type (str): The resource type in the configuration.
            unmatched_config_vars (set): The unmatched config variables.
            unmatched_resource_vars (set): The unmatched resource variables.
        """
        super(UnmatchedVariablesError, self).__init__(
            self.CUSTOM_ERROR_MSG.format(
                rule_id,
                resource_type,
                ','.join(unmatched_config_vars),
                ','.join(unmatched_resource_vars)))


class ConditionParseError(Error):
    """ConditionParseError."""

    CUSTOM_ERROR_MSG = ('Rule condition parse error: '
                        'rule_id={0}, condition={1}\n{2}')

    def __init__(self, rule_id, config_condition, parse_error):
        """Init.

        Args:
            rule_id (str): The rule id.
            config_condition (str): The condition with the parse error.
            parse_error (ParseException): The pyparsing.ParseException.
        """
        super(ConditionParseError, self).__init__(
            self.CUSTOM_ERROR_MSG.format(
                rule_id, config_condition, parse_error))


def main(args):
    parser = ap.ArgumentParser()
    parser.add_argument('--rules-path', required=True)
    parsed_args = parser.parse_args()

    RulesConfigValidator.validate(parsed_args.rules_path)


if __name__ == '__main__':
    main(sys.argv[1:])
