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

import itertools
import os

from collections import defaultdict

import pyparsing

from google.cloud.forseti.common.util import config_validator
from google.cloud.forseti.auditor import condition_parser


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
        2. Rule names should be unique.
        3. Configuration variables should all matched to each
           resource's variables.
        4. Configuration condition statement should parse without error.

        TODO:
        1. Each rule.type is a valid module.
        2. Each resource.type is a valid module.
        3. Resource types should be unique within a rule configuration.

        Args:
            rules_config_path (str): The rules configuration path.

        Returns:
            dict: The validated configuration.

        Raises:
            InvalidRulesConfigError: When the rules config is invalid.
        """
        # Validate rules against the rules config schema.
        config, schema_errors = RulesConfigValidator._validate_schema(
            rules_config_path)

        # All the rule names found in the config
        #   rule_name => # of rule_names found in config
        rule_names = defaultdict(int)

        # UnmatchedVariablesError for each unmatched variable
        unmatched_vars_errs = []

        # ConditionParserError for each invalid condition
        invalid_condition_errs = []

        for rule in config.get('rules', []):
            # Keep track rule name occurrences.
            rule_names[rule['name']] += 1

            rule_config = rule.get('configuration')
            if not rule_config:
                continue

            config_vars = set(rule_config.get('variables', []))
            config_resources = rule_config.get('resources', {})

            unmatched_vars_errs = (
                RulesConfigValidator._check_unmatched_config_vars(
                    rule['name'], config_vars, config_resources))

            try:
                RulesConfigValidator._check_invalid_condition(
                    rule['name'], config_vars, rule_config.get('condition', ''))
            except ConditionParseError as cpe:
                invalid_condition_errs.append(cpe)

        errors_iter = itertools.chain(
            # Schema errors
            schema_errors,

            # Errors for dupliate rule names
            [DuplicateRuleNameError(rule_name)
             for rule_name in rule_names
             if rule_names[rule_name] > 1],

            # Unmatched configuration variables
            unmatched_vars_errs,

            # Invalid conditions
            invalid_condition_errs
        )

        errors = [str(err) for err in errors_iter]
        if errors:
            raise InvalidRulesConfigError(errors)

        return config

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
            rule_name, config_vars, config_resources):
        """Check that configuration variables are found in resource variables.

        Check that all configuration['variables'] are present in
        configuration['resources'] variables.

        Args:
            rule_name (str): The rule name.
            config_vars (set): The set of rule configuration variables.
            config_resources (list): The rule configuration resources.

        Returns:
            list: A list of UnmatchedVariablesErrors
        """
        unmatched_vars_errs = []
        for resource in config_resources:
            # {'resources': [
            #   {'variables': {
            #     'key': 'value',
            #     ...
            #    }, ...}, ...], ...}
            resource_vars = set([
                res_var
                for res_var in resource.get('variables', {}).keys()])

            unmatched_config_vars = config_vars - resource_vars
            unmatched_resource_vars = resource_vars - config_vars
            if unmatched_config_vars or unmatched_resource_vars:
                unmatched_vars_errs.append(
                    UnmatchedVariablesError(
                        rule_name,
                        resource.get('type'),
                        unmatched_config_vars,
                        unmatched_resource_vars))
        return unmatched_vars_errs

    @staticmethod
    def _check_invalid_condition(rule_name, config_vars, config_condition):
        """Check that conditional statement parses.

        Args:
            rule_name (str): The rule name.
            config_vars (set): The configuration variables.
            config_condition (str): The rule configuration condition.

        Raises:
            ConditionParseError: The ConditionParseError corresponding to
                the invalid configuration conditions.
        """
        cond_parser = condition_parser.ConditionParser(
            {cfg_var: 1 for cfg_var in config_vars})

        try:
            cond_parser.eval_filter(config_condition)
        except pyparsing.ParseException as parse_err:
            raise ConditionParseError(rule_name, config_condition, parse_err)


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


class DuplicateRuleNameError(Error):
    """DuplicateRuleNameError."""

    CUSTOM_ERROR_MSG = 'Found duplicate rule name: {0}'

    def __init__(self, rule_name):
        """Init.

        Args:
            rule_name (str): The rule name.
        """
        super(DuplicateRuleNameError, self).__init__(
            self.CUSTOM_ERROR_MSG.format(rule_name))
        self.rule_name = rule_name


class UnmatchedVariablesError(Error):
    """UnmatchedVariablesError."""

    CUSTOM_ERROR_MSG = ('Unmatched config variables: '
                        'rule_name={0}, resource_type={1}\n'
                        'Unmatched config_vars={2}\n'
                        'Unmatched resource_vars={3}')

    def __init__(self,
                 rule_name,
                 resource_type,
                 unmatched_config_vars,
                 unmatched_resource_vars):
        """Init.

        Args:
            rule_name (str): The rule name.
            resource_type (str): The resource type in the configuration.
            unmatched_config_vars (set): The unmatched config variables.
            unmatched_resource_vars (set): The unmatched resource variables.
        """
        super(UnmatchedVariablesError, self).__init__(
            self.CUSTOM_ERROR_MSG.format(
                rule_name,
                resource_type,
                ','.join(unmatched_config_vars),
                ','.join(unmatched_resource_vars)))


class ConditionParseError(Error):
    """ConditionParseError."""

    CUSTOM_ERROR_MSG = ('Rule condition parse error: '
                        'rule_name={0}, condition={1}\n{2}')

    def __init__(self, rule_name, config_condition, parse_error):
        """Init.

        Args:
            rule_name (str): The rule name.
            config_condition (str): The condition with the parse error.
            parse_error (ParseException): The pyparsing.ParseException.
        """
        super(ConditionParseError, self).__init__(
            self.CUSTOM_ERROR_MSG.format(
                rule_name, config_condition, parse_error))
