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

"""Rule class.

This is a generic class that handles a basic rule, as defined in
schema/rules.json.
"""

from collections import namedtuple

from google.cloud.forseti.auditor import condition_parser
from google.cloud.forseti.common.util import class_loader_util
from google.cloud.forseti.common.util import log_util

LOGGER = log_util.get_logger(__name__)


class Rule(object):
    """The base class for Rules."""

    def __init__(self, rule_id=None, description=None):
        """Initialize.

        Args:
            rule_id (str): The rule id.
            description (str): The rule description.
        """
        self.rule_id = rule_id
        self.description = description
        self.config_variables = {}
        self.resource_config = []
        self.condition = None

    def __eq__(self, other):
        """Test equality.

        Make this simple: a Rule equals another Rule if the rule ids are
        the same.

        Args:
            other (object): The other object to test against.

        Returns:
            bool: True if equal, False otherwise.
        """
        if not isinstance(other, type(self)):
            return NotImplemented
        return self.rule_id == other.rule_id

    def __ne__(self, other):
        """Test inequality.

        Args:
            other (object): The other object to test against.

        Returns:
            bool: True if not equal, False otherwise.
        """
        return not self == other

    @staticmethod
    def create_rule(rule_definition):
        """Instantiate a rule based on its definition.

        Rule schema can be found in
        google/cloud/forseti/auditor/schema/rules.json.

        Args:
            rule_definition (dict): The rule definition properties.

        Return:
            object: An instance of Rule.
        """
        new_rule = class_loader_util.load_class(rule_definition.get('type'))()

        # Set properties
        new_rule.rule_id = rule_definition.get('id')
        new_rule.description = rule_definition.get('description')

        config = rule_definition.get('configuration', {})
        new_rule.config_variables = config.get('variables', {})
        new_rule.resource_config = config.get('resources', [])
        new_rule.condition = config.get('condition')
        return new_rule

    def audit(self, resource):
        """Audit the rule definition + resource.

        Args:
            resource (GcpResource): The GcpResource to audit with current Rule.

        Returns:
            RuleResult: The result of the audit, or None if Rule does not
                apply to resource.
        """
        resource_type = '%s.%s' % (
            resource.__module__, resource.__class__.__name__)

        LOGGER.debug('... checking if %s applies to %s',
                     self.rule_id, resource_type)

        resource_cfg = None
        # Check if this Rule applies to this resource.
        for res_cfg in self.resource_config:
            if resource_type == res_cfg['type']:
                resource_cfg = res_cfg
                break

        if not resource_cfg:
            LOGGER.debug('resource config does not apply, continue on')
            return None

        # Create configuration parameter map for evaluating
        # the rule condition statement.
        resource_vars = resource_cfg.get('variables', {})
        LOGGER.debug(resource_vars)
        config_var_params = {
            var_name: getattr(resource, res_prop)
            for (var_name, res_prop) in resource_vars.iteritems()
        }
        cond_parser = condition_parser.ConditionParser(config_var_params)
        current_state = resource
        expected_state = resource
        return RuleResult(
            rule_id=self.rule_id,
            result=cond_parser.eval_filter(self.condition),
            current_state=current_state,
            expected_state=expected_state,
            snapshot_id=None, # TODO: make the result snapshot-aware
            resource_owners=[],
            info=None)

    @property
    def type(self):
        """The `type` property of this class.

        Returns:
            str: The type name, comprising module and class name.
        """
        return '%s.%s' % (self.__module__, self.__class__.__name__)


# The result of rule evaluation.
#
# Properties::
#   rule_id (str): The rule id.
#   result (boolean): True if the rule condition is met, otherwise False.
#   current_state (dict): The GCP Resource in json/dict format.
#   expected_state (dict): The GCP Resource in json/dict format.
#   snapshot_id (str): The snapshot id.
#   resource_owners (list): A list of the owners (IAM members as a string).
#   info (str): Additional information about the rule.
RuleResult = namedtuple('RuleResult',
                        ['rule_id',
                         'result',
                         'current_state',
                         'expected_state',
                         'snapshot_id',
                         'resource_owners',
                         'info'])
