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

import importlib

from collections import namedtuple

from google.cloud.security.auditor import condition_parser


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
        self.config_variables = []
        self.resource_config = []
        self.condition = None

    @staticmethod
    def create_rule(rule_definition):
        """Instantiate a rule based on its definition.

        Args:
            rule_definition (dict): The rule definition properties.

        Return:
            object: An instance of Rule.
        """
        parts = rule_definition.get('type').split('.')
        module = importlib.import_module('.'.join(parts[:-1]))
        rule_class = getattr(module, parts[-1])
        new_rule = rule_class()

        # Set properties
        new_rule.rule_id = rule_definition.get('id')
        new_rule.description = rule_definition.get('description')

        config = rule_definition.get('configuration', {})
        new_rule.config_variables = config.get('variables', [])
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

        print '... checking if %s applies to %s' % (
            self.rule_id, resource_type)

        resource_cfg = None
        # Check if this Rule applies to this resource.
        for res_cfg in self.resource_config:
            if resource_type == res_cfg['type']:
                resource_cfg = res_cfg
                break

        if not resource_cfg:
            print 'nope, continue on'
            return None

        # Create configuration parameter map for evaluating
        # the rule condition statement.
        resource_vars = resource_cfg.get('variables', {})
        print resource_vars
        config_var_params = {
            var_name: getattr(resource, res_prop)
            for (var_name, res_prop) in resource_vars.iteritems()
        }
        cond_parser = condition_parser.ConditionParser(config_var_params)
        return RuleResult(
            self.rule_id,
            resource,
            cond_parser.eval_filter(self.condition),
            {})

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
#   resource (Resource): The GCP Resource.
#   result (boolean): True if the rule condition is met, otherwise False.
#   metadata (dict): Additional data related to the Resource and
#       rule evaluation.
RuleResult = namedtuple('RuleResult',
                        ['rule_id', 'resource', 'result', 'metadata'])
