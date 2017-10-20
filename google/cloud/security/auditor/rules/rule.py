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

"""Rule class."""

import importlib

from google.cloud.security.auditor import condition_parser


class Rule(object):
    """The base class for Rules."""

    def __init__(self, rule_id=None, description=None):
        self.rule_id = rule_id
        self.description = description
        self.condition_params = []
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
        new_rule.condition_params = config.get('variables')
        new_rule.resource_config = config.get('resources')
        new_rule.condition_stmt = config.get('condition')
        return new_rule

    def audit(self, resource):
        """Audit the rule definition + resource."""
        return True

    @property
    def type(self):
        return '%s.%s' % (self.__module__, self.__class__.__name__)

