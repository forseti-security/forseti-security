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

import hashlib
import json

from google.cloud.forseti.auditor import condition_parser
from google.cloud.forseti.services.auditor import storage
from google.cloud.forseti.services.actions import action_engine_pb2
from google.cloud.forseti.common.util import class_loader_util
from google.cloud.forseti.common.util import log_util

LOGGER = log_util.get_logger(__name__)


class Rule(object):
    """The base class for Rules."""

    def __init__(self, rule_name=None, description=None):
        """Initialize.

        Args:
            rule_name (str): The rule name.
            description (str): The rule description.
        """
        self.rule_name = rule_name
        self.description = description
        self.config_variables = []
        self.resource_config = []
        self.condition = None
        self.json = None

    def __repr__(self):
        """Repr."""
        return 'Rule: <name=%s>' % self.rule_name

    def __eq__(self, other):
        """Test equality.

        Make this simple: a Rule equals another Rule if the rule names are
        the same.

        Args:
            other (object): The other object to test against.

        Returns:
            bool: True if equal, False otherwise.
        """
        if not isinstance(other, type(self)):
            return NotImplemented
        return self.rule_name == other.rule_name

    def __ne__(self, other):
        """Test inequality.

        Args:
            other (object): The other object to test against.

        Returns:
            bool: True if not equal, False otherwise.
        """
        return not self == other

    def calculate_hash(self):
        """Calculate the hash of this rule.

        Returns:
            str: The hex digest of the rule's json after it gets hashed.
        """
        return hashlib.sha1(json.dumps(self.json, sort_keys=True)).hexdigest()

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
        new_rule.rule_name = rule_definition.get('name')
        new_rule.description = rule_definition.get('description')

        config = rule_definition.get('configuration', {})
        new_rule.config_variables = config.get('variables', [])
        new_rule.resource_config = config.get('resources', [])
        new_rule.condition = config.get('condition')
        new_rule.json = rule_definition
        return new_rule

    def audit(self, resource):
        """Audit the rule definition + resource.

        Args:
            resource (object): The GCP Resource to audit with current Rule.

        Returns:
            RuleResult: The result of the audit if it evaluates to True,
                otherwise None.

        Raises:
            ResourceDataError: When there's an error loading the resource data.
        """

        LOGGER.debug('... checking if %s applies to %s',
                     self.rule_name, resource.type)

        try:
            resource_data = json.loads(resource.data)
        except ValueError:
            raise ResourceDataError(resource.data)

        resource_cfg = None
        # Check if this Rule applies to this resource.
        for res_cfg in self.resource_config:
            if resource.type == res_cfg['type']:
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
            var_name: resource_data.get(res_prop)
            for (var_name, res_prop) in resource_vars.iteritems()
        }
        cond_parser = condition_parser.ConditionParser(config_var_params)
        result = cond_parser.eval_filter(self.condition)
        if result:
            # TODO: should we be using a proto here?
            return action_engine_pb2.RuleResult(
                rule_id=self.rule_name,
                resource_type_name=resource.type_name,
                current_state=None,
                expected_state=None,
                status=storage.RuleResultStatus.ACTIVE.value)

    @property
    def type(self):
        """The `type` property of this class.

        Returns:
            str: The type name, comprising module and class name.
        """
        return '%s.%s' % (self.__module__, self.__class__.__name__)


class Error(Exception):
    """Base Error class."""

class AuditError(Error):
    """AuditError."""


class InvalidRuleTypeError(AuditError):
    """InvalidRuleTypeError."""

    def __init__(self, rule_type):
        """Init.

        Args:
            rule_type (str): The rule type.
        """
        super(InvalidRuleTypeError, self).__init__(
            'Invalid rule type: {}'.format(rule_type))


class ResourceDataError(AuditError):
    """ResourceDataError."""

    def __init__(self, resource_data):
        """Init.

        Args:
            resource_data (str): The resource data.
        """
        super(ResourceDataError, self).__init__(
            'Resource data could not be audited: {}'.format(resource_data))
