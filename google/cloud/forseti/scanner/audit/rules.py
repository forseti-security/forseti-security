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

"""Rules-related classes."""

from collections import namedtuple

from google.cloud.forseti.scanner.audit import errors as audit_errors


class Rule(object):
    """Encapsulate Rule properties from the rule definition file.

    The reason this is not a named tuple is that it needs to be hashable.
    The ResourceRules class has a set of Rules.
    """

    def __init__(self, rule_name, rule_index, bindings, mode=None):
        """Initialize.

        Args:
            rule_name (str): The name of the rule.
            rule_index (str): The rule's index in the rules file.
            bindings (list): The IamPolicyBindings for this rule.
            mode (RuleMode): The RuleMode for this rule.
        """
        self.rule_name = rule_name
        self.rule_index = rule_index
        self.bindings = bindings
        self.mode = RuleMode.verify(mode)

    def __eq__(self, other):
        """Test whether Rule equals other Rule.

        Args:
            other (object): The other object to compare.

        Returns:
            bool: True if equals, otherwise False.
        """
        if not isinstance(other, type(self)):
            return NotImplemented
        return (self.rule_name == other.rule_name and
                self.rule_index == other.rule_index and
                self.bindings == other.bindings and
                self.mode == other.mode)

    def __ne__(self, other):
        """Test whether Rule is not equal to another Rule.

        Args:
            other (object): The other object to compare.

        Returns:
            bool: True if not equals, otherwise False.
        """
        return not self == other

    def __hash__(self):
        """Make a hash of the rule index.

        For now, this will suffice since the rule index is assigned
        automatically when the rules map is built, and the scanner
        only handles one rule file at a time. Later on, we'll need to
        revisit this hash method when we process multiple rule files.

        Returns:
            int: The hash of the rule index.
        """
        return hash(self.rule_index)

    def __repr__(self):
        """Returns the string representation of this Rule.

        Returns:
            str: The representation of the Rule.
        """
        return 'Rule <{}, name={}, mode={}, bindings={}>'.format(
            self.rule_index, self.rule_name, self.mode, self.bindings)


class RuleAppliesTo(object):
    """What the rule applies to. (Default: SELF) """

    SELF = 'self'
    CHILDREN = 'children'
    SELF_AND_CHILDREN = 'self_and_children'
    apply_types = frozenset([SELF, CHILDREN, SELF_AND_CHILDREN])

    @classmethod
    def verify(cls, applies_to):
        """Verify whether the applies_to is valid.

        Args:
            applies_to (str): What the rule applies to.

        Returns:
            str: The applies_to property.

        Raises:
            InvalidRulesSchemaError if applies_to is not valid.
        """
        if applies_to not in cls.apply_types:
            raise audit_errors.InvalidRulesSchemaError(
                'Invalid applies_to: {}'.format(applies_to))
        return applies_to


class RuleMode(object):
    """The rule mode."""

    WHITELIST = 'whitelist'
    BLACKLIST = 'blacklist'
    REQUIRED = 'required'
    MATCHES = 'matches'

    modes = frozenset([WHITELIST, BLACKLIST, REQUIRED, MATCHES])

    @classmethod
    def verify(cls, mode):
        """Verify whether the mode is valid.

        Args:
            mode (str): The rules mode.

        Returns:
            str: The rules mode property.

        Raises:
            InvalidRulesSchemaError if mode is not valid.
        """
        if mode not in cls.modes:
            raise audit_errors.InvalidRulesSchemaError(
                'Invalid rule mode: {}'.format(mode))
        return mode


# Rule violation.
# resource_type: string
# resource_id: string
# rule_name: string
# rule_index: int
# violation_type: VIOLATION_TYPE
# role: string
# members: tuple of IamPolicyBindings
RuleViolation = namedtuple('RuleViolation',
                           ['resource_type', 'resource_id', 'full_name',
                            'rule_name', 'rule_index', 'violation_type',
                            'role', 'members', 'resource_data'])
