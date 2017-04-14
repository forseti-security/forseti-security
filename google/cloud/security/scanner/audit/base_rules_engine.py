# Copyright 2017 Google Inc.
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

"""Base class for policy scanner rules engines.

Loads YAML rules either from local file system or Cloud Storage bucket.
"""

import abc

from google.cloud.security.common.util import file_loader
from google.cloud.security.common.util import log_util
from google.cloud.security.scanner.audit import errors as audit_errors

LOGGER = log_util.get_logger(__name__)


class BaseRulesEngine(object):
    """The base class for the rules engine."""

    def __init__(self,
                 rules_file_path=None):
        """Initialize.

        Args:
            rules_file_path: The path to the rules file.
        """
        if not rules_file_path:
            raise audit_errors.InvalidRuleDefinitionError(
                'File path: {}'.format(rules_file_path))
        self.full_rules_path = rules_file_path.strip()

    def build_rule_book(self):
        """Build RuleBook from the rules definition file."""
        raise NotImplementedError('Implement in a child class.')

    def find_policy_violations(self, resource, policy, force_rebuild=False):
        """Determine whether IAM policy violates rules."""
        raise NotImplementedError('Implement in a child class.')

    def _load_rule_definitions(self):
        """Load the rule definitions file from GCS or local filesystem.

        Returns:
            The parsed dict from the rule definitions file.
        """
        return file_loader.read_and_parse_file(self.full_rules_path)

class BaseRuleBook(object):
    """Base class for RuleBooks.

    The RuleBook class encapsulates the logic for how the RulesEngine will
    lookup rules and find policy discrepancies. The actual structure of
    the RuleBook depends on how rules should be applied. For example,
    Organization resource rules would be applied in a hierarchical manner.
    """
    __metaclass__ = abc.ABCMeta

    @abc.abstractmethod
    def add_rule(self, rule_def, rule_index):
        """Add rule to rule book."""
        raise NotImplementedError('Implement add_rule() in subclass')

class RuleAppliesTo(object):
    """What the rule applies to. (Default: SELF) """

    SELF = 'self'
    CHILDREN = 'children'
    SELF_AND_CHILDREN = 'self_and_children'
    apply_types = frozenset([SELF, CHILDREN, SELF_AND_CHILDREN])

    @classmethod
    def verify(cls, applies_to):
        """Verify whether the applies_to is valid."""
        if applies_to not in cls.apply_types:
            raise audit_errors.InvalidRulesSchemaError(
                'Invalid applies_to: {}'.format(applies_to))
        return applies_to


class RuleMode(object):
    """The rule mode."""

    WHITELIST = 'whitelist'
    BLACKLIST = 'blacklist'
    REQUIRED = 'required'

    modes = frozenset([WHITELIST, BLACKLIST, REQUIRED])

    @classmethod
    def verify(cls, mode):
        """Verify whether the mode is valid."""
        if mode not in cls.modes:
            raise audit_errors.InvalidRulesSchemaError(
                'Invalid rule mode: {}'.format(mode))
        return mode
