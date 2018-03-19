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

"""Base class for policy scanner rules engines.

Loads YAML rules either from local file system or Cloud Storage bucket.
"""

import abc

from google.cloud.forseti.common.util import file_loader
from google.cloud.forseti.common.util import logger
from google.cloud.forseti.scanner.audit import errors as audit_errors

LOGGER = logger.get_logger(__name__)


class BaseRulesEngine(object):
    """The base class for the rules engine."""

    def __init__(self,
                 rules_file_path=None,
                 snapshot_timestamp=None):
        """Initialize.

        Args:
            rules_file_path (str): The path of the rules file, either
                local or GCS.
            snapshot_timestamp (str): The snapshot to associate any
                data lookups.
        """
        if not rules_file_path:
            raise audit_errors.InvalidRuleDefinitionError(
                'File path: {}'.format(rules_file_path))
        self.full_rules_path = rules_file_path.strip()
        self.snapshot_timestamp = snapshot_timestamp

    def build_rule_book(self, global_configs):
        """Build RuleBook from the rules definition file.

        Args:
            global_configs (dict): The global Forseti configuration.

        Raises:
            NotImplementedError: The method should be defined in subclass.
        """
        raise NotImplementedError('Implement in a child class.')

    def _load_rule_definitions(self):
        """Load the rule definitions file from GCS or local filesystem.

        Returns:
            dict: The parsed dict from the rule definitions file.
        """
        LOGGER.debug('Loading %r rules from %r', self, self.full_rules_path)
        rules = file_loader.read_and_parse_file(self.full_rules_path)
        LOGGER.debug('Got rules: %r', rules)
        return rules


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
        """Add rule to rule book.

        Args:
            rule_def (dict): Add a rule definition to the rule book.
            rule_index (int): The index of the rule.

        Raises:
            NotImplementedError: The method should be defined in subclass.
        """
        raise NotImplementedError('Implement add_rule() in subclass')
