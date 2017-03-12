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

from google.cloud.security.common.util import file_loader
from google.cloud.security.common.util.log_util import LogUtil
from google.cloud.security.scanner.audit.errors import InvalidRuleDefinitionError


class BaseRulesEngine(object):
    """The base class for the rules engine."""

    def __init__(self,
                 rules_file_path=None,
                 logger_name=None):
        """Initialize.

        Args:
            rules_file_path: The path to the rules file.
            logger_name: The name of module for logger.
        """
        if not rules_file_path:
            raise InvalidRuleDefinitionError(
                'File path: {}'.format(rules_file_path))
        self.full_rules_path = rules_file_path.strip()

        if not logger_name:
            logger_name = __name__
        self.logger = LogUtil.setup_logging(logger_name)

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

#pylint: disable=too-few-public-methods
#TODO(carise): Investigate not using a class for a storage object.
class BaseRuleBook(object):
    """Base class for RuleBooks.

    The RuleBook class encapsulates the logic for how the RulesEngine will
    lookup rules and find policy discrepancies. The actual structure of
    the RuleBook depends on how rules should be applied. For example,
    Organization resource rules would be applied in a hierarchical manner.
    """

    def __init__(self, logger_name=None):
        if not logger_name:
            logger_name = __name__
        self.logger = LogUtil.setup_logging(logger_name)
