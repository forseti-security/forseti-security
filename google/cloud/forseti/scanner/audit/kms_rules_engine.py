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
"""Rules engine for if there is a mismatch between ."""

from collections import namedtuple
import json
import threading

from google.cloud.forseti.common.gcp_type import errors as resource_errors
from google.cloud.forseti.common.gcp_type import resource as resource_mod
from google.cloud.forseti.common.gcp_type import resource_util
from google.cloud.forseti.common.util import logger, date_time, string_formats
from google.cloud.forseti.scanner.audit import base_rules_engine as bre
from google.cloud.forseti.scanner.audit import errors as audit_errors

LOGGER = logger.get_logger(__name__)


class KMSRulesEngine(bre.BaseRulesEngine):
    """Rules engine for KMS scanner."""

    def __init__(self, rules_file_path, snapshot_timestamp=None):
        """Initialize.

        Args:
            rules_file_path (str): file location of rules
            snapshot_timestamp (str): snapshot timestamp. Defaults to None.
                If set, this will be the snapshot timestamp
                used in the engine.
        """
        super(KMSRulesEngine,
              self).__init__(rules_file_path=rules_file_path)
        self.rule_book = None
        self.snapshot_timestamp = snapshot_timestamp
        self._lock = threading.Lock()

    def build_rule_book(self, global_configs=None):
        """Build ServiceAccountKeyRuleBook from the rules definition file.

        Args:
            global_configs (dict): Global configurations.
        """
        with self._lock:
            self.rule_book = KMSRuleBook(
                self._load_rule_definitions())

    def find_violations(self, kms, force_rebuild=False):
        """Determine whether service account key age violates rules.

        Args:
            service_account (ServiceAccount): A service account resource to
            check.
            force_rebuild (bool): If True, rebuilds the rule book. This will
                reload the rules definition file and add the rules to the book.

        Returns:
             generator: A generator of rule violations.
        """
        if self.rule_book is None or force_rebuild:
            self.build_rule_book()
        return self.rule_book.find_violations(kms)


class KMSRuleBook(bre.BaseRuleBook):
    """The RuleBook for KMS rules."""

    def __init__(self, rule_defs=None):
        """Initialization.

        Args:
            rule_defs (list): KMS rule definition dicts
        """
        super(KMSRuleBook, self).__init__()
        self._lock = threading.Lock()
        self.resource_rules_map = {}
        if not rule_defs:
            self.rule_defs = {}
        else:
            self.rule_defs = rule_defs
            self.add_rules(rule_defs)

    def add_rules(self, rule_defs):
        """Add rules to the rule book.

        Args:
            rule_defs (dict): rule definitions dictionary
        """
        for (i, rule) in enumerate(rule_defs.get('rules', [])):
            self.add_rule(rule, i)

    def add_rule(self, rule_def, rule_index):
        """Add a rule to the rule book.

        Args:
            rule_def (dict): A dictionary containing rule definition
                properties.
            rule_index (int): The index of the rule from the rule definitions.
                Assigned automatically when the rule book is built.
        """


    def get_resource_rules(self, resource):
        """Get all the resource rules for resource.

        Args:
            resource (Resource): The gcp_type Resource find in the map.

        Returns:
            ResourceRules: A ResourceRules object.
        """
        return self.resource_rules_map.get(resource)


class Rule(object):
    """Rule properties from the rule definition file, also finds violations."""

    def __init__(self, rule_name, rule_index,
                 key_max_age):
        """Initialize.

        Args:
            rule_name (str): Name of the loaded rule
            rule_index (int): The index of the rule from the rule definitions
            key_max_age (int): Max allowed age in days of service
                account key
        """
        self.rule_name = rule_name
        self.rule_index = rule_index
        self.key_max_age = key_max_age
