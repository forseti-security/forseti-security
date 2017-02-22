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

import json
import os
import yaml

from google.cloud.security.common.gcp_api import storage
from google.cloud.security.common.util.log_util import LogUtil
from google.cloud.security.scanner.audit.errors import InvalidRuleDefinitionError


class BaseRulesEngine(object):
    """The base class for the rules engine."""

    def __init__(self,
                 rules_file_path=None,
                 rules_bucket=None,
                 logger_name=None):
        """Initialize.

        Args:
            rules_file_path: The path to the rules file.
            rules_bucket: The bucket where the rules file is stored,
                if any.
            logger_name: The name of module for logger.
        """
        self.filetype_handlers = {
            'json': {
                'string': self._parse_json_string,
                'file': self._parse_json_file
            },
            'yaml': {
                'string': self._parse_yaml_string,
                'file': self._parse_yaml_file
            }
        }

        if not rules_file_path:
            raise InvalidRuleDefinitionError(
                'File path: {}'.format(rules_file_path))
        self.rules_file_path = rules_file_path.strip()
        self.filetype_handler = None
        self._setup_filetype_handler()

        self.rules_bucket = rules_bucket
        if not logger_name:
            logger_name = __name__
        self.logger = LogUtil.setup_logging(logger_name)

    def build_rule_book(self):
        """Build RuleBook from the rules definition file."""
        raise NotImplementedError('Implement in a child class.')

    def find_policy_violations(self, resource, policy, force_rebuild=False):
        """Determine whether IAM policy violates rules."""
        raise NotImplementedError('Implement in a child class.')

    def _setup_filetype_handler(self):
        """Attach a file type handler for parsing the rule file."""
        file_ext = self.rules_file_path.split('.')[-1]

        if file_ext not in self.filetype_handlers:
            raise InvalidRuleDefinitionError(
                'Unsupported file type: {}'.format(file_ext))

        self.filetype_handler = self.filetype_handlers[file_ext]

    def _load_rule_definitions(self):
        """Load the rule definitions file from GCS or local filesystem.

        Returns:
            The parsed dict from the rule definitions file.
        """
        if self.rules_bucket:
            return self._load_rules_from_gcs()
        else:
            return self._load_rules_from_local()

    def _load_rules_from_gcs(self):
        """Load rules file from GCS.

        Returns:
            The parsed dict from the rule definitions file.
        """
        storage_client = storage.StorageClient()

        file_content = storage_client.get_textfile_object(
            bucket=self.rules_bucket, object_name=self.rules_file_path)

        return self._parse_string(file_content)

    def _load_rules_from_local(self):
        """Load rules file from local path.

        Returns:
            The parsed dict from the rule definitions file.
        """
        with open(os.path.abspath(self.rules_file_path), 'r') as rules_file:
            return self._parse_file(rules_file)

    def _parse_string(self, data=None):
        """Parse the rules from a string into a dict."""
        return self.filetype_handler['string'](data)

    def _parse_file(self, data=None):
        """Parse the rules from a file into a dict."""
        return self.filetype_handler['file'](data)

    def _parse_json_string(self, data=None):
        """Parse the rules from a string of json."""
        try:
            return json.loads(data)
        except ValueError as json_error:
            raise json_error

    def _parse_json_file(self, data=None):
        """Parse the rules from a json file."""
        try:
            return json.load(data)
        except ValueError as json_error:
            raise json_error

    def _parse_yaml_string(self, data=None):
        """Parse the rules from a string of yaml."""
        try:
            return yaml.safe_load(data)
        except yaml.YAMLError as yaml_error:
            self.logger.error(yaml_error)
            raise yaml_error

    def _parse_yaml_file(self, data=None):
        """Parse the rules from a yaml file."""
        try:
            return yaml.load(data)
        except yaml.YAMLError as yaml_error:
            self.logger.error(yaml_error)
            raise yaml_error


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
