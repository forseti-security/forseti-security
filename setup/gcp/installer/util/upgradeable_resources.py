# Copyright 2017 The Forseti Security Authors. All rights reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Upgradeable resources. Resources that can be ported to a newer version."""

import os
import tempfile

import constants
import files
import utils


class Rule(object):
    """Rule file."""
    data = {}

    def __init__(self, file_name, path):
        """Init.

        Args:
            file_name (str): Name of the rule file.
            path (str): Path to the rule file.
        """
        self.file_name = file_name
        self.path = path


class ForsetiV1Configuration(object):
    """Forseti V1 Configuration."""
    _rules = []
    _config = {}

    def __init__(self, project_id, name, zone):
        """Init.

        Args:
            project_id (str): Id of the project.
            name (str): Name of the v1 vm instance.
            zone (str): Zone of the v1 vm instance.
        """
        self.project_id = project_id
        self.name = name
        self.zone = zone
        timestamp = utils.extract_timestamp_from_name(name)
        self.gcs_location = constants.DEFAULT_BUCKET_FMT_V1.format(
            project_id, timestamp)
        self.populate_rule_paths()

    def populate_rule_paths(self):
        """Populate all the v1 conf/rule paths."""
        for rule_file in constants.FORSETI_V1_RULE_FILES:
            rule_path = '{}/rules/{}'.format(self.gcs_location, rule_file)
            self._rules.append(Rule(rule_file, rule_path))

    def fetch_information_from_gcs(self):
        """Fetch all v1 conf/rules information from GCS."""
        self._fetch_config_from_gcs()
        self._fetch_rules_from_gcs()

    def _fetch_config_from_gcs(self):
        """Fetch v1 configuration from GCS."""
        # Create a temp directory
        tempdir = tempfile.mkdtemp()

        # Copy file from GCS to the temp directory
        config_path = '{}/configs/forseti_conf.yaml'.format(
            self.gcs_location)
        success = files.copy_file_to_destination(config_path, tempdir)

        if not success:
            self._config = {}
        else:
            # Load the file into dictionary
            local_file_path = os.path.join(tempdir, 'forseti_conf.yaml')
            self._config = files.read_yaml_file_from_local(local_file_path)

            # Remove the saved file
            os.unlink(local_file_path)
        # Remove the temp directory
        os.rmdir(tempdir)

    def _fetch_rules_from_gcs(self):
        """Fetch v1 rules from GCS."""
        # Create a temp directory
        tempdir = tempfile.mkdtemp()

        rules_to_remove = []

        # Copy files from GCS to the temp directory
        for rule in self._rules:
            success = files.copy_file_to_destination(rule.path, tempdir)
            if not success:
                rules_to_remove.append(rule)
                continue
            if 'gke' in rule.file_name:
                rule.file_name = rule.file_name.replace('gke', 'ke')
            local_file_path = os.path.join(tempdir, rule.file_name)
            rule.data = files.read_yaml_file_from_local(local_file_path)
            os.unlink(local_file_path)

        # Remove bad rules
        for rule in rules_to_remove:
            self._rules.remove(rule)

        # Remove the saved file and the temp directory
        os.rmdir(tempdir)

    @property
    def rules(self):
        """Rule objects.

        Returns:
            list: List of rule objects
        """
        return self._rules

    @property
    def config(self):
        """Config object.

        Returns:
            dict: Config object
        """
        return self._config
