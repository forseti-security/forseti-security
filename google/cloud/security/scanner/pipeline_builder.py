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

"""Builds the inventory pipelines to run, and in the correct order to run."""

import importlib
import inspect
import sys

from google.cloud.security.common.util import log_util
from google.cloud.security.scanner import pipeline_requirements_map


LOGGER = log_util.get_logger(__name__)


class PipelineBuilder(object):
    """Inventory Pipeline Builder."""

    def __init__(self, global_configs, scanner_configs, snapshot_timestamp):
        """Initialize the scanner builder.

        Args:
            global_configs (dict): Global configurations.
            scanner_configs (dict): Scanner configurations.
            snapshot_timestamp (str): The snapshot timestamp
        """
        self.global_configs = global_configs
        self.scanner_configs = scanner_configs
        self.snapshot_timestamp = snapshot_timestamp

    def build(self):
        """Build the enabled scanners to run.

        Returns:
            list: List of pipelines instances that will be run.
        """
        runnable_scanners = []
        for pipeline in self.scanner_configs.get('pipelines'):
            if pipeline.get('enabled'):
                module_path = 'google.cloud.security.scanner.scanners.{}'
                module_name = module_path.format(
                    pipeline_requirements_map.REQUIREMENTS_MAP
                    .get(pipeline.get('name'))
                    .get('module_name'))
                try:
                    module = importlib.import_module(module_name)
                except (ImportError, TypeError, ValueError) as e:
                    LOGGER.error('Unable to import %s\n%s', module_name, e)
                    continue

                class_name = (
                    pipeline_requirements_map.REQUIREMENTS_MAP
                    .get(pipeline.get('name'))
                    .get('class_name'))
                try:
                    scanner_class = getattr(module, class_name)
                except AttributeError:
                    LOGGER.error('Unable to instantiate %s\n%s',
                                 class_name, sys.exc_info()[0])
                    continue

                # Simple way to find the path to folders directory no matter
                # where forseti runs.
                scanner_path = inspect.getfile(scanner_class)
                rules_path = scanner_path.split('/google/cloud/security')[0]
                rule_filename = (pipeline_requirements_map.REQUIREMENTS_MAP
                                .get(pipeline.get('name'))
                                .get('rule_filename'))
                rule = '{}/rules/{}'.format(rules_path, rule_filename)

                scanner = scanner_class(self.global_configs,
                                        self.scanner_configs,
                                        self.snapshot_timestamp,
                                        rule)
                runnable_scanners.append(scanner)

        return runnable_scanners
