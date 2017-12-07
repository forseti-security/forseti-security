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

"""Builds the scanners to run."""

import importlib
import inspect
import sys

from google.cloud.forseti.common.util import log_util
from google.cloud.forseti.scanner import scanner_requirements_map


LOGGER = log_util.get_logger(__name__)


class ScannerBuilder(object):
    """Scanner Builder."""

    def __init__(self, global_configs, scanner_configs, service_config,
                 model_name, snapshot_timestamp):
        """Initialize the scanner builder.

        Args:
            global_configs (dict): Global configurations.
            scanner_configs (dict): Scanner configurations.
            service_config (ServiceConfig): Forseti 2.0 service configs
            model_name (str): name of the data model
            snapshot_timestamp (str): The snapshot timestamp
        """
        self.global_configs = global_configs
        self.scanner_configs = scanner_configs
        self.service_config = service_config,
        self.model_name = model_name
        self.snapshot_timestamp = snapshot_timestamp

    def build(self):
        """Build the enabled scanners to run.

        Returns:
            list: Scanner instances that will be run.
        """
        runnable_scanners = []
        for scanner in self.scanner_configs.get('scanners'):
            if scanner.get('enabled'):
                module_path = 'google.cloud.forseti.scanner.scanners.{}'
                module_name = module_path.format(
                    scanner_requirements_map.REQUIREMENTS_MAP
                    .get(scanner.get('name'))
                    .get('module_name'))
                try:
                    module = importlib.import_module(module_name)
                except (ImportError, TypeError, ValueError) as e:
                    LOGGER.error('Unable to import %s\n%s', module_name, e)
                    continue

                class_name = (
                    scanner_requirements_map.REQUIREMENTS_MAP
                    .get(scanner.get('name'))
                    .get('class_name'))
                try:
                    scanner_class = getattr(module, class_name)
                except AttributeError:
                    LOGGER.error('Unable to instantiate %s\n%s',
                                 class_name, sys.exc_info()[0])
                    continue

                # Simple way to find the path to folders directory no matter
                # where forseti runs.
                rules_path = self.scanner_configs.get('rules_path')
                if rules_path is None:
                    scanner_path = inspect.getfile(scanner_class)
                    rules_path = scanner_path.split('/google/cloud/forseti')[0]
                    rules_path += '/rules'

                rules_filename = (scanner_requirements_map.REQUIREMENTS_MAP
                                  .get(scanner.get('name'))
                                  .get('rules_filename'))
                rules = '{}/{}'.format(rules_path, rules_filename)
                LOGGER.info('Initializing the rules engine:\nUsing rules: %s',
                            rules)

                scanner = scanner_class(self.global_configs,
                                        self.scanner_configs,
                                        self.service_config,
                                        self.model_name,
                                        self.snapshot_timestamp,
                                        rules)
                runnable_scanners.append(scanner)

        return runnable_scanners
