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

from google.cloud.forseti.common.util import logger
from google.cloud.forseti.scanner import scanner_requirements_map

LOGGER = logger.get_logger(__name__)


class ScannerBuilder(object):
    """Scanner Builder."""

    def __init__(self, global_configs, scanner_configs, service_config,
                 model_name, snapshot_timestamp, scanner_name=None):
        """Initialize the scanner builder.

        Args:
            global_configs (dict): Global configurations.
            scanner_configs (dict): Scanner configurations.
            service_config (ServiceConfig): Service configuration.
            model_name (str): name of the data model
            snapshot_timestamp (str): The snapshot timestamp
            scanner_name (str): Name of the specified scanner to run separately
        """
        self.global_configs = global_configs
        self.scanner_configs = scanner_configs
        self.service_config = service_config
        self.model_name = model_name
        self.snapshot_timestamp = snapshot_timestamp
        self.scanner_name = scanner_name

    def build(self):
        """Build the enabled scanners to run.
        Returns:
            list: Scanner instances that will be run.
        """
        runnable_scanners = []
        if self.scanner_name:
            # remove the _scanner from scanner name so that it matches the key
            # in requirements map
            scanner = self._instantiate_scanner(self.scanner_name[:-8])
            # TODO: add a unit test for _instantiate_scanner
            if scanner:
                runnable_scanners.append(scanner)
        else:
            for scanner in self.scanner_configs.get('scanners'):
                if scanner.get('enabled'):
                    scanner = self._instantiate_scanner(scanner.get('name'))
                    if scanner:
                        runnable_scanners.append(scanner)

        return runnable_scanners

    def _instantiate_scanner(self, scanner_name):
        """Make individual scanners based on the scanner name.

        Args:
            scanner_name (str): the name of the scanner as
            in the requirements_map

        Returns:
            scanner: the individual scanner instance
        """

        module_path = 'google.cloud.forseti.scanner.scanners.{}'

        requirements_map = scanner_requirements_map.REQUIREMENTS_MAP
        if scanner_name not in requirements_map:
            log_message = (
                'Configured scanner is undefined '
                'in scanner requirements map : %s')
            LOGGER.error(log_message, scanner_name)
            return None

        LOGGER.info(scanner_requirements_map.REQUIREMENTS_MAP.get(scanner_name))

        module_name = module_path.format(
            scanner_requirements_map.REQUIREMENTS_MAP.get(
                scanner_name).get('module_name'))

        try:
            module = importlib.import_module(module_name)
        except (ImportError, TypeError, ValueError):
            LOGGER.exception('Unable to import %s\n', module_name)
            return None

        class_name = (
            scanner_requirements_map.REQUIREMENTS_MAP.get(
                scanner_name).get('class_name'))
        try:
            scanner_class = getattr(module, class_name)
        except AttributeError:
            LOGGER.exception('Unable to instantiate %s', class_name)
            return None

        rules_filename = (scanner_requirements_map.REQUIREMENTS_MAP
                          .get(scanner_name)
                          .get('rules_filename'))

        rules_path = self.scanner_configs.get('rules_path')
        if rules_path is None:
            scanner_path = inspect.getfile(scanner_class)
            rules_path = scanner_path.split('/google/cloud/forseti')[0]
            rules_path += '/rules'
        rules = '{}/{}'.format(rules_path, rules_filename)

        LOGGER.info('Initializing the rules engine:\nUsing rules: %s',
                    rules)

        scanner = scanner_class(self.global_configs,
                                self.scanner_configs,
                                self.service_config,
                                self.model_name,
                                self.snapshot_timestamp,
                                rules)
        return scanner
