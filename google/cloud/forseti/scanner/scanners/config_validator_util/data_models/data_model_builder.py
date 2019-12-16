# Copyright 2019 The Forseti Security Authors. All rights reserved.
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

"""Builds the data models."""

from builtins import object
import importlib

from google.cloud.forseti.common.util import logger
from google.cloud.forseti.scanner.scanners.config_validator_util.data_models \
    import data_model_requirements_map

LOGGER = logger.get_logger(__name__)


class DataModelBuilder(object):
    """Data Model Builder."""
    def __init__(self, global_configs, scanner_configs, service_config,
                 model_name):
        """Initialize the data model builder.

        Args:
            global_configs (dict): Global configurations.
            service_config (ServiceConfig): Service configuration.
            scanner_configs (dict): Scanner configurations.
            model_name (str): name of the data model
        """
        self.global_configs = global_configs
        self.scanner_configs = scanner_configs
        self.service_config = service_config
        self.model_name = model_name

    def build(self):
        """Build the data models.

        Returns:
            list: data model instances that will be created.
        """
        data_models = []
        requirements_map = data_model_requirements_map.REQUIREMENTS_MAP

        for scanner in self.scanner_configs.get('scanners'):
            scanner_name = scanner.get('name')
            if scanner.get('enabled') and requirements_map.get(scanner_name):
                data_model = self._instantiate_data_model(scanner_name)
                if data_model:
                    data_models.append(data_model)
        return data_models

    def _instantiate_data_model(self, data_model_name):
        """Make individual data models based on the data model name.

        Args:
            data_model_name (str): the name of the data model to create in the
            requirements_map.

        Returns:
            data_model: the individual data model instance.
        """
        module_path = 'google.cloud.forseti.scanner.scanners.' \
                      'config_validator_util.data_models.{}'

        requirements_map = data_model_requirements_map.REQUIREMENTS_MAP

        LOGGER.debug('Initializing Config Validator data model: %s - %s',
                     data_model_name, requirements_map.get(data_model_name))

        module_name = module_path.format(
            requirements_map.get(
                data_model_name).get('module_name'))

        try:
            module = importlib.import_module(module_name)
        except (ImportError, TypeError, ValueError):
            LOGGER.exception('Unable to import %s for building '
                             'Config Validator data model.\n',
                             module_name)
            return None

        class_name = requirements_map.get(
            data_model_name).get('class_name')

        try:
            data_model_class = getattr(module, class_name)
        except AttributeError:
            LOGGER.exception('Unable to instantiate %s for building '
                             'Config Validator data model.\n',
                             class_name)
            return None

        data_model = data_model_class(self.global_configs,
                                      self.scanner_configs,
                                      self.service_config,
                                      self.model_name)
        return data_model
