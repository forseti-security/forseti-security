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

"""Base data model."""

from builtins import object
import abc

from future.utils import with_metaclass
from google.cloud.forseti.common.util import logger


LOGGER = logger.get_logger(__name__)


class BaseDataModel(with_metaclass(abc.ABCMeta, object)):
    """This is a base class skeleton for data models."""

    def __init__(self, global_configs, scanner_configs, service_config,
                 model_name):
        """Constructor for the base pipeline.

        Args:
            global_configs (dict): Global configurations.
            scanner_configs (dict): Scanner configurations.
            service_config (ServiceConfig): Service configuration.
            model_name (str): name of the data model.
        """
        self.global_configs = global_configs
        self.scanner_configs = scanner_configs
        self.service_config = service_config
        self.model_name = model_name

    @abc.abstractmethod
    def retrieve(self, iam_policy=False):
        """Retrieves the data.

        Args:
            iam_policy (bool): Retrieve iam policies only if set to true.
        """
        pass
