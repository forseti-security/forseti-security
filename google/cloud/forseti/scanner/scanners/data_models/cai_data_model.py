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

"""Cloud Asset Inventory (CAI) Data Model."""

from google.cloud.forseti.common.util import logger
from google.cloud.forseti.scanner.scanners.data_models import base_data_model
from google.cloud.forseti.services.model.importer import importer

LOGGER = logger.get_logger(__name__)


class CaiDataModel(base_data_model.BaseDataModel):
    """Cloud Asset Inventory (CAI) Data Model."""

    def __init__(self, global_configs, service_config, model_name):
        """Constructor for the base pipeline.

        Args:
            global_configs (dict): Global configurations.
            service_config (ServiceConfig): Service configuration.
            model_name (str): name of the data model
        """
        super(CaiDataModel, self).__init__(
            global_configs=global_configs,
            service_config=service_config,
            model_name=model_name)

    def retrieve(self, iam_policy=False):
        """Retrieves the data.

        If iam_policy is not set, it will retrieve all the resources
        except iam policies.

        Args:
            iam_policy (bool): Retrieve iam policies only if set to true.

        Returns:
            list: dict of CAI resources data.
        """
        model_manager = self.service_config.model_manager
        scoped_session, data_access = model_manager.get(self.model_name)

        if not iam_policy:
            resource_types = importer.GCP_TYPE_LIST
            data_type = 'resource'
        else:
            resource_types = ['iam_policy']
            data_type = 'iam_policy'

        cai_resources = []

        with scoped_session as session:
            # fetching GCP resources based on their types.
            LOGGER.info('Retrieving GCP %s data.', data_type)
            for resource_type in resource_types:
                for resource in data_access.scanner_iter(session,
                                                         resource_type,
                                                         stream_results=False):
                    resource_item = {'data_type': data_type,
                                     'primary_key': resource.type_name,
                                     'resource': resource,
                                     'resource_type': resource.type}
                    cai_resources.append(resource_item)

        return cai_resources
