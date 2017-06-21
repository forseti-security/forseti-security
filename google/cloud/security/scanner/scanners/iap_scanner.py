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

"""Scanner for the Identity-Aware Proxy rules engine."""
import collections

from google.cloud.security.common.util import log_util
from google.cloud.security.common.data_access import backend_service_dao
from google.cloud.security.common.data_access import firewall_rule_dao
from google.cloud.security.common.data_access import instance_dao
from google.cloud.security.common.data_access import instance_group_dao
from google.cloud.security.common.data_access import instance_group_manager_dao
from google.cloud.security.common.data_access import instance_template_dao
#from google.cloud.security.common.gcp_type.resource import ResourceType
from google.cloud.security.scanner.scanners import base_scanner

LOGGER = log_util.get_logger(__name__)


IapData = collections.namedtuple('IapData',
                                 ['backend_services',
                                  'instances',
                                  'instance_groups',
                                  'instance_group_managers',
                                  'instance_templates',
                                  ])
IapResource = collections.namedtuple('IapResource',
                                     ['backend_service', 'iap_data']


class IapScanner(base_scanner.BaseScanner):
    """Pipeline to IAP-related data from DAO"""
    def __init__(self, snapshot_timestamp):
        """Initialization.

        Args:
            snapshot_timestamp: The snapshot timestamp
        """
        super(IapScanner, self).__init__(
            snapshot_timestamp)
        self.snapshot_timestamp = snapshot_timestamp

    def _get_backend_services(self):
        return backend_service_dao.BackendServiceDao().\
                        get_backend_services(self.snapshot_timestamp)

    def _get_instances(self):
        return instance_dao.InstanceDao().\
                        get_instances(self.snapshot_timestamp)

    def _get_instance_groups(self):
        return instance_group_dao.InstanceGroupDao().\
                        get_instance_groups(self.snapshot_timestamp)

    def _get_instance_group_managers(self):
        return instance_group_manager_dao.InstanceGroupManagerDao().\
                        get_instance_group_managers(self.snapshot_timestamp)

    def _get_instance_templates(self):
        return instance_template_dao.InstanceTemplateDao().\
                        get_instance_templates(self.snapshot_timestamp)

    @staticmethod
    def _get_resource_count(iap_data):
        """Get resource counts.

        Returns:
            Resource count map
        """
        resource_counts = {
            ResourceType.BACKEND_SERVICE: len(iap_data.backend_services),
            ResourceType.INSTANCE: len(iap_data.instances),
            ResourceType.INSTANCE_GROUP: len(iap_data.instance_groups),
            ResourceType.INSTANCE_GROUP_MANAGER: len(
                iap_data.instance_group_managers),
            ResourceType.INSTANCE_TEMPLATE: len(iap_data.instance_templates),
        }

        return resource_counts

    def run(self):
        """Runs the data collection."""
        iap_data = IapData(
            backend_services=self._get_backend_services(),
            instances=self._get_instances(),
            instance_groups=self._get_instance_groups(),
            instance_group_managers=self._get_instance_group_managers(),
            instance_templates=self._get_instance_templates(),
        )

        resource_counts = self._get_resource_count(iap_data)

        return iap_data, resource_counts

    # pylint: disable=arguments-differ
    def find_violations(self, iap_data, rules_engine):
        """Find violations in the policies.

        Returns:
            A list of violations
        """

        all_violations = []
        LOGGER.info('Finding IAP violations...')

        for backend_service in iap_data.backend_services:
            LOGGER.debug('%s', backend_service.name)
            violations = rules_engine.find_policy_violations(
                IapResource(backend_service=backend_service,
                            iap_data=iap_data))
            LOGGER.debug(violations)
            all_violations.extend(violations)
        return all_violations
