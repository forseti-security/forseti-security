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

"""Config Validator Scanner."""

from google.protobuf import json_format

from google.cloud.forseti.common.util import logger
from google.cloud.forseti.scanner.scanners import base_scanner
from google.cloud.forseti.scanner.scanners.config_validator_util import (
    cv_data_converter)
from google.cloud.forseti.scanner.scanners.config_validator_util import (
    validator_client)
from google.cloud.forseti.scanner.scanners.data_models import data_model_builder


LOGGER = logger.get_logger(__name__)


class ConfigValidatorScanner(base_scanner.BaseScanner):
    """Config Validator Scanner."""

    VIOLATION_TYPE = 'CONFIG_VALIDATOR_VIOLATION'

    def __init__(self, global_configs, scanner_configs, service_config,
                 model_name, snapshot_timestamp, rules):
        """Constructor for the base pipeline.

         Args:
             global_configs (dict): Global configurations.
             scanner_configs (dict): Scanner configurations.
             service_config (ServiceConfig): Service configuration.
             model_name (str): name of the data model
             snapshot_timestamp (str): Timestamp, formatted as YYYYMMDDTHHMMSSZ.
             rules (str): Fully-qualified path and filename of the rules file.
         """
        super(ConfigValidatorScanner, self).__init__(
            global_configs, scanner_configs, service_config,
            model_name, snapshot_timestamp, rules)
        self.validator_client = validator_client.ValidatorClient()

        # Maps CAI resource name-> (full_name, resource_data).
        self.resource_lookup_table = {}

    def _flatten_violations(self, violations):
        """Flatten Config Validator violations into a dict for each violation.

        Args:
            violations (list): The Config Validator violations to flatten.

        Yields:
            dict: Iterator of Config Validator violations
                as a dict per violation.
        """

        for violation in violations:
            resource_id = violation.resource.split('/')[-1]
            full_name, resource_type, resource_data = (
                self.resource_lookup_table.get(violation.resource,
                                               ('', '', '')))
            yield {
                'resource_id': resource_id,
                'resource_type': resource_type,
                'resource_name': violation.resource,
                'full_name': full_name,
                'rule_index': 0,
                'rule_name': violation.constraint,
                'violation_type': self.VIOLATION_TYPE,
                'violation_data': json_format.MessageToDict(
                    violation.metadata, including_default_value_fields=True),
                'resource_data': resource_data,
                'violation_message': violation.message
            }

    def _output_results(self, all_violations):
        """Output results.

        Args:
            all_violations (List[RuleViolation]): A list of
                flattened Config Validator violations.
        """
        self._output_results_to_db(all_violations)

    def _retrieve(self, iam_policy=False):
        """Retrieves the data for scanner.

        If iam_policy is not set, it will retrieve all the resources
        except iam policies.

        Args:
            iam_policy (bool): Retrieve iam policies only if set to true.

        Yields:
            Asset: Config Validator Asset.

        Raises:
            ValueError: if resources have an unexpected type.
        """
        self.resource_lookup_table = {}
        data_models = (
            data_model_builder
            .DataModelBuilder(self.global_configs,
                              self.service_config,
                              self.model_name)
            .build()
        )

        for data_model in data_models:
            data = data_model.retrieve(iam_policy)
            for resource_object in data:
                data_type = resource_object.get('data_type')
                primary_key = resource_object.get('primary_key')
                resource = resource_object.get('resource')
                resource_type = resource_object.get('resource_type')

                if (not resource.cai_resource_name and
                        resource_type in
                        cv_data_converter.MOCK_CAI_RESOURCE_TYPE_MAPPING):
                    resource = cv_data_converter.convert_data_to_cai_asset(
                        primary_key, resource, resource_type)

                elif (not resource.cai_resource_name and
                      resource_type not in
                      cv_data_converter.MOCK_CAI_RESOURCE_TYPE_MAPPING):
                    LOGGER.debug('Resource type %s is not currently '
                                 'supported in Config Validator scanner.',
                                 resource.type)
                    continue

                self.resource_lookup_table[resource.cai_resource_name] = (
                    resource.full_name,
                    resource.cai_resource_type,
                    resource.data)

                yield cv_data_converter.convert_data_to_cv_asset(
                    resource, data_type)

    def _retrieve_flattened_violations(self, iam_policy=False):
        """Retrieve flattened violations by flattening the config validator
        violations returned by the config validator client.

        If iam_policy is not set, it will retrieve violations from all resources
        except iam policies.

        Args:
            iam_policy (bool): Retrieve flattened IAM policy violations.

        Yields:
            list: A list of flattened violations.
        """
        # Clean up the validator environment by doing a reset pre audit.
        self.validator_client.reset()

        # Get all the data in Config Validator Asset format.
        cv_assets = self._retrieve(iam_policy=iam_policy)

        for violations in self.validator_client.paged_review(cv_assets):
            flattened_violations = self._flatten_violations(violations)
            yield flattened_violations
        # Clean up the lookup table to free up the memory.
        self.resource_lookup_table = {}

    def run(self):
        """Runs the Config Validator Scanner.

        Note: Resources and iam policies audit are separated into 2 steps.
        That's mainly because there is no good way of identifying from config
        validator validation whether a violation is an iam policy violation or
        a resource violation, the resource name for both will be the same and
        it will be hard for Forseti to retrieve the right resource_data for the
        corresponding violation types.
        """
        # TODO: break up the _retrieve_flattened_violations method.
        # Retrieving resource violations.

        for flattened_violations in self._retrieve_flattened_violations():
            # Write resource violations to the db.
            self._output_results(flattened_violations)

        for flattened_violations in self._retrieve_flattened_violations(
                iam_policy=True):
            # Write iam violations to the db.
            self._output_results(flattened_violations)
