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

"""Base scanner."""

import abc
import os
import shutil

from google.cloud.forseti.common.gcp_api import storage
from google.cloud.forseti.common.util import logger


LOGGER = logger.get_logger(__name__)


class BaseScanner(object):
    """This is a base class skeleton for scanners."""
    __metaclass__ = abc.ABCMeta

    OUTPUT_TIMESTAMP_FMT = '%Y%m%dT%H%M%SZ'
    SCANNER_OUTPUT_CSV_FMT = 'scanner_output_base.{}.csv'

    def __init__(self, global_configs, scanner_configs, service_config,
                 model_name, audit_invocation_time, rules):
        """Constructor for the base pipeline.

        Args:
            global_configs (dict): Global configurations.
            scanner_configs (dict): Scanner configurations.
            service_config (ServiceConfig): Service configuration.
            model_name (str): name of the data model.
            audit_invocation_time (datetime): The time of a given invocation of
                scanner.
            rules (str): Fully-qualified path and filename of the rules file.
        """
        self.global_configs = global_configs
        self.scanner_configs = scanner_configs
        self.service_config = service_config
        self.model_name = model_name
        self.audit_invocation_time = audit_invocation_time
        self.rules = rules

    @abc.abstractmethod
    def run(self):
        """Runs the pipeline."""
        pass

    def _output_results_to_db(self, violations):
        """Output scanner results to DB.

        Args:
            violations (list): A list of violations.

        Returns:
            list: Violations that encountered an error during insert.
        """
        model_description = (
            self.service_config.model_manager.get_description(self.model_name))
        inventory_index_id = (
            model_description.get('source_info').get('inventory_index_id'))

        # TODO: Capture violations errors with the new violation_access.
        # Add a unit test for the errors.
        (inserted_row_count, violation_errors) = (0, [])

        violation_access = self.service_config.violation_access(
            self.service_config.engine)
        violation_access.create(violations, inventory_index_id,
                                self.audit_invocation_time)
        # TODO: figure out what to do with the errors. For now, just log it.
        LOGGER.debug('Inserted %s rows with %s errors',
                     inserted_row_count, len(violation_errors))

        return violation_errors

    def _get_output_filename(self):
        """Create the output filename.

        Returns:
            str: The output filename for the csv, formatted with the
                now_utc timestamp.
        """
        output_timestamp = self._get_audit_invocation_time_str()
        output_filename = self.SCANNER_OUTPUT_CSV_FMT.format(output_timestamp)

        return output_filename

    def _upload_csv(self, output_path, csv_name):
        """Upload CSV to Cloud Storage.

        Args:
            output_path (str): The output path for the csv.
            csv_name (str): The csv_name.
        """
        output_filename = self._get_output_filename()

        # If output path was specified, copy the csv temp file either to
        # a local file or upload it to Google Cloud Storage.
        full_output_path = os.path.join(output_path, output_filename)
        LOGGER.info('Output path: %s', full_output_path)

        if output_path.startswith('gs://'):
            # An output path for GCS must be the full
            # `gs://bucket-name/path/for/output`
            storage_client = storage.StorageClient()
            storage_client.put_text_file(
                csv_name, full_output_path)
        else:
            # Otherwise, just copy it to the output path.
            shutil.copy(csv_name, full_output_path)

    def _get_audit_invocation_time_str(self):
        """Return a consistent strftime of the the invocation_id.

            Returns:
                str: A timestamp in the classes default format.
        """
        return self.audit_invocation_time.strftime(self.OUTPUT_TIMESTAMP_FMT)
