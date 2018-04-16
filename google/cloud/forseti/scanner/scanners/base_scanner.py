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
from google.cloud.forseti.common.util import string_formats
from google.cloud.forseti.common.util.index_state import IndexState
from google.cloud.forseti.services.scanner import dao as scanner_dao


LOGGER = logger.get_logger(__name__)


class BaseScanner(object):
    """This is a base class skeleton for scanners."""
    __metaclass__ = abc.ABCMeta

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
        self.global_configs = global_configs
        self.scanner_configs = scanner_configs
        self.service_config = service_config
        self.model_name = model_name
        self.snapshot_timestamp = snapshot_timestamp
        self.rules = rules

    @abc.abstractmethod
    def run(self):
        """Runs the pipeline."""
        pass

    def _upload_csv(self, output_path, now_utc, csv_name):
        """Upload CSV to Cloud Storage.

        Args:
            output_path (str): The output path for the csv.
            now_utc (datetime): The UTC timestamp of "now".
            csv_name (str): The csv_name.
        """
        output_filename = self.get_output_filename(now_utc)

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

    @staticmethod
    def get_output_filename(now_utc):
        """Create the output filename.

        Args:
            now_utc (datetime): The datetime now in UTC. Generated at the top
                level to be consistent across the scan.

        Returns:
            str: The output filename for the csv, formatted with the
                now_utc timestamp.
        """
        output_timestamp = now_utc.strftime(
            string_formats.TIMESTAMP_TIMEZONE_FILES)
        output_filename = string_formats.SCANNER_OUTPUT_CSV_FMT.format(
            output_timestamp)
        return output_filename

    def _output_results_to_db(self, violations):
        """Output scanner results to DB.

        Args:
            violations (list): A list of violations.
        """
        model_description = (
            self.service_config.model_manager.get_description(self.model_name))
        inventory_index_id = (
            model_description.get('source_info').get('inventory_index_id'))

        violation_access = self.service_config.violation_access
        scanner_index_id = scanner_dao.get_latest_scanner_index_id(
            violation_access.session, inventory_index_id,
            index_state=IndexState.RUNNING)
        violation_access.create(violations, scanner_index_id)
