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

"""Base scanner."""

import abc

from google.cloud.security.common.data_access import errors as db_errors
from google.cloud.security.common.data_access import violation_dao
from google.cloud.security.common.util import log_util


LOGGER = log_util.get_logger(__name__)


class BaseScanner(object):
    """This is a base class skeleton for data retrival pipelines"""
    __metaclass__ = abc.ABCMeta

    def __init__(self, global_configs, scanner_configs, snapshot_timestamp,
                 rules):
        """Constructor for the base pipeline.

        Args:
            global_configs (dict): Global configurations.
            scanner_configs (dict): Scanner configurations.
            snapshot_timestamp (str): Timestamp, formatted as YYYYMMDDTHHMMSSZ.
            rules (str): Fully-qualified path and filename of the rules file.
        """
        self.global_configs = global_configs
        self.scanner_configs = scanner_configs
        self.snapshot_timestamp = snapshot_timestamp
        self.rules = rules

    @abc.abstractmethod
    def run(self):
        """Runs the pipeline."""
        pass

    @abc.abstractmethod
    def _retrieve(self, **kwargs):
        """Runs the pipeline.

        Args:
            **kwargs: Arbitrary keyword arguments.
        """
        pass

    @abc.abstractmethod
    def _find_violations(self, **kwargs):
        """Find violations.


        Args:
            **kwargs: Arbitrary keyword arguments.
        """
        pass

    @abc.abstractmethod
    def _output_results(self, **kwargs):
        """Output results.

        Args:
            **kwargs: Arbitrary keyword arguments.
        """
        pass

    def _output_results_to_db(self, resource_name, violations):
        """Output scanner results to DB.

        Args:
            resource_name (str): Resource name.
            violations (list): A list of violations.

        Returns:
            list: Violations that encountered an error during insert.
        """
        resource_name = 'violations'
        (inserted_row_count, violation_errors) = (0, [])
        try:
            vdao = violation_dao.ViolationDao(self.global_configs)
            (inserted_row_count, violation_errors) = vdao.insert_violations(
                violations,
                resource_name=resource_name,
                snapshot_timestamp=self.snapshot_timestamp)
        except db_errors.MySQLError as err:
            LOGGER.error('Error importing violations to database: %s', err)

        # TODO: figure out what to do with the errors. For now, just log it.
        LOGGER.debug('Inserted %s rows with %s errors',
                     inserted_row_count, len(violation_errors))

        return violation_errors
