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

"""Scanner for the IAM rules engine."""

from datetime import datetime
import itertools
import os
import shutil
import sys

from google.cloud.security.common.gcp_api import storage
from google.cloud.security.common.data_access import csv_writer
from google.cloud.security.common.data_access import errors as db_errors
from google.cloud.security.common.data_access import folder_dao
from google.cloud.security.common.data_access import organization_dao
from google.cloud.security.common.data_access import project_dao
from google.cloud.security.common.gcp_type.resource import ResourceType
from google.cloud.security.common.util import log_util
from google.cloud.security.notifier import notifier
from google.cloud.security.scanner.audit import iam_rules_engine
from google.cloud.security.scanner.scanners import base_scanner

# pylint: disable=arguments-differ


LOGGER = log_util.get_logger(__name__)


class IamPolicyScanner(base_scanner.BaseScanner):
    """Scanner for IAM data."""

    SCANNER_OUTPUT_CSV_FMT = 'scanner_output.{}.csv'
    OUTPUT_TIMESTAMP_FMT = '%Y%m%dT%H%M%SZ'

    def __init__(self, global_configs, scanner_configs, snapshot_timestamp,
                 rules):
        """Initialization.

        Args:
            global_configs (dict): Global configurations.
            scanner_configs (dict): Scanner configurations.
            snapshot_timestamp (str): Timestamp, formatted as YYYYMMDDTHHMMSSZ.
            rules (str): Fully-qualified path and filename of the rules file.
        """
        super(IamPolicyScanner, self).__init__(
            global_configs,
            scanner_configs,
            snapshot_timestamp,
            rules)
        self.rules_engine = iam_rules_engine.IamRulesEngine(
            rules_file_path=self.rules,
            snapshot_timestamp=self.snapshot_timestamp)
        self.rules_engine.build_rule_book(self.global_configs)

    def _get_output_filename(self, now_utc):
        """Create the output filename.

        Args:
            now_utc (datetime): The datetime now in UTC. Generated at the top
                level to be consistent across the scan.

        Returns:
            str: The output filename for the csv, formatted with the
                now_utc timestamp.
        """
        output_timestamp = now_utc.strftime(self.OUTPUT_TIMESTAMP_FMT)
        output_filename = self.SCANNER_OUTPUT_CSV_FMT.format(output_timestamp)
        return output_filename

    def _upload_csv(self, output_path, now_utc, csv_name):
        """Upload CSV to Cloud Storage.

        Args:
            output_path (str): The output path for the csv.
            now_utc (datetime): The UTC timestamp of "now".
            csv_name (str): The csv_name.
        """
        output_filename = self._get_output_filename(now_utc)

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
    def _flatten_violations(violations):
        """Flatten RuleViolations into a dict for each RuleViolation member.

        Args:
            violations (list): The RuleViolations to flatten.

        Yields:
            dict: Iterator of RuleViolations as a dict per member.
        """
        for violation in violations:
            for member in violation.members:
                violation_data = {}
                violation_data['role'] = violation.role
                violation_data['member'] = '%s:%s' % (member.type, member.name)

                yield {
                    'resource_id': violation.resource_id,
                    'resource_type': violation.resource_type,
                    'rule_index': violation.rule_index,
                    'rule_name': violation.rule_name,
                    'violation_type': violation.violation_type,
                    'violation_data': violation_data
                }

    def _output_results(self, all_violations, resource_counts):
        """Output results.

        Args:
            all_violations (list): A list of violations
            resource_counts (dict): Resource count map.
        """
        resource_name = 'violations'

        all_violations = list(self._flatten_violations(all_violations))
        violation_errors = self._output_results_to_db(resource_name,
                                                      all_violations)

        # Write the CSV for all the violations.
        if self.scanner_configs.get('output_path'):
            LOGGER.info('Writing violations to csv...')
            output_csv_name = None
            with csv_writer.write_csv(
                resource_name=resource_name,
                data=all_violations,
                write_header=True) as csv_file:
                output_csv_name = csv_file.name
                LOGGER.info('CSV filename: %s', output_csv_name)

                # Scanner timestamp for output file and email.
                now_utc = datetime.utcnow()

                output_path = self.scanner_configs.get('output_path')
                if not output_path.startswith('gs://'):
                    if not os.path.exists(
                            self.scanner_configs.get('output_path')):
                        os.makedirs(output_path)
                    output_path = os.path.abspath(output_path)
                self._upload_csv(output_path, now_utc, output_csv_name)

                # Send summary email.
                # TODO: Untangle this email by looking for the csv content
                # from the saved copy.
                if self.global_configs.get('email_recipient') is not None:
                    payload = {
                        'email_sender':
                            self.global_configs.get('email_sender'),
                        'email_recipient':
                            self.global_configs.get('email_recipient'),
                        'sendgrid_api_key':
                            self.global_configs.get('sendgrid_api_key'),
                        'output_csv_name': output_csv_name,
                        'output_filename': self._get_output_filename(now_utc),
                        'now_utc': now_utc,
                        'all_violations': all_violations,
                        'resource_counts': resource_counts,
                        'violation_errors': violation_errors
                    }
                    message = {
                        'status': 'scanner_done',
                        'payload': payload
                    }
                    notifier.process(message)

    def _find_violations(self, policies):
        """Find violations in the policies.

        Args:
            policies (list): The list of policies to find violations in.

        Returns:
            list: A list of all violations
        """
        policies = itertools.chain(*policies)
        all_violations = []
        LOGGER.info('Finding policy violations...')
        for (resource, policy) in policies:
            LOGGER.debug('%s => %s', resource, policy)
            violations = self.rules_engine.find_policy_violations(
                resource, policy)
            all_violations.extend(violations)
        return all_violations

    @staticmethod
    def _get_resource_count(**kwargs):
        """Get resource count for IAM policies.

        Args:
            kwargs: The policies to get resource counts for.

        Returns:
            dict: Resource count map.
        """
        resource_counts = {
            ResourceType.ORGANIZATION: len(kwargs.get('org_iam_policies', [])),
            ResourceType.FOLDER: len(kwargs.get('folder_iam_policies', [])),
            ResourceType.PROJECT: len(kwargs.get('project_iam_policies', [])),
        }

        return resource_counts

    def _get_org_iam_policies(self):
        """Get orgs from data source.

        Returns:
            dict: Org policies from inventory.
        """
        org_policies = {}
        try:
            org_dao = organization_dao.OrganizationDao(self.global_configs)
            org_policies = org_dao.get_org_iam_policies(
                'organizations', self.snapshot_timestamp)
        except db_errors.MySQLError as e:
            LOGGER.error('Error getting Organization IAM policies: %s', e)
        return org_policies

    def _get_folder_iam_policies(self):
        """Get folder IAM policies from data source.

        Returns:
            dict: The folder policies.
        """
        folder_policies = {}
        try:
            fdao = folder_dao.FolderDao(self.global_configs)
            folder_policies = fdao.get_folder_iam_policies(
                'folders', self.snapshot_timestamp)
        except db_errors.MySQLError as e:
            LOGGER.error('Error getting Folder IAM policies: %s', e)
        return folder_policies

    def _get_project_iam_policies(self):
        """Get projects from data source.

        Returns:
            dict: Project policies from inventory.
        """
        project_policies = {}
        project_policies = (project_dao
                            .ProjectDao(self.global_configs)
                            .get_project_policies('projects',
                                                  self.snapshot_timestamp))
        return project_policies

    def _retrieve(self):
        """Retrieves the data for scanner.

        Returns:
            list: List of IAM policy data.
            dict: A dict of resource counts.
        """
        policy_data = []
        org_policies = self._get_org_iam_policies()
        folder_policies = self._get_folder_iam_policies()
        project_policies = self._get_project_iam_policies()

        if not any([org_policies, folder_policies, project_policies]):
            LOGGER.warn('No policies found. Exiting.')
            sys.exit(1)
        resource_counts = self._get_resource_count(
            org_iam_policies=org_policies,
            folder_iam_policies=folder_policies,
            project_iam_policies=project_policies)
        policy_data.append(org_policies.iteritems())
        policy_data.append(folder_policies.iteritems())
        policy_data.append(project_policies.iteritems())

        return policy_data, resource_counts

    def run(self):
        """Runs the data collection."""

        policy_data, resource_counts = self._retrieve()
        all_violations = self._find_violations(policy_data)
        self._output_results(all_violations, resource_counts)
