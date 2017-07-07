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

from google.cloud.security.common.util import log_util
from google.cloud.security.common.gcp_api import storage
from google.cloud.security.common.data_access import csv_writer
from google.cloud.security.common.data_access import errors as db_errors
from google.cloud.security.common.data_access import organization_dao
from google.cloud.security.common.data_access import project_dao
from google.cloud.security.common.gcp_type.resource import ResourceType
from google.cloud.security.notifier import notifier
from google.cloud.security.scanner.scanners import base_scanner
from google.cloud.security.scanner.audit import iam_rules_engine


LOGGER = log_util.get_logger(__name__)


class IamPolicyScanner(base_scanner.BaseScanner):
    """Pipeline to IAM data from DAO"""

    SCANNER_OUTPUT_CSV_FMT = 'scanner_output.{}.csv'
    OUTPUT_TIMESTAMP_FMT = '%Y%m%dT%H%M%SZ'

    def __init__(self, global_configs, scanner_configs, snapshot_timestamp,
                 rules):
        """Constructor for the base pipeline.

        Args:
            global_configs (dict): Global configurations.
            cycle_timestamp: String of timestamp, formatted as

        Returns:
            None
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
            now_utc: The datetime now in UTC. Generated at the top level to be
                consistent across the scan.
    
        Returns:
            The output filename for the csv, formatted with the now_utc timestamp.
        """
    
        output_timestamp = now_utc.strftime(self.OUTPUT_TIMESTAMP_FMT)
        output_filename = self.SCANNER_OUTPUT_CSV_FMT.format(output_timestamp)
        return output_filename

    def _upload_csv(self, output_path, now_utc, csv_name):
        """Upload CSV to Cloud Storage.
    
        Args:
            output_path: The output path for the csv.
            now_utc: The UTC timestamp of "now".
            csv_name: The csv_name.
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

    def _flatten_violations(self, violations):
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
                        'email_sender': self.global_configs.get('email_sender'),
                        'email_recipient': self.global_configs.get('email_recipient'),
                        'sendgrid_api_key': self.global_configs.get('sendgrid_api_key'),
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

    # pylint: disable=arguments-differ
    def find_violations(self, policies):
        """Find violations in the policies.

        Args:
            policies: The list of policies to find violations in.
            rules_engine: The rules engine to run.

        Returns:
            A list of violations
        """        
        policies = itertools.chain(*policies)
        all_violations = []
        LOGGER.info('Finding policy violations...')
        for (resource, policy) in policies:
            LOGGER.debug('%s => %s', resource, policy)
            violations = self.rules_engine.find_policy_violations(
                resource, policy)
            LOGGER.debug(violations)
            all_violations.extend(violations)
        return all_violations


    @staticmethod
    def _get_resource_count(org_policies, project_policies):
        """Get resource count for org and project policies.

        Args:
            org_policies: organisation policies from inventory
            project_pollicies: project policies from inventory.
        Returns:
            Resource count map
        """
        resource_counts = {
            ResourceType.ORGANIZATION: len(org_policies),
            ResourceType.PROJECT: len(project_policies),
        }

        return resource_counts

    def _get_org_policies(self):
        """Get orgs from data source.

        Args:
            timestamp: The snapshot timestamp.

        Returns:
            The org policies.
        """
        org_policies = {}
        try:
            org_dao = organization_dao.OrganizationDao(self.global_configs)
            org_policies = org_dao.get_org_iam_policies(
                'organizations', self.snapshot_timestamp)
        except db_errors.MySQLError as e:
            LOGGER.error('Error getting Organization IAM policies: %s', e)
        return org_policies

    def _get_project_policies(self):
        """Get projects from data source.

        Args:
            timestamp: The snapshot timestamp.

        Returns:
            The project policies.
        """
        project_policies = {}
        project_policies = (project_dao
                            .ProjectDao(self.global_configs)
                            .get_project_policies('projects',
                                                  self.snapshot_timestamp))
        return project_policies

    def _retrieve(self):
        policy_data = []
        org_policies = self._get_org_policies()
        project_policies = self._get_project_policies()

        if not org_policies and not project_policies:
            LOGGER.warn('No policies found. Exiting.')
            sys.exit(1)
        resource_counts = self._get_resource_count(org_policies,
                                                   project_policies)
        policy_data.append(org_policies.iteritems())
        policy_data.append(project_policies.iteritems())

        return policy_data, resource_counts

    def run(self):
        """Runs the data collection."""
        
        policy_data, resource_counts = self._retrieve()
        all_violations = self.find_violations(policy_data)
        self._output_results(all_violations, resource_counts)
