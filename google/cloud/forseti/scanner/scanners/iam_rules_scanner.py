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

"""Scanner for the IAM rules engine."""

from datetime import datetime
import os
import sys

from google.cloud.forseti.common.data_access import csv_writer
from google.cloud.forseti.common.gcp_type.folder import Folder
from google.cloud.forseti.common.gcp_type.organization import Organization
from google.cloud.forseti.common.gcp_type.project import Project
from google.cloud.forseti.common.gcp_type.resource import ResourceType
from google.cloud.forseti.common.util import log_util
from google.cloud.forseti.notifier import notifier
from google.cloud.forseti.scanner.audit import iam_rules_engine
from google.cloud.forseti.scanner.scanners import base_scanner


LOGGER = log_util.get_logger(__name__)


class IamPolicyScanner(base_scanner.BaseScanner):
    """Scanner for IAM data."""

    SCANNER_OUTPUT_CSV_FMT = 'scanner_output_iam.{}.csv'

    def __init__(self, global_configs, scanner_configs, service_config,
                 model_name, snapshot_timestamp, rules):
        """Initialization.

        Args:
            global_configs (dict): Global configurations.
            scanner_configs (dict): Scanner configurations.
            service_config (ServiceConfig): Forseti 2.0 service configs
            model_name (str): name of the data model
            snapshot_timestamp (str): Timestamp, formatted as YYYYMMDDTHHMMSSZ.
            rules (str): Fully-qualified path and filename of the rules file.
        """
        super(IamPolicyScanner, self).__init__(
            global_configs,
            scanner_configs,
            service_config,
            model_name,
            snapshot_timestamp,
            rules)
        self.rules_engine = iam_rules_engine.IamRulesEngine(
            rules_file_path=self.rules,
            snapshot_timestamp=self.snapshot_timestamp)
        self.rules_engine.build_rule_book(self.global_configs)

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
                violation_data['full_name'] = violation.full_name
                violation_data['role'] = violation.role
                violation_data['member'] = '%s:%s' % (member.type, member.name)

                yield {
                    'resource_id': violation.resource_id,
                    'resource_type': violation.resource_type,
                    'full_name': violation.full_name,
                    'rule_index': violation.rule_index,
                    'rule_name': violation.rule_name,
                    'violation_type': violation.violation_type,
                    'violation_data': violation_data,
                    'inventory_data': violation.inventory_data
                }

    def _output_results(self, all_violations, resource_counts):
        """Output results.

        Args:
            all_violations (list): A list of violations
            resource_counts (dict): Resource count map.
        """
        resource_name = 'violations'

        all_violations = list(self._flatten_violations(all_violations))
        violation_errors = self._output_results_to_db(all_violations)

        # Write the CSV for all the violations.
        # TODO: Move this into the base class? The IAP scanner version of this
        # is a wholesale copy.
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
                        'email_description': 'Policy Scan',
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
            policies (list): The list of (gcp_type, forseti_data_model_resource)
                tuples to find violations in.

        Returns:
            list: A list of all violations
        """
        all_violations = []
        LOGGER.info('Finding IAM policy violations...')
        for (resource, policy) in policies:
            # At this point, the variable's meanings are switched:
            # "policy" is really the resource from the data model.
            # "resource" is the generated Forseti gcp type.
            LOGGER.debug('%s => %s', resource, policy)
            violations = self.rules_engine.find_policy_violations(
                resource, policy)
            all_violations.extend(violations)
        return all_violations

    def _retrieve(self):
        """Retrieves the data for scanner.

        Returns:
            list: List of (gcp_type, forseti_data_model_resource) tuples.
            dict: A dict of resource counts.
        """
        model_manager = self.service_config.model_manager
        scoped_session, data_access = model_manager.get(self.model_name)
        with scoped_session as session:

            policy_data = []
            supported_iam_types = ['organization', 'folder', 'project']
            org_iam_policy_counter = 0
            folder_iam_policy_counter = 0
            project_iam_policy_counter = 0

            for policy in data_access.scanner_iter(session, 'iam_policy'):
                if policy.parent.type not in supported_iam_types:
                    continue

                if policy.parent.type == 'project':
                    project_iam_policy_counter += 1
                    policy_data.append(
                        (Project(policy.parent.name,
                                 policy.full_name,
                                 policy.data),
                         policy))
                elif policy.parent.type == 'folder':
                    folder_iam_policy_counter += 1
                    policy_data.append(
                        (Folder(
                            policy.parent.name,
                            policy.full_name,
                            policy.data),
                         policy))
                elif policy.parent.type == 'organization':
                    org_iam_policy_counter += 1
                    policy_data.append(
                        (Organization(
                            policy.parent.name,
                            policy.full_name,
                            policy.data),
                         policy))

        if not policy_data:
            LOGGER.warn('No policies found. Exiting.')
            sys.exit(1)

        resource_counts = {
            ResourceType.ORGANIZATION: org_iam_policy_counter,
            ResourceType.FOLDER: folder_iam_policy_counter,
            ResourceType.PROJECT: project_iam_policy_counter,
        }

        return policy_data, resource_counts

    def run(self):
        """Runs the data collection."""

        policy_data, resource_counts = self._retrieve()
        all_violations = self._find_violations(policy_data)
        self._output_results(all_violations, resource_counts)
