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

import json

from google.cloud.forseti.common.gcp_type.billing_account import BillingAccount
from google.cloud.forseti.common.gcp_type.bucket import Bucket
from google.cloud.forseti.common.gcp_type.folder import Folder
from google.cloud.forseti.common.gcp_type import iam_policy
from google.cloud.forseti.common.gcp_type.organization import Organization
from google.cloud.forseti.common.gcp_type.project import Project
from google.cloud.forseti.common.gcp_type.resource import ResourceType
from google.cloud.forseti.common.util import logger
from google.cloud.forseti.scanner.audit import iam_rules_engine
from google.cloud.forseti.scanner.scanners import base_scanner

LOGGER = logger.get_logger(__name__)


# pylint: disable=too-many-branches
def _add_bucket_ancestor_bindings(policy_data):
    """Add bucket relevant IAM policy bindings from ancestors.

    Resources can inherit policy bindings from ancestors in the resource
    manager tree. For example: a GCS bucket inherits a 'objectViewer' role
    from a project or folder (up in the tree).

    So far the IAM rules engine only checks the set of bindings directly
    attached to a resource (direct bindings set (DBS)). We need to add
    relevant bindings inherited from ancestors to DBS so that these are
    also checked for violations.

    If we find one more than one binding with the same role name, we need to
    merge the members.

    NOTA BENE: this function only handles buckets and bindings relevant to
    these at present (but can and should be expanded to handle projects and
    folders going forward).

    Args:
        policy_data (list): list of (parent resource, iam_policy resource,
            policy bindings) tuples to find violations in.
    """
    storage_iam_roles = frozenset([
        'roles/storage.admin',
        'roles/storage.objectViewer',
        'roles/storage.objectCreator',
        'roles/storage.objectAdmin',
    ])
    bucket_data = []
    for (resource, _, bindings) in policy_data:
        if resource.type == 'bucket':
            bucket_data.append((resource, bindings))

    for bucket, bucket_bindings in bucket_data:
        all_ancestor_bindings = []
        for (resource, _, bindings) in policy_data:
            if resource.full_name == bucket.full_name:
                continue
            if bucket.full_name.find(resource.full_name):
                continue
            all_ancestor_bindings.append(bindings)

        for ancestor_bindings in all_ancestor_bindings:
            for ancestor_binding in ancestor_bindings:
                if ancestor_binding.role_name not in storage_iam_roles:
                    continue
                if ancestor_binding in bucket_bindings:
                    continue
                # Do we have a binding with the same 'role_name' already?
                for bucket_binding in bucket_bindings:
                    if bucket_binding.role_name == ancestor_binding.role_name:
                        bucket_binding.merge_members(ancestor_binding)
                        break
                else:
                    # no, add ancestor binding.
                    bucket_bindings.append(ancestor_binding)


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
                violation_data = {
                    'full_name': violation.full_name,
                    'role': violation.role, 'member': '%s:%s' % (member.type,
                                                                 member.name)
                }

                yield {
                    'resource_name': member,
                    'resource_id': violation.resource_id,
                    'resource_type': violation.resource_type,
                    'full_name': violation.full_name,
                    'rule_index': violation.rule_index,
                    'rule_name': violation.rule_name,
                    'violation_type': violation.violation_type,
                    'violation_data': violation_data,
                    'resource_data': violation.resource_data
                }

    def _output_results(self, all_violations):
        """Output results.

        Args:
            all_violations (list): A list of violations.
        """
        all_violations = self._flatten_violations(all_violations)
        self._output_results_to_db(all_violations)

    def _find_violations(self, policies):
        """Find violations in the policies.

        Args:
            policies (list): list of (parent resource, iam_policy resource,
                policy bindings) tuples to find violations in.

        Returns:
            list: A list of all violations
        """
        all_violations = []
        LOGGER.info('Finding IAM policy violations...')
        for (resource, policy, policy_bindings) in policies:
            # At this point, the variable's meanings are switched:
            # "policy" is really the resource from the data model.
            # "resource" is the generated Forseti gcp type.
            LOGGER.debug('%s => %s', resource, policy)
            violations = self.rules_engine.find_violations(
                resource, policy, policy_bindings)
            all_violations.extend(violations)
        return all_violations

    def _retrieve(self):
        """Retrieves the data for scanner.

        Returns:
            list: List of (gcp_type, forseti_data_model_resource) tuples.
            dict: A dict of resource counts.

        Raises:
            NoDataError: If no policies are found.
        """
        model_manager = self.service_config.model_manager
        scoped_session, data_access = model_manager.get(self.model_name)
        with scoped_session as session:

            policy_data = []
            supported_iam_types = [
                ResourceType.ORGANIZATION, ResourceType.BILLING_ACCOUNT,
                ResourceType.FOLDER, ResourceType.PROJECT, ResourceType.BUCKET]
            resource_counts = {iam_type: 0 for iam_type in supported_iam_types}

            for policy in data_access.scanner_iter(session, 'iam_policy'):
                if policy.parent.type not in supported_iam_types:
                    continue

                policy_bindings = filter(None, [  # pylint: disable=bad-builtin
                    iam_policy.IamPolicyBinding.create_from(b)
                    for b in json.loads(policy.data).get('bindings', [])])

                resource_counts[policy.parent.type] += 1
                if policy.parent.type == ResourceType.BUCKET:
                    policy_data.append(
                        (Bucket(policy.parent.name,
                                policy.parent.full_name,
                                policy.data),
                         policy, policy_bindings))
                elif policy.parent.type == ResourceType.PROJECT:
                    policy_data.append(
                        (Project(policy.parent.name,
                                 policy.parent.full_name,
                                 policy.data),
                         policy, policy_bindings))
                elif policy.parent.type == ResourceType.FOLDER:
                    policy_data.append(
                        (Folder(
                            policy.parent.name,
                            policy.parent.full_name,
                            policy.data),
                         policy, policy_bindings))
                elif policy.parent.type == ResourceType.BILLING_ACCOUNT:
                    policy_data.append(
                        (BillingAccount(policy.parent.name,
                                        policy.parent.full_name,
                                        policy.data),
                         policy, policy_bindings))
                elif policy.parent.type == ResourceType.ORGANIZATION:
                    policy_data.append(
                        (Organization(
                            policy.parent.name,
                            policy.parent.full_name,
                            policy.data),
                         policy, policy_bindings))

        if not policy_data:
            LOGGER.warn('No policies found.')
            return [], 0

        return policy_data, resource_counts

    def run(self):
        """Runs the data collection."""
        policy_data, _ = self._retrieve()
        _add_bucket_ancestor_bindings(policy_data)
        all_violations = self._find_violations(policy_data)
        self._output_results(all_violations)
