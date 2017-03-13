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

"""Manages enforcement of policies for a single cloud project."""

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function

import hashlib
import threading
from googleapiclient import errors
from google.apputils import datelib

from google.cloud.security.common.gcp_api import compute
from google.cloud.security.common.util.log_util import LogUtil
from google.cloud.security.enforcer import enforcer_log_pb2
from google.cloud.security.enforcer import gce_firewall_enforcer as fe

STATUS_SUCCESS = enforcer_log_pb2.SUCCESS
STATUS_ERROR = enforcer_log_pb2.ERROR
STATUS_SKIPPED = enforcer_log_pb2.SKIPPED
STATUS_DELETED = enforcer_log_pb2.PROJECT_DELETED

# Default number of times to try applying the firewall policy to a project
# before the status is changed to ERROR and the enforcement fails.
MAX_ENFORCEMENT_RETRIES = 3

LOGGER = LogUtil.setup_logging(__name__)


class ProjectEnforcer(object):
    """Manages enforcement of policies for a single cloud project."""

    # pylint: disable=too-many-instance-attributes
    def __init__(self,
                 project_id,
                 dry_run=False,
                 project_sema=None,
                 max_running_operations=0):
        """Initialize.

        Args:
          project_id: The project id for the project to enforce.
          dry_run: Set to true to ensure no actual changes are made to the
              project. EnforcePolicy will still return a ProjectResult proto
              showing the changes that would have been made.
          project_sema: An optional semaphore object, used to limit the number
              of concurrent projects getting written to.
          max_running_operations: Used to limit the number of concurrent running
              operations on an API.

        """
        self.project_id = project_id

        self.result = enforcer_log_pb2.ProjectResult()
        self.result.project_id = self.project_id

        self._dry_run = dry_run

        self._project_sema = project_sema
        if max_running_operations:
            self._operation_sema = threading.BoundedSemaphore(
                value=max_running_operations)
        else:
            self._operation_sema = None

    # pylint: disable=too-many-return-statements,too-many-branches
    # TODO: Investigate not having to disable some of these messages.
    def enforce_firewall_policy(self,
                                firewall_policy,
                                compute_service=None,
                                networks=None,
                                allow_empty_ruleset=False,
                                prechange_callback=None,
                                retry_on_dry_run=False,
                                maximum_retries=MAX_ENFORCEMENT_RETRIES):
        """Enforces the firewall policy on the project.

        Args:
          firewall_policy: A list of rules to enforce on the project.
          compute_service: A Compute service object. If not provided, one will
              be created using the default credentials.
          networks: An optional list of network names to apply the policy to. If
              undefined, then the policy will be applied to all networks.
          allow_empty_ruleset: If set to true and firewall_policy has no rules,
              all current firewall rules will be deleted from the project.
          prechange_callback: An optional callback function to pass to
              FirewallEnforcer.apply_firewall. It gets called if the
              firewall policy for a project does not match the expected policy,
              before any changes are actually applied. If the callback returns
              False then no changes will be made to the project. If it returns
              True then the changes will be pushed.

              See FirewallEnforcer.apply_firewall() docstring for more details.
          retry_on_dry_run: Set to True to retry applying firewall rules when
              the expected policy does not match the current policy when
              dry_run is enabled.
          maximum_retries: The number of times enforce_firewall_policy will
              attempt to set the current firewall policy to the expected
              firewall policy. Set to 0 to disable retry behavior.

        Returns:
          A ProjectResult proto with details on the status of the enforcement
          and an audit log with any changes made.
        """
        if not compute_service:
            gce_api = compute.ComputeClient()
            compute_service = gce_api.service

        # pylint: disable=attribute-defined-outside-init
        # TODO: Investigate improving to avoid the pylint disable.
        self.firewall_api = fe.ComputeFirewallAPI(compute_service,
                                                  dry_run=self._dry_run)

        # pylint: disable=attribute-defined-outside-init
        # TODO: Investigate improving to avoid the pylint disable.
        self.firewall_policy = firewall_policy

        if networks:
            self.project_networks = sorted(networks)
        else:
            self.project_networks = self._get_project_networks()

        self.result.timestamp_sec = datelib.Timestamp.now().AsMicroTimestamp()

        try:
            # pylint: disable=attribute-defined-outside-init
            # TODO: Investigate improving to avoid the pylint disable.
            self.enforcer = self._initialize_firewall_enforcer()
        except EnforcementError as e:
            return self._set_error_status(e.reason())
        except ProjectDeletedError as e:
            self.result.status = STATUS_DELETED
            self.result.status_reason = 'Project scheduled for deletion: %s' % e
            LOGGER.warn('Project %s scheduled for deletion: %s',
                        self.project_id, e)

            return self.result
        except ComputeApiDisabledError as e:
            # Reuse the DELETED status, since the project should be moved to the
            # archive queue if the API is disabled.
            self.result.status = STATUS_DELETED
            self.result.status_reason = 'Project has GCE API disabled: %s' % e
            LOGGER.warn('Project %s has the GCE API disabled: %s',
                        self.project_id, e)

            return self.result

        retry_enforcement_count = 0
        while True:
            try:
                change_count = self.enforcer.apply_firewall(
                    prechange_callback=prechange_callback,
                    allow_empty_ruleset=allow_empty_ruleset,
                    networks=self.project_networks)
            except fe.FirewallEnforcementFailedError as e:
                return self._set_error_status(
                    'error enforcing firewall for project: %s', e)

            try:
                # pylint: disable=attribute-defined-outside-init
                # TODO: Investigate improving to avoid the pylint disable.
                self.rules_after_enforcement = self._get_current_fw_rules()
            except EnforcementError as e:
                return self._set_error_status(e.reason())

            if not change_count:
                # Don't attempt to retry if there were no changes. This can be
                # caused by the prechange callback returning false or an
                # exception.
                break

            if ((self._dry_run and not retry_on_dry_run) or
                    self.rules_after_enforcement == self.expected_rules):
                break

            retry_enforcement_count += 1
            if retry_enforcement_count <= maximum_retries:
                LOGGER.warn('New firewall rules do not match the expected '
                            'rules enforced by the policy for project %s, '
                            'retrying. (Retry #%d)', self.project_id,
                            retry_enforcement_count)
                self.enforcer.refresh_current_rules()
            else:
                return self._set_error_status('New firewall rules do not match '
                                              'the expected rules enforced by '
                                              'the policy')

        self.result.status = STATUS_SUCCESS
        self._update_fw_results()

        if not self.result.gce_firewall_enforcement.rules_modified_count:
            LOGGER.info('Firewall policy not changed for %s', self.project_id)

        return self.result

    def _initialize_firewall_enforcer(self):
        """Gets current and expected rules, returns a FirewallEnforcer object.

        Returns:
          A new FirewallEnforcer object configured with the expected policy for
          the project.

        Raises:
          EnforcementError: Raised if there are any errors fetching the current
              firewall rules or building the expected rules from the policy.
        """

        # pylint: disable=attribute-defined-outside-init
        # TODO: Investigate improving to avoid the pylint disable.
        if not self.project_networks:
            raise EnforcementError(STATUS_ERROR,
                                   'no networks found for project')

        self.rules_before_enforcement = self._get_current_fw_rules()
        # pylint: disable=attribute-defined-outside-init
        # TODO: Investigate improving to avoid the pylint disable.
        self.expected_rules = fe.FirewallRules(self.project_id)
        try:
            for network_name in self.project_networks:
                self.expected_rules.add_rules(
                    self.firewall_policy, network_name=network_name)
        except fe.InvalidFirewallRuleError as e:
            raise EnforcementError(STATUS_ERROR, 'error adding the expected '
                                   'firewall rules from the policy: %s' % e)

        enforcer = fe.FirewallEnforcer(
            self.project_id,
            self.firewall_api,
            self.expected_rules,
            self.rules_before_enforcement,
            project_sema=self._project_sema,
            operation_sema=self._operation_sema)

        return enforcer

    def _get_project_networks(self):
        """Enumerate the current project networks and returns a sorted list."""
        networks = set()
        try:
            response = self.firewall_api.list_networks(
                self.project_id, fields='items/selfLink')
        except errors.HttpError as e:
            LOGGER.error('Error listing networks for project %s: %s',
                         self.project_id, e)
        else:
            for item in response.get('items', []):
                if 'selfLink' in item:
                    network_name = fe.get_network_name_from_url(
                        item['selfLink'])
                    networks.add(network_name)
                else:
                    LOGGER.error('Network URL not found in %s for project %s',
                                 item, self.project_id)
        return sorted(networks)

    def _get_current_fw_rules(self):
        """Create a new FirewallRules object with the current rules.

        Returns:
          A new FirewallRules object with the current rules added to it.

        Raises:
          EnforcementError: Raised if there are any exceptions raised while
              adding the firewall rules.
        """
        current_rules = fe.FirewallRules(self.project_id)
        try:
            current_rules.add_rules_from_api(self.firewall_api)
        except errors.HttpError as e:
            # Handle race condition where a project is deleted after it is
            # enqueued.
            error_msg = str(
                e)  # HttpError Class decodes json encoded error into str
            if ((e.resp.status in (400, 404) and
                 ('Invalid value for project' in error_msg or
                  'Failed to find project' in error_msg))
                    or  # Error string changed
                    (e.resp.status == 403 and
                     'scheduled for deletion' in error_msg)):
                raise ProjectDeletedError(error_msg)
            elif (e.resp.status == 403 and
                  'Compute Engine API has not been used' in error_msg):
                raise ComputeApiDisabledError(error_msg)
            else:
                raise EnforcementError(STATUS_ERROR,
                                       'error getting current firewall '
                                       'rules from API: %s' % e)
        except fe.InvalidFirewallRuleError as e:
            raise EnforcementError(STATUS_ERROR,
                                   'error getting current firewall '
                                   'rules from API: %s' % e)
        return current_rules

    def _update_fw_results(self):
        """Update the result proto with details on any changes made."""
        results = self.result.gce_firewall_enforcement
        results.rules_modified_count = 0

        for rule in sorted(
                [r['name'] for r in self.enforcer.get_inserted_rules()]):
            results.rules_added.append(rule)
            results.rules_modified_count += 1

        for rule in sorted(
                [r['name'] for r in self.enforcer.get_deleted_rules()]):
            results.rules_removed.append(rule)
            results.rules_modified_count += 1

        for rule in sorted(
                [r['name'] for r in self.enforcer.get_updated_rules()]):
            results.rules_updated.append(rule)
            results.rules_modified_count += 1

        # If an error occured during enforcement, rules_after_enforcement may
        # not exist yet.
        # pylint: disable=attribute-defined-outside-init
        # TODO: Investigate improving to avoid the pylint disable.
        if not hasattr(self, 'rules_after_enforcement'):
            try:
                self.rules_after_enforcement = self._get_current_fw_rules()
            except EnforcementError as e:
                LOGGER.error(
                    'Project %s raised an error while listing firewall '
                    'rules after enforcement: %s', self.project_id, e)

                # Ensure original rules are in audit log in case roll back is
                # required
                results.rules_before.json = (
                    self.rules_before_enforcement.as_json())
                results.rules_before.hash = (
                    hashlib.sha256(results.rules_before.json).hexdigest())
                return

        if self.rules_before_enforcement != self.rules_after_enforcement:
            results.rules_before.json = self.rules_before_enforcement.as_json()
            results.rules_before.hash = (
                hashlib.sha256(results.rules_before.json).hexdigest())
            results.rules_after.json = self.rules_after_enforcement.as_json()
            results.rules_after.hash = (
                hashlib.sha256(results.rules_after.json).hexdigest())

        for (rule_name,
             rule) in sorted(self.rules_after_enforcement.rules.items()):
            if rule == self.rules_before_enforcement.rules.get(rule_name, {}):
                results.rules_unchanged.append(rule_name)

        if (self.result.status == STATUS_SUCCESS and
                results.rules_modified_count and not results.rules_updated and
                not results.rules_unchanged):
            # Check if all previous rules were deleted and all current rules
            # were added during this enforcement. If so, this is a newly
            # enforced project.
            previous_fw_rules_count = len(self.rules_before_enforcement.rules)
            current_fw_rules_count = len(self.rules_after_enforcement.rules)
            if (len(results.rules_removed) >= previous_fw_rules_count and
                    len(results.rules_added) == current_fw_rules_count):
                LOGGER.info(
                    'Project %s had all of its firewall rules changed..',
                    self.project_id)
                results.all_rules_changed = True

    def _set_error_status(self, msg, *args):
        """Set status to result ERROR and update the reason string from msg."""
        if args:
            msg %= args

        self.result.status = STATUS_ERROR
        self.result.status_reason = msg
        LOGGER.warn('Project %s had an error: %s', self.project_id, msg)

        if hasattr(self, 'enforcer'):  # Verify enforcer was initialized.
            self._update_fw_results()

        return self.result


class Error(Exception):
    """Base error class for the module."""


class EnforcementError(Error):
    """Error encountered while enforcing firewall on project."""

    def __init__(self, status, reason):
        self._status = int(status)
        self._status_string = enforcer_log_pb2.EnforcementStatus.Name(status)
        self._reason = reason
        super(EnforcementError, self).__init__(str(self))

    def status(self):
        """Return status."""
        return self._status

    def reason(self):
        """Return reason."""
        return self._reason

    def __str__(self):
        return '{}: {}'.format(self._status_string, self._reason)


class ProjectDeletedError(Error):
    """Error raised if a project to be enforced has been marked for deletion."""


class ComputeApiDisabledError(Error):
    """Error raised if a project to be enforced has the compute API disabled."""
