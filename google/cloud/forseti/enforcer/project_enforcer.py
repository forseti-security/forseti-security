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

"""Manages enforcement of policies for a single cloud project."""

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function

import hashlib

from google.cloud.forseti.common.gcp_api import compute
from google.cloud.forseti.common.gcp_api import errors as api_errors
from google.cloud.forseti.common.util import date_time
from google.cloud.forseti.common.util import logger
from google.cloud.forseti.enforcer import enforcer_log_pb2
from google.cloud.forseti.enforcer import gce_firewall_enforcer as fe

STATUS_SUCCESS = enforcer_log_pb2.SUCCESS
STATUS_ERROR = enforcer_log_pb2.ERROR
STATUS_SKIPPED = enforcer_log_pb2.SKIPPED
STATUS_DELETED = enforcer_log_pb2.PROJECT_DELETED
STATUS_UNSPECIFIED = enforcer_log_pb2.ENFORCEMENT_STATUS_UNSPECIFIED

# Default number of times to try applying the firewall policy to a project
# before the status is changed to ERROR and the enforcement fails.
MAX_ENFORCEMENT_RETRIES = 3

LOGGER = logger.get_logger(__name__)


class ProjectEnforcer(object):
    """Manages enforcement of policies for a single cloud project."""

    def __init__(self,
                 project_id,
                 global_configs=None,
                 compute_client=None,
                 dry_run=False,
                 project_sema=None,
                 max_running_operations=0):
        """Initialize.

        Args:
            project_id (str): The project id for the project to enforce.
            global_configs (dict): Global configurations.
            compute_client (ComputeClient): A Compute API client.
                If not provided, one will be created using the default
                credentials.
            dry_run (bool): Set to true to ensure no actual changes are made to
                the project. EnforcePolicy will still return a ProjectResult
                proto showing the changes that would have been made.
            project_sema (threading.BoundedSemaphore): An optional semaphore
                object, used to limit the number of concurrent projects getting
                written to.
            max_running_operations (int): [DEPRECATED] Used to limit the number
                of concurrent running operations on an API.
        """
        self.project_id = project_id

        if not compute_client:
            compute_client = compute.ComputeClient(global_configs,
                                                   dry_run=dry_run)

        self.compute_client = compute_client

        self.result = enforcer_log_pb2.ProjectResult()
        self.result.status = STATUS_UNSPECIFIED
        self.result.project_id = self.project_id
        self.result.timestamp_sec = date_time.get_utc_now_microtimestamp()

        self._dry_run = dry_run

        self._project_sema = project_sema
        if max_running_operations:
            LOGGER.warn(
                'Max running operations is deprecated. Argument ignored.')

        self._operation_sema = None

    def enforce_firewall_policy(self,
                                firewall_policy,
                                networks=None,
                                allow_empty_ruleset=False,
                                prechange_callback=None,
                                add_rule_callback=None,
                                retry_on_dry_run=False,
                                maximum_retries=MAX_ENFORCEMENT_RETRIES):
        """Enforces the firewall policy on the project.

        Args:
            firewall_policy (list): A list of firewall rules that should be
                configured on the project networks.
            networks (list): A list of networks on the project that the
                policy applies to. If undefined, then the policy will be applied
                to all networks.
            allow_empty_ruleset (bool): If set to true and firewall_policy has
                no rules, all current firewall rules will be deleted from the
                project.
            prechange_callback (Callable): See FirewallEnforcer.apply_firewall()
                docstring for more details.
            add_rule_callback (Callable): A callback function that checks
                whether a firewall rule should be applied. If the callback
                returns False, that rule will not be modified.
            retry_on_dry_run (bool): Set to True to retry applying firewall
                rules when the expected policy does not match the current policy
                when dry_run is enabled.
            maximum_retries (int): The number of times enforce_firewall_policy
                will attempt to set the current firewall policy to the expected
                firewall policy. Set to 0 to disable retry behavior.

        Returns:
            enforcer_log_pb2.ProjectResult: A proto with details on the status
            of the enforcement and an audit log with any changes made.
        """
        try:
            if networks:
                networks = sorted(networks)
            else:
                networks = self._get_project_networks()
                if not networks:
                    self._set_error_status('no networks found for project')
                    return self.result

            expected_rules = self._get_expected_rules(networks,
                                                      firewall_policy)

            rules_before_enforcement = self._get_current_fw_rules(
                add_rule_callback)

        except EnforcementError as e:
            self._set_error_status(e.reason())
        except (ComputeApiDisabledError, ProjectDeletedError) as e:
            self._set_deleted_status(e)

        else:

            firewall_enforcer = self._initialize_firewall_enforcer(
                expected_rules, rules_before_enforcement,
                add_rule_callback)

            rules_after_enforcement = self._apply_firewall_policy(
                firewall_enforcer,
                expected_rules,
                networks,
                allow_empty_ruleset,
                prechange_callback,
                add_rule_callback,
                retry_on_dry_run,
                maximum_retries)

            if self.result.status == STATUS_UNSPECIFIED:
                self.result.status = STATUS_SUCCESS

            self._update_fw_results(firewall_enforcer,
                                    rules_before_enforcement,
                                    rules_after_enforcement)

        if not self.result.gce_firewall_enforcement.rules_modified_count:
            LOGGER.info('Firewall policy not changed for %s', self.project_id)

        return self.result

    def _apply_firewall_policy(self,
                               firewall_enforcer,
                               expected_rules,
                               networks,
                               allow_empty_ruleset,
                               prechange_callback,
                               add_rule_callback,
                               retry_on_dry_run,
                               maximum_retries):
        """Attempt to enforce the expected rules until successful.

        Args:
            firewall_enforcer (fe.FirewallEnforcer): The firewall enforcer
                instance to use for updating the firewall rules.
            expected_rules (fe.FirewallRules): A list of expected firewall
                rules to apply to the project.
            networks (list): A list of networks on the project that the policy
                applies to.
            allow_empty_ruleset (bool): If set to true and firewall_policy has
                no rules, all current firewall rules will be deleted from the
                project.
            prechange_callback (Callable): See FirewallEnforcer.apply_firewall()
                docstring for more details.
            add_rule_callback (Callable): A callback function that checks
                whether a firewall rule should be applied. If the callback
                returns False, that rule will not be modified.
            retry_on_dry_run (bool): Set to True to retry applying firewall
                rules when the expected policy does not match the current policy
                when dry_run is enabled.
            maximum_retries (int): The number of times enforce_firewall_policy
                will attempt to set the current firewall policy to the expected
                firewall policy. Set to 0 to disable retry behavior.

        Returns:
            fe.FirewallRules: A FirewallRules instance with the firewall rules
                configured on the project after enforcement.
        """
        rules_after_enforcement = None
        retry_enforcement_count = 0
        while True and self.result.status not in (STATUS_ERROR, STATUS_DELETED):
            change_count = 0
            try:
                change_count = firewall_enforcer.apply_firewall(
                    prechange_callback=prechange_callback,
                    allow_empty_ruleset=allow_empty_ruleset,
                    networks=networks)
            except fe.FirewallEnforcementFailedError as e:
                self._set_error_status(
                    'error enforcing firewall for project: %s', e)
                change_count = None

            try:
                rules_after_enforcement = self._get_current_fw_rules(
                    add_rule_callback)
            except EnforcementError as e:
                self._set_error_status(e.reason())
                change_count = None

            if not change_count:
                # Don't attempt to retry if there were no changes. This can be
                # caused by the prechange callback returning false or an
                # exception.
                break

            if ((self._dry_run and not retry_on_dry_run) or
                    rules_after_enforcement == expected_rules):
                break

            retry_enforcement_count += 1
            if retry_enforcement_count <= maximum_retries:
                LOGGER.warn('New firewall rules do not match the expected '
                            'rules enforced by the policy for project %s, '
                            'retrying. (Retry #%d)', self.project_id,
                            retry_enforcement_count)
                firewall_enforcer.refresh_current_rules()
            else:
                self._set_error_status('New firewall rules do not match '
                                       'the expected rules enforced by '
                                       'the policy')
        return rules_after_enforcement

    def _initialize_firewall_enforcer(self,
                                      expected_rules,
                                      rules_before_enforcement,
                                      add_rule_callback=None):
        """Gets current and expected rules, returns a FirewallEnforcer object.

        Args:
            expected_rules (fe.FirewallRules): A list of expected firewall
                rules to apply to the project.
            rules_before_enforcement (fe.FirewallRules): The list of current
                firewall rules configured on the project.
            add_rule_callback (Callable): A callback function that checks
                whether a firewall rule should be applied. If the callback
                returns False, that rule will not be modified.

        Returns:
            fe.FirewallEnforcer: A new FirewallEnforcer object configured with
                the expected policy for the project.
        """
        enforcer = fe.FirewallEnforcer(
            self.project_id,
            self.compute_client,
            expected_rules,
            rules_before_enforcement,
            project_sema=self._project_sema,
            operation_sema=self._operation_sema,
            add_rule_callback=add_rule_callback)

        return enforcer

    def _get_project_networks(self):
        """Enumerate the current project networks and returns a sorted list.

        Returns:
            list: A sorted list of network names.


        Raises:
            ProjectDeletedError: Raised if the project has been deleted.
            ComputeApiDisabledError: Raised if the Compute API is not enabled on
                the project.
            EnforcementError: Raised if there are any exceptions raised while
                adding the firewall rules.
        """
        networks = set()
        try:
            results = self.compute_client.get_networks(self.project_id)

        except api_errors.ApiNotEnabledError as e:
            LOGGER.exception('Error listing networks for project %s: %s',
                             self.project_id, e)
            raise ComputeApiDisabledError(e)
        except api_errors.ApiExecutionError as e:
            http_error = e.http_error
            if _is_project_deleted_error(http_error):
                LOGGER.warn('Project %s has been deleted.', self.project_id)
                raise ProjectDeletedError(str(http_error))

            LOGGER.exception('Error listing networks for project %s: %s',
                             self.project_id, e)
            raise EnforcementError(
                STATUS_ERROR,
                'error getting current networks from API: %s' % http_error)

        for network in results:
            network_name = fe.get_network_name_from_url(
                network['selfLink'])
            networks.add(network_name)

        return sorted(networks)

    def _get_expected_rules(self, networks, firewall_policy):
        """Builds a FirewallRules object with the rules that should be defined.

        Args:
            networks (list): A list of networks on the project that the
                policy applies to.
            firewall_policy (list): A list of firewall rules that should be
                configured on the project networks.

        Returns:
            fe.FirewallRules: A new FirewallRules object with the expected
                policy.

        Raises:
            EnforcementError: Raised if one or more firewall rules in the policy
                are invalid.
        """
        expected_rules = fe.FirewallRules(self.project_id)
        try:
            for network_name in networks:
                expected_rules.add_rules(
                    firewall_policy, network_name=network_name)
        except fe.InvalidFirewallRuleError as e:
            raise EnforcementError(STATUS_ERROR, 'error adding the expected '
                                   'firewall rules from the policy: %s' % e)
        return expected_rules

    def _get_current_fw_rules(self, add_rule_callback=None):
        """Create a new FirewallRules object with the current rules.

        Args:
            add_rule_callback (Callable): A callback function that checks
                whether a firewall rule should be applied. If the callback
                returns False, that rule will not be modified.

        Returns:
            fe.FirewallRules: A new FirewallRules object with the current rules
                added to it.

        Raises:
            ProjectDeletedError: Raised if the project has been deleted.
            ComputeApiDisabledError: Raised if the Compute API is not enabled on
                the project.
            EnforcementError: Raised if there are any exceptions raised while
                adding the firewall rules.
        """
        current_rules = fe.FirewallRules(self.project_id,
                                         add_rule_callback=add_rule_callback)
        try:
            current_rules.add_rules_from_api(self.compute_client)
        except api_errors.ApiNotEnabledError as e:
            LOGGER.error('Error getting firewall rules for project %s: %s',
                         self.project_id, e)
            raise ComputeApiDisabledError(e)
        except api_errors.ApiExecutionError as e:
            http_error = e.http_error
            if _is_project_deleted_error(http_error):
                LOGGER.warn('Project %s has been deleted.', self.project_id)
                raise ProjectDeletedError(str(http_error))

            raise EnforcementError(
                STATUS_ERROR,
                'error getting current firewall rules from API: %s'
                % http_error)
        except fe.InvalidFirewallRuleError as e:
            raise EnforcementError(STATUS_ERROR,
                                   'error getting current firewall '
                                   'rules from API: %s' % e)
        return current_rules

    def _update_fw_results(self,
                           firewall_enforcer,
                           rules_before_enforcement,
                           rules_after_enforcement):
        """Update the result proto with details on any changes made.

        Args:
            firewall_enforcer (fe.FirewallEnforcer): The firewall enforcer
                instance to use for updating the firewall rules.
            rules_before_enforcement (fe.FirewallRules): The firewall rules
                before enforcer made any changes.
            rules_after_enforcement (fe.FirewallRules): The firewall rules
                after enforcer made any changes.
        """
        results = self.result.gce_firewall_enforcement
        results.rules_modified_count = 0

        for rule in sorted(
                [r['name'] for r in firewall_enforcer.get_inserted_rules()]):
            results.rules_added.append(rule)
            results.rules_modified_count += 1

        for rule in sorted(
                [r['name'] for r in firewall_enforcer.get_deleted_rules()]):
            results.rules_removed.append(rule)
            results.rules_modified_count += 1

        for rule in sorted(
                [r['name'] for r in firewall_enforcer.get_updated_rules()]):
            results.rules_updated.append(rule)
            results.rules_modified_count += 1

        # If an error occurred during enforcement, rules_after_enforcement may
        # not exist yet.
        if not rules_after_enforcement:
            LOGGER.error(
                'Project %s could not list firewall rules after enforcement',
                self.project_id)

            # Ensure original rules are in audit log in case roll back is
            # required
            results.rules_before.json = rules_before_enforcement.as_json()
            results.rules_before.hash = (
                hashlib.sha256(results.rules_before.json).hexdigest())
            return

        if rules_before_enforcement != rules_after_enforcement:
            results.rules_before.json = rules_before_enforcement.as_json()
            results.rules_before.hash = (
                hashlib.sha256(results.rules_before.json).hexdigest())
            results.rules_after.json = rules_after_enforcement.as_json()
            results.rules_after.hash = (
                hashlib.sha256(results.rules_after.json).hexdigest())

        for (rule_name,
             rule) in sorted(rules_after_enforcement.rules.items()):
            if rule == rules_before_enforcement.rules.get(rule_name, {}):
                results.rules_unchanged.append(rule_name)

        if (self.result.status == STATUS_SUCCESS and
                results.rules_modified_count and not results.rules_updated and
                not results.rules_unchanged):
            # Check if all previous rules were deleted and all current rules
            # were added during this enforcement. If so, this is a newly
            # enforced project.
            previous_fw_rules_count = len(rules_before_enforcement.rules)
            current_fw_rules_count = len(rules_after_enforcement.rules)
            if (len(results.rules_removed) >= previous_fw_rules_count and
                    len(results.rules_added) == current_fw_rules_count):
                LOGGER.info(
                    'Project %s had all of its firewall rules changed..',
                    self.project_id)
                results.all_rules_changed = True

    def _set_error_status(self, msg, *args):
        """Set status to result ERROR and update the reason string from msg.

        Args:
            msg (str): The error message to use as the status reason.
            *args (list): Optional args to format the msg string with.
        """
        if args:
            msg %= args

        self.result.status = STATUS_ERROR
        self.result.status_reason = msg
        LOGGER.warn('Project %s had an error: %s', self.project_id, msg)

    def _set_deleted_status(self, e):
        """Set status of result to DELETED and update reason string.

        Args:
            e (Exception): The exception raised.
        """
        self.result.status = STATUS_DELETED
        if isinstance(e, ProjectDeletedError):
            self.result.status_reason = (
                'Project scheduled for deletion: %s' % e)
            LOGGER.warn('Project %s scheduled for deletion: %s',
                        self.project_id, e)
        elif isinstance(e, ComputeApiDisabledError):
            self.result.status_reason = (
                'Project has GCE API disabled: %s' % e)
            LOGGER.warn('Project %s has the GCE API disabled: %s',
                        self.project_id, e)


def _is_project_deleted_error(err):
    """Checks if the error is due to the project having been deleted.

    Args:
        err (HttpError): The error message returned by the API call.

    Returns:
        bool: True if the project was deleted, else False.
    """
    error_msg = str(
        err)  # HttpError Class decodes json encoded error into str
    if ((err.resp.status in (400, 404) and
         ('Invalid value for project' in error_msg or
          # Error string changed.
          'Failed to find project' in error_msg)) or
            (err.resp.status == 403 and
             'scheduled for deletion' in error_msg)):
        return True
    return False


class Error(Exception):
    """Base error class for the module."""


class EnforcementError(Error):
    """Error encountered while enforcing firewall on project."""

    def __init__(self, status, reason):
        """Initialize.

        Args:
            status (int): The status code to use for the error.
            reason (str): The reason to use for the error.
        """
        self._status = int(status)
        self._status_string = enforcer_log_pb2.EnforcementStatus.Name(status)
        self._reason = reason
        super(EnforcementError, self).__init__(str(self))

    def status(self):
        """Return status.

        Returns:
            int: Status code.
        """
        return self._status

    def reason(self):
        """Return reason.

        Returns:
            str: Status reason.
        """
        return self._reason

    def __str__(self):
        """Stringify.

        Returns:
            str: The stringified error message.
        """
        return '{}: {}'.format(self._status_string, self._reason)


class ProjectDeletedError(Error):
    """Error raised if a project to be enforced has been marked for deletion."""


class ComputeApiDisabledError(Error):
    """Error raised if a project to be enforced has the compute API disabled."""
