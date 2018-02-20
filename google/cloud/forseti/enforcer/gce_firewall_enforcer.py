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
"""Core classes for firewall policy enforcement and calls to the compute API.

Simplifies the interface with the compute API for managing firewall policies.
"""

import hashlib
import httplib
import json
import operator
import socket
import ssl
import time

from googleapiclient import errors
import httplib2
from retrying import retry
from google.apputils import datelib
from google.cloud.forseti.common.util import logger

# TODO: The next editor must remove this disable and correct issues.
# pylint: disable=missing-type-doc,missing-return-type-doc,missing-return-doc
# pylint: disable=missing-param-doc,missing-raises-doc,too-many-lines

# The name of the GCE API.
API_NAME = 'compute'

# The root of the GCE API.
API_ROOT = 'https://www.googleapis.com/'

# The version of the GCE API to use.
API_VERSION = 'beta'

# The compute engine scope.
SCOPE = 'https://www.googleapis.com/auth/compute'

LOGGER = logger.get_logger(__name__)

# What transient exceptions should be retried.
RETRY_EXCEPTIONS = (httplib.ResponseNotReady, httplib.IncompleteRead,
                    httplib2.ServerNotFoundError, socket.error, ssl.SSLError,)

# Allowed items in a firewall rule.
ALLOWED_RULE_ITEMS = frozenset(('allowed', 'denied', 'description', 'direction',
                                'name', 'network', 'priority', 'sourceRanges',
                                'destinationRanges', 'sourceTags',
                                'targetTags'))

# Maximum time to allow an active API operation to wait for status=Done
OPERATION_TIMEOUT = 600.0


class Error(Exception):
    """Base error class for the module."""


class InvalidFirewallRuleError(Error):
    """Raised if a firewall rule doesn't look like a firewall rule should."""


class FirewallRuleValidationError(Error):
    """Raised if a firewall rule fails validation."""


class DuplicateFirewallRuleNameError(Error):
    """Raised if a rule name is reused in a policy, names must be unique."""


class FirewallEnforcementFailedError(Error):
    """Updating firewall for project failed."""


class FirewallEnforcementInsertFailedError(FirewallEnforcementFailedError):
    """Insertion of a firewall rule failed."""


class FirewallEnforcementUpdateFailedError(FirewallEnforcementFailedError):
    """Update of a firewall rule failed."""


class FirewallEnforcementDeleteFailedError(FirewallEnforcementFailedError):
    """Deletion of a firewall rule failed."""


class NetworkImpactValidationError(FirewallEnforcementFailedError):
    """Raised if a firewall rule is to be applied to a disallowed network."""


class EmptyProposedFirewallRuleSetError(FirewallEnforcementFailedError):
    """Raised if the proposed firewall rule set is empty."""


class FirewallQuotaExceededError(FirewallEnforcementFailedError):
    """Raised if the proposed changes would exceed firewall quota."""


def http_retry(e):
    """retry_on_exception for retry. Returns True for exceptions to retry."""
    if isinstance(e, RETRY_EXCEPTIONS):
        return True

    return False


def get_network_name_from_url(network_url):
    """Given a network URL, return the name of the network.

    Args:
      network_url: str - the fully qualified network url, such as
        (https://www.googleapis.com/compute/v1/projects/'
        'my-proj/global/networks/my-network')

    Returns:
      str - the network name, my-network in the previous example
    """
    return network_url.split('/')[-1]


def build_network_url(project, network):
    """Render the network url from project and network names.

    Args:
      project: A str- The name of the GCE project to operate upon.
      network: A str- The name of the network to operate upon.

    Returns:
      The fully qualified network url for the given project/network.
    """
    return (u'%(root)s%(api_name)s/%(version)s/projects/%(project)s/global/'
            'networks/%(network)s') % {
                'api_name': API_NAME,
                'network': network,
                'project': project,
                'root': API_ROOT,
                'version': API_VERSION
            }


class ComputeFirewallAPI(object):
    """Wrap calls to the Google Compute Engine API.

    API calls are decorated with retry to ensure temporary network errors do not
    cause failures.

    If initialized in dry run mode, calls which could modify the compute project
    are no-ops and always return a successful result.
    """

    def __init__(self, gce_service, dry_run=False):
        """Constructor.

        Args:
          gce_service: A GCE service object built using the discovery API.
          dry_run: Bool - True to perform a dry run for reporting firewall
              changes.
        """
        self.gce_service = gce_service
        self._dry_run = dry_run

    # pylint: disable=no-self-use

    @retry(
        retry_on_exception=http_retry,
        wait_exponential_multiplier=1000,
        stop_max_attempt_number=4)

    def _execute(self, request):
        """Execute the request and retry logic."""

        return request.execute(num_retries=4)
    # pylint: enable=no-self-use

    def list_networks(self, project, fields=None):
        """List the networks associated with a GCE project.

        Args:
          project: The id of the project to query.
          fields: If defined, limits the response to a subset of all fields.

        Returns:
          The GCE response.
        """
        LOGGER.debug('Listing networks...')
        request = self.gce_service.networks().list(
            project=project, fields=fields)
        return self._execute(request)

    def list_firewalls(self, project, page_token=None):
        """List the firewalls of a given project.

        Args:
          project: The id of the project to query.
          page_token: A str or None- if set, then a pageToken
              to pass to the GCE api call.

        Returns:
          The GCE response.
        """
        LOGGER.debug('Listing firewalls...')
        request = self.gce_service.firewalls().list(
            project=project, pageToken=page_token)
        return self._execute(request)

    def get_firewalls_quota(self, project):
        """Fetch the current FIREWALLS quota for the project.

        Args:
          project: The id of the project to query.

        Returns:
          A dictionary with three keys, metric, limit and usage.

          Example:
          {"metric": "FIREWALLS",
           "limit": 100,
           "usage": 9}
        """
        request = self.gce_service.projects().get(
            project=project, fields='quotas')
        response = self._execute(request)

        for quota in response.get('quotas', []):
            if quota.get('metric', '') == 'FIREWALLS':
                return quota

        return {}

    def delete_firewall_rule(self, project, rule):
        """Delete firewall rules.

        Args:
          project: The id of the project to modify.
          rule: The firewall rule dict to delete.

        Returns:
          The GCE response.
        """
        LOGGER.info('Deleting firewall rule %s on project %s. Deleted rule: %s',
                    rule['name'], project, json.dumps(rule))
        if self._dry_run:
            return self._create_dry_run_response(rule['name'])
        request = self.gce_service.firewalls().delete(
            firewall=rule['name'], project=project)
        return self._execute(request)

    def insert_firewall_rule(self, project, rule):
        """Insert a firewall rule.

        Args:
          project: The id of the project to modify.
          rule: The firewall rule dict to add.

        Returns:
          The GCE response.
        """
        LOGGER.info(
            'Inserting firewall rule %s on project %s. Inserted rule: %s',
            rule['name'], project, json.dumps(rule))
        if self._dry_run:
            return self._create_dry_run_response(rule['name'])
        request = self.gce_service.firewalls().insert(
            body=rule, project=project)
        return self._execute(request)

    def update_firewall_rule(self, project, rule):
        """Update a firewall rule.

        Args:
          project: The id of the project to modify.
          rule: The firewall rule dict to update.

        Returns:
          The GCE response.
        """
        LOGGER.info('Updating firewall rule %s on project %s. Updated rule: %s',
                    rule['name'], project, json.dumps(rule))
        if self._dry_run:
            return self._create_dry_run_response(rule['name'])
        request = self.gce_service.firewalls().update(
            body=rule, firewall=rule['name'], project=project)
        return self._execute(request)

    # TODO: Investigate improving so we can avoid the pylint disable.
    # pylint: disable=too-many-locals
    def wait_for_any_to_complete(self, project, responses, timeout=0):
        """Wait for one or more requests to complete.

        Args:
          project: The id of the project to query.
          responses: A list of Response objects from GCE for the operation.
          timeout: An optional maximum time in seconds to wait for an operation
              to complete. Operations that exceed the timeout are marked as
              Failed.

        Returns:
          A tuple of (completed, still_running) requests.
        """
        started_timestamp = time.time()

        while True:
            completed_operations = []
            running_operations = []
            for response in responses:
                status = response['status']
                if status == 'DONE':
                    completed_operations.append(response)
                    continue

                operation_name = response['name']
                LOGGER.debug('Checking on operation %s', operation_name)
                request = self.gce_service.globalOperations().get(
                    project=project, operation=operation_name)
                response = self._execute(request)
                status = response['status']
                LOGGER.info('status of %s is %s', operation_name, status)
                if response['status'] == 'DONE':
                    completed_operations.append(response)
                    continue

                if timeout and time.time() - started_timestamp > timeout:
                    # Add a timeout error to the response
                    LOGGER.error(
                        'Operation %s did not complete before timeout of %f, '
                        'marking operation as failed.', operation_name, timeout)
                    response.setdefault('error', {}).setdefault(
                        'errors', []).append({
                            'code':
                                'OPERATION_TIMEOUT',
                            'message': (
                                'Operation exceeded timeout for completion '
                                'of %0.2f seconds' % timeout)
                        })
                    completed_operations.append(response)
                else:
                    # Operation still running
                    running_operations.append(response)

            if completed_operations or not responses:
                break
            else:
                time.sleep(2)

        for response in completed_operations:
            try:
                op_insert_timestamp = datelib.Timestamp.FromString(
                    response.get('insertTime', '')).AsSecondsSinceEpoch()
                op_start_timestamp = datelib.Timestamp.FromString(
                    response.get('startTime', '')).AsSecondsSinceEpoch()
                op_end_timestamp = datelib.Timestamp.FromString(
                    response.get('endTime', '')).AsSecondsSinceEpoch()
            except ValueError:
                op_insert_timestamp = op_start_timestamp = op_end_timestamp = 0

            op_wait_time = op_end_timestamp - op_insert_timestamp
            op_exec_time = op_end_timestamp - op_start_timestamp
            LOGGER.info('Operation %s completed. Operation type: %s, '
                        'request time: %s, start time: %s, finished time: %s, '
                        'req->end seconds: %i, start->end seconds: %i.',
                        response.get('name', ''),
                        response.get('operationType', ''),
                        response.get('insertTime', ''),
                        response.get('startTime', ''),
                        response.get('endTime', ''), op_wait_time, op_exec_time)
            LOGGER.debug('Operation response object: %r', response)

        return (completed_operations, running_operations)

    def wait_for_all_to_complete(self, project, responses, timeout=0):
        """Wait for all requests to complete.

        Args:
          project: The id of the project to query.
          responses: A list of Response objects from GCE for the operation.
          timeout: An optional maximum time in seconds to wait for an operation
              to complete. Operations that exceed the timeout are marked as
              Failed.

        Returns:
          A list of completed requests.
        """
        completed_operations = []
        running_operations = responses

        while running_operations:
            (completed, running_operations) = (self.wait_for_any_to_complete(
                project, running_operations, timeout))
            completed_operations.extend(completed)

        return completed_operations

    # pylint: disable=no-self-use
    # TODO: Investigate fixing the pylint issue.
    def is_successful(self, response):
        """Checks if the operation finished with no errors.

        If the operation response contains an 'error' key, then the error code
        is checked. Any error code that is not ignored causes this to return
        False.

        Args:
          response: A GlobalOperations response object from an API call.

        Returns:
          True if there were no errors, or all errors are ignored, otherwise
          False.
        """
        success = True
        if 'error' in response:
            # 'error' should always contains an 'errors' list:
            if 'errors' in response['error']:
                for error in response['error']['errors']:
                    # TODO: Verify current codes.
                    # We ignore the following errors:
                    # RESOURCE_ALREADY_EXISTS: Because another program somewhere
                    #     else could have already added the rule.
                    # INVALID_FIELD_VALUE: Because the network probably
                    #     disappeared out from under us.
                    if error.get('code') in [
                            'RESOURCE_ALREADY_EXISTS', 'INVALID_FIELD_VALUE'
                    ]:
                        LOGGER.warn('Ignoring error: %s', error)
                    else:
                        LOGGER.error('Response has error: %s', error)
                        success = False
            else:
                LOGGER.error('Unknown error response: %s', response['error'])
                success = False
        return success

    # pylint: disable=no-self-use
    # TODO: Investigate fixing the pylint issue.
    def _create_dry_run_response(self, rule_name):
        """A fake successful completed response.

        This is used for dry run execution to prevent any changes to the
        existing firewall rules on a project.

        Args:
          rule_name: The name of the firewall rule this response is for.

        Returns:
          A fake successful completed response.
        """
        return {'status': 'DONE', 'name': rule_name}


class FirewallRules(object):
    """A collection of validated firewall rules."""

    DEFAULT_PRIORITY = 1000
    DEFAULT_DIRECTION = 'INGRESS'

    def __init__(self, project, rules=None, add_rule_callback=None):
        """Constructor.

        Args:
          project: The GCE project id the rules apply to.
          rules: A list of rule dicts to add to the object.
          add_rule_callback: A callback function that checks whether a firewall
            rule should be applied. If the callback returns False, that rule
            will not be modified.

        Raises:
          DuplicateFirewallRuleNameError: Two or more rules have the same name.
          InvalidFirewallRuleError: One or more rules failed validation.
        """
        self._project = project
        self.rules = {}
        self._add_rule_callback = add_rule_callback
        if rules:
            self.add_rules(rules)

    def __eq__(self, other):
        """Equality."""
        return self.rules == other.rules

    def __ne__(self, other):
        """Not Equal."""
        return self.rules != other.rules

    def add_rules_from_api(self, firewall_api):
        """Loads rules from compute.firewalls().list().

        Args:
          firewall_api: A ComputeFirewallAPI instance for interfacing with GCE
              API.

        Raises:
          DuplicateFirewallRuleNameError: Two rules have the same name.
          InvalidFirewallRuleError: A rule failed validation.
        """
        if self.rules:
            LOGGER.warn(
                'Can not import rules from the API into a FirewallRules '
                'object with rules already added')
            return

        page_token = ''
        while True:
            if page_token:
                response = firewall_api.list_firewalls(
                    self._project, page_token=page_token)
            else:
                response = firewall_api.list_firewalls(self._project)

            for item in response.get('items', []):
                rule = dict([(key, item[key]) for key in ALLOWED_RULE_ITEMS
                             if key in item])
                self.add_rule(rule)

            # Are there additional pages of data?
            if 'nextPageToken' in response:
                page_token = response['nextPageToken']
            else:
                break

    def add_rules(self, rules, network_name=None):
        """Adds rules from a list of rule dicts.

        Args:
          rules: A list of rule dicts to add to the object
          network_name: If set, rules which have no network currently defined
              will have their network set to network_name, and network_name will
              be prepended to the rule name.

              Rules that do have a network defined have their network matched
              against network_name, and if they differ the rule is not added.

        Raises:
          DuplicateFirewallRuleNameError: Two or more rules have the same name.
          InvalidFirewallRuleError: One or more rules failed validation.
        """
        for rule in rules:
            self.add_rule(rule, network_name=network_name)

    def add_rule(self, rule, network_name=None):
        """Adds rule to the self.rules dictionary.

        Args:
          rule: A valid dict representing a GCE firewall rule
          network_name: If set, rules which have no network currently defined
              will have their network set to network_name, and network_name will
              be prepended to the rule name.

              Rules that do have a network defined have their network matched
              against network_name, and if they differ the rule is not added.

        Raises:
          DuplicateFirewallRuleNameError: Two or more rules have the same name.
          InvalidFirewallRuleError: One or more rules failed validation.
        """
        if not isinstance(rule, dict):
            raise InvalidFirewallRuleError(
                'Invalid rule type. Found %s expected dict' % type(rule))

        new_rule = self._order_lists_in_rule(rule)

        if network_name:
            if 'network' in new_rule:
                rule_network = get_network_name_from_url(new_rule['network'])
                if rule_network != network_name:
                    # Don't add the rule if it's network does not match
                    # network_name
                    LOGGER.info('Firewall rule does not apply to network %s, '
                                'skipping: %s', rule_network,
                                json.dumps(new_rule))
                    return
            else:
                new_rule['network'] = build_network_url(self._project,
                                                        network_name)

                # Update the rule name by prepending the network, so it is
                # unique. If the new rule does not have a name defined it will
                # fail the _check_rule_before_adding validation and an
                # InvalidFirewallRuleError exception will be raised.
                if 'name' in new_rule:
                    # Truncate network name if too long. This may result in
                    # duplicate rule names, which will cause the network name
                    # to be changed to a md5 hash representation.
                    new_name = '%s-%s' % (
                        network_name[:(62 - len(new_rule['name']))],
                        new_rule['name'])

                    while new_name in self.rules:
                        # Firewall rule names must start with [a-z], hashes
                        # could start with a number, so we prepend hn-
                        # (hashed network) to the name.
                        network_name = 'hn-' + hashlib.md5(
                            network_name).hexdigest()
                        new_name = '%s-%s' % (
                            network_name[:(62 - len(new_rule['name']))],
                            new_rule['name'])

                    new_rule['name'] = new_name

        if 'priority' not in new_rule:
            new_rule['priority'] = self.DEFAULT_PRIORITY

        if 'direction' not in new_rule:
            new_rule['direction'] = self.DEFAULT_DIRECTION

        if self._check_rule_before_adding(new_rule):
            self.rules[new_rule['name']] = new_rule

    def filtered_by_networks(self, networks):
        """Returns the subset of rules that apply to the specified network(s).

        Args:
          networks: A list of one or more network names to fetch rules for.

        Returns:
          A dictionary of rules that apply to the filtered networks.
        """
        filtered_rules = {}
        for rule_name, rule in self.rules.items():
            if get_network_name_from_url(rule['network']) in networks:
                filtered_rules[rule_name] = rule

        return filtered_rules

    def as_json(self):
        """Export rules to a json string.

        The JSON string should be an array of Firewall resource objects, see
        https://cloud.google.com/compute/docs/reference/latest/firewalls
        for details. Only the fields in ALLOWED_RULE_ITEMS are permitted.

        Returns:
          A JSON string with an array of rules sorted by network and name.
        """
        rules = sorted(
            self.rules.values(), key=operator.itemgetter('network', 'name'))
        return json.dumps(rules, sort_keys=True)

    def add_rules_from_json(self, json_rules):
        """Import rules from a json string as exported by as_json.

        The JSON string should be an array of Firewall resource objects, see
        https://cloud.google.com/compute/docs/reference/latest/firewalls
        for details. Only the fields in ALLOWED_RULE_ITEMS are permitted.

        The legacy format from older versions of GCE Enforcer is also supported.
        This format wraps the array of Firewall resources in a dictionary under
        the key 'items'.

        Args:
          json_rules: The JSON formatted string containing the rules to import.

        Raises:
          DuplicateFirewallRuleNameError: Two or more rules have the same name.
          InvalidFirewallRuleError: One or more rules failed validation.
        """
        if self.rules:
            LOGGER.warn('Can not import from JSON into a FirewallRules object '
                        'with rules already added')
            return

        rules = json.loads(json_rules)
        if isinstance(rules, list):
            for rule in rules:
                self.add_rule(rule)

        elif isinstance(rules, dict):
            if 'items' in rules:
                for item in rules['items']:
                    rule = dict([(key, item[key]) for key in ALLOWED_RULE_ITEMS
                                 if key in item])
                    self.add_rule(rule)

    def _order_lists_in_rule(self, unsorted_rule):
        """Recursively iterates a rule dictionary and sorts any lists.

        This ensures that two rule with the same polices, but with unordered
        lists will compare equal when tested.

        Args:
          unsorted_rule: A rule dictionary that has not been sorted.

        Returns:
          A new rule dictionary with the lists sorted
        """
        sorted_rule = {}
        for key, value in unsorted_rule.items():
            if isinstance(value, list):
                if value and isinstance(value[0], dict):  # List of dictionaries
                    for i, entry in enumerate(value):
                        value[i] = self._order_lists_in_rule(entry)

                sorted_rule[key] = sorted(value)
            elif isinstance(value, dict):
                sorted_rule[key] = self._order_lists_in_rule(value)
            else:
                sorted_rule[key] = value
        return sorted_rule

    # TODO: clean up break up into additional methods
    # pylint: disable=too-many-branches
    def _check_rule_before_adding(self, rule):
        """Validates that a rule is valid and not a duplicate.

        Validation is based on reference:
        https://cloud.google.com/compute/docs/reference/beta/firewalls and
        https://cloud.google.com/compute/docs/vpc/firewalls#gcp_firewall_rule_summary_table
        If add_rule_callback is set, this will also confirm that
        add_rule_callback returns True for the rule, otherwise it will not add
        the rule.

        Args:
          rule: The rule to validate.

        Returns:
          True if rule is valid, False if the add_rule_callback returns False.

        Raises:
          DuplicateFirewallRuleNameError: Two or more rules have the same name.
          InvalidFirewallRuleError: One or more rules failed validation.
        """
        unknown_keys = set(rule.keys()) - ALLOWED_RULE_ITEMS
        if unknown_keys:
            # This is probably the result of a API version upgrade that didn't
            # properly update this function (or a broken binary).
            raise InvalidFirewallRuleError(
                'An unexpected entry exists in a firewall rule dict: "%s".' %
                ','.join(list(unknown_keys)))

        for key in ['name', 'network']:
            if key not in rule:
                raise InvalidFirewallRuleError(
                    'Rule missing required field "%s": "%s".' % (key, rule))

        if 'direction' not in rule or rule['direction'] == 'INGRESS':
            if 'sourceRanges' not in rule and 'sourceTags' not in rule:
                raise InvalidFirewallRuleError(
                    'Ingress rule missing required field oneof '
                    '"sourceRanges" or "sourceTags": "%s".' % rule)

            if 'destinationRanges' in rule:
                raise InvalidFirewallRuleError(
                    'Ingress rules cannot include "destinationRanges": "%s".'
                    % rule)

        elif rule['direction'] == 'EGRESS':
            if 'sourceRanges' in rule or 'sourceTags' in rule:
                raise InvalidFirewallRuleError(
                    'Egress rules cannot include "sourceRanges", "sourceTags":'
                    '"%s".' % rule)

            if 'destinationRanges' not in rule:
                raise InvalidFirewallRuleError(
                    'Egress rule missing required field "destinationRanges":'
                    '"%s".'% rule)

        else:
            raise InvalidFirewallRuleError(
                'Rule "direction" must be either "INGRESS" or "EGRESS": "%s".'
                % rule)

        max_256_value_keys = set(
            ['sourceRanges', 'sourceTags', 'targetTags', 'destinationRanges'])
        for key in max_256_value_keys:
            if key in rule and len(rule[key]) > 256:
                raise InvalidFirewallRuleError(
                    'Rule entry "%s" must contain 256 or fewer values: "%s".'
                    % (key, rule))

        if (('allowed' not in rule and 'denied' not in rule) or
                ('allowed' in rule and 'denied' in rule)):
            raise InvalidFirewallRuleError(
                'Rule must contain oneof "allowed" or "denied" entries: '
                ' "%s".' % rule)

        if 'allowed' in rule:
            for allow in rule['allowed']:
                if 'IPProtocol' not in allow:
                    raise InvalidFirewallRuleError(
                        'Allow rule in %s missing required field '
                        '"IPProtocol": "%s".' % (rule['name'], allow))

        elif 'denied' in rule:
            for deny in rule['denied']:
                if 'IPProtocol' not in deny:
                    raise InvalidFirewallRuleError(
                        'Deny rule in %s missing required field '
                        '"IPProtocol": "%s".' % (rule['name'], deny))

        if 'priority' in rule:
            try:
                priority = int(rule['priority'])
            except ValueError:
                raise InvalidFirewallRuleError(
                    'Rule "priority" could not be converted to an integer: '
                    '"%s".' % rule)
            if priority < 0 or priority > 65535:
                raise InvalidFirewallRuleError(
                    'Rule "priority" out of range 0-65535: "%s".' % rule)

        if len(rule['name']) > 63:
            raise InvalidFirewallRuleError(
                'Rule name exceeds length limit of 63 chars: "%s".' %
                rule['name'])

        # TODO: Verify rule name matches regex of allowed
        # names from reference

        if rule['name'] in self.rules:
            raise DuplicateFirewallRuleNameError(
                'Rule %s already defined in rules: %s' %
                (rule['name'], ', '.join(sorted(self.rules.keys()))))

        if self._add_rule_callback:
            if not self._add_rule_callback(rule):
                return False

        return True
    # pylint: enable=too-many-branches

# pylint: disable=too-many-instance-attributes
# TODO: Investigate improving so we can avoid the pylint disable.
class FirewallEnforcer(object):
    """Enforce a set of firewall rules for use with GCE projects."""

    def __init__(self,
                 project,
                 firewall_api,
                 expected_rules,
                 current_rules=None,
                 project_sema=None,
                 operation_sema=None,
                 add_rule_callback=None):
        """Constructor.

        Args:
          project: The id of the cloud project to enforce the firewall on.
          firewall_api: A ComputeFirewallAPI instance for interfacing with GCE
              API.
          expected_rules: A FirewallRules object with the expected rules to be
              enforced on the project.
          current_rules: A FirewallRules object with the current rules for the
              project. If not defined, the API will be queried and the existing
              rules imported into current_rules when apply_firewall is called
              for the project.
          project_sema: An optional semaphore object, used to limit the number
              of concurrent projects getting written to.
          operation_sema: An optional semaphore object, used to limit the number
              of concurrent write operations on project firewalls.
          add_rule_callback: A callback function that checks whether a firewall
              rule should be applied. If the callback returns False, that rule
              will not be modified.
        """
        self.project = project
        self.firewall_api = firewall_api
        self.expected_rules = expected_rules

        if current_rules:
            self.current_rules = current_rules
        else:
            self.current_rules = None

        self.project_sema = project_sema
        self.operation_sema = operation_sema

        self._add_rule_callback = add_rule_callback

        # Initialize private parameters
        self._rules_to_delete = []
        self._rules_to_insert = []
        self._rules_to_update = []

        self._deleted_rules = []
        self._inserted_rules = []
        self._updated_rules = []

    def apply_firewall(self,
                       prechange_callback=None,
                       networks=None,
                       allow_empty_ruleset=False):
        """Enforce the expected firewall rules on the project.

        Args:
          prechange_callback: An optional callback function that will get called
              if the firewall policy for a project does not match the expected
              policy, before any changes are actually applied. If the callback
              returns False then no changes will be made to the project. If it
              returns True then the changes will be pushed. If
              prechange_callback is set to None then the callback will be
              skipped and enforcement will continue as though it had returned
              True.

              The callback template is callback_func(project,
                                                     rules_to_delete,
                                                     rules_to_insert,
                                                     rules_to_update)

              The callback may be used to limit the kinds of firewall changes
              that are allowed to be pushed for a project, limit the number of
              rules that can get changed, to check if the project should have
              rules changed, etc.

              The callback may also raise FirewallEnforcementFailedError if it
              determines that the set of changes to the policy could result in
              an outage for an underlying service, or otherwise are inconsistent
              with business rules. This will cause the enforcement to fail.

          networks: A list of networks to limit rule changes to. Rules on
              networks not in the list will not be changed.

              Note- This can lead to duplicate rule name collisions since all
                    rules are not included when building the change set. The
                    change set will be validated before getting enforced and any
                    errors will cause a FirewallEnforcementFailedError exception
                    to be raised.

          allow_empty_ruleset: If set to true and expected_rules has no rules,
              all current firewall rules will be deleted from the project.

        Returns:
          The total number of firewall rules deleted, inserted and updated.

        Raises:
          EmptyProposedFirewallRuleSetError: An error occurred while updating
              the firewall. The calling code should validate the current state
              of the project firewall, and potentially revert to the old
              firewall rules.

              Any rules changed before the error occured can be retrieved by
              calling the Get(Deleted|Inserted|Updated)Rules methods.
        """
        # Reset change sets to empty lists
        self._rules_to_delete = []
        self._rules_to_insert = []
        self._rules_to_update = []

        if not self.current_rules:
            self.refresh_current_rules()

        if not self.expected_rules.rules and not allow_empty_ruleset:
            raise EmptyProposedFirewallRuleSetError(
                'No rules defined in the expected rules.')

        # Check if current rules match expected rules, so no changes are needed
        if networks:
            if (self.current_rules.filtered_by_networks(networks) ==
                    self.expected_rules.filtered_by_networks(networks)):
                LOGGER.info(
                    'Current and expected rules match for project %s on '
                    'network(s) "%s".', self.project, ','.join(networks))
                return 0
        elif self.current_rules == self.expected_rules:
            LOGGER.info('Current and expected rules match for project %s.',
                        self.project)
            return 0

        self._build_change_set(networks)
        self._validate_change_set(networks)
        delete_before_insert = self._check_change_operation_order(
            len(self._rules_to_insert), len(self._rules_to_delete))

        if self.project_sema:
            self.project_sema.acquire()

        try:
            if prechange_callback:
                if not prechange_callback(self.project, self._rules_to_delete,
                                          self._rules_to_insert,
                                          self._rules_to_update):
                    LOGGER.warn(
                        'The Prechange Callback returned False for project %s, '
                        'changes will not be applied.', self.project)
                    return 0
            changed_count = self._apply_change_set(delete_before_insert)
        finally:
            if self.project_sema:
                self.project_sema.release()

        return changed_count

    def refresh_current_rules(self):
        """Updates the current rules for the project using the compute API."""
        current_rules = FirewallRules(self.project,
                                      add_rule_callback=self._add_rule_callback)
        current_rules.add_rules_from_api(self.firewall_api)

        self.current_rules = current_rules

    def get_deleted_rules(self):
        """Returns the list of deleted rules."""
        return self._deleted_rules

    def get_inserted_rules(self):
        """Returns the list of inserted rules."""
        return self._inserted_rules

    def get_updated_rules(self):
        """Returns the list of updated rules."""
        return self._updated_rules

    def _build_change_set(self, networks=None):
        """Enumerate changes between the current and expected firewall rules."""
        if networks:
            # Build new firewall rules objects from the subset of rules for
            # networks
            current_rules = self.current_rules.filtered_by_networks(networks)
            expected_rules = self.expected_rules.filtered_by_networks(networks)
        else:
            current_rules = self.current_rules.rules
            expected_rules = self.expected_rules.rules

        for rule_name in current_rules:
            if rule_name not in expected_rules:
                self._rules_to_delete.append(rule_name)

        for rule_name in expected_rules:
            if rule_name not in current_rules:
                self._rules_to_insert.append(rule_name)

        for rule_name in expected_rules:
            if rule_name in current_rules:
                if expected_rules[rule_name] != current_rules[rule_name]:
                    self._rules_to_update.append(rule_name)

    def _validate_change_set(self, networks=None):
        """Validate the changeset will not leave the project in a bad state."""
        for rule_name in self._rules_to_insert:
            if (rule_name in self.current_rules.rules and
                    rule_name not in self._rules_to_delete):
                raise FirewallRuleValidationError(
                    'The rule %s is in the rules to insert set, but the same '
                    'rule name already exists on project %s. It may be used on '
                    'a different network.' % (rule_name, self.project))

        if networks:
            for rule_name in self._rules_to_update:
                impacted_network = get_network_name_from_url(
                    self.current_rules.rules[rule_name]['network'])
                if impacted_network not in networks:
                    raise NetworkImpactValidationError(
                        'The rule %s is in the rules to update set, but it is '
                        'currently on a network, "%s", that is not in the '
                        'allowed networks list for project %s: "%s". Updating '
                        'the rule to %s would impact the wrong network.' %
                        (rule_name, impacted_network, self.project,
                         ', '.join(networks),
                         self.expected_rules.rules[rule_name]))

    def _check_change_operation_order(self, insert_count, delete_count):
        """Check if enough quota to do the firewall changes insert first.

        If current usage is near the limit, check if deleting current rules
        before adding the new rules would allow the project to stay below quota.

        Args:
          insert_count: The number of rules that will be inserted.
          delete_count: The number of rules that will be deleted.

        Returns:
          True if existing rules should be deleted before new rules are
          inserted, otherwise false.

        Raises:
          FirewallQuotaExceededError: Raised if there is not enough quota for
          the required policy to be applied.
        """
        delete_before_insert = False

        firewalls_quota = self.firewall_api.get_firewalls_quota(self.project)
        if firewalls_quota:
            usage = firewalls_quota.get('usage', 0)
            limit = firewalls_quota.get('limit', 0)
            if usage + insert_count > limit:
                if usage - delete_count + insert_count > limit:
                    raise FirewallQuotaExceededError(
                        'Firewall enforcement cannot update the policy for '
                        'project %s without exceed the current firewalls '
                        'quota: %u,' %(self.project, limit))
                else:
                    LOGGER.info('Switching to "delete first" rule update order '
                                'for project %s.', self.project)
                    delete_before_insert = True
        else:
            LOGGER.warn('Unknown firewall quota, switching to "delete first" '
                        'rule update order for project %s.', self.project)
            delete_before_insert = True

        return delete_before_insert

    def _apply_change_set(self, delete_before_insert):
        """Updates project firewall rules based on the generated changeset.

           Extends self._(deleted|inserted|updated)_rules with the rules
           changed by these operations.

        Args:
          delete_before_insert: If true, delete operations are completed before
          inserts. Otherwise insert operations are completed first.

        Returns:
          The total number of firewall rules deleted, inserted and updated.

        Raises:
          FirewallEnforcementFailedError: Raised if one or more changes fails.
        """
        change_count = 0
        if delete_before_insert:
            change_count += self._delete_rules()
            change_count += self._insert_rules()
        else:
            change_count += self._insert_rules()
            change_count += self._delete_rules()

        change_count += self._update_rules()
        return change_count

    def _insert_rules(self):
        """Insert new rules into the project firewall."""
        change_count = 0
        if self._rules_to_insert:
            LOGGER.info('Inserting rules: %s', ', '.join(self._rules_to_insert))
            rules = [
                self.expected_rules.rules[rule_name]
                for rule_name in self._rules_to_insert
            ]
            insert_function = self.firewall_api.insert_firewall_rule
            (successes, failures, change_errors) = self._apply_change(
                insert_function, rules)
            self._inserted_rules.extend(successes)
            change_count += len(successes)
            if failures:
                raise FirewallEnforcementInsertFailedError(
                    'Firewall enforcement failed while inserting rules for '
                    'project {}. The following errors were encountered: {}'
                    .format(self.project, change_errors))

        return change_count

    def _delete_rules(self):
        """Delete old rules from the project firewall."""
        change_count = 0
        if self._rules_to_delete:
            LOGGER.info('Deleting rules: %s', ', '.join(self._rules_to_delete))
            rules = [
                self.current_rules.rules[rule_name]
                for rule_name in self._rules_to_delete
            ]
            delete_function = self.firewall_api.delete_firewall_rule
            (successes, failures, change_errors) = self._apply_change(
                delete_function, rules)
            self._deleted_rules.extend(successes)
            change_count += len(successes)
            if failures:
                raise FirewallEnforcementDeleteFailedError(
                    'Firewall enforcement failed while deleting rules for '
                    'project {}. The following errors were encountered: {}'
                    .format(self.project, change_errors))
        return change_count

    def _update_rules(self):
        """Update existing rules in the project firewall."""
        change_count = 0
        if self._rules_to_update:
            LOGGER.info('Updating rules: %s', ', '.join(self._rules_to_update))
            rules = [
                self.expected_rules.rules[rule_name]
                for rule_name in self._rules_to_update
            ]
            update_function = self.firewall_api.update_firewall_rule
            (successes, failures, change_errors) = self._apply_change(
                update_function, rules)
            self._updated_rules.extend(successes)
            change_count += len(successes)
            if failures:
                raise FirewallEnforcementUpdateFailedError(
                    'Firewall enforcement failed while deleting rules for '
                    'project {}. The following errors were encountered: {}'
                    .format(self.project, change_errors))

        return change_count

    # pylint: disable=too-many-statements,too-many-branches,too-many-locals
    # TODO: Look at not having some of these disables.
    def _apply_change(self, firewall_function, rules):
        """Modify the firewall using the passed in function and rules.

        If self.operation_sema is defined, then the number of outstanding
        changes is limited to the number of semaphore locks that can be
        acquired.

        Args:
          firewall_function: The delete|insert|update function to call for this
              set of rules
          rules: A list of rules to pass to the firewall_function.

        Returns:
          A tuple with the rules successfully changed by this function and the
          rules that failed.
        """
        applied_rules = []
        failed_rules = []
        change_errors = []
        if not rules:
            return (applied_rules, failed_rules, change_errors)

        successes = []
        failures = []
        running_operations = []
        finished_operations = []
        operations = {}
        for rule in rules:
            if self.operation_sema:
                if not self.operation_sema.acquire(False):  # Non-blocking
                    # No semaphore available, wait for one or more ops to
                    # complete.
                    if running_operations:
                        (completed, running_operations) = (
                            self.firewall_api.wait_for_any_to_complete(
                                self.project, running_operations,
                                OPERATION_TIMEOUT))
                        finished_operations.extend(completed)
                        for response in completed:
                            self.operation_sema.release()

                    self.operation_sema.acquire(True)  # Blocking

            try:
                response = firewall_function(self.project, rule)
            except errors.HttpError as e:
                LOGGER.error(
                    'Error changing firewall rule %s for project %s: %s',
                    rule.get('name', ''), self.project, e)
                error_str = 'Rule: %s\nError: %s' % (rule.get('name', ''), e)
                change_errors.append(error_str)
                failed_rules.append(rule)
                if self.operation_sema:
                    self.operation_sema.release()
                continue

            if 'name' in response:
                operations[response['name']] = rule
                running_operations.append(response)
            else:
                LOGGER.error('The response object returned by %r(%s, %s) is '
                             'invalid. It does not contain a "name" key: %s',
                             firewall_function, self.project,
                             json.dumps(rule), json.dumps(response))
                failed_rules.append(rule)
                if self.operation_sema:
                    self.operation_sema.release()

        responses = self.firewall_api.wait_for_all_to_complete(
            self.project, running_operations, OPERATION_TIMEOUT)
        finished_operations.extend(responses)

        if self.operation_sema:
            for response in responses:
                self.operation_sema.release()

        for response in finished_operations:
            if self.firewall_api.is_successful(response):
                successes.append(response)
            else:
                failures.append(response)

        for result in successes:
            operation_name = result.get('name', '')
            if operation_name in operations:
                applied_rules.append(operations[operation_name])
            else:
                LOGGER.warn(
                    'Successful result contained an unknown operation name, '
                    '"%s": %s', operation_name, json.dumps(result))

        for result in failures:
            operation_name = result.get('name', '')
            if operation_name in operations:
                LOGGER.error(
                    'The firewall rule %s for project %s received the '
                    'following error response during the last operation: %s',
                    operations[operation_name], self.project,
                    json.dumps(result))
                failed_rules.append(operations[operation_name])
            else:
                LOGGER.warn(
                    'Failure result contained an unknown operation name, '
                    '"%s": %s', operation_name, json.dumps(result))

        return (applied_rules, failed_rules, change_errors)
