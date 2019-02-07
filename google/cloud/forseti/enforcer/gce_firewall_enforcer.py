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
"""Core classes for firewall policy enforcement.

Simplifies the interface with the compute API for managing firewall policies.
"""
import hashlib
import httplib
import json
import operator
import socket
import ssl

import httplib2
from google.cloud.forseti.common.gcp_api import errors as api_errors
from google.cloud.forseti.common.util import logger

# The name of the GCE API.
API_NAME = 'compute'

# The root of the GCE API.
API_ROOT = 'https://www.googleapis.com/'

# The version of the GCE API to use.
API_VERSION = 'v1'

LOGGER = logger.get_logger(__name__)

# What transient exceptions should be retried.
RETRY_EXCEPTIONS = (httplib.ResponseNotReady, httplib.IncompleteRead,
                    httplib2.ServerNotFoundError, socket.error, ssl.SSLError,)

# Allowed items in a firewall rule.
ALLOWED_RULE_ITEMS = frozenset(('allowed', 'denied', 'description', 'direction',
                                'disabled', 'logConfig', 'name', 'network',
                                'priority', 'sourceRanges', 'destinationRanges',
                                'sourceTags', 'targetTags'))

# Maximum time to allow an active API operation to wait for status=Done
OPERATION_TIMEOUT = 120.0

# The number of times to retry an operation if it times out before completion.
OPERATION_RETRY_COUNT = 5


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


def get_network_name_from_url(network_url):
    """Given a network URL, return the name of the network.

    Args:
        network_url (str): The fully qualified network url, such as
            ('<root>/compute/v1/projects/my-proj/global/networks/my-network')

    Returns:
        str: The network name, my-network in the previous example
    """
    return network_url.split('/')[-1]


def build_network_url(project, network):
    """Render the network url from project and network names.

    Args:
        project (str): The name of the GCE project to operate upon.
        network (str): The name of the network to operate upon.

    Returns:
        str: The fully qualified network url for the given project/network.
    """
    return (u'%(root)s%(api_name)s/%(version)s/projects/%(project)s/global/'
            'networks/%(network)s') % {'api_name': API_NAME,
                                       'network': network,
                                       'project': project,
                                       'root': API_ROOT,
                                       'version': API_VERSION}


def _is_successful(operation):
    """Checks if the operation finished with no errors.

    If the operation response contains an 'error' key, then the error code
    is checked. Any error code that is not ignored causes this to return
    False.

    Args:
        operation (dict): A Compute GlobalOperations response object from an API
            call.

    Returns:
        bool: True if there were no errors, or all errors are ignored, otherwise
            False.
    """
    success = True
    if 'error' in operation:
        # 'error' should always contains an 'errors' list:
        if 'errors' in operation['error']:
            for err in operation['error']['errors']:
                # We ignore the following errors:
                # RESOURCE_ALREADY_EXISTS: Because another program somewhere
                #     else could have already added the rule.
                # INVALID_FIELD_VALUE: Because the network probably
                #     disappeared out from under us.
                if err.get('code') in ['RESOURCE_ALREADY_EXISTS',
                                       'INVALID_FIELD_VALUE']:
                    LOGGER.warn('Ignoring error: %s', err)
                else:
                    LOGGER.error('Operation has error: %s', err)
                    success = False
        else:
            LOGGER.error('Unknown error response: %s', operation['error'])
            success = False
    return success


def filter_rules_by_network(rules, network):
    """Returns the subset of rules that apply to the specified network(s).

    Args:
        rules (list): A list of rule dicts to filter.
        network (str): The network name to restrict rules to. If no network
            specified then all rules are returned.

    Returns:
        list: A list of rules that apply to the filtered networks.
    """
    if not network:
        return rules

    filtered_rules = []
    for rule in rules:
        if get_network_name_from_url(rule['network']) == network:
            filtered_rules.append(rule)

    return filtered_rules


class FirewallRules(object):
    """A collection of validated firewall rules."""

    DEFAULT_PRIORITY = 1000
    DEFAULT_DIRECTION = 'INGRESS'
    DEFAULT_DISABLED = False
    DEFAULT_LOGCONFIG = {'enable': False}

    def __init__(self, project, rules=None, add_rule_callback=None):
        """Constructor.

        Args:
            project (str): The GCE project id the rules apply to.
            rules (list): A list of rule dicts to add to the object.
            add_rule_callback (function): A callback function that checks
                whether a firewall rule should be applied. If the callback
                returns False, that rule will not be modified.

        Raises:
            DuplicateFirewallRuleNameError: Two or more rules have the same
                name.
            InvalidFirewallRuleError: One or more rules failed validation.
        """
        self._project = project
        self.rules = {}
        self._add_rule_callback = add_rule_callback
        if rules:
            self.add_rules(rules)

    def __eq__(self, other):
        """Equality.

        Args:
            other (FirewallRules): The other object to compare with.

        Returns:
            bool: True if equal, else false.
        """
        return self.rules == other.rules

    def __ne__(self, other):
        """Not Equal.

        Args:
            other (FirewallRules): The other object to compare with.

        Returns:
            bool: True if not equal, else false.
        """
        return self.rules != other.rules

    def add_rules_from_api(self, compute_client):
        """Loads rules from compute.firewalls().list().

        Args:
          compute_client (object): A ComputeClient instance for interfacing with
              GCE API.

        Raises:
            DuplicateFirewallRuleNameError: Two or more rules have the same
                name.
            InvalidFirewallRuleError: One or more rules failed validation.
        """
        if self.rules:
            LOGGER.warn(
                'Can not import rules from the API into a FirewallRules '
                'object with rules already added')
            return

        firewall_rules = compute_client.get_firewall_rules(self._project)
        for rule in firewall_rules:
            # Only include keys in the ALLOWED_RULE_ITEMS set.
            scrubbed_rule = dict(
                [(k, v) for k, v in rule.items() if k in ALLOWED_RULE_ITEMS])
            self.add_rule(scrubbed_rule)

    def add_rules(self, rules, network_name=None):
        """Adds rules from a list of rule dicts.

        Args:
            rules (list): A list of rule dicts to add to the object
            network_name (str): If set, rules which have no network currently
                defined will have their network set to network_name, and
                network_name will be prepended to the rule name.

                Rules that do have a network defined have their network matched
                against network_name, and if they differ the rule is not added.

        Raises:
            DuplicateFirewallRuleNameError: Two or more rules have the same
                name.
            InvalidFirewallRuleError: One or more rules failed validation.
        """
        for rule in rules:
            self.add_rule(rule, network_name=network_name)

    def add_rule(self, rule, network_name=None):
        """Adds rule to the self.rules dictionary.

        Args:
            rule (dict): A valid dict representing a GCE firewall rule
            network_name (str): If set, rules which have no network currently
                defined will have their network set to network_name, and
                network_name will be prepended to the rule name.

                Rules that do have a network defined have their network matched
                against network_name, and if they differ the rule is not added.

        Raises:
            DuplicateFirewallRuleNameError: Two or more rules have the same
                name.
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
                                json.dumps(new_rule, sort_keys=True))
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

        if 'logConfig' not in new_rule:
            new_rule['logConfig'] = self.DEFAULT_LOGCONFIG

        if 'disabled' not in new_rule:
            new_rule['disabled'] = self.DEFAULT_DISABLED

        if self._check_rule_before_adding(new_rule):
            self.rules[new_rule['name']] = new_rule

    def filtered_by_networks(self, networks):
        """Returns the subset of rules that apply to the specified network(s).

        Args:
            networks (list): A list of one or more network names to fetch rules
                for.

        Returns:
            dict: A dictionary of rules that apply to the filtered networks.
        """
        if not networks:
            return self.rules

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
            str: A JSON string with an array of rules sorted by network and
                name.
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
          json_rules (str): The JSON formatted string containing the rules to
              import.

        Raises:
            DuplicateFirewallRuleNameError: Two or more rules have the same
                name.
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
            unsorted_rule (dict): A rule dictionary that has not been sorted.

        Returns:
            dict: A new rule dictionary with the lists sorted
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
            rule (dict): The rule to validate.

        Returns:
            bool: True if rule is valid, False if the add_rule_callback returns
                False.

        Raises:
            DuplicateFirewallRuleNameError: Two or more rules have the same
                name.
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
            if 'destinationRanges' in rule:
                raise InvalidFirewallRuleError(
                    'Ingress rules cannot include "destinationRanges": "%s".'
                    % rule)

        elif rule['direction'] == 'EGRESS':
            if 'sourceRanges' in rule or 'sourceTags' in rule:
                raise InvalidFirewallRuleError(
                    'Egress rules cannot include "sourceRanges", "sourceTags":'
                    '"%s".' % rule)

        else:
            raise InvalidFirewallRuleError(
                'Rule "direction" must be either "INGRESS" or "EGRESS": "%s".'
                % rule)

        max_256_value_keys = {'sourceRanges', 'sourceTags', 'targetTags',
                              'destinationRanges'}
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
                 compute_client,
                 expected_rules,
                 current_rules=None,
                 project_sema=None,
                 operation_sema=None,
                 add_rule_callback=None):
        """Constructor.

        Args:
            project (str): The id of the cloud project to enforce the firewall
                on.
            compute_client (object): A ComputeClient instance for interfacing
                with GCE API.
            expected_rules (object): A FirewallRules object with the expected
                rules to be enforced on the project.
            current_rules (object): A FirewallRules object with the current
                rules for the project. If not defined, the API will be queried
                and the existing rules imported into current_rules when
                apply_firewall is called for the project.
            project_sema (object): An optional semaphore object, used to limit
                the number of concurrent projects getting written to.
            operation_sema (object): [DEPRECATED] An optional semaphore object,
                used to limit the number of concurrent write operations on
                project firewalls.
            add_rule_callback (function): A callback function that checks
                whether a firewall rule should be applied. If the callback
                returns False, that rule will not be modified.
        """
        self.project = project
        self.compute_client = compute_client
        self.expected_rules = expected_rules

        if current_rules:
            self.current_rules = current_rules
        else:
            self.current_rules = None

        self.project_sema = project_sema
        if operation_sema:
            LOGGER.warn(
                'Operation semaphore is deprecated. Argument ignored.')
        self.operation_sema = None

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
            prechange_callback (function): An optional callback function that
                will get called if the firewall policy for a project does not
                match the expected policy, before any changes are actually
                applied. If the callback returns False then no changes will be
                made to the project. If it returns True then the changes will be
                pushed. If prechange_callback is set to None then the callback
                will be skipped and enforcement will continue as though it had
                returned True.

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
                an outage for an underlying service, or otherwise are
                inconsistent with business rules. This will cause the
                enforcement to fail.

            networks (list): A list of networks to limit rule changes to. Rules
                on networks not in the list will not be changed.

                Note- This can lead to duplicate rule name collisions since all
                      rules are not included when building the change set. The
                      change set will be validated before getting enforced and
                      any errors will cause a FirewallEnforcementFailedError
                      exception to be raised.

            allow_empty_ruleset (booL): If set to true and expected_rules has no
                rules, all current firewall rules will be deleted from the
                project.

        Returns:
            int: The total number of firewall rules deleted, inserted and
                updated.

        Raises:
            EmptyProposedFirewallRuleSetError: An error occurred while updating
                the firewall. The calling code should validate the current state
                of the project firewall, and potentially revert to the old
                firewall rules.

                Any rules changed before the error occurred can be retrieved by
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

        if (self.current_rules.filtered_by_networks(networks) ==
                self.expected_rules.filtered_by_networks(networks)):
            LOGGER.info(
                'Current and expected rules match for project %s.',
                self.project)
            return 0

        self._build_change_set(networks)
        self._validate_change_set(networks)
        if prechange_callback:
            if not prechange_callback(self.project, self._rules_to_delete,
                                      self._rules_to_insert,
                                      self._rules_to_update):
                LOGGER.warn(
                    'The Prechange Callback returned False for project %s, '
                    'changes will not be applied.', self.project)
                return 0

        if self.project_sema:
            self.project_sema.acquire()

        try:
            delete_before_insert = self._check_change_operation_order(
                len(self._rules_to_insert), len(self._rules_to_delete))
            changed_count = 0
            if not networks:
                networks = [None]  # Default to all networks
            for network in networks:
                changed_count += self._apply_change_set(
                    delete_before_insert, network)
        finally:
            if self.project_sema:
                self.project_sema.release()

        return changed_count

    def refresh_current_rules(self):
        """Updates the current rules for the project using the compute API."""
        current_rules = FirewallRules(self.project,
                                      add_rule_callback=self._add_rule_callback)
        current_rules.add_rules_from_api(self.compute_client)

        self.current_rules = current_rules

    def get_deleted_rules(self):
        """Returns the list of deleted rules.

        Returns:
            list: The list of deleted rules.
        """
        return self._deleted_rules

    def get_inserted_rules(self):
        """Returns the list of inserted rules.

        Returns:
            list: The list of inserted rules.
        """
        return self._inserted_rules

    def get_updated_rules(self):
        """Returns the list of updated rules.

        Returns:
            list: The list of updated rules.
        """
        return self._updated_rules

    def _build_change_set(self, networks=None):
        """Enumerate changes between the current and expected firewall rules.

        Args:
            networks (list): The network names to restrict rules to. If no
                networks specified then all rules are returned.
        """
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
        """Validate the changeset will not leave the project in a bad state.

        Args:
            networks (list): The network names to restrict rules to. If no
                networks specified then all rules are returned.

        Raises:
            FirewallRuleValidationError: Raised if a rule name to be inserted
                already exists on the project.

            NetworkImpactValidationError: Raised if a rule to be changed exists
                on a network not in the networks list.
        """
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
            insert_count (int): The number of rules that will be inserted.
            delete_count (int): The number of rules that will be deleted.

        Returns:
            bool: True if existing rules should be deleted before new rules are
              inserted, otherwise false.

        Raises:
            FirewallQuotaExceededError: Raised if there is not enough quota for
                the required policy to be applied.
        """
        delete_before_insert = False

        try:
            firewall_quota = self.compute_client.get_firewall_quota(
                self.project)
        except KeyError as e:
            LOGGER.error('Error getting quota for project %s, %s',
                         self.project,
                         e)
            firewall_quota = None

        if firewall_quota:
            usage = firewall_quota.get('usage', 0)
            limit = firewall_quota.get('limit', 0)
            if usage + insert_count > limit:
                if usage - delete_count + insert_count > limit:
                    raise FirewallQuotaExceededError(
                        'Firewall enforcement cannot update the policy for '
                        'project %s without exceed the current firewalls '
                        'quota: %u,' % (self.project, limit))
                else:
                    LOGGER.info('Switching to "delete first" rule update order '
                                'for project %s.', self.project)
                    delete_before_insert = True
        else:
            LOGGER.warn('Unknown firewall quota, switching to "delete first" '
                        'rule update order for project %s.', self.project)
            delete_before_insert = True

        return delete_before_insert

    def _apply_change_set(self, delete_before_insert, network):
        """Updates project firewall rules based on the generated changeset.

        Extends self._(deleted|inserted|updated)_rules with the rules changed by
        these operations.

        Args:
            delete_before_insert (bool): If true, delete operations are
                completed before inserts. Otherwise insert operations are
                completed first.
            network (str): The network to limit rule changes to. Rules on
                other networks will not be changed. If not set, then all rules
                are in the change set are applied.

        Returns:
            int: The total number of firewall rules deleted, inserted and
                updated.
        """
        change_count = 0
        if delete_before_insert:
            change_count += self._delete_rules(network)
            change_count += self._insert_rules(network)
        else:
            change_count += self._insert_rules(network)
            change_count += self._delete_rules(network)

        change_count += self._update_rules(network)
        return change_count

    def _insert_rules(self, network):
        """Insert new rules into the project firewall.

        Args:
            network (str): The network name to restrict rules to. If no network
                specified then all new rules are inserted.

        Returns:
            int: The count of rules inserted.

        Raises:
            FirewallEnforcementInsertFailedError: Raised if one or more changes
                fails.
        """
        change_count = 0
        if self._rules_to_insert:
            LOGGER.info('Inserting rules: %s', ', '.join(self._rules_to_insert))
            rules = filter_rules_by_network([
                self.expected_rules.rules[rule_name]
                for rule_name in self._rules_to_insert
            ], network)
            insert_function = self.compute_client.insert_firewall_rule
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

    def _delete_rules(self, network):
        """Delete old rules from the project firewall.

        Args:
            network (str): The network name to restrict rules to. If no network
                specified then all unexpected rules are deleted.

        Returns:
            int: The count of rules deleted.

        Raises:
            FirewallEnforcementDeleteFailedError: Raised if one or more changes
                fails.
        """
        change_count = 0
        if self._rules_to_delete:
            LOGGER.info('Deleting rules: %s', ', '.join(self._rules_to_delete))
            rules = filter_rules_by_network([
                self.current_rules.rules[rule_name]
                for rule_name in self._rules_to_delete
            ], network)
            delete_function = self.compute_client.delete_firewall_rule
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

    def _update_rules(self, network):
        """Update existing rules in the project firewall using patch.

        Args:
            network (str): The network name to restrict rules to. If no network
                specified then all changed rules are updated.

        Returns:
            int: The count of rules updated.

        Raises:
            FirewallEnforcementUpdateFailedError: Raised if one or more changes
                fails.
        """
        change_count = 0
        if self._rules_to_update:
            LOGGER.info('Updating rules: %s', ', '.join(self._rules_to_update))
            rules = filter_rules_by_network([
                self.expected_rules.rules[rule_name]
                for rule_name in self._rules_to_update
            ], network)
            patch_function = self.compute_client.patch_firewall_rule
            (successes, failures, change_errors) = self._apply_change(
                patch_function, rules)
            self._updated_rules.extend(successes)
            change_count += len(successes)
            if failures:
                raise FirewallEnforcementUpdateFailedError(
                    'Firewall enforcement failed while deleting rules for '
                    'project {}. The following errors were encountered: {}'
                    .format(self.project, change_errors))

        return change_count

    def _apply_change(self, firewall_function, rules):
        """Modify the firewall using the passed in function and rules.

        If self.operation_sema is defined, then the number of outstanding
        changes is limited to the number of semaphore locks that can be
        acquired.

        Args:
            firewall_function (function): The delete|insert|update function to
                call for this set of rules
            rules (list): A list of rules to pass to the firewall_function.

        Returns:
            tuple: A tuple with the rules successfully changed by this function
                and the rules that failed.
        """
        applied_rules = []
        failed_rules = []
        change_errors = []
        if not rules:
            return applied_rules, failed_rules, change_errors

        for rule in rules:
            try:
                response = firewall_function(self.project,
                                             rule,
                                             blocking=True,
                                             retry_count=OPERATION_RETRY_COUNT,
                                             timeout=OPERATION_TIMEOUT)
            except (api_errors.ApiNotEnabledError,
                    api_errors.ApiExecutionError) as e:
                LOGGER.exception(
                    'Error changing firewall rule %s for project %s: %s',
                    rule.get('name', ''), self.project, e)

                error_str = 'Rule: %s\nError: %s' % (rule.get('name', ''), e)
                change_errors.append(error_str)
                failed_rules.append(rule)
                continue
            except api_errors.OperationTimeoutError as e:
                LOGGER.exception(
                    'Timeout changing firewall rule %s for project %s: %s',
                    rule.get('name', ''), self.project, e)
                error_str = 'Rule: %s\nError: %s' % (rule.get('name', ''), e)
                change_errors.append(error_str)
                failed_rules.append(rule)
                continue

            if _is_successful(response):
                applied_rules.append(rule)
            else:
                failed_rules.append(rule)

        return applied_rules, failed_rules, change_errors
