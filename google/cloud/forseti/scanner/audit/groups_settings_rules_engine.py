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
"""Rules engine for checking crypto keys configuration."""

from collections import namedtuple
import datetime
import threading

from google.cloud.forseti.common.gcp_type import resource
from google.cloud.forseti.common.gcp_type import resource_util
from google.cloud.forseti.common.util import logger, date_time, string_formats
from google.cloud.forseti.scanner.audit import base_rules_engine as bre
from google.cloud.forseti.scanner.audit import errors as audit_errors

LOGGER = logger.get_logger(__name__)

VIOLATION_TYPE = 'GSUITE_GROUPS_SETTINGS_VIOLATION'

# Rule Modes.
WHITELIST = 'whitelist'
BLACKLIST = 'blacklist'
REQUIRED = 'required'
RULE_MODES = frozenset([BLACKLIST, WHITELIST])


class GroupsSettingsRulesEngine(bre.BaseRulesEngine):
    """Rules engine for Groups Settings scanner."""

    def __init__(self, rules_file_path, snapshot_timestamp=None):
        """Initialize.

        Args:
            rules_file_path (str): file location of rules
            snapshot_timestamp (str): snapshot timestamp. Defaults to None.
                If set, this will be the snapshot timestamp
                used in the engine.
        """
        super(GroupsSettingsRulesEngine,
              self).__init__(rules_file_path=rules_file_path)
        self.rule_book = None
        self.snapshot_timestamp = snapshot_timestamp
        self._lock = threading.Lock()

    def build_rule_book(self, global_configs=None):
        """Build GroupsSettingsRuleBook from the rules definition file.

        Args:
            global_configs (dict): Global configurations.
        """
        with self._lock:
            self.rule_book = GroupsSettingsRuleBook(
                self._load_rule_definitions())

    def find_violations(self, settings, force_rebuild=False):
        """Determine whether Groups Settings violates rules.

        Args:
            settings (GroupsSettings): A GroupsSettings resource to check.
            force_rebuild (bool): If True, rebuilds the rule book. This will
                reload the rules definition file and add the rules to the book.

        Returns:
             generator: A generator of rule violations.
        """
        res = self.rule_book is None or force_rebuild
        if res:
            self.build_rule_book()
        violations = self.rule_book.find_violations(settings)

        return violations

    def add_rules(self, rules):
        """Add rules to the rule book.

        Args:
            rules (list): The list of rules to add to the book.
        """
        if self.rule_book is not None:
            self.rule_book.add_rules(rules)


class GroupsSettingsRuleBook(bre.BaseRuleBook):
    """The RuleBook for GroupsSettings rules."""

    supported_settings = frozenset([
    'whoCanAdd', 'whoCanJoin', 
    'whoCanViewMembership', 'whoCanViewGroup', 'whoCanInvite', 
    'allowExternalMembers', 'whoCanLeaveGroup'])

    def __init__(self, rule_defs=None):
        """Initialization.

        Args:
            rule_defs (list): GroupsSettings rule definition dicts
        """
        super(GroupsSettingsRuleBook, self).__init__()
        self._lock = threading.Lock()
        self.resource_rules_map = {}
        if not rule_defs:
            self.rule_defs = {}
        else:
            self.rule_defs = rule_defs
            self.add_rules(rule_defs)

    def __eq__(self, other):
        """Equals.

        Args:
            other (object): Object to compare.
        Returns:
            bool: True or False.
        """
        if not isinstance(other, type(self)):
            return NotImplemented
        return self.resource_rules_map == other.resource_rules_map

    def __ne__(self, other):
        """Not Equals.

        Args:
            other (object): Object to compare.
        Returns:
            bool: True or False.
        """
        return not self == other

    def __repr__(self):
        """Object representation.

        Returns:
            str: The object representation.
        """
        return 'GroupsSettingsRuleBook <{}>'.format(self.resource_rules_map)

    def add_rules(self, rule_defs):
        """Add rules to the rule book.

        Args:
            rule_defs (dict): rule definitions dictionary
        """
        print("adding rules for groups settings")
        for (i, rule) in enumerate(rule_defs.get('rules', [])):
            self.add_rule(rule, i)

    def add_rule(self, rule_def, rule_index):
        """Add a rule to the rule book.

        Args:
            rule_def (dict): A dictionary containing rule definition
                properties.
            rule_index (int): The index of the rule from the rule definitions.
                Assigned automatically when the rule book is built.
        """
        mode = rule_def.get('mode')
        settings = rule_def.get('settings')
        groups_emails = rule_def.get('groups_emails')

        if settings is None or not groups_emails or mode not in RULE_MODES:
            raise audit_errors.InvalidRulesSchemaError(
                'Faulty rule {}'.format(rule_index))

        for rule_setting in settings:
            if rule_setting not in self.supported_settings:
                raise audit_errors.InvalidRulesSchemaError(
                    'Faulty rule {}'.format(rule_index))

        for group_email in groups_emails:
            # For each resource id associated with the rule, create a
            # mapping of resource => rules.
            gcp_resource = resource_util.create_resource(
                resource_id=group_email,
                resource_type=resource.ResourceType.GROUPS_SETTINGS)

            rule_def_resource = {
                'settings': settings,
                'mode': mode
            }
            rule = Rule(rule_name=rule_def.get('name'),
                        rule_index=rule_index,
                        rule=rule_def_resource)

            resource_rules = self.resource_rules_map.setdefault(
                gcp_resource, ResourceRules(resource=gcp_resource))

            if not resource_rules:
                self.resource_rules_map[rule_index] = rule
            if rule not in resource_rules.rules:
                resource_rules.rules.add(rule)

    def get_resource_rules(self, resource):
        """Get all the resource rules for resource.

        Args:
            resource (Resource): The gcp_type Resource find in the map.

        Returns:
            ResourceRules: A ResourceRules object.
        """
        return self.resource_rules_map.get(resource)

    def find_violations(self, settings):
        """Find groups settings violations in the rule book.

        Args:
            settings (GroupsSettings): The GCP resource to check for violations.

        Returns:
            RuleViolation: resource groups settings rule violations.
        """
        LOGGER.debug('Looking for groups settings violations: %s',
                     settings.name)
        violations = []

        resource_rules = self.get_resource_rules(settings)
        if resource_rules:
            violations.extend(
                resource_rules.find_violations(settings))

        wildcard_resource = resource_util.create_resource( 
            resource_id='*', resource_type=settings.type)

        resource_rules = self.get_resource_rules(wildcard_resource)
        if resource_rules:
            violations.extend(
                resource_rules.find_violations(settings))

        LOGGER.debug('Returning violations: %r', violations)
        return violations


class ResourceRules(object):
    """An association of a resource to rules."""

    def __init__(self,
                 resource=None,
                 rules=None):
        """Initialize.

        Args:
            resource (Resource): The resource to associate with the rule.
            rules (set): rules to associate with the resource.
        """
        if not isinstance(rules, set):
            rules = set([])
        self.resource = resource
        self.rules = rules

    def find_violations(self, settings):
        """Determine if the policy binding matches this rule's criteria.

        Args:
            settings (GroupsSettings): groups settings resource.

        Returns:
            list: RuleViolation
        """
        violations = []
        for rule in self.rules:
            rule_violations = rule.find_violations(settings)
            if rule_violations:
                violations.extend(rule_violations)
        return violations

    def __eq__(self, other):
        """Compare == with another object.

        Args:
            other (ResourceRules): object to compare with

        Returns:
            int: comparison result
        """
        if not isinstance(other, type(self)):
            return NotImplemented
        return (self.resource == other.resource and
                self.rules == other.rules)

    def __ne__(self, other):
        """Compare != with another object.

        Args:
            other (object): object to compare with

        Returns:
            int: comparison result
        """
        return not self == other

    def __repr__(self):
        """String representation of this node.

        Returns:
            str: debug string
        """
        return 'GroupsSettingsResourceRules<resource={}, rules={}>'.format(
            self.resource, self.rules)


class Rule(object):
    """Rule properties from the rule definition file, also finds violations."""

    def __init__(self, rule_name, rule_index, rule):
        """Initialize.

        Args:
            rule_name (str): Name of the loaded rule.
            rule_index (int): The index of the rule from the rule definitions.
            rule (dict): The rule definition from the file.
        """
        self.rule_name = rule_name
        self.rule_index = rule_index
        self.rule = rule

    def rule_requirements(self):
        """Used to create violation reason.

       Returns: 
           str of property:value couples specified in rule,
           joined by AND.
        """
        rule_list = []
        for setting, value in self.rule['settings'].iteritems():
            rule_list.append('{}:{}'.format(setting, value))
        return ' AND '.join(rule_list)        

    def find_blacklist_violation(self, settings):
        """Finds violations in case that rule is blacklist.
        Args:
            settings (GroupsSettings): 
        Returns:
            violation_reason (str): Statement of what the broken rule required,
                or empty string in case that rule is not violated.
        """
        violation_reason = ''
        if not self.rule['settings']:
            return violation_reason

        violates_every_setting_in_rule = True
        for setting, value in self.rule['settings'].iteritems():
            if getattr(settings, setting) != value:
                violates_every_setting_in_rule = False
        if violates_every_setting_in_rule:
            violation_reason = "rule specified ({}) together is not allowed".format(self.rule_requirements())

        return violation_reason

    def find_whitelist_violation(self, settings):
        """Finds violations in case that rule is whitelist.
        Args:
            settings (GroupsSettings): 
        Returns:
            violation_reason (str): Statement of what the broken rule required,
                or empty string in case that rule is not violated.
        """
        violation_reason = ''
        a_setting_doesnt_match = False
        for setting, value in self.rule['settings'].iteritems():
            if getattr(settings, setting) != value:
                a_setting_doesnt_match = True
        if a_setting_doesnt_match:
            violation_reason = "rule specified ({}) is required".format(self.rule_requirements())

        return violation_reason

    def find_violations(self, settings):
        """Find GroupsSettings violations.

        Args:
            settings (GroupsSettings): The resource to check for violations.

        Returns:
            list: Returns a list of RuleViolation named tuples.
        """
        violations = []
        if settings.id == 'data-scientists@henrychang.mygbiz.com':
            print("found data scientists")
        if self.rule['mode'] == BLACKLIST:
            violation_reason = self.find_blacklist_violation(settings)
        elif self.rule['mode'] == WHITELIST:
            violation_reason = self.find_whitelist_violation(settings)

        if violation_reason: 
            violations.append(RuleViolation(
                group_email=settings.id,
                resource_type=settings.type,
                rule_index=self.rule_index,
                rule_name=self.rule_name,
                violation_type=VIOLATION_TYPE,
                violation_reason=violation_reason,
                whoCanAdd=settings.whoCanAdd,
                whoCanJoin=settings.whoCanJoin,
                whoCanViewMembership=settings.whoCanViewMembership,
                whoCanViewGroup=settings.whoCanViewGroup,
                whoCanInvite=settings.whoCanInvite,
                allowExternalMembers=settings.allowExternalMembers,
                whoCanLeaveGroup=settings.whoCanLeaveGroup
                ))
        return violations

    def __eq__(self, other):
        """Test whether Rule equals other Rule.

        Args:
            other (Rule): object to compare to

        Returns:
            int: comparison result
        """
        if not isinstance(other, type(self)):
            return NotImplemented
        return (self.rule_name == other.rule_name and
                self.rule_index == other.rule_index)

    def __ne__(self, other):
        """Test whether Rule is not equal to another Rule.

        Args:
            other (object): object to compare to

        Returns:
            int: comparison result
        """
        return not self == other

    def __hash__(self):
        """Make a hash of the rule index.

        Returns:
            int: The hash of the rule index.
        """
        return hash(self.rule_index)


# pylint: enable=inconsistent-return-statements

# Rule violation.
# group_email: string
# resource_type: string
# rule_index: int
# rule_name: string
# violation_type: string
# violation_reason: string
# whoCanAdd: string
# whoCanJoin: string
# whoCanViewMembership: string
# whoCanViewGroup: string
# whoCanInvite: string
# allowExternalMembers: bool
# whoCanLeaveGroup: string
RuleViolation = namedtuple('RuleViolation',
                           ['group_email', 'resource_type','rule_index', 
                            'rule_name', 'violation_type', 'violation_reason',
                            'whoCanAdd', 'whoCanJoin', 'whoCanViewMembership',
                            'whoCanViewGroup', 'whoCanInvite', 
                            'allowExternalMembers', 'whoCanLeaveGroup'])
