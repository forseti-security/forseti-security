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

"""Rules engine for NetworkInterface."""
from collections import namedtuple
import itertools
import re

from google.cloud.forseti.common.gcp_type import resource as resource_mod
from google.cloud.forseti.common.util.regular_exp import escape_and_globify
from google.cloud.forseti.common.util import logger
from google.cloud.forseti.scanner.audit import base_rules_engine as bre
from google.cloud.forseti.scanner.audit import errors as audit_errors


LOGGER = logger.get_logger(__name__)


class InstanceNetworkInterfaceRulesEngine(bre.BaseRulesEngine):
    """Rules engine for InstanceNetworkInterfaceRules."""

    def __init__(self, rules_file_path, snapshot_timestamp=None):
        """Initialize.

        Args:
            rules_file_path (str): file location of rules
            snapshot_timestamp (str): timestamp for database.
        """
        super(InstanceNetworkInterfaceRulesEngine,
              self).__init__(rules_file_path=rules_file_path)
        self.rule_book = None

    def build_rule_book(self, global_configs=None):
        """Build InstanceNetworkInterfaceRuleBook from rules definition file.

        Args:
            global_configs (dict): Global Configs
        """
        self.rule_book = InstanceNetworkInterfaceRuleBook(
            self._load_rule_definitions())

    def find_violations(self, instance_network_interface, force_rebuild=False):
        """Determine whether the networks violates rules.

        Args:
            instance_network_interface (list): list of
                instance_network_interface
            force_rebuild (bool): set to false to not force a rebuiid

        Return:
            list: iterator of all violations
        """
        violations = itertools.chain()
        if self.rule_book is None or force_rebuild:
            self.build_rule_book()
        resource_rules = self.rule_book.get_resource_rules()

        for rule in resource_rules:
            violations = itertools.chain(violations,
                                         rule.find_violations(
                                             instance_network_interface))
        return violations

    def add_rules(self, rules):
        """Add rules to the rule book.

        Args:
            rules (dicts): rule definitions
        """
        if self.rule_book is not None:
            self.rule_book.add_rules(rules)


class InstanceNetworkInterfaceRuleBook(bre.BaseRuleBook):
    """The RuleBook for enforced networks resources."""

    def __init__(self,
                 rule_defs=None):
        """Initialize.

        Args:
            rule_defs (dict): The parsed dictionary of rules from the YAML
                definition file.
        """
        super(InstanceNetworkInterfaceRuleBook, self).__init__()
        self.resource_rules_map = {}
        if not rule_defs:
            self.rule_defs = {}
        else:
            self.rule_defs = rule_defs
            self.add_rules(rule_defs)

    def add_rules(self, rule_defs):
        """Add rules to the rule book.

        Args:
            rule_defs (dict): rules definitions
        """
        for (i, rule) in enumerate(rule_defs.get('rules', [])):
            self.add_rule(rule, i)

    def add_rule(self, rule_def, rule_index):
        """Add a rule to the rule book.

        Add a rule to the rule book.

        The rule supplied to this method is the dictionary parsed from
        the rules definition file.

        For example, this rule...

        # rules yaml:
            rules:
          - name: all networks covered in whitelist
            project: '*'
            network: '*'
            is_external_network: True
            whitelist:
              master:
                - master-1
              network:
                - network-1
                - network-2
              default:
                - default-1

        ... gets parsed into:
        {
            "rules": [
                {
                    "name": "all networks covered in whitelist",
                    "project": "*",
                    "network": "*",
                    "is_external_network": true,
                    "whitelist": {
                        "master": [
                            "master-1"
                        ],
                        "network": [
                            "network-1",
                            "network-2"
                        ],
                        "default": [
                            "default-1"
                        ]
                    }
                }
            ]
        }

        Args:
            rule_def (dict): A dictionary containing rule definition properties.
            rule_index (int): The index of the rule from the rule definitions.
                Assigned automatically when the rule book is built.
        """
        project = rule_def.get('project')
        network = rule_def.get('network')
        whitelist = rule_def.get('whitelist')
        is_external_network = rule_def.get('is_external_network')

        if ((whitelist is None) or
                (project is None) or
                (network is None) or
                (is_external_network is None)):
            raise audit_errors.InvalidRulesSchemaError(
                'Faulty rule {}'.format(rule_def.get('name')))

        rule_def_resource = {'whitelist': whitelist,
                             'project': escape_and_globify(project),
                             'network': escape_and_globify(network),
                             'is_external_network': is_external_network}

        rule = Rule(rule_name=rule_def.get('name'),
                    rule_index=rule_index,
                    rules=rule_def_resource)

        resource_rules = self.resource_rules_map.get(rule_index)
        if not resource_rules:
            self.resource_rules_map[rule_index] = rule

    def get_resource_rules(self):
        """Get all the resource rules.

        Return:
            list: resource_rules_map values
        """
        return self.resource_rules_map.values()


class Rule(object):
    """The rules class for instance_network_interface."""

    def __init__(self, rule_name, rule_index, rules):
        """Initialize.

        Args:
            rule_name (str): Name of the loaded rule
            rule_index (int): The index of the rule from the  definitions
            rules (dict): The resources associated with the rules like
                the whitelist
        """
        self.rule_name = rule_name
        self.rule_index = rule_index
        self.rules = rules

    def find_violations(self, instance_network_interface_list):
        """Raise violation is the ip is not in the whitelist.

        Args:
            instance_network_interface_list (list): list
                of InstanceNetworkInterface objects

         Yields:
            namedtuple: Returns RuleViolation named tuple
        """
        for instance_network_interface in instance_network_interface_list:
            network_and_project = re.search(
                r'compute/.*/projects/([^/]*).*networks/([^/]*)',
                instance_network_interface.network)
            project = network_and_project.group(1)
            network = network_and_project.group(2)
            is_external_network = (instance_network_interface.access_configs is
                                   not None)
            ips = None
            if (network not in self.rules['whitelist'].get(project, []) and
                    is_external_network):
                ips = [config['natIP']
                       for config in instance_network_interface.access_configs
                       if 'natIP' in config]
                yield self.RuleViolation(
                    resource_name=instance_network_interface.name,
                    resource_type=resource_mod.ResourceType.INSTANCE,
                    resource_id=instance_network_interface.name,
                    full_name=instance_network_interface.full_name,
                    rule_name=self.rule_name,
                    rule_index=self.rule_index,
                    violation_type='INSTANCE_NETWORK_INTERFACE_VIOLATION',
                    project=project,
                    network=network,
                    ip=ips,
                    resource_data=instance_network_interface.as_json())

    # Rule violation.
    # resource_type: string
    # rule_name: string
    # rule_index: int
    # violation_type: UNENFORCED_NETWORK_VIOLATION
    # project: string
    # network: string
    # ip: string
    RuleViolation = namedtuple('RuleViolation',
                               ['resource_type', 'resource_id', 'full_name',
                                'rule_name', 'rule_index', 'violation_type',
                                'project', 'network', 'ip', 'resource_data',
                                'resource_name'])
