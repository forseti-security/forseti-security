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

"""Rules engine for Blacklist of IP addresses ."""
import itertools
import re
import urllib2
import struct
import socket


from collections import namedtuple


from google.cloud.security.common.util.regex_util import escape_and_globify
from google.cloud.security.common.util import log_util
from google.cloud.security.scanner.audit import base_rules_engine as bre
from google.cloud.security.scanner.audit import errors as audit_errors
from pprint import pprint as pp


LOGGER = log_util.get_logger(__name__)


class BlacklistRulesEngine(bre.BaseRulesEngine):
    """Rules engine for BlacklistRules."""

    def __init__(self, rules_file_path, snapshot_timestamp=None):
        """Initialize.

        Args:
            rules_file_path (str): file location of rules
            snapshot_timestamp (str): timestamp for database.
        """
        super(BlacklistRulesEngine,
              self).__init__(rules_file_path=rules_file_path)
        self.rule_book = None

    def build_rule_book(self, global_configs=None):
        """Build BlacklistRuleBook from rules definition file.

        Args:
            global_configs (dict): Global Configs
        """
        self.rule_book = BlacklistRuleBook(
            self._load_rule_definitions())

    def find_policy_violations(self, instance_network_interface,
                               force_rebuild=False):
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

class BlacklistRuleBook(bre.BaseRuleBook):
    """The RuleBook for networks resources."""

    def __init__(self,
                 rule_defs=None):
        """Initialize.

        Args:
            rule_defs (dict): The parsed dictionary of rules from the YAML
                definition file.
        """
        super(BlacklistRuleBook, self).__init__()
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
        """Add a rule to the rule book."""

        ip_file_url = rule_def.get('threats_url')

        ips, nets = self.get_and_parse_threat_url(ip_file_url)

        rule_def_resource = {
             "ips_list": ips,
             "nets_list": nets
        }

        rule = Rule(rule_name=rule_def.get('name'),
                        rule_index=rule_index,
                        rules=rule_def_resource)

        resource_rules = self.resource_rules_map.get(rule_index)

        if not resource_rules:
                self.resource_rules_map[rule_index] = rule


    def get_resource_rules(self):
        """Get all the resource rules for (resource, RuleAppliesTo.*).

        Returns:
           list:  A list of ResourceRules.
        """
        resource_rules = []

        for resource_rule in self.resource_rules_map:
            resource_rules.append(self.resource_rules_map[resource_rule])

        return resource_rules

    def get_and_parse_threat_url(self, url):
        data = urllib2.urlopen(url).read()
        ips = re.findall( r'[0-9]+(?:\.[0-9]+){3}', data)
        nets = re.findall( r'(?<!\d\.)(?<!\d)(?:\d{1,3}\.){3}\d{1,3}/\d{1,2}(?!\d|(?:\.\d))', data)
        return ips, nets

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

    def addressInNetwork(self, ip, net):
       ipaddr = struct.unpack("!I",socket.inet_aton(ip))[0]
       netstr, bits = net.split('/')
       netaddr = struct.unpack("!I",socket.inet_aton(netstr))[0]
       mask = (0xffffffff << (32 - int(bits))) & 0xffffffff
       return (ipaddr & mask) == (netaddr & mask)

    def check_if_blacklisted(self, ip):
        if ip in self.rules['ips_list']:
            return True
        for ip_network in self.rules['nets_list']:
            if self.addressInNetwork(ip, ip_network):
                return True
        return False        


    def find_violations(self, instance_network_interface):
        """Raise violation is the ip is not in the whitelist.

        Args:
            instance_network_interface a InstanceNetworkInterface object

         Yields:
            namedtuple: Returns RuleViolation named tuple
        """

        network_and_project = re.search(
            r'compute/v1/projects/([^/]*).*networks/([^/]*)',
            instance_network_interface.network)
        project = network_and_project.group(1)
        network = network_and_project.group(2)

        for access_config in instance_network_interface.access_configs:
            ip = access_config['natIP']
            if self.check_if_blacklisted(ip):
                yield self.RuleViolation(
                    resource_type='instance',
                    rule_name=self.rule_name,
                    rule_index=self.rule_index,
                    violation_type='BLACKLIST_VIOLATION',
                    project=project,
                    network=network,
                    ip=access_config['natIP'])

    # Rule violation.
    # resource_type: string
    # rule_name: string
    # rule_index: int
    # violation_type: BLACKLIST_VIOLATION
    # project: string
    # network: string
    # ip: string
    RuleViolation = namedtuple('RuleViolation',
                               ['resource_type', 'rule_name',
                                'rule_index', 'violation_type', 'project',
                                'network', 'ip'])
