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

"""Scanner for the Identity-Aware Proxy rules engine."""
import collections
import re

from google.cloud.security.common.util import log_util
from google.cloud.security.common.data_access import backend_service_dao
from google.cloud.security.common.data_access import firewall_rule_dao
from google.cloud.security.common.data_access import instance_dao
from google.cloud.security.common.data_access import instance_group_dao
from google.cloud.security.common.data_access import instance_group_manager_dao
from google.cloud.security.common.data_access import instance_template_dao
from google.cloud.security.scanner.scanners import base_scanner

LOGGER = log_util.get_logger(__name__)
INSTANCE_URL_RE = re.compile(
    r'''(?x)^.*
        /projects/(?P<project>.*?)
        /zones/(?P<zone>.*?)
        /instances/(?P<name>.*)$''')
INSTANCE_GROUP_URL_RE = re.compile(
    r'''(?x)^.*
        /projects/(?P<project>.*?)
        /regions/(?P<region>.*?)
        /instanceGroups/(?P<name>.*)$''')
INSTANCE_TEMPLATE_URL_RE = re.compile(
    r'''(?x)^.*
        /projects/(?P<project>.*?)
        /global
        /instanceTemplates/(?P<name>.*)$''')
NETWORK_URL_RE = re.compile(
    r'''(?x)^.*
        (?:projects/(?P<project>.*?)/)?
        global
        /networks/(?P<name>.*)$''')


BackendServicePath = collections.namedtuple(
    'BackendServicePath',
    ['project', 'name'])
InstanceGroupPath = collections.namedtuple(
    'InstanceGroupPath',
    ['project', 'region', 'name'])
InstancePath = collections.namedtuple(
    'InstancePath',
    ['project', 'zone', 'name'])
InstanceTemplatePath = collections.namedtuple(
    'InstanceTemplatePath',
    ['project', 'name'])
IapResource = collections.namedtuple(
    'IapResource',
    ['backend_service_name',
     'backend_service_project',
     'alternate_services',
     'direct_access_sources',
     'iap_enabled',
    ])
NetworkPath = collections.namedtuple(
    'NetworkPath',
    ['project', 'name'])
NetworkPort = collections.namedtuple(
    'NetworkPort',
    ['network', 'port'])


class _RunData(object):
    def __init__(self, backend_services, firewall_rules, instances,
                 instance_groups, instance_group_managers, instance_templates):
        self.backend_services = backend_services
        self.firewall_rules = firewall_rules
        self.instances_by_path = dict(
            (InstancePath(
                project_id=instance.project_id,
                zone=instance.zone,
                name=instance.name),
             instance) for instance in instances)

        self.instance_groups_by_path = dict(
            (InstanceGroupPath(
                project=instance_group.project_id,
                region=instance_group.region,
                name=instance_group.name),
             instance_group) for instance_group in instance_groups)

        self.instance_templates_by_instance_group_path = {}
        instance_templates_by_path = dict(
            (InstanceTemplatePath(
                project=instance_template.project_id,
                name=instance_template.name),
             instance_template)
            for instance_template in instance_templates)
        for instance_group_manager in instance_group_managers:
            instance_group_url = instance_group_manager.instance_group
            if not instance_group_url:
                continue
            instance_group_path = self._instance_group_url_to_path(
                instance_group_url)
            instance_template_url = instance_group_manager.instance_template
            match = INSTANCE_TEMPLATE_URL_RE.match(instance_template_url)
            instance_template_path = InstanceTemplatePath(
                project=match.group('project'),
                name=match.group('name'))
            instance_template = instance_templates_by_path.get(
                instance_template_path)
            if instance_template:
                self.instance_templates_by_instance_group_path[
                    instance_group_path] = instance_template

    @classmethod
    def _instance_group_url_to_path(cls, instance_group_url):
        match = INSTANCE_GROUP_URL_RE.match(instance_group_url)
        return InstanceGroupPath(
            project=match.group('project'),
            region=match.group('region'),
            name=match.group('name'))

    def instance_group_network_port(self, backend_service, instance_group):
        port = self.find_instance_group_port(backend_service,
                                             instance_group)
        return NetworkPort(
            network=self.network_url_to_path(
                instance_group.network,
                project=instance_group.project_id),
            port=port)

    def find_instance_group_by_url(self, instance_group_url):
        target_path = self._instance_group_url_to_path(instance_group_url)
        return self.instance_groups_by_path.get(target_path)

    def find_instance_by_url(self, instance_url):
        match = INSTANCE_URL_RE.match(instance_url)
        target_path = InstancePath(
            project=match.group('project'),
            zone=match.group('zone'),
            name=match.group('name'))
        return self.instances_by_path.get(target_path)

    @classmethod
    def find_instance_group_port(cls, backend_service, instance_group):
        if backend_service.port_name:
            for named_port in instance_group.named_ports:
                if named_port.name == backend_service.port_name:
                    return int(named_port.port_number)
        return int(backend_service.port)

    def firewall_allowed_sources(self, network_port, tag):
        allowed_sources = set()

        def firewall_entry_applies(firewall_entry):
            if firewall_entry.IPProtocol not in (6, '6', 'tcp'):
                return False
            if not firewall_entry.ports:
                return True
            for fw_port_range in firewall_entry.ports:
                fw_port_range = str(fw_port_range)
                if '-' in fw_port_range:
                    range_ends = fw_port_range.split('-')
                    fw_port_min = int(range_ends[0])
                    fw_port_max = int(range_ends[1])
                else:
                    fw_port_min = int(fw_port_range)
                    fw_port_max = int(fw_port_range)
                if (network_port.port >= fw_port_min and
                        network_port.port <= fw_port_max):
                    return True
            return False


        relevant_rules_by_priority = collections.defaultdict(lambda: [])
        for firewall_rule in self.firewall_rules:
            firewall_network = self.network_url_to_path(
                firewall_rule.network, firewall_rule.project_id)
            if firewall_network != network_port.network:
                continue

            if firewall_rule.tags and tag not in firewall_rule.tags:
                continue

            if firewall_rule.direction and firewall_rule.direction != 'INGRESS':
                continue

            relevant_rules_by_priority[firewall_rule.priority].append(
                firewall_rule)
        priorities = relevant_rules_by_priority.keys()
        priorities.sort()
        for priority in priorities:
            # DENY at a given priority takes precedence over ALLOW
            for firewall_rule in relevant_rules_by_priority[priority]:
                for allowed in firewall_rule.allowed:
                    if firewall_entry_applies(allowed):
                        allowed_sources.update(firewall_rule.source_ranges)
                        allowed_sources.update(firewall_rule.source_tags)
                        continue
            for firewall_rule in relevant_rules_by_priority[priority]:
                for denied in firewall_rule.denied:
                    if firewall_entry_applies(denied):
                        allowed_sources.difference_update(
                            firewall_rule.source_ranges)
                        allowed_sources.difference_update(
                            firewall_rule.source_tags)
        return allowed_sources

    @classmethod
    def network_url_to_path(cls, network_url, project):
        # Accept network 'URLs' as seen in firewall rule resources.
        # xref:
        # https://cloud.google.com/compute/docs/reference/latest/firewalls
        match = NETWORK_URL_RE.match(network_url)
        return NetworkPath(
            project=match.group('project') or project,
            name=match.group('name'))

    def tags_for_instance_group(self, instance_group):
        tags = set()

        # Get tags from actual instances.
        for instance_url in instance_group.instance_urls:
            instance = self.find_instance_by_url(instance_url)
            if not instance:
                continue
            tags.update(instance.tags)

        # If it's a managed instance group, also get tags from the
        # instance template.
        instance_group_path = InstanceGroupPath(
            project=instance_group.project_id,
            region=instance_group.region,
            name=instance_group.name)
        instance_template = self.instance_templates_by_instance_group_path.get(
            instance_group_path)
        if instance_template:
            template_tags = instance_template.properties.get('tags', {})
            tags.update(template_tags.get('items', []))

        return tags


class IapScanner(base_scanner.BaseScanner):
    """Pipeline to IAP-related data from DAO"""
    def __init__(self, snapshot_timestamp):
        """Initialization.

        Args:
            snapshot_timestamp: The snapshot timestamp
        """
        super(IapScanner, self).__init__(
            snapshot_timestamp)
        self.snapshot_timestamp = snapshot_timestamp

    def _get_backend_services(self):
        return backend_service_dao.BackendServiceDao().\
                        get_backend_services(self.snapshot_timestamp)

    def _get_firewall_rules(self):
        return firewall_rule_dao.FirewallRuleDao().\
                        get_firewall_rules(self.snapshot_timestamp)

    def _get_instances(self):
        return instance_dao.InstanceDao().\
                        get_instances(self.snapshot_timestamp)

    def _get_instance_groups(self):
        return instance_group_dao.InstanceGroupDao().\
                        get_instance_groups(self.snapshot_timestamp)

    def _get_instance_group_managers(self):
        return instance_group_manager_dao.InstanceGroupManagerDao().\
                        get_instance_group_managers(self.snapshot_timestamp)

    def _get_instance_templates(self):
        return instance_template_dao.InstanceTemplateDao().\
                        get_instance_templates(self.snapshot_timestamp)

    def run(self):
        """Runs the data collection."""
        run_data = _RunData(
            backend_services=self._get_backend_services(),
            firewall_rules=self._get_firewall_rules(),
            instances=self._get_instances(),
            instance_groups=self._get_instance_groups(),
            instance_group_managers=self._get_instance_group_managers(),
            instance_templates=self._get_instance_templates(),
            )

        iap_resources = []
        for backend_service in run_data.backend_services:
            alternate_services = set()
            direct_access_sources = set()
            for backend in backend_service.backends:
                instance_group = run_data.find_instance_group_by_url(
                    backend.group)
                if not instance_group:
                    continue

                network_port = run_data.instance_group_network_port(
                    backend_service, instance_group)

                tags = run_data.tags_for_instance_group(instance_group)
                for tag in tags:
                    direct_access_sources.update(
                        run_data.firewall_allowed_sources(
                            network_port, tag))

                for backend_service2 in run_data.backend_services:
                    found_alternate_service = False
                    for backend2 in backend_service2.backends:
                        instance_group2 = run_data.find_instance_group_by_url(
                            backend2.group)
                        if not instance_group2:
                            continue
                        network_port2 = run_data.instance_group_network_port(
                            backend_service2, instance_group2)
                        if network_port != network_port2:
                            continue
                        if instance_group == instance_group2:
                            found_alternate_service = True
                            break
                        for instance_url in instance_group.urls:
                            if instance_url in instance_group2.instance_urls:
                                found_alternate_service = True
                                break

                    if found_alternate_service:
                        alternate_services.add(BackendServicePath(
                            project=backend_service2.project_id,
                            name=backend_service2.name))
            iap_resources.append(IapResource(
                backend_service_name=backend_service.name,
                backend_service_project=backend_service.project_id,
                alternate_services=alternate_services,
                direct_access_sources=direct_access_sources,
                iap_enabled=(backend_service.iap.get('enabled', False)
                             if backend_service.iap else False)))

        return iap_resources

    # pylint: disable=arguments-differ
    def find_violations(self, iap_data, rules_engine):
        """Find violations in the policies.

        Returns:
            A list of violations
        """

        all_violations = []
        LOGGER.info('Finding IAP violations...')

        for backend_service in iap_data.backend_services:
            LOGGER.debug('%s', backend_service.name)
            violations = rules_engine.find_policy_violations(
                IapResource(backend_service=backend_service,
                            iap_data=iap_data))
            LOGGER.debug(violations)
            all_violations.extend(violations)
        return all_violations
