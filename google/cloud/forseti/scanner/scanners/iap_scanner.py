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

"""Scanner for the Identity-Aware Proxy rules engine."""
import collections

from google.cloud.forseti.common.gcp_type import (
    backend_service as backend_service_type)
from google.cloud.forseti.common.gcp_type import (
    firewall_rule as firewall_rule_type)
from google.cloud.forseti.common.gcp_type import instance as instance_type
from google.cloud.forseti.common.gcp_type import (
    instance_group as instance_group_type)
from google.cloud.forseti.common.gcp_type import (
    instance_group_manager as instance_group_manager_type)
from google.cloud.forseti.common.gcp_type import (
    instance_template as instance_template_type)
from google.cloud.forseti.common.gcp_type import project as project_type
from google.cloud.forseti.common.gcp_type import network as network_type
from google.cloud.forseti.common.gcp_type.resource import ResourceType
from google.cloud.forseti.common.util import logger
from google.cloud.forseti.scanner.audit import iap_rules_engine
from google.cloud.forseti.scanner.scanners import base_scanner

LOGGER = logger.get_logger(__name__)
IapResource = collections.namedtuple(
    'IapResource', ['project_full_name',
                    'backend_service',
                    'alternate_services',
                    'direct_access_sources',
                    'iap_enabled']
)
NetworkPort = collections.namedtuple(
    'NetworkPort',
    ['network', 'port'])


class _RunData(object):
    """Information needed to compute IAP properties."""

    def __init__(self, backend_services, firewall_rules, instances,
                 instance_groups, instance_group_managers, instance_templates):
        """Initialize.

        Args:
            backend_services (list): BackendService
            firewall_rules (list): FirewallRule
            instances (list): Instance
            instance_groups (list): InstanceGroup
            instance_group_managers (list): InstanceGroupMananger
            instance_templates (list): InstanceTemplate
        """
        self.resource_counts = {
            ResourceType.BACKEND_SERVICE: len(backend_services),
            ResourceType.FIREWALL_RULE: len(firewall_rules),
            ResourceType.INSTANCE: len(instances),
            ResourceType.INSTANCE_GROUP: len(instance_groups),
            ResourceType.INSTANCE_GROUP_MANAGER: len(instance_group_managers),
            ResourceType.INSTANCE_TEMPLATE: len(instance_templates),
        }
        self.backend_services = backend_services
        self.firewall_rules = firewall_rules
        self.instances_by_key = dict((instance.key, instance)
                                     for instance in instances)
        self.instance_groups_by_key = dict((instance_group.key, instance_group)
                                           for instance_group
                                           in instance_groups)

        self.instance_templates_by_group_key = {}
        instance_templates_by_key = dict((instance_template.key,
                                          instance_template)
                                         for instance_template
                                         in instance_templates)
        for instance_group_manager in instance_group_managers:
            instance_group_url = instance_group_manager.instance_group
            if not instance_group_url:
                continue
            instance_group_key = instance_group_type.Key.from_url(
                instance_group_url)
            instance_template_url = instance_group_manager.instance_template
            instance_template_key = instance_template_type.Key.from_url(
                instance_template_url)
            instance_template = instance_templates_by_key.get(
                instance_template_key)
            if instance_template:
                self.instance_templates_by_group_key[
                    instance_group_key] = instance_template

    @staticmethod
    def instance_group_network_port(backend_service, instance_group):
        """Which network and port is used for a service's backends?

        A backend service can communicate with its backends on a
        different network and port number for each of the service's
        backend instance groups.

        Args:
            backend_service (BackendService): service to find port for
            instance_group (InstanceGroup): group to find port for

        Returns:
            NetworkPort: how the service communicates with backends
        """
        # Field 'port' from backend service has been deprecated in favor of
        # portName. PortName is required when the load balancing scheme is
        # EXTERNAL. When the load balancing scheme is INTERNAL, this field
        # is not used, it has the same behavior of port so we can just use
        # portName to get the port from instance group.

        port = -1

        if backend_service.port:
            # Although deprecated, it's still returned by the API and might
            # contain legacy data for customers who have not migrated.
            port = int(backend_service.port)

        if backend_service.port_name:
            for named_port in instance_group.named_ports or []:
                if named_port.get('name') == backend_service.port_name:
                    port = int(named_port.get('port'))
                    break
        if port == -1:
            LOGGER.error('NetworkPort can not be constructed. Unable to '
                         'find the appropriate port from backend service '
                         'or instance group.')
            return None
        return NetworkPort(
            network=network_type.Key.from_url(
                instance_group.network,
                project_id=instance_group.project_id),
            port=port)

    def find_instance_group_by_url(self, instance_group_url):
        """Find an instance group for the given URL.

        Args:
            instance_group_url (str): instance group URL

        Returns:
            InstanceGroup: instance group
        """
        if not instance_group_url:
            return None

        target_key = instance_group_type.Key.from_url(instance_group_url)
        return self.instance_groups_by_key.get(target_key)

    def find_instance_by_url(self, instance_url):
        """Find an instance for the given URL.

        Args:
            instance_url (str): instance URL

        Returns:
            Instance: instance
        """
        target_key = instance_type.Key.from_url(instance_url)
        return self.instances_by_key.get(target_key)

    def firewall_allowed_sources(self, network_port, tag):
        """Which source (networks, tags) can connect to the given destination?

        Args:
            network_port (NetworkPort): connection destination
            tag (str): instance tag for destination instance

        Returns:
            set: allowed source networks and tags
        """
        allowed_sources = set()

        def firewall_entry_applies(firewall_entry):
            """Does a firewall entry match the current source?

            Args:
                firewall_entry (dict): An 'allowed' or 'denied' dict from
                                       a FirewallRule.

            Returns:
                bool: whether the entry is relevant to the source being
                      evaluated
            """
            if firewall_entry.get('IPProtocol') not in (
                    None, 6, '6', 'tcp', 'all'):
                return False
            if not firewall_entry.get('ports'):
                return True
            for fw_port_range in firewall_entry.get('ports'):
                fw_port_range = str(fw_port_range)
                if '-' in fw_port_range:
                    range_ends = fw_port_range.split('-')
                    fw_port_min = int(range_ends[0])
                    fw_port_max = int(range_ends[1])
                else:
                    fw_port_min = int(fw_port_range)
                    fw_port_max = int(fw_port_range)
                if fw_port_min <= network_port.port <= fw_port_max:
                    return True
            return False

        relevant_rules_by_priority = collections.defaultdict(lambda: [])
        for firewall_rule in self.firewall_rules:
            firewall_network = network_type.Key.from_url(
                firewall_rule.network, project_id=firewall_rule.project_id)
            if firewall_network != network_port.network:
                continue

            if (firewall_rule.target_tags and
                    tag not in firewall_rule.target_tags):
                continue

            if firewall_rule.direction and firewall_rule.direction != 'INGRESS':
                continue

            relevant_rules_by_priority[firewall_rule.priority].append(
                firewall_rule)
        priorities = relevant_rules_by_priority.keys()
        priorities.sort(reverse=True)
        for priority in priorities:
            # DENY at a given priority takes precedence over ALLOW
            for firewall_rule in relevant_rules_by_priority[priority]:
                for allowed in firewall_rule.allowed or []:
                    if firewall_entry_applies(allowed):
                        allowed_sources.update(
                            firewall_rule.source_ranges or [])
                        allowed_sources.update(
                            firewall_rule.source_tags or [])
                        continue
            for firewall_rule in relevant_rules_by_priority[priority]:
                for denied in firewall_rule.denied or []:
                    if firewall_entry_applies(denied):
                        allowed_sources.difference_update(
                            firewall_rule.source_ranges or [])
                        allowed_sources.difference_update(
                            firewall_rule.source_tags or [])
        return allowed_sources

    def tags_for_instance_group(self, instance_group):
        """Which instance tags are used for an instance group?

        Includes tags used by instances in the group and, for managed
        groups, tags in the group's template.

        Args:
            instance_group (InstanceGroup): the group to query tags for

        Returns:
            set: tags
        """
        tags = set()

        # Get tags from actual instances.
        for instance_url in instance_group.instance_urls:
            instance = self.find_instance_by_url(instance_url)
            if not instance:
                continue
            tags.update(instance.tags.get('items', []))

        # If it's a managed instance group, also get tags from the
        # instance template.
        instance_template = self.instance_templates_by_group_key.get(
            instance_group.key)
        if instance_template:
            template_tags = instance_template.properties.get('tags', {})
            tags.update(template_tags.get('items', []))

        return tags

    def make_iap_resource(self, backend_service, project_full_name):
        """Get an IapResource for a service.

        Args:
            backend_service (BackendService): service to create a resource for
            project_full_name (str): The full path to the parent project
                including all ancestors.

        Returns:
            IapResource: the corresponding resource
        """
        alternate_services = set()
        direct_access_sources = set()
        for backend in backend_service.backends:
            instance_group = self.find_instance_group_by_url(
                backend.get('group'))
            if not instance_group:
                continue

            network_port = self.instance_group_network_port(
                backend_service, instance_group)

            if not network_port:
                continue

            direct_access_sources.update(
                self.firewall_allowed_sources(network_port, None))
            tags = self.tags_for_instance_group(instance_group)
            for tag in tags:
                direct_access_sources.update(
                    self.firewall_allowed_sources(
                        network_port, tag))

        # Don't count the load balancer as a direct access source.
        # The load balancer egress IPs are documented here:
        #     https://cloud.google.com/compute/docs/load-balancing/http/
        # (In theory they can change, but it's not common (since it's
        # a backwards-incompatible change for HTTP load balancer
        # customers.) 35.191/16 was recently announced; when Google
        # added that one, they sent out a mandatory service
        # announcement a year before the new range was used.)
        direct_access_sources.discard('130.211.0.0/22')
        direct_access_sources.discard('35.191.0.0/16')

        for backend_service2 in self.backend_services:
            if self.is_alternate_service(backend_service, backend_service2):
                alternate_services.add(backend_service2.key)

        return IapResource(
            project_full_name=project_full_name,
            backend_service=backend_service,
            alternate_services=alternate_services,
            direct_access_sources=direct_access_sources,
            iap_enabled=(backend_service.iap.get('enabled', False)
                         if backend_service.iap else False))

    def is_alternate_service(self, backend_service, backend_service2):
        """Do two backend services expose any of the same (instance, port) ?

        Args:
            backend_service (BackendService): One backend service
            backend_service2 (BackendService): The other backend service

        Returns:
            bool: whether the two services share any (instance, port)
        """
        if backend_service2.key == backend_service.key:
            return False
        for backend in backend_service.backends:
            instance_group = self.find_instance_group_by_url(
                backend.get('group'))
            if not instance_group:
                continue

            network_port = self.instance_group_network_port(
                backend_service, instance_group)
            if not network_port:
                continue

            for backend2 in backend_service2.backends:
                instance_group2 = self.find_instance_group_by_url(
                    backend2.get('group'))
                if not instance_group2:
                    continue
                network_port2 = self.instance_group_network_port(
                    backend_service2, instance_group2)
                if not network_port2:
                    continue
                if network_port != network_port2:
                    continue
                if instance_group == instance_group2:
                    return True
                for instance_url in instance_group.instance_urls:
                    if instance_url in instance_group2.instance_urls:
                        return True
            return False


class IapScanner(base_scanner.BaseScanner):
    """Pipeline to IAP-related data from DAO."""

    SCANNER_OUTPUT_CSV_FMT = 'scanner_output_iap.{}.csv'

    def __init__(self, global_configs, scanner_configs, service_config,
                 model_name, snapshot_timestamp, rules):
        """Initialization.

        Args:
            global_configs (dict): Global configurations.
            scanner_configs (dict): Scanner configurations.
            service_config (ServiceConfig): Forseti 2.0 service configs
            model_name (str): name of the data model
            snapshot_timestamp (str): The snapshot timestamp.
            rules (str): Fully-qualified path and filename of the rules file.
        """
        super(IapScanner, self).__init__(
            global_configs, scanner_configs, service_config, model_name,
            snapshot_timestamp, rules)
        self.rules_engine = iap_rules_engine.IapRulesEngine(
            rules_file_path=self.rules,
            snapshot_timestamp=self.snapshot_timestamp)
        self.rules_engine.build_rule_book(self.global_configs)
        self.scoped_session, self.data_access = (
            service_config.model_manager.get(model_name))

    @staticmethod
    def _flatten_violations(violations):
        """Flatten RuleViolations into a dict for each RuleViolation member.

        Args:
            violations (list): The RuleViolations to flatten.

        Yields:
            dict: Iterator of RuleViolations as a dict per member.
        """
        for violation in violations:
            alternate_services = ['%s/%s' % (bs_key.project_id, bs_key.name)
                                  for bs_key
                                  in violation.alternate_services_violations]
            alternate_services.sort()
            alternate_services_str = ', '.join(alternate_services)

            direct_access_sources = violation.direct_access_sources_violations
            direct_access_sources.sort()
            direct_access_str = ', '.join(direct_access_sources)

            violation_data = {
                'alternate_services_violations': alternate_services_str,
                'direct_access_sources_violations': direct_access_str,
                'iap_enabled_violation': str(violation.iap_enabled_violation),
                'resource_name': violation.resource_name
            }

            yield {
                'resource_id': violation.resource_id,
                'resource_name': violation.resource_name,
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

    def _get_backend_services(self, parent_type_name):
        """Retrieves backend services.

        Args:
            parent_type_name (str): The parent resource type and name to pull.

        Returns:
            list: BackendService
        """
        backend_services = []
        with self.scoped_session as session:
            for backend_service in self.data_access.scanner_iter(
                    session, 'backendservice',
                    parent_type_name=parent_type_name):
                backend_services.append(
                    backend_service_type.BackendService.from_json(
                        full_name=backend_service.full_name,
                        project_id=backend_service.parent.name,
                        json_string=backend_service.data))
        return backend_services

    def _get_firewall_rules(self, parent_type_name):
        """Retrieves firewall rules.

        Args:
            parent_type_name (str): The parent resource type and name to pull.

        Returns:
            list: FirewallRule
        """
        firewall_rules = []
        with self.scoped_session as session:
            for firewall_rule in self.data_access.scanner_iter(
                    session, 'firewall', parent_type_name=parent_type_name):
                firewall_rules.append(
                    firewall_rule_type.FirewallRule.from_json(
                        project_id=firewall_rule.parent.name,
                        json_string=firewall_rule.data))
        return firewall_rules

    def _get_instances(self, parent_type_name):
        """Retrieves instances.

        Args:
            parent_type_name (str): The parent resource type and name to pull.

        Returns:
            list: Instance
        """
        instances = []
        with self.scoped_session as session:
            for instance in self.data_access.scanner_iter(
                    session, 'instance', parent_type_name=parent_type_name):
                project = project_type.Project(
                    project_id=instance.parent.name,
                    full_name=instance.parent.full_name,
                )
                instances.append(
                    instance_type.Instance.from_json(
                        parent=project,
                        json_string=instance.data))
        return instances

    def _get_instance_groups(self, parent_type_name):
        """Retrieves instance groups.

        Args:
            parent_type_name (str): The parent resource type and name to pull.

        Returns:
            list: InstanceGroup
        """
        instance_groups = []
        with self.scoped_session as session:
            for instance_group in self.data_access.scanner_iter(
                    session, 'instancegroup',
                    parent_type_name=parent_type_name):
                instance_groups.append(
                    instance_group_type.InstanceGroup.from_json(
                        project_id=instance_group.parent.name,
                        json_string=instance_group.data))
        return instance_groups

    def _get_instance_group_managers(self, parent_type_name):
        """Retrieves instance group managers.

        Args:
            parent_type_name (str): The parent resource type and name to pull.

        Returns:
            list: InstanceGroupManager
        """
        instance_group_managers = []
        with self.scoped_session as session:
            for instance_group_manager in self.data_access.scanner_iter(
                    session, 'instancegroupmanager',
                    parent_type_name=parent_type_name):
                instance_group_managers.append(
                    instance_group_manager_type.InstanceGroupManager.from_json(
                        project_id=instance_group_manager.parent.name,
                        json_string=instance_group_manager.data))
        return instance_group_managers

    def _get_instance_templates(self, parent_type_name):
        """Retrieves instance templates.

        Args:
            parent_type_name (str): The parent resource type and name to pull.

        Returns:
            list: InstanceTemplate
        """
        instance_templates = []
        with self.scoped_session as session:
            for instance_template in self.data_access.scanner_iter(
                    session, 'instancetemplate',
                    parent_type_name=parent_type_name):
                instance_templates.append(
                    instance_template_type.InstanceTemplate.from_json(
                        project_id=instance_template.parent.name,
                        json_string=instance_template.data))
        return instance_templates

    def _retrieve(self):
        """Retrieves the data for the scanner.

        Yields:
            list: A list of IAP Resources for a project, to pass to the rules
                engine
            dict: A dict of resource counts for the project.
        """
        projects = []
        with self.scoped_session as session:
            for project in self.data_access.scanner_iter(session, 'project'):
                projects.append(project)

        for parent in projects:
            backend_services = self._get_backend_services(parent.type_name)
            firewall_rules = self._get_firewall_rules(parent.type_name)
            instances = self._get_instances(parent.type_name)
            instance_groups = self._get_instance_groups(parent.type_name)
            instance_group_managers = self._get_instance_group_managers(
                parent.type_name)
            instance_templates = self._get_instance_templates(parent.type_name)

            run_data = _RunData(
                backend_services=backend_services,
                firewall_rules=firewall_rules,
                instances=instances,
                instance_groups=instance_groups,
                instance_group_managers=instance_group_managers,
                instance_templates=instance_templates)

            iap_resources = []
            for backend in backend_services:
                iap_resources.append(
                    run_data.make_iap_resource(backend, parent.full_name))
            yield iap_resources, run_data.resource_counts

    def _find_violations(self, iap_data):
        """Find IAP violations.

        Args:
            iap_data (iter): Generator of IAP resources and resource counts
                per project in the inventory.

        Returns:
            list: RuleViolation
        """
        LOGGER.info('Finding IAP violations with %r...',
                    self.rules_engine)
        ret = []
        resource_counts = collections.defaultdict(int)
        for (iap_resources, project_resource_counts) in iap_data:
            for iap_resource in iap_resources:
                ret.extend(self.rules_engine.find_violations(iap_resource))

            for key, value in project_resource_counts.items():
                resource_counts[key] += value

        LOGGER.debug('find_violations returning %r', ret)
        return ret, dict(resource_counts)

    def run(self):
        """Runs the data collection."""

        LOGGER.debug('In run')
        iap_data = self._retrieve()
        all_violations, _ = self._find_violations(iap_data)
        self._output_results(all_violations)
