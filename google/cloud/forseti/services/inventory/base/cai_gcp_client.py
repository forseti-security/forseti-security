# Copyright 2018 The Forseti Security Authors. All rights reserved.
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
"""Cloud Asset and GCP API hybrid client fassade."""

# pylint: disable=too-many-lines

import itertools
import os

from google.cloud.forseti.common.util import logger
from google.cloud.forseti.services.inventory.base import gcp
from google.cloud.forseti.services.inventory.base import iam_helpers
from google.cloud.forseti.services.inventory.cai_temporary_storage import (
    CaiDataAccess)
from google.cloud.forseti.services.inventory.cai_temporary_storage import (
    ContentTypes)

LOGGER = logger.get_logger(__name__)


def _fixup_resource_keys(resource, key_map, only_fixup_lists=False):
    """Correct different attribute names between CAI and json representation.
    Args:
        resource (dict): The resource dictionary to scan for keys in the
            key_map.
        key_map (dict): A map of bad_key:good_key pairs, any instance of bad_key
            in the resource dict is replaced with an instance of good_key.
        only_fixup_lists (bool): If true, only keys that have values which are
            lists will be fixed. This allows the case where there is the same
            key used for both a scalar entry and a list entry, and only the
            list entry should change to the different key.
    Returns:
        dict: A resource dict with all bad keys replaced with good keys.
    """
    fixed_resource = {}
    for key, value in list(resource.items()):
        if isinstance(value, dict):
            # Recursively fix keys in sub dictionaries.
            value = _fixup_resource_keys(value, key_map)
        elif isinstance(value, list):
            # Recursively fix keys in sub dictionaries in lists.
            new_value = []
            for item in value:
                if isinstance(item, dict):
                    item = _fixup_resource_keys(item, key_map)
                new_value.append(item)
            value = new_value

        # Only replace the old key with the new key if the value of the field
        # is a list. This behavior can be overridden by setting the optional
        # argument only_fixup_lists to False.
        should_update_key = bool(
            not only_fixup_lists or isinstance(value, list))
        if key in key_map and should_update_key:
            fixed_resource[key_map[key]] = value
        else:
            fixed_resource[key] = value

    return fixed_resource


# pylint: disable=too-many-public-methods
class CaiApiClientImpl(gcp.ApiClientImpl):
    """The gcp api client Implementation"""

    def __init__(self, config, engine, tmpfile):
        """Initialize.

        Args:
            config (dict): GCP API client configuration.
            engine (object): Database engine to operate on.
            tmpfile (str): The temporary file storing the cai sqlite database.
        """
        super(CaiApiClientImpl, self).__init__(config)
        self.dao = CaiDataAccess()
        self.engine = engine
        self.tmpfile = tmpfile

    def __del__(self):
        """Destructor."""
        if os.path.exists(self.tmpfile):
            os.unlink(self.tmpfile)

    def fetch_bigquery_iam_policy(self, project_id, project_number, dataset_id):
        """Gets IAM policy of a bigquery dataset from Cloud Asset data.

        Args:
            project_id (str): id of the project to query.
            project_number (str): number of the project to query.
            dataset_id (str): id of the dataset to query.

        Returns:
            dict: Dataset IAM Policy.
        """
        bigquery_name_fmt = '//bigquery.googleapis.com/projects/{}/datasets/{}'

        # Try fetching with project id, if that returns nothing, fall back to
        # project number.
        resource, meta_data = self.dao.fetch_cai_asset(
            ContentTypes.iam_policy,
            'bigquery.googleapis.com/Dataset',
            bigquery_name_fmt.format(project_id, dataset_id),
            self.engine)

        if not resource:
            resource, meta_data = self.dao.fetch_cai_asset(
                ContentTypes.iam_policy,
                'bigquery.googleapis.com/Dataset',
                bigquery_name_fmt.format(project_number, dataset_id),
                self.engine)

        if resource:
            return resource, meta_data

        return {}, None

    def fetch_bigquery_dataset_policy(self, project_id, project_number,
                                      dataset_id):
        """Dataset policy Iterator for a dataset from Cloud Asset data.

        Args:
            project_id (str): id of the project to query.
            project_number (str): number of the project to query.
            dataset_id (str): id of the dataset to query.

        Returns:
            dict: Dataset Policy.
        """

        resource, metadata = self.fetch_bigquery_iam_policy(
            project_id, project_number, dataset_id)

        if resource:
            return (iam_helpers.convert_iam_to_bigquery_policy(resource),
                    metadata)

        return {}, None

    def iter_bigquery_datasets(self, project_number):
        """Iterate Datasets from Cloud Asset data.

        Args:
            project_number (str): number of the project to query.

        Yields:
            dict: Generator of datasets.
        """

        resources = self.dao.iter_cai_assets(
            ContentTypes.resource,
            'bigquery.googleapis.com/Dataset',
            '//cloudresourcemanager.googleapis.com/projects/{}'.format(
                project_number),
            self.engine)

        for dataset in resources:
            yield dataset

    def iter_bigquery_tables(self, dataset_reference):
        """Iterate Tables from Cloud Asset data.

         Args:
            dataset_reference (dict): dataset to reference.

         Yields:
            dict: Generator of tables.
        """

        bigquery_name_fmt = '//bigquery.googleapis.com/projects/{}/datasets/{}'

        resources = self.dao.iter_cai_assets(
            ContentTypes.resource,
            'bigquery.googleapis.com/Table',
            bigquery_name_fmt.format(
                dataset_reference['projectId'], dataset_reference['datasetId']),
            self.engine)

        for table in resources:
            yield table

    def iter_bigtable_clusters(self, project_id, instance_id):
        """Iterate Bigtable Clusters from Cloud Asset data.

        Args:
            project_id (str): The Project id.
            instance_id (str): The Bigtable Instance id.

        Yields:
            dict: Generator of Bigtable Clusters.
        """

        resources = self.dao.iter_cai_assets(
            ContentTypes.resource,
            'bigtableadmin.googleapis.com/Cluster',
            '//bigtable.googleapis.com/projects/{}/instances/{}'.format(
                project_id, instance_id),
            self.engine)

        for cluster in resources:
            yield cluster

    def iter_bigtable_instances(self, project_number):
        """Iterate Bigtable Instances from Cloud Asset data.

        Args:
            project_number (str): The project number.

        Yields:
            dict: Generator of Bigtable Instances.
        """

        resources = self.dao.iter_cai_assets(
            ContentTypes.resource,
            'bigtableadmin.googleapis.com/Instance',
            '//cloudresourcemanager.googleapis.com/projects/{}'.format(
                project_number),
            self.engine)

        for instance in resources:
            yield instance

    def iter_bigtable_tables(self, project_id, instance_id):
        """Iterate Bigtable Table from Cloud Asset data.

        Args:
            project_id (str): The Project id.
            instance_id (str): The Bigtable Instance id.

        Yields:
            dict: Generator of Bigtable Tables.
        """

        resources = self.dao.iter_cai_assets(
            ContentTypes.resource,
            'bigtableadmin.googleapis.com/Table',
            '//bigtable.googleapis.com/projects/{}/instances/{}'.format(
                project_id, instance_id),
            self.engine)

        for cluster in resources:
            yield cluster

    def fetch_billing_account_iam_policy(self, account_id):
        """Gets IAM policy of a Billing Account from Cloud Asset data.

        Args:
            account_id (str): id of the billing account to get policy.

        Returns:
            dict: Billing Account IAM policy.
        """
        resource = self.dao.fetch_cai_asset(
            ContentTypes.iam_policy,
            'cloudbilling.googleapis.com/BillingAccount',
            '//cloudbilling.googleapis.com/{}'.format(account_id),
            self.engine)
        if resource:
            return resource

        return {}, None

    def iter_billing_accounts(self):
        """Iterate Billing Accounts in an organization from Cloud Asset data.

        Yields:
            dict: Generator of billing accounts.
        """
        resources = self.dao.iter_cai_assets(
            ContentTypes.resource,
            'cloudbilling.googleapis.com/BillingAccount',
            '',  # Billing accounts have no parent resource.
            self.engine)
        for account in resources:
            yield account

    def iter_cloudsql_instances(self, project_id, project_number):
        """Iterate Cloud sql instances from Cloud Asset data.

        Args:
            project_id (str): id of the project to query.
            project_number (str): number of the project to query.

        Yields:
            dict: Generator of cloudsql instances.
        """
        resources = list(self.dao.iter_cai_assets(
            ContentTypes.resource,
            'sqladmin.googleapis.com/Instance',
            '//cloudresourcemanager.googleapis.com/projects/{}'.format(
                project_number),
            self.engine))
        if not resources:
            # CloudSQL instances may not have parent data from CAI.
            resources = list(self.dao.iter_cai_assets(
                ContentTypes.resource,
                'sqladmin.googleapis.com/Instance',
                '//cloudsql.googleapis.com/projects/{}'.format(project_id),
                self.engine))

        for instance in resources:
            yield instance

    def _iter_compute_resources(self, asset_type, project_number):
        """Iterate Compute resources from Cloud Asset data.

        Args:
            asset_type (str): The Compute asset type to iterate.
            project_number (str): number of the project to query.

        Returns:
            generator: A generator of resources from Cloud Asset data.
        """
        return self.dao.iter_cai_assets(
            ContentTypes.resource,
            'compute.googleapis.com/{}'.format(asset_type),
            '//cloudresourcemanager.googleapis.com/projects/{}'.format(
                project_number),
            self.engine)

    def iter_compute_address(self, project_number):
        """Iterate Addresses from Cloud Asset data.

        Args:
            project_number (str): number of the project to query.

        Yields:
            dict: Generator of address resources.
        """
        cai_to_gcp_key_map = {
            'user': 'users',
        }

        address_resources = self._iter_compute_resources('Address',
                                                         project_number)

        global_address_resources = self._iter_compute_resources('GlobalAddress',
                                                                project_number)

        resources = itertools.chain(address_resources, global_address_resources)

        for address, metadata in resources:
            yield (
                _fixup_resource_keys(address, cai_to_gcp_key_map),
                metadata)

    def iter_compute_autoscalers(self, project_number):
        """Iterate Autoscalers from Cloud Asset data.

        Args:
            project_number (str): number of the project to query.

        Yields:
            dict: Generator of autoscaler resources.
        """
        resources = self._iter_compute_resources('Autoscaler', project_number)
        for autoscaler in resources:
            yield autoscaler

    def iter_compute_backendbuckets(self, project_number):
        """Iterate Backend buckets from Cloud Asset data.

        Args:
            project_number (str): number of the project to query.

        Yields:
            dict: Generator of backend bucket resources.
        """
        resources = self._iter_compute_resources('BackendBucket',
                                                 project_number)
        for backendbucket in resources:
            yield backendbucket

    def iter_compute_backendservices(self, project_number):
        """Iterate Backend services from Cloud Asset data.

        Args:
            project_number (str): number of the project to query.

        Yields:
            dict: Generator of backend service.
        """
        backendservice = self._iter_compute_resources('BackendService',
                                                      project_number)

        region_backendservice = self._iter_compute_resources(
            'RegionBackendService', project_number)

        resources = itertools.chain(backendservice, region_backendservice)

        for backendservice in resources:
            yield backendservice

    def iter_compute_disks(self, project_number):
        """Iterate Compute Engine disks from Cloud Asset data.

        Args:
            project_number (str): number of the project to query.

        Yields:
            dict: Generator of Compute Disk.
        """
        disks = self._iter_compute_resources('Disk', project_number)

        region_disks = self._iter_compute_resources('RegionDisk',
                                                    project_number)

        resources = itertools.chain(disks, region_disks)

        for disk in resources:
            yield disk

    def iter_compute_firewalls(self, project_number):
        """Iterate Compute Engine Firewalls from Cloud Asset data.

        Args:
            project_number (str): number of the project to query.

        Yields:
            dict: Generator of Compute Engine Firewall.
        """
        resources = self._iter_compute_resources('Firewall', project_number)
        for rule in resources:
            yield rule

    def iter_compute_forwardingrules(self, project_number):
        """Iterate Forwarding Rules from Cloud Asset data.

        Args:
            project_number (str): number of the project to query.

        Yields:
            dict: Generator of forwarding rule resources.
        """
        forwardingrule_resources = self._iter_compute_resources(
            'ForwardingRule', project_number)

        global_forwardingrule_resources = self._iter_compute_resources(
            'GlobalForwardingRule', project_number)

        resources = itertools.chain(forwardingrule_resources,
                                    global_forwardingrule_resources)

        for forwarding_rule in resources:
            yield forwarding_rule

    def iter_compute_healthchecks(self, project_number):
        """Iterate Health checks from Cloud Asset data.

        Args:
            project_number (str): number of the project to query.

        Yields:
            dict: Generator of health check resources.
        """
        resources = self._iter_compute_resources('HealthCheck', project_number)
        for healthcheck in resources:
            yield healthcheck

    def iter_compute_httphealthchecks(self, project_number):
        """Iterate HTTP Health checks from Cloud Asset data.

        Args:
            project_number (str): number of the project to query.

        Yields:
            dict: Generator of HTTP health check resources.
        """
        resources = self._iter_compute_resources('HttpHealthCheck',
                                                 project_number)
        for httphealthcheck in resources:
            yield httphealthcheck

    def iter_compute_httpshealthchecks(self, project_number):
        """Iterate HTTPS Health checks from Cloud Asset data.

        Args:
            project_number (str): number of the project to query.

        Yields:
            dict: Generator of HTTPS health check resources.
        """
        resources = self._iter_compute_resources('HttpsHealthCheck',
                                                 project_number)
        for httpshealthcheck in resources:
            yield httpshealthcheck

    def iter_compute_ig_managers(self, project_number):
        """Iterate Instance Group Manager from Cloud Asset data.

        Args:
            project_number (str): number of the project to query.

        Yields:
            dict: Generator of instance group manager resources.
        """
        resources = self._iter_compute_resources('InstanceGroupManager',
                                                 project_number)
        for igmanager in resources:
            yield igmanager

    def iter_compute_images(self, project_number):
        """Iterate Images from Cloud Asset data.

        Args:
            project_number (str): number of the project to query.

        Yields:
            dict: Generator of image resources.
        """
        resources = self._iter_compute_resources('Image', project_number)
        for image in resources:
            yield image

    def iter_compute_instancegroups(self, project_number):
        """Iterate Compute Engine groups from Cloud Asset data.

        Args:
            project_number (str): number of the project to query.

        Yields:
            dict: Generator of Compute Instance group.
        """
        resources = self._iter_compute_resources('InstanceGroup',
                                                 project_number)
        for instancegroup in resources:
            yield instancegroup

    def iter_compute_instances(self, project_number):
        """Iterate compute engine instance from Cloud Asset data.

        Args:
            project_number (str): number of the project to query.

        Yields:
            dict: Generator of Compute Engine Instance resources.
        """
        resources = self._iter_compute_resources('Instance', project_number)
        for instance in resources:
            yield instance

    def iter_compute_instancetemplates(self, project_number):
        """Iterate Instance Templates from Cloud Asset data.

        Args:
            project_number (str): number of the project to query.

        Yields:
            dict: Generator of instance template resources.
        """
        resources = self._iter_compute_resources('InstanceTemplate',
                                                 project_number)
        for instancetemplate in resources:
            yield instancetemplate

    def iter_compute_interconnects(self, project_number):
        """Iterate Interconnects from Cloud Asset data.

        Args:
            project_number (str): number of the project to query.

        Yields:
            dict: Generator of instance interconnect resources.
        """

        interconnect_resources = self._iter_compute_resources('Interconnect',
                                                              project_number)

        for interconnect in interconnect_resources:
            yield interconnect

    def iter_compute_interconnect_attachments(self, project_number):
        """Iterate Interconnect Attachments from Cloud Asset data.

        Args:
            project_number (str): number of the project to query.

        Yields:
            dict: Generator of instance interconnect attachment resources.
        """

        attachment_resources = self._iter_compute_resources(
            'InterconnectAttachment',
            project_number)

        for attachment in attachment_resources:
            yield attachment

    def iter_compute_licenses(self, project_number):
        """Iterate Licenses from Cloud Asset data.

        Args:
            project_number (str): number of the project to query.

        Yields:
            dict: Generator of license resources.
        """
        resources = self._iter_compute_resources('License', project_number)
        for compute_license in resources:
            yield compute_license

    def iter_compute_networks(self, project_number):
        """Iterate Networks from Cloud Asset data.

        Args:
            project_number (str): number of the project to query.

        Yields:
            dict: Generator of network resources.
        """
        resources = self._iter_compute_resources('Network', project_number)
        for network in resources:
            yield network

    def iter_compute_project(self, project_number):
        """Iterate Project from Cloud Asset data.

        Will only ever return up to 1 result. Ensures compatibility with other
        resource iterators.

        Args:
            project_number (str): number of the project to query.

        Yields:
            dict: Generator of compute project resources.
        """
        resources = self._iter_compute_resources('Project', project_number)
        for project in resources:
            yield project

    def iter_compute_routers(self, project_number):
        """Iterate Compute Engine routers from Cloud Asset data.

        Args:
            project_number (str): number of the project to query.

        Yields:
            dict: Generator of Compute Routers.
        """
        resources = self._iter_compute_resources('Router', project_number)
        for router in resources:
            yield router

    def iter_compute_securitypolicies(self, project_number):
        """Iterate Security Policies from Cloud Asset data.

        Args:
            project_number (str): number of the project to query.

        Yields:
            dict: Generator of instance Security Policies.
        """

        securitypolicies = self._iter_compute_resources('SecurityPolicy',
                                                        project_number)

        for securitypolicy in securitypolicies:
            yield securitypolicy

    def iter_compute_snapshots(self, project_number):
        """Iterate Compute Engine snapshots from Cloud Asset data.

        Args:
            project_number (str): number of the project to query.

        Yields:
            dict: Generator of Compute Snapshots.
        """
        resources = self._iter_compute_resources('Snapshot', project_number)
        for snapshot in resources:
            yield snapshot

    def iter_compute_sslcertificates(self, project_number):
        """Iterate SSL certificates from Cloud Asset data.

        Args:
            project_number (str): number of the project to query.

        Yields:
            dict: Generator of ssl certificate resources.
        """
        resources = self._iter_compute_resources('SslCertificate',
                                                 project_number)
        for sslcertificate in resources:
            yield sslcertificate

    def iter_compute_subnetworks(self, project_number):
        """Iterate Subnetworks from Cloud Asset data.

        Args:
            project_number (str): number of the project to query.

        Yields:
            dict: Generator of subnetwork resources.
        """
        resources = self._iter_compute_resources('Subnetwork',
                                                 project_number)
        for subnetwork in resources:
            yield subnetwork

    def iter_compute_targethttpproxies(self, project_number):
        """Iterate Target HTTP proxies from Cloud Asset data.

        Args:
            project_number (str): number of the project to query.

        Yields:
            dict: Generator of target http proxy resources.
        """
        resources = self._iter_compute_resources('TargetHttpProxy',
                                                 project_number)
        for targethttpproxy in resources:
            yield targethttpproxy

    def iter_compute_targethttpsproxies(self, project_number):
        """Iterate Target HTTPS proxies from Cloud Asset data.

        Args:
            project_number (str): number of the project to query.

        Yields:
            dict: Generator of target https proxy resources.
        """
        resources = self._iter_compute_resources('TargetHttpsProxy',
                                                 project_number)
        for targethttpsproxy in resources:
            yield targethttpsproxy

    def iter_compute_targetinstances(self, project_number):
        """Iterate Target Instances from Cloud Asset data.

        Args:
            project_number (str): number of the project to query.

        Yields:
            dict: Generator of target instance resources.
        """
        resources = self._iter_compute_resources('TargetInstance',
                                                 project_number)
        for targetinstance in resources:
            yield targetinstance

    def iter_compute_targetpools(self, project_number):
        """Iterate Target Pools from Cloud Asset data.

        Args:
            project_number (str): number of the project to query.

        Yields:
            dict: Generator of target pool resources.
        """
        resources = self._iter_compute_resources('TargetPool', project_number)
        for targetpool in resources:
            yield targetpool

    def iter_compute_targetsslproxies(self, project_number):
        """Iterate Target SSL proxies from Cloud Asset data.

        Args:
            project_number (str): number of the project to query.

        Yields:
            dict: Generator of target ssl proxy resources.
        """
        resources = self._iter_compute_resources('TargetSslProxy',
                                                 project_number)
        for targetsslproxy in resources:
            yield targetsslproxy

    def iter_compute_targettcpproxies(self, project_number):
        """Iterate Target TCP proxies from Cloud Asset data.

        Args:
            project_number (str): number of the project to query.

        Yields:
            dict: Generator of target tcp proxy resources.
        """
        resources = self._iter_compute_resources('TargetTcpProxy',
                                                 project_number)
        for targettcpproxy in resources:
            yield targettcpproxy

    def iter_compute_targetvpngateways(self, project_number):
        """Iterate Target VPN Gateways from Cloud Asset data.

        Args:
            project_number (str): number of the project to query.

        Yields:
            dict: Generator of target tcp proxy resources.
        """
        resources = self._iter_compute_resources('TargetVpnGateway',
                                                 project_number)
        for targetvpngateway in resources:
            yield targetvpngateway

    def iter_compute_urlmaps(self, project_number):
        """Iterate URL maps from Cloud Asset data.

        Args:
            project_number (str): number of the project to query.

        Yields:
            dict: Generator of url map resources.
        """
        resources = self._iter_compute_resources('UrlMap', project_number)
        for urlmap in resources:
            yield urlmap

    def iter_compute_vpntunnels(self, project_number):
        """Iterate VPN tunnels from Cloud Asset data.

        Args:
            project_number (str): number of the project to query.

        Yields:
            dict: Generator of vpn tunnel resources.
        """
        resources = self._iter_compute_resources('VpnTunnel', project_number)
        for vpntunnel in resources:
            yield vpntunnel

    def iter_container_clusters(self, project_number):
        """Iterate Kubernetes Engine Cluster from Cloud Asset data.

        Args:
            project_number (str): number of the project to query.

        Yields:
            dict: Generator of Kubernetes Engine Cluster resources.
        """
        resources = self.dao.iter_cai_assets(
            ContentTypes.resource,
            'container.googleapis.com/Cluster',
            '//cloudresourcemanager.googleapis.com/projects/{}'.format(
                project_number),
            self.engine)
        for cluster in resources:
            yield cluster

    def fetch_crm_folder(self, folder_id):
        """Fetch Folder data from Cloud Asset data.

        Args:
            folder_id (str): id of the folder to query.

        Returns:
            dict: Folder resource.
        """
        resource = self.dao.fetch_cai_asset(
            ContentTypes.resource,
            'cloudresourcemanager.googleapis.com/Folder',
            '//cloudresourcemanager.googleapis.com/{}'.format(folder_id),
            self.engine)
        if resource:
            return resource

        return {}, None

    def fetch_crm_folder_iam_policy(self, folder_id):
        """Folder IAM policy in a folder from Cloud Asset data.

        Args:
            folder_id (str): id of the folder to get policy.

        Returns:
            dict: Folder IAM policy.
        """
        resource = self.dao.fetch_cai_asset(
            ContentTypes.iam_policy,
            'cloudresourcemanager.googleapis.com/Folder',
            '//cloudresourcemanager.googleapis.com/{}'.format(folder_id),
            self.engine)
        if resource:
            return resource

        return {}, None

    def fetch_crm_organization(self, org_id):
        """Fetch Organization data from Cloud Asset data.

        Args:
            org_id (str): id of the organization to get.

        Returns:
            dict: Organization resource.
        """
        resource = self.dao.fetch_cai_asset(
            ContentTypes.resource,
            'cloudresourcemanager.googleapis.com/Organization',
            '//cloudresourcemanager.googleapis.com/{}'.format(org_id),
            self.engine)
        if resource:
            return resource

        return {}, None

    def fetch_crm_organization_iam_policy(self, org_id):
        """Organization IAM policy from Cloud Asset data.

        Args:
            org_id (str): id of the organization to get policy.

        Returns:
            dict: Organization IAM policy.
        """
        resource = self.dao.fetch_cai_asset(
            ContentTypes.iam_policy,
            'cloudresourcemanager.googleapis.com/Organization',
            '//cloudresourcemanager.googleapis.com/{}'.format(org_id),
            self.engine)
        if resource:
            return resource

        return {}, None

    def fetch_crm_project(self, project_number):
        """Fetch Project data from Cloud Asset data.

        Args:
            project_number (str): number of the project to query.

        Returns:
            dict: Project resource.
        """
        resource = self.dao.fetch_cai_asset(
            ContentTypes.resource,
            'cloudresourcemanager.googleapis.com/Project',
            '//cloudresourcemanager.googleapis.com/projects/{}'.format(
                project_number),
            self.engine)
        if resource:
            return resource

        return {}, None

    def fetch_crm_project_iam_policy(self, project_number):
        """Project IAM policy from Cloud Asset data.

        Args:
            project_number (str): number of the project to query.

        Returns:
            dict: Project IAM Policy.
        """
        resource = self.dao.fetch_cai_asset(
            ContentTypes.iam_policy,
            'cloudresourcemanager.googleapis.com/Project',
            '//cloudresourcemanager.googleapis.com/projects/{}'.format(
                project_number),
            self.engine)
        if resource:
            return resource

        return {}, None

    def iter_crm_folders(self, parent_id):
        """Iterate Folders from Cloud Asset data.

        Args:
            parent_id (str): id of the parent of the folder

        Yields:
            dict: Generator of folders
        """
        resources = self.dao.iter_cai_assets(
            ContentTypes.resource,
            'cloudresourcemanager.googleapis.com/Folder',
            '//cloudresourcemanager.googleapis.com/{}'.format(parent_id),
            self.engine)
        for folder in resources:
            yield folder

    def iter_kubernetes_nodes(self, project_id, zone, cluster):
        """Iterate k8s nodes in a cluster from Cloud Asset data.

        Args:
            project_id (str): id of the project to query.
            zone (str): The zone the cluster is in.
            cluster (str): The cluster name.

        Yields:
            dict: Generator of nodes.
        """
        resources = self.dao.iter_cai_assets(
            ContentTypes.resource,
            'k8s.io/Node',
            '//container.googleapis.com/projects/{}/zones/{}/clusters/{}'
            .format(project_id, zone, cluster),
            self.engine)
        for node in resources:
            yield node

    def iter_kubernetes_pods(self, project_id, zone, cluster, namespace):
        """Iterate k8s pods in a namespace from Cloud Asset data.

        Args:
            project_id (str): id of the project to query.
            zone (str): The zone the cluster is in.
            cluster (str): The cluster name.;
            namespace (str): The namespace name.

        Yields:
            dict: Generator of pods.
        """
        resources = self.dao.iter_cai_assets(
            ContentTypes.resource,
            'k8s.io/Pod',
            '//container.googleapis.com/projects/{}/zones/{}/clusters/{}/k8s/'
            'namespaces/{}'.format(project_id, zone, cluster, namespace),
            self.engine)
        for pod in resources:
            yield pod

    def iter_kubernetes_namespaces(self, project_id, zone, cluster):
        """Iterate k8s namespaces in a cluster from Cloud Asset data.

        Args:
            project_id (str): id of the project to query.
            zone (str): The zone the cluster is in.
            cluster (str): The cluster name.

        Yields:
            dict: Generator of namespaces.
        """
        resources = self.dao.iter_cai_assets(
            ContentTypes.resource,
            'k8s.io/Namespace',
            '//container.googleapis.com/projects/{}/zones/{}/clusters/{}'
            .format(project_id, zone, cluster),
            self.engine)
        for namespace in resources:
            yield namespace

    def iter_kubernetes_roles(self, project_id, zone, cluster, namespace):
        """Iterate k8s roles in a namespace from Cloud Asset data.

        Args:
            project_id (str): id of the project to query.
            zone (str): The zone the cluster is in.
            cluster (str): The cluster name.
            namespace (str): The namespace name.

        Yields:
            dict: Generator of roles.
        """
        resources = self.dao.iter_cai_assets(
            ContentTypes.resource,
            'rbac.authorization.k8s.io/Role',
            '//container.googleapis.com/projects/{}/zones/{}/clusters/{}/k8s/'
            'namespaces/{}'.format(project_id, zone, cluster, namespace),
            self.engine)
        for role in resources:
            yield role

    def iter_kubernetes_rolebindings(self,
                                     project_id,
                                     zone,
                                     cluster,
                                     namespace):
        """Iterate k8s role bindings in a namespace from Cloud Asset data.

        Args:
            project_id (str): id of the project to query.
            zone (str): The zone the cluster is in.
            cluster (str): The cluster name.
            namespace (str): The namespace name.

        Yields:
            dict: Generator of role bindings.
        """
        resources = self.dao.iter_cai_assets(
            ContentTypes.resource,
            'rbac.authorization.k8s.io/RoleBinding',
            '//container.googleapis.com/projects/{}/zones/{}/clusters/{}/k8s/'
            'namespaces/{}'.format(project_id, zone, cluster, namespace),
            self.engine)
        for role_binding in resources:
            yield role_binding

    def iter_kubernetes_clusterroles(self, project_id, zone, cluster):
        """Iterate k8s cluster roles in a cluster from Cloud Asset data.

        Args:
            project_id (str): id of the project to query.
            zone (str): The zone the cluster is in.
            cluster (str): The cluster name.

        Yields:
            dict: Generator of cluster roles.
        """
        resources = self.dao.iter_cai_assets(
            ContentTypes.resource,
            'rbac.authorization.k8s.io/ClusterRole',
            '//container.googleapis.com/projects/{}/zones/{}/clusters/{}'
            .format(project_id, zone, cluster),
            self.engine)
        for cluster_role in resources:
            yield cluster_role

    def iter_kubernetes_clusterrolebindings(self, project_id, zone, cluster):
        """Iterate k8s cluster role bindings in a cluster from Cloud Asset data.

        Args:
            project_id (str): id of the project to query.
            zone (str): The zone the cluster is in.
            cluster (str): The cluster name.

        Yields:
            dict: Generator of cluster role bindings.
        """
        resources = self.dao.iter_cai_assets(
            ContentTypes.resource,
            'rbac.authorization.k8s.io/ClusterRoleBinding',
            '//container.googleapis.com/projects/{}/zones/{}/clusters/{}'
            .format(project_id, zone, cluster),
            self.engine)
        for cluster_role_binding in resources:
            yield cluster_role_binding

    def iter_crm_projects(self, parent_type, parent_id):
        """Iterate Projects from Cloud Asset data.

        Args:
            parent_type (str): type of the parent, "folder" or "organization".
            parent_id (str): id of the parent of the folder.

        Yields:
            dict: Generator of Project resources
        """
        resources = self.dao.iter_cai_assets(
            ContentTypes.resource,
            'cloudresourcemanager.googleapis.com/Project',
            '//cloudresourcemanager.googleapis.com/{}s/{}'.format(parent_type,
                                                                  parent_id),
            self.engine)
        for project in resources:
            yield project

    def iter_crm_organization_access_policies(self, org_id):
        """Iterate access policies in an organization from Cloud Asset data.

        Args:
            org_id (str): id of the organization to get the Policy.

        Yields:
            dict: Generator of access policies for an organization.
        """
        resources = self.dao.iter_cai_assets(
            ContentTypes.access_policy,
            'cloudresourcemanager.googleapis.com/Organization',
            '//cloudresourcemanager.googleapis.com/{}'.format(org_id),
            self.engine)
        for access_policy in resources:
            yield access_policy

    def iter_crm_organization_access_levels(self, access_policy_id):
        """Iterate access levels from Cloud Asset data.

        Args:
            access_policy_id (str): id of the policy.

        Yields:
            dict: Generator of access levels in an organization.
        """
        resources = self.dao.iter_cai_assets(
            ContentTypes.access_level,
            'cloudresourcemanager.googleapis.com/Organization',
            access_policy_id,
            self.engine)
        for access_level in resources:
            yield access_level

    # pylint: disable=using-constant-test,inconsistent-return-statements
    def fetch_crm_organization_service_perimeter(self, access_policy_id):
        """Gets service perimeter from Cloud Asset data.

        Args:
            access_policy_id (str): id of the policy.

        Returns:
            dict: Service Perimeter resource.
        """
        resource = self.dao.iter_cai_assets(
            ContentTypes.service_perimeter,
            'cloudresourcemanager.googleapis.com/Organization',
            access_policy_id,
            self.engine)
        if resource:
            return resource

    def iter_crm_organization_org_policies(self, org_id):
        """Iterates organization policies from Cloud Asset data in an org.

        Args:
            org_id (str): id of the organization to get the policy.

        Yields:
            dict: Generator of organization policies for an organization.
        """
        resources = self.dao.iter_cai_assets(
            ContentTypes.org_policy,
            'cloudresourcemanager.googleapis.com/Organization',
            '//cloudresourcemanager.googleapis.com/{}'.format(org_id),
            self.engine)
        for org_policy in resources:
            data, metadata = org_policy
            # data[0] is needed to retrieve the only Organization Policy from
            # the list.
            yield data[0], metadata

    def iter_crm_project_org_policies(self, project_number):
        """Iterates organization policies from Cloud Asset data in a project.

        Args:
            project_number (str): number of the project to query.

        Yields:
            dict: Generator of organization policies for a project.
        """
        resources = self.dao.iter_cai_assets(
            ContentTypes.org_policy,
            'cloudresourcemanager.googleapis.com/Project',
            '//cloudresourcemanager.googleapis.com/projects/{}'.format(
                project_number),
            self.engine)
        for org_policy in resources:
            data, metadata = org_policy
            # data[0] is needed to retrieve the only Organization Policy from
            # the list.
            yield data[0], metadata

    def iter_crm_folder_org_policies(self, folder_id):
        """Iterate organization policies in a folder from Cloud Asset data.

        Args:
            folder_id (str): id of the folder to get the policy.

        Yields:
            dict: Generator of organization policies for a folder.
        """
        resources = self.dao.iter_cai_assets(
            ContentTypes.org_policy,
            'cloudresourcemanager.googleapis.com/Folder',
            '//cloudresourcemanager.googleapis.com/{}'.format(folder_id),
            self.engine)
        for org_policy in resources:
            data, metadata = org_policy
            # data[0] is needed to retrieve the only Organization Policy from
            # the list.
            yield data[0], metadata

    def fetch_dataproc_cluster_iam_policy(self, cluster):
        """Fetch Dataproc Cluster IAM Policy from Cloud Asset data.

        Args:
            cluster (str): The Dataproc cluster to query, must be in the format
                projects/{PROJECT_ID}/regions/{REGION}/clusters/{CLUSTER_NAME}

        Returns:
            dict: Cluster IAM policy.
        """
        resource = self.dao.fetch_cai_asset(
            ContentTypes.iam_policy,
            'dataproc.googleapis.com/Cluster',
            '//dataproc.googleapis.com/{}'.format(cluster),
            self.engine)
        if resource:
            return resource

        # Clusters with no IAM policy return an empty dict.
        return {}, None

    def iter_dataproc_clusters(self, project_id, region=None):
        """Iterate Dataproc clusters from GCP API.

        Args:
            project_id (str): id of the project to query.
            region (str): The region to query. Not required when using Cloud
                Asset API.

        Yields:
            dict: Generator of Cluster resources.
        """
        del region  # Used by API not CAI.
        resources = self.dao.iter_cai_assets(
            ContentTypes.resource,
            'dataproc.googleapis.com/Cluster',
            '//dataproc.googleapis.com/projects/{}'.format(project_id),
            self.engine)
        for cluster in resources:
            yield cluster

    def iter_dns_managedzones(self, project_number):
        """Iterate CloudDNS Managed Zones from Cloud Asset data.

        Args:
            project_number (str): number of the parent project.

        Yields:
            dict: Generator of ManagedZone resources
        """
        resources = self.dao.iter_cai_assets(
            ContentTypes.resource,
            'dns.googleapis.com/ManagedZone',
            '//cloudresourcemanager.googleapis.com/projects/{}'.format(
                project_number),
            self.engine)
        for managedzone in resources:
            yield managedzone

    def iter_dns_policies(self, project_number):
        """Iterate CloudDNS Policies from Cloud Asset data.

        Args:
            project_number (str): number of the parent project of the policy.

        Yields:
            dict: Generator of ManagedZone resources
        """
        resources = self.dao.iter_cai_assets(
            ContentTypes.resource,
            'dns.googleapis.com/Policy',
            '//cloudresourcemanager.googleapis.com/projects/{}'.format(
                project_number),
            self.engine)
        for policy in resources:
            yield policy

    def fetch_gae_app(self, project_id):
        """Fetch the AppEngine App from Cloud Asset data.

        Args:
            project_id (str): id of the project to query

        Returns:
            dict: AppEngine App resource.
        """
        resource = self.dao.fetch_cai_asset(
            ContentTypes.resource,
            'appengine.googleapis.com/Application',
            '//appengine.googleapis.com/apps/{}'.format(project_id),
            self.engine)
        return resource

    def iter_gae_services(self, project_id):
        """Iterate gae services from Cloud Asset data.

        Args:
            project_id (str): id of the project to query

        Yields:
            dict: Generator of AppEngine Service resources.
        """
        resources = self.dao.iter_cai_assets(
            ContentTypes.resource,
            'appengine.googleapis.com/Service',
            '//appengine.googleapis.com/apps/{}'.format(project_id),
            self.engine)
        for service in resources:
            yield service

    def iter_gae_versions(self, project_id, service_id):
        """Iterate gae versions from Cloud Asset data.

        Args:
            project_id (str): id of the project to query
            service_id (str): id of the appengine service

        Yields:
            dict: Generator of AppEngine Version resources.
        """
        resources = self.dao.iter_cai_assets(
            ContentTypes.resource,
            'appengine.googleapis.com/Version',
            '//appengine.googleapis.com/apps/{}/services/{}'.format(project_id,
                                                                    service_id),
            self.engine)
        for version in resources:
            yield version

    def fetch_iam_serviceaccount_iam_policy(self, name, unique_id):
        """Service Account IAM policy from Cloud Asset data.

        Args:
            name (str): The service account name to query, must be in the format
                projects/{PROJECT_ID}/serviceAccounts/{SERVICE_ACCOUNT_EMAIL}
            unique_id (str): The unique id of the service account.

        Returns:
            dict: Service Account IAM policy.
        """
        # CAI indexes iam policy by service account unique id, not email.
        # This transforms the name to the format expected by CAI.
        name_parts = name.split('/')
        name_parts[-1] = unique_id
        name = '/'.join(name_parts)

        resource = self.dao.fetch_cai_asset(
            ContentTypes.iam_policy,
            'iam.googleapis.com/ServiceAccount',
            '//iam.googleapis.com/{}'.format(name),
            self.engine)
        if resource:
            return resource

        # Service accounts with no IAM policy return an empty dict.
        return {}, None

    def iter_iam_organization_roles(self, org_id):
        """Iterate Organization roles from Cloud Asset data.

        Args:
            org_id (str): id of the organization to get.

        Yields:
            dict: Generator of organization role.
        """
        resources = self.dao.iter_cai_assets(
            ContentTypes.resource,
            'iam.googleapis.com/Role',
            '//cloudresourcemanager.googleapis.com/{}'.format(org_id),
            self.engine)
        for role in resources:
            yield role

    def iter_iam_project_roles(self, project_id, project_number):
        """Iterate Project roles in a project from Cloud Asset data.

        Args:
            project_id (str): id of the project to query.
            project_number (str): number of the project to query.

        Yields:
            dict: Generator of project roles.
        """
        del project_id  # Used by API not CAI.
        resources = self.dao.iter_cai_assets(
            ContentTypes.resource,
            'iam.googleapis.com/Role',
            '//cloudresourcemanager.googleapis.com/projects/{}'.format(
                project_number),
            self.engine)
        for role in resources:
            yield role

    def iter_iam_serviceaccounts(self, project_id, project_number):
        """Iterate Service Accounts in a project from Cloud Asset data.

        Args:
            project_id (str): id of the project to query.
            project_number (str): number of the project to query.

        Yields:
            dict: Generator of service account.
        """
        del project_id  # Used by API not CAI.
        resources = self.dao.iter_cai_assets(
            ContentTypes.resource,
            'iam.googleapis.com/ServiceAccount',
            '//cloudresourcemanager.googleapis.com/projects/{}'.format(
                project_number),
            self.engine)
        for serviceaccount in resources:
            yield serviceaccount

    def iter_iam_serviceaccount_keys(self, project_id, serviceaccount_id):
        """Iterate Service Account Keys in a project from Cloud Asset data.

        Args:
            project_id (str): id of the project to query.
            serviceaccount_id (str): id of the service account to query.

        Yields:
            dict: Generator of service account.
        """
        resources = self.dao.iter_cai_assets(
            ContentTypes.resource,
            'iam.googleapis.com/ServiceAccountKey',
            '//iam.googleapis.com/projects/{}/serviceAccounts/{}'.format(
                project_id, serviceaccount_id),
            self.engine)
        for serviceaccount_key in resources:
            yield serviceaccount_key

    def fetch_kms_cryptokey_iam_policy(self, cryptokey):
        """Fetch KMS Cryptokey IAM Policy from Cloud Asset data.

        Args:
            cryptokey (str): The KMS cryptokey to query, must be in the format
                projects/{PROJECT_ID}/locations/{LOCATION}/keyRings/{RING_NAME}/
                cryptoKeys/{CRYPTOKEY_NAME}

        Returns:
            dict: KMS Cryptokey IAM policy
        """
        resource = self.dao.fetch_cai_asset(
            ContentTypes.iam_policy,
            'cloudkms.googleapis.com/CryptoKey',
            '//cloudkms.googleapis.com/{}'.format(cryptokey),
            self.engine)
        if resource:
            return resource

        # Cryptokeys with no IAM policy return an empty dict.
        return {}, None

    def fetch_kms_keyring_iam_policy(self, keyring):
        """Fetch KMS Keyring IAM Policy from Cloud Asset data.

        Args:
            keyring (str): The KMS keyring to query, must be in the format
                projects/{PROJECT_ID}/locations/{LOCATION}/keyRings/{RING_NAME}

        Returns:
            dict: KMS Keyring IAM policy
        """
        resource = self.dao.fetch_cai_asset(
            ContentTypes.iam_policy,
            'cloudkms.googleapis.com/KeyRing',
            '//cloudkms.googleapis.com/{}'.format(keyring),
            self.engine)
        if resource:
            return resource

        # Keyrings with no IAM policy return an empty dict.
        return {}, None

    def iter_kms_cryptokeys(self, parent):
        """Iterate KMS Cryptokeys in a keyring from Cloud Asset data.

        Args:
            parent (str): The KMS keyring to query, must be in the format
                projects/{PROJECT_ID}/locations/{LOCATION}/keyRings/{RING_NAME}

        Yields:
            dict: Generator of KMS Cryptokey resources
        """
        resources = self.dao.iter_cai_assets(
            ContentTypes.resource,
            'cloudkms.googleapis.com/CryptoKey',
            '//cloudkms.googleapis.com/{}'.format(parent),
            self.engine)
        for cryptokey in resources:
            yield cryptokey

    def iter_kms_cryptokeyversions(self, parent):
        """Iterate KMS Cryptokey Versions from Cloud Asset data.

        Args:
            parent (str): The KMS keyring to query, must be in the format
                projects/{PROJECT_ID}/locations/{LOCATION}/keyRings/{RING_NAME}/
                cryptoKeys/{CRYPTOKEY_NAME}

        Yields:
            dict: Generator of KMS Cryptokeyversion resources
        """
        resources = self.dao.iter_cai_assets(
            ContentTypes.resource,
            'cloudkms.googleapis.com/CryptoKeyVersion',
            '//cloudkms.googleapis.com/{}'.format(parent),
            self.engine)
        for cryptokeyversion in resources:
            yield cryptokeyversion

    def iter_kms_keyrings(self, project_id, location=None):
        """Iterate KMS Keyrings in a project from Cloud Asset data.

        Args:
            project_id (str): id of the project to query.
            location (str): The location to query. Not required when
                using Cloud Asset API.

        Yields:
            dict: Generator of KMS Keyring resources
        """
        del location  # Used by API not CAI.
        resources = self.dao.iter_cai_assets(
            ContentTypes.resource,
            'cloudkms.googleapis.com/KeyRing',
            '//cloudkms.googleapis.com/projects/{}'.format(project_id),
            self.engine)
        for keyring in resources:
            yield keyring

    def fetch_pubsub_subscription_iam_policy(self, name):
        """PubSub Subscription IAM policy from Cloud Asset data.

        Args:
            name (str): The pubsub topic to query, must be in the format
               projects/{PROJECT_ID}/subscriptions/{SUBSCRIPTION_NAME}

        Returns:
            dict: PubSub Topic IAM policy
        """
        resource = self.dao.fetch_cai_asset(
            ContentTypes.iam_policy,
            'pubsub.googleapis.com/Subscription',
            '//pubsub.googleapis.com/{}'.format(name),
            self.engine)
        if resource:
            return resource

        # Subscriptions with no IAM policy return an empty dict.
        return {}, None

    def fetch_pubsub_topic_iam_policy(self, name):
        """PubSub Topic IAM policy from Cloud Asset data.

        Args:
            name (str): The pubsub topic to query, must be in the format
                projects/{PROJECT_ID}/topics/{TOPIC_NAME}

        Returns:
            dict: PubSub Topic IAM policy
        """
        resource = self.dao.fetch_cai_asset(
            ContentTypes.iam_policy,
            'pubsub.googleapis.com/Topic',
            '//pubsub.googleapis.com/{}'.format(name),
            self.engine)
        if resource:
            return resource

        # Topics with no IAM policy return an empty dict.
        return {}, None

    def iter_pubsub_subscriptions(self, project_id, project_number):
        """Iterate PubSub subscriptions from GCP API.

        Args:
            project_id (str): id of the project to query.
            project_number (str): number of the project to query.

        Yields:
            dict: Generator of Pubsub Subscription resources
        """
        del project_id  # Used by API not CAI.
        resources = self.dao.iter_cai_assets(
            ContentTypes.resource,
            'pubsub.googleapis.com/Subscription',
            '//cloudresourcemanager.googleapis.com/projects/{}'.format(
                project_number),
            self.engine)
        for subscription in resources:
            yield subscription

    def iter_pubsub_topics(self, project_id, project_number):
        """Iterate PubSub topics from Cloud Asset data.

        Args:
            project_id (str): id of the project to query.
            project_number (str): number of the project to query.

        Yields:
            dict: Generator of Pubsub Topic resources
        """
        del project_id  # Used by API not CAI.
        resources = self.dao.iter_cai_assets(
            ContentTypes.resource,
            'pubsub.googleapis.com/Topic',
            '//cloudresourcemanager.googleapis.com/projects/{}'.format(
                project_number),
            self.engine)
        for topic in resources:
            yield topic

    def iter_spanner_instances(self, project_number):
        """Iterate Spanner Instances from Cloud Asset data.

        Args:
            project_number (str): number of the project to query.

        Yields:
            dict: Generator of Spanner Instance resources
        """
        resources = self.dao.iter_cai_assets(
            ContentTypes.resource,
            'spanner.googleapis.com/Instance',
            '//cloudresourcemanager.googleapis.com/projects/{}'.format(
                project_number),
            self.engine)
        for spanner_instance in resources:
            yield spanner_instance

    def iter_spanner_databases(self, parent):
        """Iterate Spanner Databases from Cloud Asset data.

        Args:
            parent (str): parent spanner instance to query.

        Yields:
            dict: Generator of Spanner Database resources
        """
        resources = self.dao.iter_cai_assets(
            ContentTypes.resource,
            'spanner.googleapis.com/Database',
            '//spanner.googleapis.com/{}'.format(parent),
            self.engine)
        for spanner_database in resources:
            yield spanner_database

    def fetch_storage_bucket_acls(self, bucket_id, project_id, project_number):
        """Bucket Access Controls from GCP API.

        Args:
            bucket_id (str): id of the bucket to query.
            project_id (str): id of the project to query.
            project_number (str): number of the project to query.

        Returns:
            list: Bucket Access Controls.
        """
        iam_policy, metadata = self.fetch_storage_bucket_iam_policy(bucket_id)
        if iam_policy:
            return iam_helpers.convert_iam_to_bucket_acls(
                iam_policy,
                bucket_id,
                project_id,
                project_number), metadata
        # Return empty list if IAM policy isn't present.
        return [], None

    def fetch_storage_bucket_iam_policy(self, bucket_id):
        """Bucket IAM policy Iterator from Cloud Asset data.

        Args:
            bucket_id (str): id of the bucket to query

        Returns:
            dict: Bucket IAM policy
        """
        resource = self.dao.fetch_cai_asset(
            ContentTypes.iam_policy,
            'storage.googleapis.com/Bucket',
            '//storage.googleapis.com/{}'.format(bucket_id),
            self.engine)
        if resource:
            return resource

        return {}, None

    def iter_storage_buckets(self, project_number):
        """Iterate Buckets from GCP API.

        Args:
            project_number (str): number of the project to query.

        Yields:
            dict: Generator of buckets.
        """
        resources = self.dao.iter_cai_assets(
            ContentTypes.resource,
            'storage.googleapis.com/Bucket',
            '//cloudresourcemanager.googleapis.com/projects/{}'.format(
                project_number),
            self.engine)
        for bucket in resources:
            yield bucket
