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

import threading

from google.cloud.forseti.common.util import logger
from google.cloud.forseti.services import db
from google.cloud.forseti.services.inventory.base import gcp
from google.cloud.forseti.services.inventory.storage import CaiDataAccess
from google.cloud.forseti.services.inventory.storage import ContentTypes

LOCAL_THREAD = threading.local()
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
    for key, value in resource.items():
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


def _convert_iam_to_bigquery_policy(iam_policy):
    """Converts an IAM policy to a bigquery Access Policy.

    The is used for backwards compatibility between data returned from live
    API and the data stored in CAI. Once the live API returns IAM policies
    instead, this can be deprecated.

    Args:
        iam_policy (dict): The BigQuery dataset IAM policy.

    Returns:
        list: A list of access policies.

        An example return value:

            [
                {'role': 'WRITER', 'specialGroup': 'projectWriters'},
                {'role': 'OWNER', 'specialGroup': 'projectOwners'},
                {'role': 'OWNER', 'userByEmail': 'user@domain.com'},
                {'role': 'READER', 'specialGroup': 'projectReaders'}
            ]
    """
    # Map of iam policy roles to bigquery access policy roles.
    iam_to_access_policy_role_map = {
        'roles/bigquery.dataEditor': 'WRITER',
        'roles/bigquery.dataOwner': 'OWNER',
        'roles/bigquery.dataViewer': 'READER'
    }
    # Map iam policy member type to bigquery access policy member type.
    # The value of the map is a tuple of access policy member type and access
    # policy member value pairs. If the member value is None, then the value
    # from the IAM policy binding is used.
    iam_to_access_policy_member_map = {
        'allAuthenticatedUsers': ('specialGroup', 'allAuthenticatedUsers'),
        'projectEditor': ('specialGroup', 'projectWriters'),
        'projectOwner': ('specialGroup', 'projectOwners'),
        'projectViewer': ('specialGroup', 'projectReaders'),
        'domain': ('domain', None),
        'group': ('groupByEmail', None),
        'user': ('userByEmail', None),
    }

    access_policies = []
    for binding in iam_policy.get('bindings', []):
        if binding.get('role', '') in iam_to_access_policy_role_map:
            role = iam_to_access_policy_role_map[binding['role']]
            for member in binding.get('members', []):
                # The 'allAuthenticatedUsers' member does not contain ':' so it
                # needs to be handled seperately.
                if ':' in member:
                    member_type, member_value = member.split(':', 1)
                else:
                    member_type = member
                    member_value = None
                if member_type in iam_to_access_policy_member_map:
                    new_type, new_value = (
                        iam_to_access_policy_member_map[member_type])
                    if not new_value:
                        new_value = member_value
                    access_policies.append({'role': role, new_type: new_value})
    return access_policies


# pylint: disable=too-many-public-methods
class CaiApiClientImpl(gcp.ApiClientImpl):
    """The gcp api client Implementation"""

    def __init__(self, config, engine, parallel, session):
        """Initialize.

        Args:
            config (dict): GCP API client configuration.
            engine (object): Database engine to operate on.
            parallel (bool): If true, use the parallel crawler implementation.
            session (object): Database session.
        """
        super(CaiApiClientImpl, self).__init__(config)
        self.dao = CaiDataAccess()
        self.engine = engine
        self.parallel = parallel
        self.cai_session = session
        self._local = LOCAL_THREAD

    @property
    def session(self):
        """Return a thread local CAI read only session object.

        Returns:
            object: A thread local Session.
        """
        if not self.parallel:
            # SQLite doesn't support per thread sessions cleanly, so use global
            # session.
            return self.cai_session

        if hasattr(self._local, 'cai_session'):
            return self._local.cai_session

        self._local.cai_session = db.create_readonly_session(engine=self.engine)
        return self._local.cai_session

    def fetch_bigquery_dataset_policy(self, project_number, dataset_id):
        """Dataset policy Iterator for a dataset from Cloud Asset data.

        Args:
            project_number (str): number of the project to query.
            dataset_id (str): id of the dataset to query.

        Returns:
            dict: Dataset Policy.
        """
        resource = self.dao.fetch_cai_asset(
            ContentTypes.iam_policy,
            'google.bigquery.Dataset',
            '//bigquery.googleapis.com/projects/{}/datasets/{}'.format(
                project_number, dataset_id),
            self.session)
        if resource:
            return _convert_iam_to_bigquery_policy(resource)
        # Fall back to live API if the data isn't in the CAI cache.
        return super(CaiApiClientImpl, self).fetch_bigquery_dataset_policy(
            project_number, dataset_id)

    def iter_bigquery_datasets(self, project_number):
        """Iterate Datasets from Cloud Asset data.

        Args:
            project_number (str): number of the project to query.

        Yields:
            dict: Generator of datasets.
        """
        resources = self.dao.iter_cai_assets(
            ContentTypes.resource,
            'google.bigquery.Dataset',
            '//cloudresourcemanager.googleapis.com/projects/{}'.format(
                project_number),
            self.session)
        for dataset in resources:
            yield dataset

    def fetch_billing_account_iam_policy(self, account_id):
        """Gets IAM policy of a Billing Account from Cloud Asset data.

        Args:
            account_id (str): id of the billing account to get policy.

        Returns:
            dict: Billing Account IAM policy.
        """
        resource = self.dao.fetch_cai_asset(
            ContentTypes.iam_policy,
            'google.cloud.billing.BillingAccount',
            '//cloudbilling.googleapis.com/{}'.format(account_id),
            self.session)
        if resource:
            return resource
        # Fall back to live API if the data isn't in the CAI cache.
        return super(CaiApiClientImpl, self).fetch_billing_account_iam_policy(
            account_id)

    def iter_billing_accounts(self):
        """Iterate Billing Accounts in an organization from Cloud Asset data.

        Yields:
            dict: Generator of billing accounts.
        """
        resources = self.dao.iter_cai_assets(
            ContentTypes.resource,
            'google.cloud.billing.BillingAccount',
            '',  # Billing accounts have no parent resource.
            self.session)
        for account in resources:
            yield account

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
            'google.compute.{}'.format(asset_type),
            '//cloudresourcemanager.googleapis.com/projects/{}'.format(
                project_number),
            self.session)

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
        cai_to_gcp_key_map = {
            'backend': 'backends',
            'healthCheck': 'healthChecks',
        }
        resources = self._iter_compute_resources('BackendService',
                                                 project_number)
        for backendservice in resources:
            yield _fixup_resource_keys(backendservice, cai_to_gcp_key_map)

    def iter_compute_disks(self, project_number):
        """Iterate Compute Engine disks from Cloud Asset data.

        Args:
            project_number (str): number of the project to query.

        Yields:
            dict: Generator of Compute Disk.
        """
        cai_to_gcp_key_map = {
            'license': 'licenses',
            'guestOsFeature': 'guestOsFeatures',
            'user': 'users',
            'replicaZone': 'replicaZones',
            'licenseCode': 'licenseCodes',
        }
        resources = self._iter_compute_resources('Disk', project_number)
        for disk in resources:
            yield _fixup_resource_keys(disk, cai_to_gcp_key_map)

    def iter_compute_firewalls(self, project_number):
        """Iterate Compute Engine Firewalls from Cloud Asset data.

        Args:
            project_number (str): number of the project to query.

        Yields:
            dict: Generator of Compute Engine Firewall.
        """
        cai_to_gcp_key_map = {
            'ipProtocol': 'IPProtocol',
            'port': 'ports',
            'sourceRange': 'sourceRanges',
            'sourceServiceAccount': 'sourceServiceAccounts',
            'sourceTag': 'sourceTags',
            'targetRange': 'targetRanges',
            'targetServiceAccount': 'targetServiceAccounts',
            'targetTag': 'targetTags',
        }
        resources = self._iter_compute_resources('Firewall', project_number)
        for rule in resources:
            yield _fixup_resource_keys(rule, cai_to_gcp_key_map)

    def iter_compute_forwardingrules(self, project_number):
        """Iterate Forwarding Rules from GCP API.

        Args:
            project_number (str): number of the project to query.

        Yields:
            dict: Generator of forwarding rule resources.
        """
        cai_to_gcp_key_map = {
            'ipAddress': 'IPAddress',
            'ipProtocol': 'IPProtocol',
        }
        resources = self._iter_compute_resources('ForwardingRule',
                                                 project_number)
        for forwarding_rule in resources:
            yield _fixup_resource_keys(forwarding_rule, cai_to_gcp_key_map)

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
        cai_to_gcp_key_map = {
            'namedPort': 'namedPorts',
            'targetPool': 'targetPools',
        }
        resources = self._iter_compute_resources('InstanceGroupManager',
                                                 project_number)
        for igmanager in resources:
            yield _fixup_resource_keys(igmanager, cai_to_gcp_key_map)

    def iter_compute_images(self, project_number):
        """Iterate Images from Cloud Asset data.

        Args:
            project_number (str): number of the project to query.

        Yields:
            dict: Generator of image resources.
        """
        cai_to_gcp_key_map = {
            'guestOsFeature': 'guestOsFeatures',
            'license': 'licenses',
            'licenseCode': 'licenseCodes',
        }
        resources = self._iter_compute_resources('Image', project_number)
        for image in resources:
            yield _fixup_resource_keys(image, cai_to_gcp_key_map)

    def iter_compute_instancegroups(self, project_number):
        """Iterate Compute Engine groups from Cloud Asset data.

        Args:
            project_number (str): number of the project to query.

        Yields:
            dict: Generator of Compute Instance group.
        """
        cai_to_gcp_key_map = {
            'namedPort': 'namedPorts',
        }
        resources = self._iter_compute_resources('InstanceGroup',
                                                 project_number)
        for instancegroup in resources:
            yield _fixup_resource_keys(instancegroup, cai_to_gcp_key_map)

    def iter_compute_instances(self, project_number):
        """Iterate compute engine instance from Cloud Asset data.

        Args:
            project_number (str): number of the project to query.

        Yields:
            dict: Generator of Compute Engine Instance resources.
        """
        cai_to_gcp_key_map = {
            'accessConfig': 'accessConfigs',
            'aliasIpRange': 'aliasIpRanges',
            'disk': 'disks',
            'diskConfig': 'diskConfigs',
            'guestAccelerator': 'guestAccelerators',
            'guestOsFeature': 'guestOsFeatures',
            'item': 'items',
            'license': 'licenses',
            'networkInterface': 'networkInterfaces',
            'nodeAffinity': 'nodeAffinities',
            'resourcePolicy': 'resourcePolicies',
            'scope': 'scopes',
            'serviceAccount': 'serviceAccounts',
            'tag': 'tags',
        }
        resources = self._iter_compute_resources('Instance', project_number)
        for instance in resources:
            yield _fixup_resource_keys(instance, cai_to_gcp_key_map)

    def iter_compute_instancetemplates(self, project_number):
        """Iterate Instance Templates from Cloud Asset data.

        Args:
            project_number (str): number of the project to query.

        Yields:
            dict: Generator of instance template resources.
        """
        cai_to_gcp_key_map = {
            'accessConfig': 'accessConfigs',
            'aliasIpRange': 'aliasIpRanges',
            'disk': 'disks',
            'diskConfig': 'diskConfigs',
            'guestAccelerator': 'guestAccelerators',
            'guestOsFeature': 'guestOsFeatures',
            'item': 'items',
            'license': 'licenses',
            'networkInterface': 'networkInterfaces',
            'nodeAffinity': 'nodeAffinities',
            'resourcePolicy': 'resourcePolicies',
            'scope': 'scopes',
            'serviceAccount': 'serviceAccounts',
            'tag': 'tags',
        }
        resources = self._iter_compute_resources('InstanceTemplate',
                                                 project_number)
        for instancetemplate in resources:
            yield _fixup_resource_keys(instancetemplate, cai_to_gcp_key_map)

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
        cai_to_gcp_key_map = {
            'subnetwork': 'subnetworks',
        }
        resources = self._iter_compute_resources('Network', project_number)
        for network in resources:
            yield _fixup_resource_keys(network, cai_to_gcp_key_map)

    def iter_compute_routers(self, project_number):
        """Iterate Compute Engine routers from Cloud Asset data.

        Args:
            project_number (str): number of the project to query.

        Yields:
            dict: Generator of Compute Routers.
        """
        cai_to_gcp_key_map = {
            'advertisedGroup': 'advertisedGroups',
            'advertisedIpRange': 'advertisedIpRanges',
            'bgpPeer': 'bgpPeers',
            'interface': 'interfaces',
        }
        resources = self._iter_compute_resources('Router', project_number)
        for router in resources:
            yield _fixup_resource_keys(router, cai_to_gcp_key_map)

    def iter_compute_snapshots(self, project_number):
        """Iterate Compute Engine snapshots from Cloud Asset data.

        Args:
            project_number (str): number of the project to query.

        Yields:
            dict: Generator of Compute Snapshots.
        """
        cai_to_gcp_key_map = {
            'guestOsFeature': 'guestOsFeatures',
            'license': 'licenses',
            'licenseCode': 'licenseCodes',
        }
        resources = self._iter_compute_resources('Snapshot', project_number)
        for snapshot in resources:
            yield _fixup_resource_keys(snapshot, cai_to_gcp_key_map)

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
        cai_to_gcp_key_map = {
            'sslCertificate': 'sslCertificates',
        }
        resources = self._iter_compute_resources('TargetHttpsProxy',
                                                 project_number)
        for targethttpsproxy in resources:
            yield _fixup_resource_keys(targethttpsproxy, cai_to_gcp_key_map)

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
        cai_to_gcp_key_map = {
            'healthCheck': 'healthChecks',
            'instance': 'instances',
        }
        resources = self._iter_compute_resources('TargetPool', project_number)
        for targetpool in resources:
            yield _fixup_resource_keys(targetpool, cai_to_gcp_key_map)

    def iter_compute_targetsslproxies(self, project_number):
        """Iterate Target SSL proxies from Cloud Asset data.

        Args:
            project_number (str): number of the project to query.

        Yields:
            dict: Generator of target ssl proxy resources.
        """
        cai_to_gcp_key_map = {
            'sslCertificate': 'sslCertificates',
        }
        resources = self._iter_compute_resources('TargetSslProxy',
                                                 project_number)
        for targetsslproxy in resources:
            yield _fixup_resource_keys(targetsslproxy, cai_to_gcp_key_map)

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

    def iter_compute_urlmaps(self, project_number):
        """Iterate URL maps from Cloud Asset data.

        Args:
            project_number (str): number of the project to query.

        Yields:
            dict: Generator of url map resources.
        """
        cai_to_gcp_key_map = {
            'host': 'hosts',
            'hostRule': 'hostRules',
            'path': 'paths',
            'pathMatcher': 'pathMatchers',
            'pathRule': 'pathRules',
            'test': 'tests'
        }
        resources = self._iter_compute_resources('UrlMap', project_number)
        for urlmap in resources:
            # 'path' can be singular when scalar or plural when a list, so
            # turn on only_fixup_lists, so the singular instance isn't munged.
            yield _fixup_resource_keys(urlmap, cai_to_gcp_key_map,
                                       only_fixup_lists=True)

    def fetch_crm_folder(self, folder_id):
        """Fetch Folder data from Cloud Asset data.

        Args:
            folder_id (str): id of the folder to query.

        Returns:
            dict: Folder resource.
        """
        resource = self.dao.fetch_cai_asset(
            ContentTypes.resource,
            'google.cloud.resourcemanager.Folder',
            '//cloudresourcemanager.googleapis.com/{}'.format(folder_id),
            self.session)
        if resource:
            return resource
        # Fall back to live API if the data isn't in the CAI cache.
        return super(CaiApiClientImpl, self).fetch_crm_folder(folder_id)

    def fetch_crm_folder_iam_policy(self, folder_id):
        """Folder IAM policy in a folder from Cloud Asset data.

        Args:
            folder_id (str): id of the folder to get policy.

        Returns:
            dict: Folder IAM policy.
        """
        resource = self.dao.fetch_cai_asset(
            ContentTypes.iam_policy,
            'google.cloud.resourcemanager.Folder',
            '//cloudresourcemanager.googleapis.com/{}'.format(folder_id),
            self.session)
        if resource:
            return resource
        # Fall back to live API if the data isn't in the CAI cache.
        return super(CaiApiClientImpl, self).fetch_crm_folder_iam_policy(
            folder_id)

    def fetch_crm_organization(self, org_id):
        """Fetch Organization data from Cloud Asset data.

        Args:
            org_id (str): id of the organization to get.

        Returns:
            dict: Organization resource.
        """
        resource = self.dao.fetch_cai_asset(
            ContentTypes.resource,
            'google.cloud.resourcemanager.Organization',
            '//cloudresourcemanager.googleapis.com/{}'.format(org_id),
            self.session)
        if resource:
            return resource
        # Fall back to live API if the data isn't in the CAI cache.
        return super(CaiApiClientImpl, self).fetch_crm_organization(org_id)

    def fetch_crm_organization_iam_policy(self, org_id):
        """Organization IAM policy from Cloud Asset data.

        Args:
            org_id (str): id of the organization to get policy.

        Returns:
            dict: Organization IAM policy.
        """
        resource = self.dao.fetch_cai_asset(
            ContentTypes.iam_policy,
            'google.cloud.resourcemanager.Organization',
            '//cloudresourcemanager.googleapis.com/{}'.format(org_id),
            self.session)
        if resource:
            return resource
        # Fall back to live API if the data isn't in the CAI cache.
        return super(CaiApiClientImpl, self).fetch_crm_organization_iam_policy(
            org_id)

    def fetch_crm_project(self, project_number):
        """Fetch Project data from Cloud Asset data.

        Args:
            project_number (str): number of the project to query.

        Returns:
            dict: Project resource.
        """
        resource = self.dao.fetch_cai_asset(
            ContentTypes.resource,
            'google.cloud.resourcemanager.Project',
            '//cloudresourcemanager.googleapis.com/projects/{}'.format(
                project_number),
            self.session)
        if resource:
            return resource
        # Fall back to live API if the data isn't in the CAI cache.
        return super(CaiApiClientImpl, self).fetch_crm_project(project_number)

    def fetch_crm_project_iam_policy(self, project_number):
        """Project IAM policy from Cloud Asset data.

        Args:
            project_number (str): number of the project to query.

        Returns:
            dict: Project IAM Policy.
        """
        resource = self.dao.fetch_cai_asset(
            ContentTypes.iam_policy,
            'google.cloud.resourcemanager.Project',
            '//cloudresourcemanager.googleapis.com/projects/{}'.format(
                project_number),
            self.session)
        if resource:
            return resource
        # Fall back to live API if the data isn't in the CAI cache.
        return super(CaiApiClientImpl, self).fetch_crm_project_iam_policy(
            project_number)

    def iter_crm_folders(self, parent_id):
        """Iterate Folders from Cloud Asset data.

        Args:
            parent_id (str): id of the parent of the folder

        Yields:
            dict: Generator of folders
        """
        resources = self.dao.iter_cai_assets(
            ContentTypes.resource,
            'google.cloud.resourcemanager.Folder',
            '//cloudresourcemanager.googleapis.com/{}'.format(parent_id),
            self.session)
        for folder in resources:
            yield folder

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
            'google.cloud.resourcemanager.Project',
            '//cloudresourcemanager.googleapis.com/{}s/{}'.format(parent_type,
                                                                  parent_id),
            self.session)
        for project in resources:
            yield project

    def iter_dns_managedzones(self, project_number):
        """Iterate CloudDNS Managed Zones from Cloud Asset data.

        Args:
            project_number (str): number of the parent project.

        Yields:
            dict: Generator of ManagedZone resources
        """
        resources = self.dao.iter_cai_assets(
            ContentTypes.resource,
            'google.cloud.dns.ManagedZone',
            '//cloudresourcemanager.googleapis.com/projects/{}'.format(
                project_number),
            self.session)
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
            'google.cloud.dns.Policy',
            '//cloudresourcemanager.googleapis.com/projects/{}'.format(
                project_number),
            self.session)
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
            'google.appengine.Application',
            '//appengine.googleapis.com/apps/{}'.format(project_id),
            self.session)
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
            'google.appengine.Service',
            '//appengine.googleapis.com/apps/{}'.format(project_id),
            self.session)
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
            'google.appengine.Version',
            '//appengine.googleapis.com/apps/{}/services/{}'.format(project_id,
                                                                    service_id),
            self.session)
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
            'google.iam.ServiceAccount',
            '//iam.googleapis.com/{}'.format(name),
            self.session)
        if resource:
            return resource

        # Service accounts with no IAM policy return an empty dict.
        return {}

    def iter_iam_organization_roles(self, org_id):
        """Iterate Organization roles from Cloud Asset data.

        Args:
            org_id (str): id of the organization to get.

        Yields:
            dict: Generator of organization role.
        """
        resources = self.dao.iter_cai_assets(
            ContentTypes.resource,
            'google.iam.Role',
            '//cloudresourcemanager.googleapis.com/{}'.format(org_id),
            self.session)
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
            'google.iam.Role',
            '//cloudresourcemanager.googleapis.com/projects/{}'.format(
                project_number),
            self.session)
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
            'google.iam.ServiceAccount',
            '//cloudresourcemanager.googleapis.com/projects/{}'.format(
                project_number),
            self.session)
        for serviceaccount in resources:
            yield serviceaccount

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
            'google.pubsub.Topic',
            '//pubsub.googleapis.com/{}'.format(name),
            self.session)
        if resource:
            return resource

        # Topics with no IAM policy return an empty dict.
        return {}

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
            'google.pubsub.Topic',
            '//cloudresourcemanager.googleapis.com/projects/{}'.format(
                project_number),
            self.session)
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
            'google.spanner.Instance',
            '//cloudresourcemanager.googleapis.com/projects/{}'.format(
                project_number),
            self.session)
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
            'google.spanner.Database',
            '//spanner.googleapis.com/{}'.format(parent),
            self.session)
        for spanner_database in resources:
            yield spanner_database

    def fetch_storage_bucket_iam_policy(self, bucket_id):
        """Bucket IAM policy Iterator from Cloud Asset data.

        Args:
            bucket_id (str): id of the bucket to query

        Returns:
            dict: Bucket IAM policy
        """
        resource = self.dao.fetch_cai_asset(
            ContentTypes.iam_policy,
            'google.cloud.storage.Bucket',
            '//storage.googleapis.com/{}'.format(bucket_id),
            self.session)
        if resource:
            return resource
        # Fall back to live API if the data isn't in the CAI cache.
        return super(CaiApiClientImpl, self).fetch_storage_bucket_iam_policy(
            bucket_id)

    # Use live API because CAI does not yet have bucket ACLs.
    # def iter_storage_buckets(self, project_number):
