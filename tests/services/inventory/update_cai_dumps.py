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
"""Update CAI mock dump data with new resources.

When the inventory mock_gcp_results.py file is updated, then this script should
be run to update the cai dump files with the additional resources.

From the top forseti-security dir, run:

PYTHONPATH=. python tests/services/inventory/update_cai_dumps.py
"""
import json
import os

from tests.services.inventory import gcp_api_mocks
from google.cloud.forseti.common.util import logger
from google.cloud.forseti.services.base.config import InventoryConfig
from google.cloud.forseti.services.inventory.base.progress import Progresser
from google.cloud.forseti.services.inventory.base.storage import Memory as MemoryStorage
from google.cloud.forseti.services.inventory.crawler import run_crawler

LOGGER = logger.get_logger(__name__)
MODULE_DIR = os.path.dirname(os.path.abspath(__file__))
RESOURCE_DUMP_FILE = os.path.join(MODULE_DIR,
                                  'test_data',
                                  'mock_cai_resources.dump')
IAM_POLICY_DUMP_FILE = os.path.join(MODULE_DIR,
                                    'test_data',
                                    'mock_cai_iam_policies.dump')
ADDITIONAL_RESOURCES_FILE = os.path.join(MODULE_DIR,
                                         'test_data',
                                         'additional_cai_resources.dump')
ADDITIONAL_IAM_POLCIIES_FILE = os.path.join(MODULE_DIR,
                                            'test_data',
                                            'additional_cai_iam_policies.dump')


class TestServiceConfig(object):
    """ServiceConfig stub."""

    def __init__(self, engine, inventory_config):
        self.engine = engine
        self.inventory_config = inventory_config

    def get_engine(self):
        """Stub."""
        return self.engine


class NullProgresser(Progresser):
    """No-op progresser to suppress output."""

    def __init__(self):
        super(NullProgresser, self).__init__()

    def on_new_object(self, resource):
        pass

    def on_warning(self, warning):
        LOGGER.error("Progressor Warning: %s", warning)
        pass

    def on_error(self, error):
        LOGGER.exception("Progressor Error: %s", error)
        pass

    def get_summary(self):
        pass

def _create_asset(name, asset_type, parent_name, data_dict, iam_policy_dict):
    resource = {
        'name': name,
        'asset_type': asset_type,
        'resource': {'data': data_dict}}
    if parent_name:
        resource['resource']['parent'] = parent_name
    resource_data = json.dumps(resource, separators=(',',':'), sort_keys=True)
    if iam_policy_dict:
        iam_policy = {
            'name': name,
            'asset_type': asset_type,
            'iam_policy': iam_policy_dict}
        iam_policy_data = json.dumps(iam_policy,
                                     separators=(',',':'),
                                     sort_keys=True)
    else:
        iam_policy_data = None
    return (resource_data, iam_policy_data)


def organization(item):
    name = '//cloudresourcemanager.googleapis.com/{}'.format(item['name'])
    asset_type = 'google.cloud.resourcemanager.Organization'
    return _create_asset(name, asset_type, None, item.data(),
                         item.get_iam_policy())


def folder(item):
    name = '//cloudresourcemanager.googleapis.com/{}'.format(item['name'])
    asset_type = 'google.cloud.resourcemanager.Folder'
    parent_name = '//cloudresourcemanager.googleapis.com/{}'.format(
        item['parent'])
    return _create_asset(name, asset_type, parent_name, item.data(),
                         item.get_iam_policy())

def project(item):
    name = '//cloudresourcemanager.googleapis.com/projects/{}'.format(
        item['projectNumber'])
    asset_type = 'google.cloud.resourcemanager.Project'
    parent_name = '//cloudresourcemanager.googleapis.com/{}s/{}'.format(
        item['parent']['type'], item['parent']['id'])
    return _create_asset(name, asset_type, parent_name, item.data(),
                         item.get_iam_policy())

def appengine_app(item):
    parent = item.parent()
    name = '//appengine.googleapis.com/{}'.format(item['name'])
    asset_type = 'google.appengine.Application'
    parent_name = '//cloudresourcemanager.googleapis.com/projects/{}'.format(
        parent['projectNumber'])
    return _create_asset(name, asset_type, parent_name, item.data(), None)


def appengine_service(item):
    name = '//appengine.googleapis.com/{}'.format(item['name'])
    asset_type = 'google.appengine.Service'
    return _create_asset(name, asset_type, None, item.data(), None)


def appengine_version(item):
    name = '//appengine.googleapis.com/{}'.format(item['name'])
    asset_type = 'google.appengine.Version'
    return _create_asset(name, asset_type, None, item.data(), None)


def bigquery_dataset(item):
    parent = item.parent()
    name = '//bigquery.googleapis.com/projects/{}/datasets/{}'.format(
        parent['projectNumber'], item['datasetReference']['datasetId'])
    asset_type = 'google.bigquery.Dataset'
    parent_name = '//cloudresourcemanager.googleapis.com/projects/{}'.format(
        parent['projectNumber'])
    return _create_asset(name, asset_type, parent_name, item.data(), None)


def billing_account(item):
    name = '//cloudbilling.googleapis.com/{}'.format(item['name'])
    asset_type = 'google.cloud.billing.BillingAccount'
    parent_name = ''
    return _create_asset(name, asset_type, parent_name, item.data(),
                         item.get_iam_policy())


def bucket(item):
    parent = item.parent()
    name = '//storage.googleapis.com/{}'.format(item['name'])
    asset_type = 'google.cloud.storage.Bucket'
    parent_name = '//cloudresourcemanager.googleapis.com/projects/{}'.format(
        parent['projectNumber'])
    data = item.data()
    # CAI does not include acl data.
    data.pop('acl')
    data.pop('defaultObjectAcl')
    return _create_asset(name, asset_type, parent_name, data,
                         item.get_iam_policy())

def role(item):
    parent = item.parent()
    if not parent:
        return (None, None)

    if parent.type() == 'organization':
        parent_name = '//cloudresourcemanager.googleapis.com/{}'.format(
            parent['name'])
    else:
        parent_name = '//cloudresourcemanager.googleapis.com/projects/{}'.format(
            parent['projectNumber'])

    name = '//iam.googleapis.com/{}'.format(item['name'])
    asset_type = 'google.iam.Role'

    return _create_asset(name, asset_type, parent_name, item.data(), None)


def serviceaccount(item):
    parent = item.parent()
    name = '//iam.googleapis.com/projects/{}/serviceAccounts/{}'.format(
        item['projectId'], item['uniqueId'])
    asset_type = 'google.iam.ServiceAccount'
    parent_name = '//cloudresourcemanager.googleapis.com/projects/{}'.format(
        parent['projectNumber'])
    return _create_asset(name, asset_type, parent_name, item.data(),
                         item.get_iam_policy())


def _create_compute_asset(item, asset_type):
    parent = item.parent()
    self_link = '/'.join(item['selfLink'].split('/')[5:])
    name = '//compute.googleapis.com/{}'.format(self_link)
    parent_name = '//cloudresourcemanager.googleapis.com/projects/{}'.format(
        parent['projectNumber'])
    return _create_asset(name, asset_type, parent_name, item.data(), None)


def backendservice(item):
    return _create_compute_asset(item, 'google.compute.BackendService')


def disk(item):
    return _create_compute_asset(item, 'google.compute.Disk')


def firewall(item):
    return _create_compute_asset(item, 'google.compute.Firewall')


def forwardingrule(item):
    return _create_compute_asset(item, 'google.compute.ForwardingRule')


def image(item):
    return _create_compute_asset(item, 'google.compute.Image')


def instance(item):
    return _create_compute_asset(item, 'google.compute.Instance')


def instancegroup(item):
    return _create_compute_asset(item, 'google.compute.InstanceGroup')


def instancegroupmanager(item):
    return _create_compute_asset(item, 'google.compute.InstanceGroupManager')


def instancetemplate(item):
    return _create_compute_asset(item, 'google.compute.InstanceTemplate')


def network(item):
    return _create_compute_asset(item, 'google.compute.Network')


def snapshot(item):
    return _create_compute_asset(item, 'google.compute.Snapshot')


def subnetwork(item):
    return _create_compute_asset(item, 'google.compute.Subnetwork')



CAI_TYPE_MAP = {
    'organization': organization,
    'folder': folder,
    'project': project,
    'appengine_app': appengine_app,
    'appengine_service': appengine_service,
    'appengine_version': appengine_version,
    'billing_account': billing_account,
    'bucket': bucket,
    'backendservice': backendservice,
    'dataset': bigquery_dataset,
    'disk': disk,
    'firewall': firewall,
    'forwardingrule': forwardingrule,
    'image': image,
    'instance': instance,
    'instancegroup': instancegroup,
    'instancegroupmanager': instancegroupmanager,
    'instancetemplate': instancetemplate,
    'network': network,
    'role': role,
    'serviceaccount': serviceaccount,
    'snapshot': snapshot,
    'subnetwork': subnetwork,
}

def write_data(data, destination):
    """Write data to destination."""
    with open(destination, 'w') as f:
        for line in data:
            f.write(line)
            f.write('\n')

def convert_item_to_assets(item):
    """Convert the data in an item to Asset protos in json format."""
    if item.type() in CAI_TYPE_MAP:
        func = CAI_TYPE_MAP[item.type()]
        return func(item)
    return None, None


def main():
    """Create CAI dump files from fake data."""
    logger.enable_console_log()
    config = InventoryConfig(
        gcp_api_mocks.ORGANIZATION_ID, '', {}, '', {'enabled': False})
    service_config = TestServiceConfig('sqlite', config)
    config.set_service_config(service_config)

    resources = []
    iam_policies = []
    with MemoryStorage() as storage:
        progresser = NullProgresser()
        with gcp_api_mocks.mock_gcp():
            run_crawler(storage,
                        progresser,
                        config,
                        parallel=False)
            for item in storage.mem.values():
                (resource, iam_policy) = convert_item_to_assets(item)
                if resource:
                    resources.append(resource)
                if iam_policy:
                    iam_policies.append(iam_policy)

    with open(ADDITIONAL_RESOURCES_FILE, 'r') as f:
        for line in f:
            if line.startswith('#'):
                continue
            resources.append(line.strip())

    with open(ADDITIONAL_IAM_POLCIIES_FILE, 'r') as f:
        for line in f:
            if line.startswith('#'):
                continue
            iam_policies.append(line.strip())

    write_data(resources, RESOURCE_DUMP_FILE)
    write_data(iam_policies, IAM_POLICY_DUMP_FILE)


if __name__ == '__main__':
    main()
