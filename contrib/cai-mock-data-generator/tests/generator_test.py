import collections
import hashlib
import json
import pathlib
import unittest

from data_generator import generator
from data_generator.file_handler import read_yaml_file


class TestGenerator(unittest.TestCase):

    file_paths = ['{}/{}-resource.dump', '{}/{}-iam-policy.dump']

    def tearDown(self) -> None:
        """Remove all the dump files."""
        for path in pathlib.Path('.').glob('*.dump'):
            path.unlink()

    def test_count_folders(self):
        config_file_path = './config/config_100_folders.yaml'
        config = read_yaml_file(config_file_path)
        generator.CAIDataGenerator(config).generate()
        paths = list(map(lambda p: p.format(config.get('output_path'),
                                            config.get('output_file_name_prefix')),
                     self.file_paths))
        root_cai_name = '//cloudresourcemanager.googleapis.com/organizations/{}'.format(
            config.get('root_resource_id'))
        expected_resource_node = ResourceNode(root_cai_name, 'cloudresourcemanager.googleapis.com/Organization')
        expected_resource_node.children = [ResourceNode(i, 'cloudresourcemanager.googleapis.com/Folder') for i in range(100)]

        resource_count, root_resource_node = self.count_resource_by_type(paths[0])
        iam_count, _ = self.count_resource_by_type(paths[1])
        self.assertEqual(expected_resource_node, root_resource_node)
        self.assertEqual(1, resource_count.get('cloudresourcemanager.googleapis.com/Organization', 0))
        self.assertEqual(1, iam_count.get('cloudresourcemanager.googleapis.com/Organization', 0))
        self.assertEqual(100, resource_count.get('cloudresourcemanager.googleapis.com/Folder', 0))
        self.assertEqual(100, iam_count.get('cloudresourcemanager.googleapis.com/Folder', 0))

    def test_count_folders_projects(self):
        config_file_path = './config/config_folders_projects.yaml'
        config = read_yaml_file(config_file_path)
        generator.CAIDataGenerator(config).generate()
        paths = list(map(lambda p: p.format(config.get('output_path'),
                                            config.get('output_file_name_prefix')),
                         self.file_paths))
        root_cai_name = '//cloudresourcemanager.googleapis.com/organizations/{}'.format(
            config.get('root_resource_id'))
        expected_resource_node = ResourceNode(root_cai_name, 'cloudresourcemanager.googleapis.com/Organization')
        expected_resource_node.children = [ResourceNode(i, 'cloudresourcemanager.googleapis.com/Folder') for i in range(10)]
        for folder in expected_resource_node.children:
            folder.children = [ResourceNode(i, 'cloudresourcemanager.googleapis.com/Project') for i in range(5)]

        resource_count, root_resource_node = self.count_resource_by_type(paths[0])
        iam_count, _ = self.count_resource_by_type(paths[1])
        self.assertEqual(expected_resource_node, root_resource_node)
        self.assertEqual(1, resource_count.get('cloudresourcemanager.googleapis.com/Organization', 0))
        self.assertEqual(1, iam_count.get('cloudresourcemanager.googleapis.com/Organization', 0))
        self.assertEqual(10, resource_count.get('cloudresourcemanager.googleapis.com/Folder', 0))
        self.assertEqual(10, iam_count.get('cloudresourcemanager.googleapis.com/Folder', 0))
        self.assertEqual(50, resource_count.get('cloudresourcemanager.googleapis.com/Project', 0))
        self.assertEqual(50, iam_count.get('cloudresourcemanager.googleapis.com/Project', 0))

    def test_count_mixed(self):
        config_file_path = './config/config_mixed.yaml'
        config = read_yaml_file(config_file_path)
        generator.CAIDataGenerator(config).generate()
        paths = list(map(lambda p: p.format(config.get('output_path'),
                                            config.get('output_file_name_prefix')),
                         self.file_paths))
        root_cai_name = '//cloudresourcemanager.googleapis.com/organizations/{}'.format(
            config.get('root_resource_id'))
        expected_resource_node = ResourceNode(root_cai_name, 'cloudresourcemanager.googleapis.com/Organization')
        expected_resource_node.children = [ResourceNode('1', 'cloudresourcemanager.googleapis.com/Folder')]
        for folder in expected_resource_node.children:
            folder.children = [ResourceNode(i, 'cloudresourcemanager.googleapis.com/Folder') for i in range(2)]
            for folder_in_folder in folder.children:
                folder_in_folder.children = [ResourceNode(i, 'cloudresourcemanager.googleapis.com/Project') for i in range(2)]
                for project in folder_in_folder.children:
                    project.children = [ResourceNode(i, 'compute.googleapis.com/Firewall') for i in range(2)]
                    project.children.extend([ResourceNode(i, 'compute.googleapis.com/Disk') for i in range(2)])
                    project.children.extend([ResourceNode(i, 'compute.googleapis.com/Snapshot') for i in range(2)])
                    project.children.extend([ResourceNode(i, 'iam.googleapis.com/ServiceAccount') for i in range(2)])
                    project.children.extend([ResourceNode(i, 'storage.googleapis.com/Bucket') for i in range(2)])
                    datasets = [ResourceNode(i, 'bigquery.googleapis.com/Dataset') for i in range(2)]
                    for dataset in datasets:
                        dataset.children = [ResourceNode(i, 'bigquery.googleapis.com/Table') for i in range(2)]
                    project.children.extend(datasets)
                    appengine_applications = [ResourceNode(i, 'appengine.googleapis.com/Application') for i in range(1)]
                    for appengine_application in appengine_applications:
                        services = [ResourceNode(i, 'appengine.googleapis.com/Service') for i in range(2)]
                        for service in services:
                            service.children = [ResourceNode(i, 'appengine.googleapis.com/Version') for i in range(2)]
                        appengine_application.children = services
                    project.children.extend(appengine_applications)

        resource_count, root_resource_node = self.count_resource_by_type(paths[0])
        iam_count, _ = self.count_resource_by_type(paths[1])
        print ([root_resource_node] == [expected_resource_node])
        self.assertEqual(expected_resource_node, root_resource_node)
        self.assertEqual(1, resource_count.get('cloudresourcemanager.googleapis.com/Organization', 0))
        self.assertEqual(1, iam_count.get('cloudresourcemanager.googleapis.com/Organization', 0))
        self.assertEqual(3, resource_count.get('cloudresourcemanager.googleapis.com/Folder', 0))
        self.assertEqual(3, iam_count.get('cloudresourcemanager.googleapis.com/Folder', 0))
        self.assertEqual(4, resource_count.get('cloudresourcemanager.googleapis.com/Project', 0))
        self.assertEqual(4, iam_count.get('cloudresourcemanager.googleapis.com/Project', 0))
        self.assertEqual(8, resource_count.get('iam.googleapis.com/ServiceAccount', 0))
        self.assertEqual(8, iam_count.get('iam.googleapis.com/ServiceAccount', 0))
        self.assertEqual(8, resource_count.get('storage.googleapis.com/Bucket', 0))
        self.assertEqual(8, iam_count.get('storage.googleapis.com/Bucket', 0))
        self.assertEqual(8, resource_count.get('bigquery.googleapis.com/Dataset', 0))
        self.assertEqual(8, iam_count.get('bigquery.googleapis.com/Dataset', 0))
        self.assertEqual(8, resource_count.get('compute.googleapis.com/Firewall', 0))
        self.assertEqual(8, resource_count.get('compute.googleapis.com/Disk', 0))
        self.assertEqual(8, resource_count.get('compute.googleapis.com/Snapshot', 0))
        self.assertEqual(4, resource_count.get('appengine.googleapis.com/Application', 0))
        self.assertEqual(8, resource_count.get('appengine.googleapis.com/Service', 0))
        self.assertEqual(16, resource_count.get('appengine.googleapis.com/Version', 0))
        self.assertEqual(16, resource_count.get('bigquery.googleapis.com/Table', 0))

    @staticmethod
    def count_resource_by_type(file_path):
        """Count resource by type.

        Args:
            file_path (str): Path to the dump file.

        Returns:
            :rtype(dict, Resource): resource count and a root resource node.
        """
        results = collections.defaultdict(int)
        resource_map = {}
        root_resource = None
        with open(file_path, 'r') as f:
            for line in f:
                data = json.loads(line)
                asset_type = data.get('asset_type')
                results[asset_type] += 1

                asset_cai_name = data.get('name')
                resource = data.get('resource')
                if resource:
                    parent_cai_name = data.get('resource').get('parent', '')

                    resource = ResourceNode(asset_cai_name, asset_type)

                    if len(resource_map) == 0:
                        root_resource = resource
                    else:
                        resource_map.get(parent_cai_name).children.append(resource)

                    if resource not in resource_map:
                        resource_map[resource.resource_name] = resource
        return results, root_resource


class ResourceNode(object):
    def __init__(self, resource_name, resource_type):
        self.resource_name = resource_name
        self.resource_type = resource_type
        self.children = []

    def __eq__(self, other):
        """Check for resource type equality.
        2 resource nodes are equal iff
            1. Their resource types are the same.
            2. Their child resource node are the same.
        """
        if (self.resource_type == other.resource_type and
                self.children == other.children):
            return True
        elif (self.resource_type == other.resource_type and
              len(self.children) == len(other.children)):
            self.children.sort()
            other.children.sort()
            for i in range(len(self.children)):
                is_child_same = self.children[i] == other.children[i]
                if not is_child_same:
                    return False
            return True
        return False

    def __lt__(self, other):
        """Sort by resource type."""
        return self.resource_type > other.resource_type

    def __hash__(self):
        return int(hashlib.md5(self.resource_name.encode()).hexdigest(), 16)
