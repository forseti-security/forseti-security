import collections
import json
import unittest
import os


from data_generator import generator
from data_generator.file_handler import read_yaml_file


class TestGenerator(unittest.TestCase):

    file_paths = ['{}/{}-resource.dump', '{}/{}-iam-policy.dump']

    def test_count_folders(self):
        config_file_path = './config/config_100_folders.yaml'
        config = read_yaml_file(config_file_path)
        generator.CAIDataGenerator(config).generate()
        paths = list(map(lambda p: p.format(config.get('output_path'),
                                       config.get('output_file_name_prefix')),
                    self.file_paths))
        resource_count = self.count_resource_per_type(paths[0])
        iam_count = self.count_resource_per_type(paths[1])
        self.assertEqual(1, resource_count.get('cloudresourcemanager.googleapis.com/Organization', 0))
        self.assertEqual(1, iam_count.get('cloudresourcemanager.googleapis.com/Organization', 0))
        self.assertEqual(100, resource_count.get('cloudresourcemanager.googleapis.com/Folder', 0))
        self.assertEqual(100, iam_count.get('cloudresourcemanager.googleapis.com/Folder', 0))
        for path in paths:
            os.unlink(path)

    def test_count_folders_projects(self):
        config_file_path = './config/config_folders_projects.yaml'
        config = read_yaml_file(config_file_path)
        generator.CAIDataGenerator(config).generate()
        paths = list(map(lambda p: p.format(config.get('output_path'),
                                            config.get('output_file_name_prefix')),
                         self.file_paths))
        resource_count = self.count_resource_per_type(paths[0])
        iam_count = self.count_resource_per_type(paths[1])
        self.assertEqual(1, resource_count.get('cloudresourcemanager.googleapis.com/Organization', 0))
        self.assertEqual(1, iam_count.get('cloudresourcemanager.googleapis.com/Organization', 0))
        self.assertEqual(10, resource_count.get('cloudresourcemanager.googleapis.com/Folder', 0))
        self.assertEqual(10, iam_count.get('cloudresourcemanager.googleapis.com/Folder', 0))
        self.assertEqual(50, resource_count.get('cloudresourcemanager.googleapis.com/Project', 0))
        self.assertEqual(50, iam_count.get('cloudresourcemanager.googleapis.com/Project', 0))
        for path in paths:
            os.unlink(path)

    def test_count_mixed(self):
        config_file_path = './config/config_mixed.yaml'
        config = read_yaml_file(config_file_path)
        generator.CAIDataGenerator(config).generate()
        paths = list(map(lambda p: p.format(config.get('output_path'),
                                            config.get('output_file_name_prefix')),
                         self.file_paths))
        resource_count = self.count_resource_per_type(paths[0])
        iam_count = self.count_resource_per_type(paths[1])
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

        for path in paths:
            os.unlink(path)

    @staticmethod
    def count_resource_per_type(file_path):
        """Count resource by type.

        Args:
            file_path (str): Path to the dump file.

        Returns:
            dict: Resource_type to count dictionary.
        """
        results = collections.defaultdict(int)
        with open(file_path, 'r') as f:
            for line in f:
                data = json.loads(line)
                asset_type = data.get('asset_type')
                results[asset_type] += 1
        return results
