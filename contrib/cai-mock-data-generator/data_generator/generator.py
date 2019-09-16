# Copyright 2019 The Forseti Security Authors. All rights reserved.
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

"""Data generator."""

from concurrent.futures import ThreadPoolExecutor

import queue

from data_generator.resource import RESOURCE_DEPENDENCY_MAP
from data_generator.resource import RESOURCE_GENERATOR_FACTORY
from data_generator.file_handler import create_file_and_writer_listener


class CAIDataGenerator(object):
    """CAI data generator."""

    def __init__(self, config):
        """Init.

        Args:
            config (dict): The config object.
        """
        self.config = config
        self.iam_queue = queue.Queue()
        self.resource_queue = queue.Queue()
        self.thread_pool = ThreadPoolExecutor(max_workers=10)

    def create_writer_workers(self):
        """Create the writer workers, one for iam and one for resource."""
        output_file_path = self.config.get('output_path')
        output_file_name_prefix = self.config.get('output_file_name_prefix')

        iam_output_file = '{}/{}-iam-policy.dump'.format(output_file_path, output_file_name_prefix)
        resource_output_file = '{}/{}-resource.dump'.format(output_file_path, output_file_name_prefix)

        self.thread_pool.submit(
            create_file_and_writer_listener, iam_output_file, self.iam_queue)
        self.thread_pool.submit(
            create_file_and_writer_listener, resource_output_file, self.resource_queue)

    def _validate_config_structure(self,
                                   resource_structure,
                                   parent_resource_type,
                                   allowed_resources):
        """Validate config structure.

        Args:
            resource_structure (dict): The child resource structure.
            parent_resource_type (str): The parent resource type.
            allowed_resources (list): The list of allowed resources
                for this parent resource type.
        """
        resource_type = ''

        for key in resource_structure:
            if key in RESOURCE_GENERATOR_FACTORY:
                resource_type = key
                break

        if (resource_type == 'appengine_application' and
                resource_structure.get('resource_count') != 1):
            raise Exception('You can only have one appengine app '
                            'under a project.')

        if not resource_type:
            raise KeyError('Resource type not found under resource {} or is not supported.'.format(
                parent_resource_type))

        if resource_type not in allowed_resources:
            raise Exception('Resource {} cannot be defined under resource {}.'.format(
                            resource_type,
                            parent_resource_type))

        if resource_type not in RESOURCE_DEPENDENCY_MAP:
            raise Exception('Resource {} is not defined in the resource dependency map.'.format(
                            resource_type))

        cur_resource_structure = resource_structure.get(resource_type, [])
        for cur_sub_structure in cur_resource_structure:
            self._validate_config_structure(cur_sub_structure,
                                            resource_type,
                                            RESOURCE_DEPENDENCY_MAP.get(resource_type))

    def _validate_config(self):
        """Validate the config object to make sure the structure is correct."""
        root_resource_type = self.config.get('root_resource_type')
        resource_structure_list = self.config.get('resource_structure', [])
        for resource_structure in resource_structure_list:
            self._validate_config_structure(resource_structure,
                                            root_resource_type,
                                            RESOURCE_DEPENDENCY_MAP.get(root_resource_type))

    def generate(self):
        """Generate the mock data and output to files."""
        try:
            self._validate_config()

            self.create_writer_workers()

            root_resource_type = self.config.get('root_resource_type')
            root_resource_id = self.config.get('root_resource_id')

            generator = RESOURCE_GENERATOR_FACTORY.get(root_resource_type)
            root_resource = generator(resource_id=root_resource_id)

            self.iam_queue.put(root_resource.resource_iam_policy)
            self.resource_queue.put(root_resource.resource_data)

            resource_structure = self.config.get('resource_structure', [])

            futures = []

            for resource_sub_structure in resource_structure:
                futures.append(self.thread_pool.submit(self._generate_sub_resource,
                                                       root_resource,
                                                       resource_sub_structure))

            for future in futures:
                future.result()

        except Exception as e:
            raise e
        finally:
            self.iam_queue.join()
            self.resource_queue.join()
            self.iam_queue.put(None)
            self.resource_queue.put(None)

    def _generate_sub_resource(self, parent_resource, resource_structure):
        """Generate sub resource.

        Args:
            parent_resource (Resource): The parent resource.
            resource_structure (dict): The sub resource structure.

        """
        resource_type = ''
        for key in resource_structure:
            if key in RESOURCE_GENERATOR_FACTORY:
                resource_type = key
                break

        count = resource_structure.get('resource_count', 0)
        generator = RESOURCE_GENERATOR_FACTORY.get(resource_type)

        for i in range(0, count):
            resource = generator(parent_resource)
            if resource.resource_iam_policy:
                # Some resources don't have iam policies, e.g. bq table.
                self.iam_queue.put(resource.resource_iam_policy)
            self.resource_queue.put(resource.resource_data)

            resource_sub_structure = resource_structure.get(resource_type, [])

            for structure in resource_sub_structure:
                self._generate_sub_resource(resource, structure)
