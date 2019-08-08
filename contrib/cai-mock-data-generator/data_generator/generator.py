from concurrent.futures import ThreadPoolExecutor

import queue

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

    def generate(self):
        """Generate the mock data and output to files."""
        try:
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
                #self._generate_sub_resource(root_resource, resource_sub_structure)
                futures.append(self.thread_pool.submit(self._generate_sub_resource,
                                                       root_resource,
                                                       resource_sub_structure))

            for future in futures:
                future.result()

        except Exception as e:
            print(e)
        finally:
            self.iam_queue.put('EOQ')
            self.resource_queue.put('EOQ')

    def _generate_sub_resource(self, parent_resource, resource_structure):
        """Generate sub resource.

        Args:
            parent_resource (Resource): The parent resource.
            resource_structure (dict): The sub resource structure.

        """
        resource_type = ''
        for key in resource_structure:
            if key != 'resource_count':
                resource_type = key
                break

        count = resource_structure.get('resource_count', 0)
        generator = RESOURCE_GENERATOR_FACTORY.get(resource_type)

        for i in range(0, count):
            resource = generator(parent_resource)
            self.iam_queue.put(resource.resource_iam_policy)
            self.resource_queue.put(resource.resource_data)

            resource_sub_structure = resource_structure.get(resource_type, [])

            for structure in resource_sub_structure:
                self._generate_sub_resource(resource, structure)
