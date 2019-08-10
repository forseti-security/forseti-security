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

"""File handler."""

import yaml


def read_yaml_file(full_file_path):
    """Read and parse yaml file.

    Args:
        full_file_path (str): The full file path.
    """
    with open(full_file_path, 'r') as f:
        try:
            return yaml.safe_load(f)
        except yaml.YAMLError as yaml_error:
            raise yaml_error


def create_file_and_writer_listener(file_path, content_queue):
    """Create file and a write listener listens to the content queue.

    Args:
        file_path (str): The file path.
        content_queue (Queue): The content queue to listen to.
    """
    first_line = True  # Need to make sure there is no empty line in the file.
    with open(file_path, 'w+') as f:
        while True:
            item = content_queue.get()
            if item is None:
                break
            if first_line:
                first_line = False
                f.write(item)
            else:
                f.write('\n{}'.format(item))
            content_queue.task_done()
