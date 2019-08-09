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

"""Mock CAI data generator."""

from data_generator.file_handler import read_yaml_file
from data_generator.generator import CAIDataGenerator


if __name__ == '__main__':
    config_file_path = 'config.yaml'
    config = read_yaml_file(config_file_path)

    CAIDataGenerator(config).generate()
