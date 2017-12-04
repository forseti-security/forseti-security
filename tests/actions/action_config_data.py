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

import os
import yaml

TEST_CONFIG_PATH = os.path.abspath(os.path.dirname(__file__))


def _load_yaml(filename):
  with open(os.path.join(TEST_CONFIG_PATH, filename)) as fp:
    return yaml.safe_load(fp)

BAD_CONFIG_PATH = os.path.join(
    TEST_CONFIG_PATH, 'test_data/bad.yaml')
VALID_CONFIG1 = _load_yaml('test_data/valid_config.yaml')
VALID_CONFIG1_PATH = os.path.join(
    TEST_CONFIG_PATH, 'test_data/valid_config.yaml')
INVALID_CONFIG1 = _load_yaml('test_data/invalid_config.yaml')
INVALID_CONFIG1_PATH = os.path.join(
    TEST_CONFIG_PATH, 'test_data/invalid_config.yaml')
