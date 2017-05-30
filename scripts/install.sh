#!/bin/bash
# Copyright 2017 Google Inc.
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

# Forseti Security installer script
# Installs the python packages for Forseti.

# 1. grpcio-tools is installed first in order to build the protos.
# 2. Protos are built separately from the setup.py installation, due to
#    how setup.py and pip-installed packages don't play well together.
# 3. protobuf package is removed so that setup.py can resolve the
#    google.cloud.security module in the root directory.
# 4. Finally, run the setup.py install.
pip install grpcio-tools
python build_protos.py --clean
pip uninstall --yes protobuf
python setup.py install
