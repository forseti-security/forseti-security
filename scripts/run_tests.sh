#!/bin/sh
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

# Delete all running containers
docker rm -f $(docker ps -a -q)

docker build -t forseti/base -f scripts/docker/base . || exit 1
docker build -t forseti/build -f scripts/docker/forseti --no-cache . || exit 1
docker run -it -d --name build forseti/build /bin/bash || exit 1

docker exec -it build /bin/sh -c "coverage run --source='google.cloud.security' --omit='__init__.py' -m unittest discover -s . -p '*_test.py'" || exit 1
docker exec -it build /bin/sh -c "pylint --rcfile=pylintrc google/ scripts/gcp_setup/"
