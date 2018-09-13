#!/bin/bash
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

trap 'return_code=$?' ERR

echo "Running unittests... "

# Check to see if we're on Travis.
if [ ${TRAVIS+x} ]; then
    # We are on Travis.
    # Run our tests with codecov
    docker exec -it build /bin/bash -c "coverage run --source='google.cloud.forseti' --omit='__init__.py' -m unittest discover --verbose -s . -p '*_test.py'"
else
    # We are NOT on Travis.
    docker exec -it build /bin/bash -c "python -m unittest discover --verbose -s . -p '*_test.py'"
fi

exit ${return_code}
