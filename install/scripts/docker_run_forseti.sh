#!/bin/bash
# Copyright 2017 The Forseti Security Authors. All rights reserved.
#
# Licensed under the Apache License, Versisn 2.0 (the "License");
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

# Check to see that the docker command is available to us.
if [ -x "$(command -v docker)" ]; then
    # Docker command does exist.
    # Check to see if we're on Travis.
    if [ ${TRAVIS+x} ]; then
        # We are on Travis.
        # Required for codecov.io to export coverage within a Docker container.
        echo "We're on Travis, setting our CI_ENV... "
        CI_ENV=`bash <(curl -s https://codecov.io/env) || echo ''`
        # Start the container for testing and code verification.
        echo "Starting our container for testing and code verification... "
        docker run ${CI_ENV} -it -d --name build forseti/build /bin/bash
    else
        # We're not on Travis, run without the CI_ENV environment variable.
        echo "Starting our container for testing and code verification... "
        docker run -it -d --name build forseti/build /bin/bash
    fi
else
    echo "Can\'t run docker, exiting."
    exit 1
fi

# Test to see Forseti Security was installed, these should match the entry
# points in setup.py
echo "Testing the container for a successfull Forseti Security installation... "
docker exec -it build /bin/bash -c "hash forseti" || exit 1
docker exec -it build /bin/bash -c "hash forseti_enforcer" || exit 1
docker exec -it build /bin/bash -c "hash forseti_server" || exit 1

exit ${return_code}
