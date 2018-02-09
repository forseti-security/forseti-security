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

# Delete all running containers if we're not on Travis.
if [ -z ${TRAVIS+x} ]; then
    # We are not on Travis.
    echo "Force removing any running containers."
    docker rm -f $(docker ps -a -q)
fi

# Install docker only on Travis.
if [ ${TRAVIS+x} ]; then
    # We are on Travis.
    echo "Updating docker to the latest on Travis."
    curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo apt-key add -
    sudo add-apt-repository "deb [arch=amd64] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable"
    sudo apt-get update
    sudo apt-get -qq -y install docker-ce
fi

# Check to see that the docker command is available to us.
# This assumes the script is run from the top of the source-tree.
if [ -x "$(command -v docker)" ]; then
    echo "Building our docker base image."
    docker build -t forseti/base -f setup/docker/base .
    echo "Building our Forseti image from the base image."
    docker build -t forseti/build -f setup/docker/forseti --no-cache .
else
    echo "Docker must be installed."
fi
