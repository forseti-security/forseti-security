#!/bin/bash
# Copyright 2018 The Forseti Security Authors. All rights reserved.
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
#
# Build our Python documentation from source files with Sphinx and then insert
# the generated documentation files into the appropriate path for use by Jekyll
# when building our website

BUILD_FROM_PYTHON_SOURCE_BRANCH="${1:-master}"
TEMP_SOURCE_DIRECTORY="$(mktemp -d)"
readonly BUILD_FROM_PYTHON_SOURCE_BRANCH TEMP_SOURCE_DIRECTORY

trap 'rm -rf "${TEMP_SOURCE_DIRECTORY}"' EXIT

#######################################
# Checks out the latest version of
# sourcecode so that we can build our
# API reference documentation from the
# Python docstrings.
# Globals:
#   TEMP_SOURCE_DIRECTORY
#######################################
function checkout_python_source_to_temp_directory() {
    git clone https://github.com/GoogleCloudPlatform/forseti-security.git \
      --branch ${BUILD_FROM_PYTHON_SOURCE_BRANCH} \
      --single-branch ${TEMP_SOURCE_DIRECTORY}

    # Update git's index since checking out to a worktree in a separate
    # directory changes the contents of git's index in the current working
    # directory, due to the nature of git-checkout
    git add -u .
}

#######################################
# Use the production-ready Dockerfiles
# to build the sourcecode without
# affecting the host machine.
# Globals:
#   TEMP_SOURCE_DIRECTORY
#######################################
function build_python_source_in_docker() {
    pushd $TEMP_SOURCE_DIRECTORY
      ./install/scripts/docker_setup_forseti.sh
    popd
}

#######################################
# Generate the API reference doc from
# Python docstrings with Sphinx; the
# generated docs are baked into the
# Docker image once the build is
# finished.
#######################################
function generate_sphinx_docs_in_docker() {
    docker build \
      -t forseti/generate_sphinx_docs \
      -f scripts/docker/generate_sphinx_docs.Dockerfile ./scripts/docker
}

function copy_sphinx_docs_into_jekyll_docs() {
    # The docs have been baked into the image with docker-build; now we just
    # to copy the generated docs over from a live container
    local container_id
    container_id="$(docker create forseti/generate_sphinx_docs)"

    # Remove the old generated Sphinx docs
    rm -rf _docs/_latest/develop/reference

    # Copy generated docs from container into Jekyll
    docker cp \
      "${container_id}":/forseti-security/build/sphinx/html/. \
      _docs/_latest/develop/reference

    docker rm "${container_id}"
}

function main() {
    checkout_python_source_to_temp_directory
    build_python_source_in_docker
    generate_sphinx_docs_in_docker
    copy_sphinx_docs_into_jekyll_docs
}

main "$@"
