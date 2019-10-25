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
# Create a new documentation version when a new release is discovered in the
# repository

err() {
  echo "[$(date +'%Y-%m-%dT%H:%M:%S%z')]: $@" >&2
}

#######################################
# List all unique major and minor
# semantic versions, excluding v1.0.
# Globals:
#   None
# Arguments:
#   None
# Returns:
#   array - unique versions
#######################################
function uniq_major_minor_filter() {
    echo "$1" | grep -Po '^v2\.(2[0-9]|1[4-9])+(?=\.|$)' | uniq | sed '/v1.0/d'
}

function main() {
    local all_release_tags all_major_minor_release_tags releases doc_versions
    all_release_tags="$(git tag -l v*.*)"
    all_major_minor_release_tags="$(uniq_major_minor_filter "${all_release_tags}")"

    # sed trims this list to 10.
    releases="$(echo "${all_major_minor_release_tags}" | sort -Vr | cut -d "." -f1-2 | sed '1,10!d')"
    doc_versions="$(uniq_major_minor_filter "$(ls _docs)")"

    if [ -z "${doc_versions}" ]; then
        err "The _docs/ directory is not versioned properly. Please initialize 
            with at least one version."
        exit -1
    fi

    for release in ${releases}; do
        if [ ! -d _docs/${release} ]; then
            ./scripts/create_new_version_from_latest.sh ${release}
        fi
    done
}

main "$@"
