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
#
# Generate pages ("tombstones") for files that existed in a previous version of
# the docs, but no longer exist in latest.

function silent_pushd() {
    pushd $1 1>/dev/null 2>&1
}

function silent_popd() {
    popd 1>/dev/null 2>&1
}

function all_version_directories_except_latest() {
    find _docs -mindepth 1 -maxdepth 1 -not -path */_latest -type d
}

function latest_version_files() {
    silent_pushd _docs/_latest
        find . -type f
    silent_popd
}

function all_version_files() {
    for dir in $(all_version_directories_except_latest); do
        silent_pushd $dir
            find . -type f
        silent_popd
    done 
}

function set_union_of_all_version_files() {
    all_version_files | sort | uniq
}

#######################################
# Find files that existed in previous
# versions but no longer exist in the
# latest version.
# Globals:
#   None
# Arguments:
#   None
# Returns:
#   array - filenames
#######################################
function tombstone_files() {
    comm -23 <(set_union_of_all_version_files) <(latest_version_files | sort)
}

function generate_tombstone_files() {
    echo "Creating tombstones for:"
    for file in $(tombstone_files); do
        local filename="${file#./}"
        printf "\t${filename}\n"

        local latest_tombstone_file="_docs/latest/${filename}"
        
        local directory
        directory="$(dirname "${latest_tombstone_file}")"

        mkdir -p "${directory}" && \
        cp -u scripts/data/tombstone_template.md "${latest_tombstone_file}"
    done
}

function main() {
    generate_tombstone_files
}

main "$@"
