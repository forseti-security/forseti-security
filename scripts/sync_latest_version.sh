#!/bin/bash
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
    echo "$1" | grep -Eo 'v[0-9]+\.[0-9]+' | uniq | sed '/v1.0/d'
}

function main() {
    local all_release_tags releases doc_versions
    all_release_tags="$(git tag -l v*.*)"
    releases="$(uniq_major_minor_filter "${all_release_tags}")"
    doc_versions="$(uniq_major_minor_filter "$(ls _docs)")"

    if [ -z "${doc_versions}" ]; then
        err "The _docs/ directory is not versioned properly. Please initialize 
            with at least one version."
        exit -1
    fi

    for release in ${RELEASES}; do
        if [ ! -d _docs/${release} ]; then
            ./scripts/create_new_version_from_latest.sh ${release}
        fi
    done
}

main "$@"
