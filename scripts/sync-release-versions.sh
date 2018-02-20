#!/bin/bash
function uniq_major_minor_filter() {
    echo "$1" | grep -Eo 'v[0-9]+\.[0-9]+' | uniq | sed '/v1.0/d'
}

ALL_RELEASE_TAGS=$(git tag -l v*.*)
RELEASES=$(uniq_major_minor_filter "$ALL_RELEASE_TAGS")
DOC_VERSIONS=$(uniq_major_minor_filter "$(ls _docs)")

if [ -z "$DOC_VERSIONS" ]; then
    echo The _docs/ directory is not versioned properly. Please initialize with \
         at least one version.
    exit -1
fi

LATEST_DOC_VERSION=$(echo "$DOC_VERSIONS" | sort -r | head -n 1)

for release in $RELEASES; do
    if [ ! -d _docs/$release ]; then
        cp -R _docs/$LATEST_DOC_VERSION _docs/$release
    fi
done

