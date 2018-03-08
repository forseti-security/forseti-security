#!/bin/bash
rm -rf _docs/latest
./scripts/build_doc_version_index.sh
cp -R _docs/_latest/ _docs/latest
./scripts/generate_tombstone_files.sh
find _docs/latest -type f -exec sed -i s:/_latest:/latest:g {} +
