#!/bin/bash
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

function tombstone_files() {
  comm -23 <(set_union_of_all_version_files) <(latest_version_files | sort)
}

function generate_tombstone_files() {
  # TODO(drmorris): Tombstone file will depend upon document version index
  echo "Creating tombstones for:"
  for file in $(tombstone_files); do
    filename="${file#./}"
    printf "\t$filename\n"

    latest_tombstone_file="_docs/latest/$filename"
    directory=$(dirname "$latest_tombstone_file")

    mkdir -p "$directory" && \
    cp -u scripts/data/tombstone_template.md "$latest_tombstone_file"
  done
}

generate_tombstone_files