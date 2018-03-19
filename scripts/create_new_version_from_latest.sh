#!/bin/bash
RELEASE_VERSION="$1"

function config_has_version() {
  yq '[.defaults[].scope.path == "_docs/'$RELEASE_VERSION'"] | any' _config.yml
}

function last_config_key() {
  yq -r '. | keys_unsorted | last' _config.yml
}

function add_version_to_config() {
  echo "$(cat _config.yml <(cat scripts/data/version_config_defaults.yml | sed -e s/'\$\$VERSION\$\$'/$RELEASE_VERSION/g))" > _config.yml
}

function snapshot_docs() {
  cp -R _docs/_latest/ _docs/$RELEASE_VERSION
}

function doc_categories_has_version() {
  yq '. | has("'$RELEASE_VERSION'")' _data/doc_categories.yml
}

function snapshot_doc_categories() {
  echo "$(yq -y '. += {"'$RELEASE_VERSION'": .latest}' _data/doc_categories.yml)" > _data/doc_categories.yml
}

function update_docs_links() {
  find _docs/$RELEASE_VERSION -type f -exec sed -i s:_docs/_latest:_docs/$RELEASE_VERSION:g {} +
  find _docs/$RELEASE_VERSION -type f -exec sed -i s:docs/_latest:docs/$RELEASE_VERSION:g {} +
  find _docs/$RELEASE_VERSION -type f -exec sed -i s:_docs/latest:_docs/$RELEASE_VERSION:g {} +
  find _docs/$RELEASE_VERSION -type f -exec sed -i s:docs/latest:docs/$RELEASE_VERSION:g {} +
}

function snapshot_includes() {
  cp -R _includes/docs/latest/ _includes/docs/$RELEASE_VERSION
}

function update_includes_links() {
  find _includes/docs/$RELEASE_VERSION -type f -exec sed -i s:_docs/_latest:_docs/$RELEASE_VERSION:g {} +
  find _includes/docs/$RELEASE_VERSION -type f -exec sed -i s:docs/_latest:docs/$RELEASE_VERSION:g {} +
  find _includes/docs/$RELEASE_VERSION -type f -exec sed -i s:_docs/latest:_docs/$RELEASE_VERSION:g {} +
  find _includes/docs/$RELEASE_VERSION -type f -exec sed -i s:docs/latest:docs/$RELEASE_VERSION:g {} +
}


if [ "$(config_has_version)" = "true" ]; then
  echo "Version '$RELEASE_VERSION' is already present in _config.yml."
  exit 0
fi

if [ "$(last_config_key)" != "defaults" ]; then
  echo "Error: Please make sure that \"defaults\" is the last configuration block in _config.yml"
  exit -1
fi

echo "Adding '$RELEASE_VERSION' to _config.yml ..."
add_version_to_config

if [ "$(doc_categories_has_version)" = "true" ]; then
  echo "Version '$RELEASE_VERSION' is already present in _data/doc_categories.yml."
  echo "Please update by hand, if necessary."
else
  echo "Snapshotting latest doc categories in '_data/doc_categories.yml' for $RELEASE_VERSION ..."
  snapshot_doc_categories
fi

echo "Snapshotting latest docs to '_docs/$RELEASE_VERSION/' ..."
snapshot_docs

echo "Updating site links within '_docs/$RELEASE_VERSION/' ..."
update_docs_links

echo "Snapshotting latest includes to '_includes/docs/$RELEASE_VERSION' ..."
snapshot_includes

echo "Updating site links within '_includes/docs/$RELEASE_VERSION' ..."
update_includes_links

echo "DONE."