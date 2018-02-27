#!/bin/bash

if  [ -z ${JGT+x} ]; then
    # We don't have access to the encrypted vars.
    bundle exec jekyll build
else:
  # We do have access to the encrypted vars.
  JEKYLL_GITHUB_TOKEN=$JGTbundle exec jekyll build

bundle exec htmlproofer --check-img-http --check-opengraph --check-html \
--check-favicon --report-missing-names --report-script-embeds \
--url-ignore "/GoogleCloudPlatform/forseti-security/edit/" ./_www/www