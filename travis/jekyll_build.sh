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
set -e
trap 'return_code=$?' ERR

# Write out the Python API documentation via Sphinx
# TODO(drmorris): change branch from "stable" to "master" when after release
./scripts/generate_sphinx_docs.sh "stable"

JEKYLL_GITHUB_TOKEN=$JGT bundle exec jekyll build -V

bundle exec htmlproofer --check-img-http --check-html \
--check-favicon --report-missing-names --report-script-embeds \
--url-ignore '/GoogleCloudPlatform/forseti-security/edit/,/maxcdn.bootstrapcdn.com/,/d3js.org/' \
--file-ignore '/develop/reference/' './_www/www/'

exit ${return_code}
