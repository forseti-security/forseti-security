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

while sleep 1m; do echo "=====[  $SECONDS seconds, website still building...  ]====="; done &

JEKYLL_GITHUB_TOKEN=$JGT bundle exec jekyll build >> build.log 2 >&1

#Killing background sleep loop
kill %1

bundle exec htmlproofer --check-img-http --check-html \
--internal-domains 'forsetisecurity.org' \
--check-favicon --report-missing-names --report-script-embeds \
--url-ignore '/forseti-security/forseti-security/edit/,/maxcdn.bootstrapcdn.com/,/d3js.org/' \
--file-ignore '/develop/reference/' './_www/www/' \
--only_4xx

exit ${return_code}
