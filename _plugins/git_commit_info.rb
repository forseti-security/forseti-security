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
# This builds the _docs/latest/ pseudo-directory and updates the inverted index
# for versions to support the version dropdown on docs pages.
#
# 1. The docs are moved over from _docs/_latest/ to _docs/latest
# 2. Tombstone files for docs that existed in a previous version but no longer
#    exist in latest are generated in _docs/latest
# 3. The inverted version index is built
#
# Adds current commit information, from Git, to the list of Jekyll site
# properties
module Jekyll
  class GitCommitInfo < Generator
    def generate(site)
      commit_info = `git log -1 --pretty=format:"%cd %h" --date=format:"%Y-%m-%d %H:%M" HEAD`
      parts = /(?<datetime>\d{4}-\d{2}-\d{2} \d{2}:\d{2}) (?<hash>\h+)/.match(commit_info)

      site.data['commit'] = {
        'hash' => parts['hash'],
        'datetime' => parts['datetime']
      }
    end
  end
end
