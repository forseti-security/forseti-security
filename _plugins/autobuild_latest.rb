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
# This builds the _docs/latest/ pseudo-directory and updates the inverted index
# for versions to support the version dropdown on docs pages.
#
# 1. The docs are moved over from _docs/_latest/ to _docs/latest
# 2. Tombstone files for docs that existed in a previous version but no longer
#    exist in latest are generated in _docs/latest
# 3. The inverted version index is built
#
# This all done transparently behind-the-scenes such that _docs/latest is only
# seen and used by the Jekyll build process.
require 'jekyll'

# At the start of Jekyll's build process, create a pseudo _docs/latest directory
# to represent the latest/ documentation URLs
Jekyll::Hooks.register :site, :after_reset do |site|
  `./scripts/jekyll_site_pre_render_hook.sh`
end

# After Jekyll has written the static website to disk at _www/www, then remove
# the pseudo _docs/latest directory.
Jekyll::Hooks.register :site, :post_write do |site|
  `rm -rf _docs/latest/`
end
