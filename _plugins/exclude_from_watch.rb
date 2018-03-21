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
# There exists a set of directories that we want to (1) include in the Jekyll
# build but (2) NOT trigger another build when they are modified. Primarily,
# this is used when auto-generating files for Jekyll build usage. It prevents
# an infinite loop where the auto-generation continues to trigger a new Jekyll
# build.
#
# For example: when auto-generating the _docs/latest pseudo-directory, these new
# files cause Jekyll's watch functionality to believe files have been modified
# and trigger a new build. When triggering a new build, these files are auto-
# generated again, which causes Jekyll's watch functionality to believe they've
# been modified... and so on.
#
# We break this cycle by including these files in the build, but excluding them
# from triggering a new build on watch.
#
# We accomplish this by hooking and overriding ("monkeypatching") jekyll-watch
# gem's functionality.
require 'jekyll-watch'
module Jekyll
  module Watcher
    # replace old method by new method
    # new method is now :custom_excludes
    # overridden method is now :old_custom_excludes
    alias_method :old_custom_excludes, :custom_excludes
    def custom_excludes(options)
      Array(options['exclude'] + options['exclude_from_watch']).map { |e| Jekyll.sanitized_path(options['source'], e) }
    end
  end
end
