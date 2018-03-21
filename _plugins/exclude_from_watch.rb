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
