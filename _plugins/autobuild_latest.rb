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
