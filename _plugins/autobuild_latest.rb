require 'jekyll'

Jekyll::Hooks.register :site, :after_reset do |site|
  `./scripts/jekyll_site_pre_render_hook.sh`
end

Jekyll::Hooks.register :site, :post_write do |site|
  `rm -rf _docs/latest/`
end
