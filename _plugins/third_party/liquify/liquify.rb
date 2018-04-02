# This Liquid filter is used to liquid-parse the input.
#
# Created by @vividh (https://github.com/vividh)
# Available under MIT License.

module Jekyll
    module LiquifyFilter
        def liquify(input)
            output = Liquid::Template.parse(input)
            output.render(@context)
        end
    end
end

Liquid::Template.register_filter(Jekyll::LiquifyFilter)
