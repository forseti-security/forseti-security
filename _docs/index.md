---
title: Docs
order: 1
---
{% capture include_content %}
{% include module_inventory_content.md %}
{% endcapture %}
{{ include_content | markdownify }}
