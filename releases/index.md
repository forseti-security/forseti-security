---
layout: releases
title: Releases
---
{% for release in site.github.releases %}
  {% include releases/version_item.html release=release maxwords=50 %}
{% endfor %}
