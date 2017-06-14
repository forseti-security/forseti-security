---
title: Docs
---
<ul class="nav nav-tabs" style="margin-bottom: 20px;">
    <!-- <li><a href="#">Overview</a></li> -->
    <li class="active"><a href="#">Quick Starts</a></li>
    <li><a href="#">Development</a></li>
    <li><a href="#">How Tos</a></li>
    <li><a href="#">Resources</a></li>
</ul>

<div class="row">
<div class="col-md-3">
<div style="background-color: #f8f8f8; padding: 10px 15px">
<h4>Quick Starts</h4>
<ul class="docs-left-nav">
    <li class="active"><a href="#">Inventory</a></li>
    <li><a href="#">Scanner</a></li>
    <li><a href="#">Enforcer</a></li>
</ul>
</div>
</div>
<div id="documentation" class="col-md-7">
<!-- <h2>Main Documentation</h2> -->
{% capture include_content %}
{% include module_inventory_content.md %}
{% endcapture %}
{{ include_content | markdownify }}
</div>
<div id="toc" class="col-md-2 toc">
<ul>
    <li>
        <a href="#">Lorem ipsum</a>
        <ul>
            <li><a href="#">Lorem ipsum</a></li>
            <li><a href="#">Lorem ipsum lorem ipsum</a></li>
        </ul>
    </li>
    <li>
        <a href="#">Lorem ipsum lorem</a>
        <ul>
            <li><a href="#">Lorem ipsum lorem ipsum lorem</a></li>
            <li><a href="#">Lorem ipsum</a></li>
        </ul>
    </li>
</ul>
</div>
</div>