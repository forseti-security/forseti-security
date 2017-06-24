---
title: Frequently Asked Questions 
---
# {{ page.title }}

Here are some frequently asked questions about Forseti Security.

{% assign faqs = site.faq | sort: "order" %}

<div class="panel-group" id="accordion">
  {% for q in faqs %}

    <div class="panel panel-default">
      <div class="panel-heading">
        <h4 class="panel-title">
          <a data-toggle="collapse" data-parent="#accordion" href="#collapse{{ forloop.index }}">
            {{ q.title }}
          </a>
        </h4>
      </div>
      <div id="collapse{{ forloop.index }}" class="panel-collapse collapse">
        <div class="panel-body">
          {{ q.content }}
        </div>
      </div>
    </div>

  {% endfor %}
</div>
