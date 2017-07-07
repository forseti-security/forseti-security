---
title: Frequently Asked Questions 
---
# {{ page.title }}

Here are some frequently asked questions about Forseti Security.

{% assign grouped_faqs = site.faq | sort:"order" | group_by:"category" %}

<div class="panel-group" id="accordion">

{% for category in site.data.faq_categories %}

  <h2 id="{{ category.title | slugify }}">{{ category.title }}</h2>

  {% for faq_group in grouped_faqs %}

    {% if category.title == faq_group.name %}

      {% assign outerloop = forloop %}
      {% for q in faq_group.items %}
        {% capture unique_id %}{{ outerloop.index }}-{{ forloop.index }}{% endcapture %}
        {% include faq/qa_item.html q=q qid=unique_id accordion_id="#accordion" %}
      {% endfor %}

    {% endif %}

  {% endfor %}

{% endfor %}

</div>
