---
layout: page
title: Tools
permalink: /tools/
icon: fas fa-tools
customjs:
 - https://dogujen.github.io/assets/js/tool.js
---

# 🛠️ Tools

Soon. (This page is not completed yet.)  
{% for js in page.customjs %}
<script async type="text/javascript" src="{{ js }}"></script>
{% endfor %}
{% include tools.html %}
