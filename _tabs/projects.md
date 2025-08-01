---
layout: page
title: Projects
permalink: /projects/
icon: fas fa-diagram-project
customjs:
 - https://dogujen.github.io/assets/js/projects.js
---

<ul id="repo-list">
  <li>Loading</li>
</ul>
{% for js in page.customjs %}
<script async type="text/javascript" src="{{ js }}"></script>
{% endfor %}