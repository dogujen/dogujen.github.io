---
layout: page
title: Projects
permalink: /projects/
icon: fas fa-diagram-project
customjs:
 - https://dogujen.github.io/assets/js/projects.js
---


<div id="repo-container" class="flex-grow-1 px-xl-1">
  <div class="card p-3">Loading...</div>
</div>
{% for js in page.customjs %}
<script async type="text/javascript" src="{{ js }}"></script>
{% endfor %}