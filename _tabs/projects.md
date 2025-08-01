---
layout: page
title: Projects
permalink: /projects/
icon: fas fa-diagram-project
customjs:
 - https://dogujen.github.io/assets/js/projects.js
---


<div id="project-list">
  <article class="card-wrapper card">
    <div class="card-body">
      <p>Projects are on the way...</p>
    </div>
  </article>
</div>

{% for js in page.customjs %}
<script async type="text/javascript" src="{{ js }}"></script>
{% endfor %}