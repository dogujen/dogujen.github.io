---
layout: default
title: Repositories
permalink: /repositories/
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
<style>
.page__inner {
  max-width: 100% !important;
  padding-left: 0 !important;
  padding-right: 0 !important;
}
.page {
  padding-left: 0 !important;
  padding-right: 0 !important;
}
</style>


{% for js in page.customjs %}
<script async type="text/javascript" src="{{ js }}"></script>
{% endfor %}