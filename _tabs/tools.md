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


## ⚙ Function Caller
It's a tool for hiding your function name with chr() functions.
### Example:
Input:
```py
function_name()
```
Response:
```py
globals()[chr(102)+chr(117)+chr(110)+chr(99)+chr(116)+chr(105)+chr(111)+chr(110)+chr(95)+chr(110)+chr(97)+chr(109)+chr(101)]() #function_name()
```
---