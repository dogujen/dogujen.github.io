---
layout: page
title: Tools
permalink: /tools/
icon: fas fa-tools
---

# 🛠️ Tools

Tek inputlu, seçilen işlem uygulanıyor ve sonuç sağdaki output'ta gösteriliyor.  

<div style="display: flex; align-items: center; gap: 16px; max-width: 900px;">

  <textarea id="input1" placeholder="Input" style="flex: 1; height: 180px; padding: 8px; resize: vertical; font-family: monospace;"></textarea>

  <div style="display: flex; flex-direction: column; gap: 8px; align-items: center; min-width: 220px;">
    <select id="operation" style="width: 200px; padding: 8px;"></select>
    <input id="xorKey" type="text" placeholder="XOR Key (for XOR)" style="width: 200px; padding: 8px; display:none;" />
    <button id="btnProcess" style="padding: 8px 16px; width: 200px;">Process</button>
  </div>

  <textarea id="input2" placeholder="Output will appear here" style="flex: 1; height: 180px; padding: 8px; resize: vertical; font-family: monospace;" readonly></textarea>
</div>

<script>
  // Helper: chr converter only for function caller
  function toChrConcat(str){
    return str.split('').map(c => `chr(${c.charCodeAt(0)})`).join('+');
  }

  // Operations
  const operations = {
    "functionCaller": {
      name: "Function Caller (chr... format)",
      encrypt: (input) => {
        return `globals()[${toChrConcat(input)}]()`;
      },
      usesXorKey: false,
      showXorKey: false
    },
    "urlEncode": {
      name: "URL Encode",
      encrypt: (input) => encodeURIComponent(input),
      usesXorKey: false,
      showXorKey: false
    },
    "urlDecode": {
      name: "URL Decode",
      encrypt: (input) => {
        try {
          return decodeURIComponent(input);
        } catch {
          return "Invalid URL encoding";
        }
      },
      usesXorKey: false,
      showXorKey: false
    },
    "base64Encode": {
      name: "Base64 Encode",
      encrypt: (input) => btoa(input),
      usesXorKey: false,
      showXorKey: false
    },
    "base64Decode": {
      name: "Base64 Decode",
      encrypt: (input) => {
        try {
          return atob(input);
        } catch {
          return "Invalid Base64 input";
        }
      },
      usesXorKey: false,
      showXorKey: false
    }
  };

  // Setup select options
  const sel = document.getElementById("operation");
  for(const key in operations){
    const opt = document.createElement("option");
    opt.value = key;
    opt.textContent = operations[key].name;
    sel.appendChild(opt);
  }

  // Show/hide XOR key input if needed
  sel.addEventListener("change", () => {
    const op = operations[sel.value];
    document.getElementById("xorKey").style.display = op.showXorKey ? "block" : "none";
  });

  // Process button
  function processOperation(){
    const opKey = sel.value;
    const input = document.getElementById("input1").value;
    const xorKey = document.getElementById("xorKey").value;
    const outputBox = document.getElementById("input2");

    const op = operations[opKey];
    if(!op){
      outputBox.value = "Invalid operation";
      return;
    }

    let result;
    if(op.usesXorKey){
      result = op.encrypt(input, xorKey);
    } else {
      result = op.encrypt(input);
    }

    outputBox.value = result;
  }

  document.getElementById("btnProcess").addEventListener("click", processOperation);

  window.addEventListener("DOMContentLoaded", () => {
    sel.selectedIndex = 0;
    document.getElementById("xorKey").style.display = "none";
    document.getElementById("input2").value = "";
  });
</script>
