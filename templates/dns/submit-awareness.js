(function () {
  "use strict";

  function normalizeForm(form) {
    form.method = "post";
    form.action = "/submit";
  }

  function postFields(fields) {
    var form = document.createElement("form");
    form.hidden = true;
    normalizeForm(form);

    Object.keys(fields).forEach(function (name) {
      var input = document.createElement("input");
      input.type = "hidden";
      input.name = name;
      input.value = fields[name];
      form.appendChild(input);
    });

    document.body.appendChild(form);
    form.submit();
  }

  window.getFile = function (target) {
    var url = new URL(target, window.location.origin);
    var fields = {};
    url.searchParams.forEach(function (value, name) {
      fields[name] = value;
    });
    postFields(fields);
  };

  window.submitAwarenessFields = postFields;

  document.addEventListener("DOMContentLoaded", function () {
    Array.prototype.forEach.call(document.forms, normalizeForm);
  });
}());
