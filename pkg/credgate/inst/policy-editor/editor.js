// Clicking an endpoint row or a rule picks it in the matching select box
// (a selectize box in R, a plain select in Python).
$(document).on("click", "[data-pick]", function () {
  var target = document.getElementById($(this).data("target"));
  var value = $(this).attr("data-pick");
  if (!target) return;
  if (target.selectize) target.selectize.setValue(value);
  else $(target).val(value).trigger("change");
});

// Copy a new proxy key. The clipboard API needs HTTPS (or localhost); over
// plain HTTP, select the text and copy it the older way.
function cgCopyKey(button) {
  var text = document.getElementById("cg-new-key").innerText.trim();
  var done = function () { button.textContent = "Copied ✓"; };
  var fallback = function () {
    var area = document.createElement("textarea");
    area.value = text;
    area.setAttribute("readonly", "");
    area.style.position = "fixed";
    area.style.opacity = "0";
    document.body.appendChild(area);
    area.select();
    try { if (document.execCommand("copy")) done(); } finally { document.body.removeChild(area); }
  };
  if (navigator.clipboard && window.isSecureContext) {
    navigator.clipboard.writeText(text).then(done, fallback);
  } else {
    fallback();
  }
}
