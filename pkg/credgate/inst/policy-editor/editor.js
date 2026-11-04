// Clicking an endpoint row or a rule picks it in the matching select box.
$(document).on("click", "[data-pick]", function () {
  var target = document.getElementById($(this).data("target"));
  if (target && target.selectize) target.selectize.setValue($(this).attr("data-pick"));
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
