// Clicking an endpoint row or a rule picks it in the matching select box.
$(document).on("click", "[data-pick]", function () {
  var target = document.getElementById($(this).data("target"));
  if (target && target.selectize) target.selectize.setValue($(this).attr("data-pick"));
});
