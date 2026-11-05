# How it works

Two interactive walkthroughs, built from credgate's real output: every
score, token and decision below is what credgate produces (regenerated with
`tools/build_visuals.py`). Use synthetic data only, as here.

## A request through the proxy

Follow one prompt from an analyst's tool, through the proxy, to Claude and
back: the key is checked, identifiers are found, the policy decides each
one, Claude sees tokens and labels instead of values, and the answer is
restored before the analyst reads it. Pick a scenario to see a card with
its CVV blocked, a leaver's key refused, or a local model receiving the
text as it is.

<iframe src="../visuals/proxy.html" title="A request through the credgate proxy, step by step"
        style="width:100%;height:760px;border:0" loading="lazy" class="cg-visual"></iframe>

The policy used here tokenises identity numbers for frontier models,
redacts contact and personal details, and blocks a card sent with its CVV
and expiry. See the [proxy guide](proxy.md) to run it.

## How a match is scored

Pick an example to see each step: the text is normalised, a candidate of
the right shape is found, its checksum is checked, and its confidence is
set from the shape and raised or lowered by the words around it. Move the
minimum confidence to see which matches a policy would act on.

<iframe src="../visuals/scoring.html" title="How credgate scores a match"
        style="width:100%;height:900px;border:0" loading="lazy" class="cg-visual"></iframe>

Each type's starting confidence is set by hand in the shared spec
(`spec/detectors.yaml`), the same in R and Python, and checked against
credgate's benchmark corpus: a fixed value for most types (an Aadhaar number
that passes its checksum starts at 0.85), a value that depends on how the
match is written for some (a mobile number written with +91 starts higher
than ten bare digits), and a lower value without a keyword for shapes that
mean little alone (a voter ID format, which could be a product code). It
expresses how strong the evidence is, not a measured probability.

The rules are in the [specification](spec.md#detection-algorithm): a keyword
within 40 characters raises a score by 80% of what is left to 1, a negative
keyword halves it, and the result is rounded to two digits. In the policy
editor, Try it shows the same steps for your own text, including what was
not reported and why.

<script>
// Each visual reports its height; fit its frame to it.
window.addEventListener("message", function (e) {
  if (!e.data || typeof e.data.cgHeight !== "number") return;
  document.querySelectorAll("iframe.cg-visual").forEach(function (f) {
    if (f.contentWindow === e.source) f.style.height = Math.ceil(e.data.cgHeight) + "px";
  });
});
</script>
