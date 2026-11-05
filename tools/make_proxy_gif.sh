#!/bin/sh
# The proxy walkthrough as two GIFs (light and dark) for the README and docs,
# from docs/visuals/proxy.html: headless Chrome takes a screenshot of each
# step, ffmpeg joins them. Run tools/build_visuals.py first.
#   tools/make_proxy_gif.sh [chrome]
set -eu
root=$(cd "$(dirname "$0")/.." && pwd)
chrome=${1:-"/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"}
work=$(mktemp -d)
trap 'kill "$server" 2>/dev/null; rm -rf "$work"' EXIT
python3 -m http.server 8848 --bind 127.0.0.1 --directory "$root/docs" >/dev/null 2>&1 &
server=$!
sleep 1
for theme in light dark; do
  flag=""
  [ "$theme" = dark ] && flag="--force-dark-mode"
  for n in 1 2 3 4 5 6 7 8; do
    "$chrome" --headless=new --disable-gpu --hide-scrollbars --force-prefers-reduced-motion $flag \
      --window-size=1000,600 --screenshot="$work/$theme-$n.png" \
      "http://127.0.0.1:8848/visuals/proxy.html?scenario=frontier&step=$n&still&theme=$theme" \
      >/dev/null 2>&1
  done
  out="$root/docs/images/proxy-walkthrough-$theme.gif"
  ffmpeg -loglevel error -y -framerate 1/3 -i "$work/$theme-%d.png" \
    -vf "fps=1/3,scale=900:-1:flags=lanczos,split[a][b];[a]palettegen=max_colors=96[p];[b][p]paletteuse=dither=none" \
    -loop 0 "$out"
  echo "wrote $out"
done
