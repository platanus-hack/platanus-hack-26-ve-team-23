#!/bin/sh
# Copy the app's UI into app/ so the landing's phone shows the real interface.
# usage: ./sync-app.sh [path-to-witness-ui]   (default: ../../witness/ui)
set -eu
SRC="${1:-../../witness/ui}"
[ -f "$SRC/index.html" ] || { echo "no app UI at $SRC" >&2; exit 1; }
rm -rf app
mkdir -p app
for f in index.html style.css app.js i18n.js kit.js chart.js preview.js hawk-mark.svg; do cp "$SRC/$f" "app/$f"; done
cp -r "$SRC/fonts" app/fonts
echo "app/ updated from $SRC"
