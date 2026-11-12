#!/bin/sh
# Event Solutions – Mac programos diegimas per Terminalą:
#   curl -fsSL https://app.eventsolutions.lt/mac-install.sh | sh
# Atsisiunčia programą (Apple M… arba Intel), patikrina, įdeda į Programos (Applications),
# nuima macOS „karantino“ žymą (kitaip nepasirašyta programa gali neatsidaryti ar dingti) ir atidaro.
set -e
BASE="${ES_BASE:-https://app.eventsolutions.lt}"
A=x64
[ "$(uname -m)" = "arm64" ] && A=arm64
[ "$(/usr/sbin/sysctl -in hw.optional.arm64 2>/dev/null)" = "1" ] && A=arm64
F="EventSolutions-Mac-$A.zip"
T="$(mktemp -d /tmp/es-install.XXXXXX)"
trap 'rm -rf "$T"' EXIT

echo "Event Solutions ($( [ "$A" = arm64 ] && echo 'Apple M' || echo 'Intel' )) – atsisiunčiama…"
curl -fsSL "$BASE/EventSolutions-Mac-$A.json" -o "$T/m.json"
NUMS=$(grep -o "EventSolutions-Mac-$A\.zip\.part[0-9]*" "$T/m.json" | sed 's/.*part//' | sort -n | uniq)
SHA=$(grep -o '"sha256" *: *"[0-9a-f]\{64\}"' "$T/m.json" | grep -o '[0-9a-f]\{64\}')
if [ -z "$NUMS" ] || [ -z "$SHA" ]; then echo "Programos failų serveryje nerasta – pranešk administratoriui."; exit 1; fi
# the parts in their order (part1, part2, … part10)
for p in $NUMS; do
  curl -fL --progress-bar "$BASE/EventSolutions-Mac-$A.zip.part$p" >> "$T/$F"
done
echo "Tikrinama…"
if ! echo "$SHA  $T/$F" | /usr/bin/shasum -a 256 -c - >/dev/null 2>&1; then echo "Atsisiųstas failas sugadintas – paleisk komandą dar kartą."; exit 1; fi

DEST=/Applications
[ -w "$DEST" ] || { DEST="$HOME/Applications"; mkdir -p "$DEST"; }
APP="$DEST/Event Solutions.app"
# the running app is closed first
/usr/bin/osascript -e 'tell application "Event Solutions" to quit' >/dev/null 2>&1 || true
sleep 1
rm -rf "$APP"
/usr/bin/ditto -x -k "$T/$F" "$DEST"
/usr/bin/xattr -dr com.apple.quarantine "$APP" 2>/dev/null || true
echo "Įdiegta: $APP"
/usr/bin/open "$APP"
