#!/bin/bash
# Mirrors client installers from GitHub releases to /opt/geovpn-portal/app and writes apps.json (versions, sizes).
# Runs weekly inside the portal container (or: docker exec geovpn-portal bash /app/scripts/apps-update.sh)
set -e
D="${APP_DIR:-/opt/geovpn-portal/app}"
mkdir -p $D
declare -A SRC
rel() { curl -fsSL "https://api.github.com/repos/$1/releases/latest"; }
pick() { python3 -c "import json,sys,re; d=json.load(sys.stdin); print(d['tag_name']); [print(a['browser_download_url']) for a in d['assets'] if re.search(sys.argv[1], a['name'])]" "$1"; }

get() { # name url
  if [ ! -s "$D/$1" ] || [ "$(cat $D/.$1.src 2>/dev/null)" != "$2" ]; then
    [ -n "$2" ] || { echo "SKIP $1: asset not found in release"; return 0; }
    if curl -fsSL --retry 3 --retry-all-errors -o "$D/$1.part" "$2"; then
      mv "$D/$1.part" "$D/$1" && echo "$2" > "$D/.$1.src" && echo "downloaded $1"
    else rm -f "$D/$1.part"; echo "FAILED $1"; fi
  else echo "up to date $1"; fi
}

A=$(rel amnezia-vpn/amnezia-client)
AV=$(echo "$A" | pick 'x' | head -1)
get AmneziaVPN-windows.exe       "$(echo "$A" | pick '_windows_x64\.exe$' | sed -n 2p)"
get AmneziaVPN-android.apk       "$(echo "$A" | pick 'android11\+_arm64-v8a\.apk$' | sed -n 2p)"
get AmneziaVPN-android-9-10.apk  "$(echo "$A" | pick 'android9-10_arm64-v8a\.apk$' | sed -n 2p)"
get AmneziaVPN-macos.pkg         "$(echo "$A" | pick '_macos_x64\.pkg$' | sed -n 2p)"

H=$(rel hiddify/hiddify-app)
HV=$(echo "$H" | pick 'x' | head -1)
get Hiddify-windows.exe  "$(echo "$H" | pick 'Windows-Setup-x64\.exe$' | sed -n 2p)"
get Hiddify-android.apk  "$(echo "$H" | pick 'Android-universal\.apk$' | sed -n 2p)"
get Hiddify-macos.dmg    "$(echo "$H" | pick 'MacOS\.dmg$' | sed -n 2p)"

P=$(rel Happ-proxy/happ-desktop)
PV=$(echo "$P" | pick 'x' | head -1)
get Happ-windows.exe  "$(echo "$P" | pick '^setup-Happ\.x64\.exe$' | sed -n 2p)"
get Happ-macos.dmg    "$(echo "$P" | pick 'macOS\.universal\.dmg$' | sed -n 2p)"
PA=$(rel Happ-proxy/happ-android)
PAV=$(echo "$PA" | pick 'x' | head -1)
get Happ-android.apk  "$(echo "$PA" | pick '^Happ\.apk$' | sed -n 2p)"

T=$(rel telegramdesktop/tdesktop)
TV=$(echo "$T" | pick 'x' | head -1)
get Telegram-windows.exe "$(echo "$T" | pick '^td-setup-win-x64-[0-9.]+\.exe$' | sed -n 2p)"
get Telegram-macos.dmg   "$(echo "$T" | pick '^td-setup-mac-[0-9.]+\.dmg$' | sed -n 2p)"
# telegram.org is blocked in RU -> fetch the Android APK through our own tunnel (xray on MSK)
if [ ! -s "$D/Telegram-android.apk" ] || [ -n "$(find "$D/Telegram-android.apk" -mtime +7)" ]; then
  curl -fsSL --retry 5 --retry-all-errors --socks5-hostname 127.0.0.1:10804 -o "$D/Telegram-android.apk.part" https://telegram.org/dl/android/apk     && mv "$D/Telegram-android.apk.part" "$D/Telegram-android.apk" && echo "downloaded Telegram-android.apk"
fi

python3 - "$AV" "$HV" "$PV" "$PAV" "$TV" <<'X'
import json, os, sys
D = os.environ.get("APP_DIR", "/opt/geovpn-portal/app")
sizes = {f: os.path.getsize(os.path.join(D, f)) for f in os.listdir(D) if not f.startswith(".") and not f.endswith((".part", ".json"))}
json.dump({"versions": {"amnezia": sys.argv[1], "hiddify": sys.argv[2].lstrip("v"), "happ": sys.argv[3], "happ_android": sys.argv[4], "telegram": sys.argv[5].lstrip("v")},
           "sizes": sizes}, open(os.path.join(D, "apps.json"), "w"), indent=1)
X
chmod 644 $D/*
echo "apps mirror done"; cat $D/apps.json
