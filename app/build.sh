#!/bin/zsh
# Собирает "VPN Guard.app" рядом с этим скриптом. Запуск: ./build.sh
emulate -L zsh
set -eu
cd ${0:A:h}
APP="VPN Guard.app"
rm -rf $APP
mkdir -p $APP/Contents/MacOS
swiftc -O -o $APP/Contents/MacOS/VPNGuard main.swift
cat > $APP/Contents/Info.plist <<'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>CFBundleName</key><string>VPN Guard</string>
  <key>CFBundleIdentifier</key><string>local.vpnguard.menu</string>
  <key>CFBundleExecutable</key><string>VPNGuard</string>
  <key>CFBundlePackageType</key><string>APPL</string>
  <key>CFBundleShortVersionString</key><string>1.0</string>
  <key>LSMinimumSystemVersion</key><string>12.0</string>
  <key>LSUIElement</key><true/>
</dict></plist>
EOF
codesign -s - --force $APP >/dev/null 2>&1 || true
print -r -- "собрано: ${0:A:h}/$APP"
