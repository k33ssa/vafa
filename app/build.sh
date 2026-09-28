#!/bin/zsh
# Собирает "VPN Guard.app" рядом с этим скриптом. Запуск: ./build.sh
emulate -L zsh
set -eu
cd ${0:A:h}
APP="VPN Guard.app"
rm -rf $APP
mkdir -p $APP/Contents/MacOS
# универсальный бинарь: работает и на Apple Silicon, и на Intel
swiftc -O -target arm64-apple-macos12 -o /tmp/vpnguard-arm64.$$ main.swift
swiftc -O -target x86_64-apple-macos12 -o /tmp/vpnguard-x86.$$ main.swift
lipo -create -output $APP/Contents/MacOS/VPNGuard /tmp/vpnguard-arm64.$$ /tmp/vpnguard-x86.$$
rm -f /tmp/vpnguard-arm64.$$ /tmp/vpnguard-x86.$$
cat > $APP/Contents/Info.plist <<'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>CFBundleName</key><string>VPN Guard</string>
  <key>CFBundleIdentifier</key><string>local.vpnguard.menu</string>
  <key>CFBundleExecutable</key><string>VPNGuard</string>
  <key>CFBundlePackageType</key><string>APPL</string>
  <key>CFBundleShortVersionString</key><string>1.0</string>
  <key>LSUIElement</key><true/>
  <key>LSMinimumSystemVersion</key><string>12.0</string>
</dict></plist>
EOF
codesign -s - --force $APP >/dev/null 2>&1 || true
print -r -- "собрано: $PWD/$APP"
