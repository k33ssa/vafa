#!/bin/zsh
# Собирает "Vafa.app" рядом с этим скриптом. Запуск: ./build.sh
emulate -L zsh
set -eu
cd ${0:A:h}
APP="Vafa.app"
rm -rf $APP
mkdir -p $APP/Contents/MacOS $APP/Contents/Resources
cp Vafa.icns $APP/Contents/Resources/Vafa.icns   # иконка из assets/logo.png
# универсальный бинарь: работает и на Apple Silicon, и на Intel
swiftc -O -target arm64-apple-macos12 -o /tmp/vpnguard-arm64.$$ main.swift
swiftc -O -target x86_64-apple-macos12 -o /tmp/vpnguard-x86.$$ main.swift
lipo -create -output $APP/Contents/MacOS/VPNGuard /tmp/vpnguard-arm64.$$ /tmp/vpnguard-x86.$$
rm -f /tmp/vpnguard-arm64.$$ /tmp/vpnguard-x86.$$
cat > $APP/Contents/Info.plist <<'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>CFBundleName</key><string>Vafa</string>
  <key>CFBundleIdentifier</key><string>local.vafa.menu</string>
  <key>CFBundleIconFile</key><string>Vafa</string>
  <key>CFBundleExecutable</key><string>VPNGuard</string>
  <key>CFBundlePackageType</key><string>APPL</string>
  <key>CFBundleShortVersionString</key><string>1.0.7</string>
  <key>LSUIElement</key><true/>
  <key>LSMinimumSystemVersion</key><string>12.0</string>
</dict></plist>
EOF
# Стабильная локальная подпись (стандарт приложений, как у SimpleScreenTab): с ad-hoc «паспорт»
# приложения — хеш сборки (cdhash), и каждое обновление система видит новой программой. На macOS 26
# по ней ведётся список «Разрешить в строке меню» и место значка — после обновления значок мог
# пропасть (разборы разработчиков: jcode#1793, CodexBar#1440). Нет сертификата — ad-hoc.
ID=$(security find-identity -p codesigning 2>/dev/null | awk '/ScreenTab Local Signing/{print $2; exit}')
codesign --force --sign "${ID:--}" $APP >/dev/null 2>&1 || codesign -s - --force $APP >/dev/null 2>&1 || true
print -r -- "собрано: $PWD/$APP"
