#!/bin/zsh
# Собирает Vafa.dmg для установки на другом Маке. Запуск: ./make-dmg.sh
emulate -L zsh
set -eu
cd ${0:A:h}
./app/build.sh
STAGE=$(mktemp -d)/"Vafa"
mkdir -p "$STAGE/app"
cp vpn-guard vpn-guard.conf local.vpnguard.plist install.sh INSTALL.md "$STAGE/"
cp -R "app/Vafa.app" "$STAGE/app/"
rm -f Vafa.dmg
hdiutil create -quiet -volname "Vafa" -srcfolder "$STAGE" -format UDZO Vafa.dmg
rm -rf "${STAGE:h}"
print -r -- "готово: $PWD/Vafa.dmg"
