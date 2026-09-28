#!/bin/zsh
# Собирает VPN-Guard.dmg для установки на другом Маке. Запуск: ./make-dmg.sh
emulate -L zsh
set -eu
cd ${0:A:h}
./app/build.sh
STAGE=$(mktemp -d)/"VPN Guard"
mkdir -p "$STAGE/app"
cp vpn-guard vpn-guard.conf local.vpnguard.plist install.sh INSTALL.md "$STAGE/"
cp -R "app/VPN Guard.app" "$STAGE/app/"
rm -f VPN-Guard.dmg
hdiutil create -quiet -volname "VPN Guard" -srcfolder "$STAGE" -format UDZO VPN-Guard.dmg
rm -rf "${STAGE:h}"
print -r -- "готово: $PWD/VPN-Guard.dmg"
