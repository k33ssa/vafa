#!/bin/zsh
# Установка vpn-guard. Запускать: sudo ./install.sh
emulate -L zsh
set -eu

(( EUID == 0 )) || { print -ru2 -- "Запускать через sudo: sudo ./install.sh"; exit 1 }

SRC=${0:A:h}
CONF=/usr/local/etc/vpn-guard.conf
PLIST=/Library/LaunchDaemons/local.vpnguard.plist

for f in vpn-guard vpn-guard.conf local.vpnguard.plist; do
  [[ -f $SRC/$f ]] || { print -ru2 -- "нет файла $SRC/$f"; exit 1 }
done

install -d -m 755 -o root -g wheel /usr/local/bin /usr/local/etc /usr/local/var/log
# сам каталог 755 — в нём status.json для Vafa.app; perms/ закрыт
install -d -m 755 -o root -g wheel /usr/local/var/vpn-guard
install -d -m 700 -o root -g wheel /usr/local/var/vpn-guard/perms
install -m 755 -o root -g wheel $SRC/vpn-guard /usr/local/bin/vpn-guard

fresh=0
if [[ ! -e $CONF ]]; then
  install -m 600 -o root -g wheel $SRC/vpn-guard.conf $CONF
  fresh=1
else
  chown root:wheel $CONF; chmod 600 $CONF
  print -r -- "Конфиг $CONF уже был — оставил как есть."
fi

install -m 644 -o root -g wheel $SRC/local.vpnguard.plist $PLIST

launchctl bootout system $PLIST 2>/dev/null || true
launchctl bootstrap system $PLIST
launchctl enable system/local.vpnguard 2>/dev/null || true

# мини-приложение в строке меню (собирается ./app/build.sh)
if [[ -d "$SRC/app/Vafa.app" ]]; then
  rm -rf "/Applications/Vafa.app" "/Applications/VPN Guard.app"   # старое имя
  cp -R "$SRC/app/Vafa.app" /Applications/
  # скачанное из интернета помечено карантином — иначе Gatekeeper не откроет
  xattr -dr com.apple.quarantine "/Applications/Vafa.app" 2>/dev/null || true
  print -r -- "Приложение: /Applications/Vafa.app"
  # сразу запустить у вошедшего пользователя — щит появится в строке меню
  cu=$(stat -f '%Su' /dev/console 2>/dev/null)
  if [[ -n $cu && $cu != root ]]; then
    pkill -x VPNGuard 2>/dev/null || true
    launchctl asuser $(id -u $cu) sudo -u $cu open "/Applications/Vafa.app" || true
  fi
fi

print -r -- ""
print -r -- "Установлено:"
print -r -- "  /usr/local/bin/vpn-guard"
print -r -- "  $CONF"
print -r -- "  $PLIST  (демон загружен)"
print -r -- "  журнал: /usr/local/var/log/vpn-guard.log"
print -r -- ""
(( fresh )) || print -r -- "Конфиг $CONF был и раньше — оставлен без изменений."
print -r -- "Проверить:   sudo vpn-guard status"
print -r -- "Настройки:   sudo nano $CONF   (перечитываются сами, без перезапуска)"
