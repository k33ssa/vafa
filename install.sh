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
  # обновление: старые значения по умолчанию (опрос раз в 2 с, страна раз в 15 с) —
  # на новые (раз в секунду). Если их меняли руками — строка другая и не трогается.
  if grep -qE '^(INTERVAL=2   # как часто проверять, секунд|GEO_TTL=15   # как часто спрашивать страну выхода у Cloudflare, секунд)$' $CONF; then
    sed -i '' -e 's/^INTERVAL=2   # как часто проверять, секунд$/INTERVAL=1       # как часто проверять маршрут, секунд (по событию сети — сразу)/' \
              -e 's/^GEO_TTL=15   # как часто спрашивать страну выхода у Cloudflare, секунд$/GEO_TTL=1        # как часто спрашивать страну выхода у Cloudflare, секунд/' $CONF
    print -r -- "Конфиг: проверка VPN и страны — теперь каждую секунду."
  fi
fi

# страны блокировки (выбираются в щите). Нет файла — создать со списком по умолчанию:
# так и старые установки с geo:!RU получают Китай, Беларусь и Иран
COUNTRIES=/usr/local/etc/vpn-guard.countries
if [[ ! -e $COUNTRIES ]]; then
  print -r -- "# Пишет Vafa.app. Одна строка — один код страны (ISO, две буквы).
RU
CN
BY
IR" > $COUNTRIES
  chown root:wheel $COUNTRIES; chmod 644 $COUNTRIES
  print -r -- "Страны блокировки: RU CN BY IR ($COUNTRIES)"
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
print -r -- "  $COUNTRIES  (страны блокировки)"
print -r -- "  $PLIST  (демон загружен)"
print -r -- "  журнал: /usr/local/var/log/vpn-guard.log"
print -r -- ""
(( fresh )) || print -r -- "Конфиг $CONF был и раньше — оставлен без изменений."
print -r -- "Проверить:   sudo vpn-guard status"
print -r -- "Настройки:   sudo nano $CONF   (перечитываются сами, без перезапуска)"
