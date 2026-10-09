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

fresh=0 migrated=0
if [[ ! -e $CONF ]]; then
  install -m 600 -o root -g wheel $SRC/vpn-guard.conf $CONF
  fresh=1
else
  chown root:wheel $CONF; chmod 600 $CONF
  print -r -- "Конфиг $CONF уже был — свои настройки сохраняю, известные старые значения обновляю."
  # обновление: старые значения по умолчанию (опрос раз в 2 с, страна раз в 15 с) —
  # на новые (раз в секунду). Если их меняли руками — строка другая и не трогается.
  if grep -qE '^(INTERVAL=2   # как часто проверять, секунд|GEO_TTL=15   # как часто спрашивать страну выхода у Cloudflare, секунд)$' $CONF; then
    sed -i '' -e 's/^INTERVAL=2   # как часто проверять, секунд$/INTERVAL=1       # как часто проверять маршрут, секунд (по событию сети — сразу)/' \
              -e 's/^GEO_TTL=15   # как часто спрашивать страну выхода у Cloudflare, секунд$/GEO_TTL=1        # как часто спрашивать страну выхода у Cloudflare, секунд/' $CONF
    print -r -- "Конфиг: проверка VPN и страны — теперь каждую секунду."
    migrated=1
  fi
  # >>> перенос BLOCK_NETS (tests/run_macos.sh гоняет этот кусок на копии конфига)
  # обновление: старый список сетей Anthropic (2026-09-11) — на новый из репозитория.
  # Список правили руками — он другой, и его не трогаем. Старый конфиг — в $CONF.bak.<дата>.
  old_nets='160.79.104.0/23 160.79.106.0/24 209.249.57.0/24 38.46.212.0/24 38.84.152.0/24 2607:6bc0::/32'
  nets_block() { awk '/^BLOCK_NETS=\(/{f=1; next} f&&/^\)/{exit} f{sub(/#.*/,""); for(i=1;i<=NF;i++) printf "%s ", $i}' $1 }
  # только если BLOCK_NETS=( … ) в конфиге один и многострочный — иначе руками
  if [[ "$(nets_block $CONF)" == "$old_nets " && $(grep -c '^BLOCK_NETS=' $CONF) == 1 ]] &&
     grep -qx 'BLOCK_NETS=(' $CONF; then
    tmp=$CONF.new.$$ nb=$CONF.nets.$$
    # новый блок — через файл: BSD awk не берёт перевод строки в -v
    awk '/^BLOCK_NETS=\(/{f=1} f{print} f&&/^\)/{exit}' $SRC/vpn-guard.conf > $nb
    awk -v nbf=$nb '/^BLOCK_NETS=\(/{while ((getline l < nbf) > 0) print l; close(nbf); skip=1; next} skip&&/^\)/{skip=0; next} !skip{print}' $CONF > $tmp
    # всё, кроме блока BLOCK_NETS, должно остаться как было
    rest() { awk '/^BLOCK_NETS=\(/{s=1} !s{print} s&&/^\)/{s=0}' $1 }
    if [[ "$(nets_block $tmp)" == "$(nets_block $SRC/vpn-guard.conf)" && "$(rest $CONF)" == "$(rest $tmp)" ]] && zsh -n $tmp; then
      cp -p $CONF $CONF.bak.$(date +%Y%m%d%H%M%S)
      chown root:wheel $tmp; chmod 600 $tmp; mv -f $tmp $CONF
      print -r -- "Конфиг: сети Anthropic обновлены (160.79.104.0/21, 153.61.0.0/16 и др.), старый — $CONF.bak.*"
      print -r -- "         Комментарии в нём остались старые; свежие — в $SRC/vpn-guard.conf."
      migrated=1
    else
      rm -f $tmp
      print -r -- "Конфиг: не смог обновить BLOCK_NETS — проверь руками ($CONF)."
    fi
    rm -f $nb
  fi
  # <<< перенос BLOCK_NETS
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
# сначала enable: после «Охрана выключена» в Vafa служба disabled, и bootstrap падал
launchctl enable system/local.vpnguard 2>/dev/null || true
launchctl bootstrap system $PLIST

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
if (( ! fresh )); then
  if (( migrated )); then print -r -- "Конфиг $CONF был и раньше — свои настройки сохранены, старые значения по умолчанию обновлены."
  else print -r -- "Конфиг $CONF был и раньше — оставлен без изменений."; fi
fi
print -r -- "Проверить:   sudo vpn-guard status"
print -r -- "Настройки:   sudo nano $CONF   (перечитываются сами, без перезапуска)"
