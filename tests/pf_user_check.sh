#!/bin/zsh
# Различает ли pf на этом Маке соединения по пользователю macOS (правило `user`)?
# От ответа зависит, можно ли без Network Extension дать отдельному пользователю
# (например, тому, от кого запущен Claude Code CLI) «интернет только через туннель».
#
# Всё — только через туннель VPN (curl --interface utunN) к служебным адресам Cloudflare 1.1.1.1 и
# 1.0.0.1 (их Vafa и так спрашивает каждую секунду). Без туннеля скрипт ничего не отправляет.
# Внутри Мака (127.0.0.1) проверить нельзя: macOS пропускает локальный трафик мимо pf (проверено 14.11).
# VPN и правила Vafa не трогаются. Временные правила — в отдельном якоре com.apple/999.vafa-uidtest, снимаются
# в конце сами (и при Ctrl-C). Второй пользователь — встроенный системный nobody.
#
# Запуск: sudo ./tests/pf_user_check.sh
emulate -L zsh
(( EUID == 0 )) || { print -r -- "нужен sudo: sudo $0"; exit 1 }
ME=${SUDO_USER:-}
[[ -n $ME && $ME != root ]] || { print -r -- "запусти через sudo из своей учётки (нужен SUDO_USER)"; exit 1 }

A=com.apple/999.vafa-uidtest
IF=$(route -n get 160.79.104.10 2>/dev/null | awk '/interface:/{print $2}')
[[ $IF == utun* ]] || { print -r -- "туннеля нет (маршрут: ${IF:-нет}) — ничего не отправляю"; exit 1 }
T1=1.1.1.1 T2=1.0.0.1   # T1 — правило user nobody, T2 — контроль (режет всех)
cleanup() { pfctl -a $A -F all >/dev/null 2>&1 }
trap cleanup EXIT INT TERM

pfctl -s info 2>/dev/null | grep -q 'Status: Enabled' || { print -r -- "pf выключен — проверка не имеет смысла"; exit 1 }

# код ответа HTTP от имени пользователя $1 к адресу $2 через туннель; 000 — не прошло
get() { sudo -u $1 /usr/bin/curl -s --interface $IF --max-time 4 -o /dev/null -w '%{http_code}' https://$2/cdn-cgi/trace 2>/dev/null }

print -r -- "туннель: $IF"
print -r -- "до правил:            $ME → $T1 $(get $ME $T1), $T2 $(get $ME $T2); nobody → $T1 $(get nobody $T1), $T2 $(get nobody $T2)"

print -r -- "block return out quick proto tcp from any to $T2 port 443
block return out quick proto tcp from any to $T1 port 443 user nobody" \
  | pfctl -a $A -f - 2>&1 | grep -v -E 'ALTQ|^$|flushing|present in the main|/etc/pf.conf'
print -r -- "загружено в $A:"; pfctl -a $A -s rules 2>/dev/null | sed 's/^/   /'

c_me=$(get $ME $T2);   c_nb=$(get nobody $T2)
u_me=$(get $ME $T1);   u_nb=$(get nobody $T1)
print -r -- "контроль $T2 (режет всех): $ME → $c_me, nobody → $c_nb"
print -r -- "$T1 только для nobody:     $ME → $u_me, nobody → $u_nb"
print
if [[ $c_me != 000 || $c_nb != 000 ]]; then
  print -r -- "ИТОГ: не понять — контрольное правило не сработало (наш якорь не применяется?)"
elif [[ $u_me == 200 && $u_nb == 000 ]]; then
  print -r -- "ИТОГ: РАБОТАЕТ — pf различает пользователей (nobody отрезан, $ME проходит)"
elif [[ $u_me == 200 && $u_nb == 200 ]]; then
  print -r -- "ИТОГ: НЕ РАБОТАЕТ — правило user принимается, но ни на кого не действует"
elif [[ $u_me == 000 && $u_nb == 000 ]]; then
  print -r -- "ИТОГ: НЕ РАБОТАЕТ — правило user режет всех подряд"
else
  print -r -- "ИТОГ: странно — $ME → $u_me, nobody → $u_nb (пришли этот вывод)"
fi
# cleanup — по trap: якорь очищается
