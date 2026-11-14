#!/bin/zsh
# Различает ли pf на этом Маке соединения по пользователю macOS (правило `user`)?
# От ответа зависит, можно ли без Network Extension дать отдельному пользователю
# (например, тому, от кого запущен Claude Code CLI) «интернет только через туннель».
#
# Всё — только внутри Мака (127.0.0.1): ни одного запроса в интернет, VPN и правила Vafa
# не трогаются. Временные правила — в отдельном якоре com.apple/999.vafa-uidtest, снимаются
# в конце сами (и при Ctrl-C). Второй пользователь — встроенный системный nobody.
#
# Запуск: sudo ./tests/pf_user_check.sh
emulate -L zsh
(( EUID == 0 )) || { print -r -- "нужен sudo: sudo $0"; exit 1 }
ME=${SUDO_USER:-}
[[ -n $ME && $ME != root ]] || { print -r -- "запусти через sudo из своей учётки (нужен SUDO_USER)"; exit 1 }

A=com.apple/999.vafa-uidtest
P1=$(( 20000 + RANDOM % 10000 )); P2=$(( P1 + 1 ))
D=$(mktemp -d /tmp/vafa-uid.XXXXXX); chmod 755 $D; print ok > $D/x; chmod 644 $D/x
python3 -m http.server $P1 --bind 127.0.0.1 --directory $D >/dev/null 2>&1 & S1=$!
python3 -m http.server $P2 --bind 127.0.0.1 --directory $D >/dev/null 2>&1 & S2=$!
cleanup() { pfctl -a $A -F all >/dev/null 2>&1; kill $S1 $S2 2>/dev/null; rm -rf $D }
trap cleanup EXIT INT TERM
sleep 1.5

pfctl -s info 2>/dev/null | grep -q 'Status: Enabled' || { print -r -- "pf выключен — проверка не имеет смысла"; exit 1 }

# код ответа HTTP от имени пользователя $1 к порту $2; 000 — соединение не прошло
get() { sudo -u $1 /usr/bin/curl -s --max-time 3 -o /dev/null -w '%{http_code}' http://127.0.0.1:$2/x 2>/dev/null }

print -r -- "до правил:            $ME → $(get $ME $P1), nobody → $(get nobody $P1)"

# контроль: правило без user на P2 (видит ли pf локальный трафик вообще);
# проверка: правило с user nobody на P1
print -r -- "block return out quick proto tcp from any to 127.0.0.1 port $P2
block return out quick proto tcp from any to 127.0.0.1 port $P1 user nobody" \
  | pfctl -a $A -f - 2>&1 | grep -v -E 'ALTQ|^$|flushing|present in the main|/etc/pf.conf'
print -r -- "загружено в $A:"; pfctl -a $A -s rules 2>/dev/null | sed 's/^/   /'

c_me=$(get $ME $P2);   c_nb=$(get nobody $P2)
u_me=$(get $ME $P1);   u_nb=$(get nobody $P1)
print -r -- "контроль (режет всех): $ME → $c_me, nobody → $c_nb"
print -r -- "по пользователю nobody: $ME → $u_me, nobody → $u_nb"
print
if [[ $c_me != 000 || $c_nb != 000 ]]; then
  print -r -- "ИТОГ: не понять — pf не режет даже контрольное правило на 127.0.0.1 (локальный трафик мимо pf)"
elif [[ $u_me == 200 && $u_nb == 000 ]]; then
  print -r -- "ИТОГ: РАБОТАЕТ — pf различает пользователей (nobody отрезан, $ME проходит)"
elif [[ $u_me == 200 && $u_nb == 200 ]]; then
  print -r -- "ИТОГ: НЕ РАБОТАЕТ — правило user принимается, но ни на кого не действует"
else
  print -r -- "ИТОГ: странно — $ME → $u_me, nobody → $u_nb (пришли этот вывод)"
fi
# cleanup — по trap: якорь очищается, серверы гасятся
