#!/bin/zsh
# Тесты демона vpn-guard (macOS) без root и без настоящего VPN:
#   * «Cloudflare» — локальный HTTP, страну выхода тест меняет файлом;
#   * события сети — свой поток вместо `route -n monitor` (кроме теста 12);
#   * приложение — крошечная программа в Fake.app, её морозит и размораживает демон.
# Запуск: ./tests/run_macos.sh       (минуты две; ничего системного не трогает)
emulate -L zsh
setopt no_nomatch
zmodload zsh/datetime
cd ${0:A:h}/..

T=$(mktemp -d /tmp/vafa-test.XXXXXX)
PORT=$(( 20000 + RANDOM % 20000 ))
PASS=0 FAIL=0
typeset -a PIDS=()

cleanup() {
  stop_daemon
  for p in $PIDS[@]; do kill $p 2>/dev/null; done
  pkill -f "$T/" 2>/dev/null
  rm -rf $T
}
trap cleanup EXIT INT TERM

ok()   { print -r -- "  ok   $*"; (( PASS++ )) }
bad()  { print -r -- "  FAIL $*"; (( FAIL++ )) }
check() { local name=$1; shift; if "$@"; then ok $name; else bad $name; fi }

# ---- окружение --------------------------------------------------------------
mkdir -p $T/www $T/state $T/Fake.app/Contents/MacOS
# своя крошечная программа: копию /bin/sleep macOS убивает (подпись системного бинаря)
print -r -- '#include <unistd.h>
int main(void) { for (;;) pause(); }' > $T/fake.c
cc -o $T/Fake.app/Contents/MacOS/fake $T/fake.c || { print "нужен cc (xcode-select --install)"; exit 1 }
geo() { print -rl -- "fl=1" "loc=$1" > $T/www/trace }   # пустой аргумент — Cloudflare без страны
geo DE
python3 -m http.server $PORT --bind 127.0.0.1 --directory $T/www > $T/http.log 2>&1 &
PIDS+=$!
: > $T/events
event() { print -r -- "RTM_${1:-CHANGE}: test" >> $T/events }

conf() {   # conf <VPN_CHECK...> — остальное общее
  cat > $T/conf <<EOF
APPS=( "$T/Fake.app" )
VPN_CHECK=( $* )
VPN_REQUIRE=all
ON_DOWN=freeze
LOCK_LAUNCH=1
INTERVAL=${INTERVAL:-30}
GEO_TTL=${GEO_TTL:-600}
GEO_TTL_DOWN=${GEO_TTL_DOWN:-600}
GEO_STALE=${GEO_STALE:-0}
NOTIFY=0
EOF
  chmod 600 $T/conf
}
countries() { print -rl -- "# test" "$@" > $T/countries; chmod 600 $T/countries }

start_daemon() {
  rm -f $T/state/status.json
  VPN_GUARD_TEST=1 VPN_GUARD_CONF=$T/conf VPN_GUARD_STATE=$T/state \
  VPN_GUARD_APPS=$T/no-apps-file VPN_GUARD_COUNTRIES=$T/countries \
  VPN_GUARD_GEO_URLS="http://127.0.0.1:$PORT/trace" \
  VPN_GUARD_NET_MONITOR=${MONITOR:-"tail -n0 -F $T/events"} \
    zsh ./vpn-guard daemon >> $T/daemon.log 2>&1 &
  DPID=$!
  wait_status '"time"' 10 >/dev/null
}
stop_daemon() {
  [[ -n ${DPID:-} ]] || return 0
  kill $DPID 2>/dev/null; wait $DPID 2>/dev/null
  pkill -f "tail -n0 -F $T/events" 2>/dev/null
  pkill -CONT -f "$T/Fake.app" 2>/dev/null
  DPID=''
}

# ждать, пока в status.json появится строка; печатает, сколько ждали
wait_status() {
  local want=$1 lim=${2:-5} t0=$EPOCHREALTIME
  while (( EPOCHREALTIME - t0 < lim )); do
    grep -qF -- $want $T/state/status.json 2>/dev/null && { printf '%.1f' $(( EPOCHREALTIME - t0 )); return 0 }
    sleep 0.1
  done
  return 1
}
vpn_is() { wait_status "\"vpn\":$1" ${2:-5} >/dev/null }
fake_state() { ps -o state= -p $FAKE 2>/dev/null | cut -c1 }
geo_hits() { grep -c 'GET /trace' $T/http.log }

$T/Fake.app/Contents/MacOS/fake &
FAKE=$!; PIDS+=$FAKE
sleep 1

# ---- 1-4. страны по умолчанию, реакция по событию сети ----------------------
print "1-4. страны по умолчанию (RU CN BY IR), смена страны по событию сети"
countries RU CN BY IR
conf geo
start_daemon
check "DE — VPN поднят" vpn_is true
check "status.json перечисляет RU CN BY IR" grep -qF '"countries":["RU","CN","BY","IR"]' $T/state/status.json
for cc in CN BY IR RU; do
  geo $cc; event CHANGE
  dt=$(wait_status '"vpn":false' 5) && ok "$cc — блокировка через ${dt} с после события" || bad "$cc — нет блокировки"
  check "$cc — процесс приложения заморожен" test "$(fake_state)" = T
  geo DE; event NEWADDR
  dt=$(wait_status '"vpn":true' 5) && ok "DE — разблокировка через ${dt} с" || bad "DE — нет разблокировки"
  check "DE — процесс разморожен" test "$(fake_state)" != T
done
check "запуск приложения снова разрешён (+x вернули)" test -x $T/Fake.app/Contents/MacOS/fake

# ---- 5. без события страну не дёргаем (TTL 600 с, INTERVAL 30 с) -------------
print "5. без события сети демон спит, Cloudflare не дёргает"
h0=$(geo_hits); geo CN; sleep 5
check "смена страны без события не замечена за 5 с (нет лишних опросов)" vpn_is true 0.5
check "за 5 с ни одного запроса к Cloudflare" test $(geo_hits) -eq $h0
event CHANGE
check "событие — и блокировка" vpn_is false 5
stop_daemon

# ---- 6. свой выбор стран: файл из щита главнее ------------------------------
print "6. выбор стран в щите"
countries CN; conf geo; start_daemon
geo RU; event
check "только CN: из RU — VPN поднят" vpn_is true
geo CN; event
check "только CN: из CN — блокировка" vpn_is false
countries DE FR; event   # файл поменяли — демон перечитывает на ближайшем круге
check "переписали на DE FR: из CN — разблокировка" vpn_is true
check "status.json перечисляет DE FR" wait_status '"countries":["DE","FR"]' 3
countries ' ru' 'XYZ' 'cn  '; event
check "мусор в файле: ru/cn нормализованы, XYZ пропущен" wait_status '"countries":["RU","CN"]' 3
grep -q 'непонятный код страны: XYZ' $T/daemon.log && ok "XYZ записан в журнал" || bad "XYZ не в журнале"
countries; geo ''; event
check "пустой выбор: страна не проверяется, VPN поднят даже без ответа Cloudflare" vpn_is true
stop_daemon

# ---- 7. старый конфиг geo:!RU без файла стран --------------------------------
print "7. старый конфиг geo:!RU"
rm -f $T/countries; conf '"geo:!RU"'; start_daemon
geo CN; event
check "без файла: geo:!RU блокирует только RU (CN проходит)" vpn_is true
geo RU; event
check "без файла: RU — блокировка" vpn_is false
countries RU CN BY IR; event
geo CN; event
check "файл появился (как после install.sh): CN теперь блокируется" vpn_is false
stop_daemon

# ---- 8. Cloudflare молчит -----------------------------------------------------
print "8. нет ответа о стране"
countries RU CN BY IR; conf geo; geo DE; start_daemon
geo ''; event
check "нет ответа и GEO_STALE=0 — блокировка (лучше лишний раз)" vpn_is false
stop_daemon
GEO_STALE=60 conf geo; geo DE; start_daemon
geo ''; event; sleep 2
check "нет ответа, но GEO_STALE=60 — верим прошлой стране" vpn_is true 0.5
stop_daemon

# ---- 9. TTL при блокировке короче: разблокировка без события -----------------
print "9. блокировка: страну перепроверяем чаще (GEO_TTL_DOWN)"
INTERVAL=1 GEO_TTL=600 GEO_TTL_DOWN=3 conf geo; geo CN; start_daemon
check "CN — блокировка" vpn_is false
geo NL
dt=$(wait_status '"vpn":true' 8) && ok "сменили сервер без события сети — разблокировка через ${dt} с" || bad "не разблокировалось за 8 с"
stop_daemon

# ---- 10. монитор сети упал — работаем по таймеру -----------------------------
print "10. монитор сети не запускается"
INTERVAL=1 GEO_TTL=1 conf geo; geo DE; MONITOR=false start_daemon
geo IR
check "без монитора блокировка по таймеру" vpn_is false 6
grep -q 'монитор сети' $T/daemon.log && ok "в журнале — переход на таймер" || bad "нет записи в журнале"
stop_daemon

# ---- 11. vpn-guard check --------------------------------------------------------
print "11. vpn-guard check"
countries RU CN BY IR; conf geo; geo BY
out=$(VPN_GUARD_CONF=$T/conf VPN_GUARD_COUNTRIES=$T/countries VPN_GUARD_APPS=$T/no-apps-file \
      VPN_GUARD_GEO_URLS="http://127.0.0.1:$PORT/trace" zsh ./vpn-guard check)
print -r -- $out | sed 's/^/       /'
check "check видит BY и список стран" eval '[[ $out == *"страна выхода: BY"*"RU CN BY IR"* && $out == *"ВЫКЛЮЧЕН"* ]]'

# ---- 12. настоящий route -n monitor: демон не будит сам себя -----------------
print "12. настоящий route -n monitor, нагрузка"
countries RU CN BY IR; INTERVAL=1 GEO_TTL=1 GEO_TTL_DOWN=1 conf geo; geo DE   # как в конфиге по умолчанию
MONITOR="route -n monitor" start_daemon
h0=$(geo_hits)
typeset -A seen=(); t0=$EPOCHSECONDS
while (( EPOCHSECONDS - t0 < 30 )); do
  seen[$(grep -o '"time":[0-9]*' $T/state/status.json 2>/dev/null)]=1; sleep 0.2
done
n=${#seen}
check "за 30 с кругов ${n} (ждём ~30 при INTERVAL=1, без самоподбуживания)" test $n -le 33
h=$(( $(geo_hits) - h0 ))
check "за 30 с запросов страны: ${h} (ждём ~30 при GEO_TTL=1)" test $h -ge 25 -a $h -le 33
cpu=$(ps -o time= -p $DPID | tr -d ' ')
print "       процессорное время демона за ~30 с работы: $cpu"
pids=( $DPID $(pgrep -P $DPID) )
rss=$(ps -o rss= -p ${(j:,:)pids} | awk '{s+=$1} END {print int(s/1024)}')
print "       память демона с монитором и awk: ${rss} МБ"
stop_daemon

# ---- 13. после остановки не остаётся ни монитора, ни awk ---------------------
print "13. остановка демона убирает монитор сети"
countries RU; conf geo; MONITOR="route -n monitor" start_daemon
kids=( $(pgrep -P $DPID) ); grand=( ${(f)"$(for k in $kids; do pgrep -P $k; done)"} )
check "у работающего демона есть монитор (детей: ${#kids}, внуков: ${#grand})" test ${#kids} -ge 1
kill $DPID; wait $DPID 2>/dev/null; DPID=''; sleep 0.5
left=$(ps -o pid= -p ${(j:,:)${kids}},${(j:,:)${grand}} 2>/dev/null | grep -c .)
check "после kill демона осталось процессов монитора: $left" test $left -eq 0

print
print "итог: прошло $PASS, упало $FAIL"
(( FAIL == 0 ))
