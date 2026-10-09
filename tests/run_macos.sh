#!/bin/zsh
# Тесты демона vpn-guard (macOS) без root и без настоящего VPN:
#   * «Cloudflare» — локальный HTTP, страну выхода тест меняет файлом;
#   * события сети — свой поток вместо `route -n monitor` (кроме теста 12);
#   * приложение — крошечная программа в Fake.app, её морозит и размораживает демон;
#   * pf — tests/fake-pfctl: состояние в файлах, правила проверяет настоящий парсер
#     (/sbin/pfctl -nvf - работает без root); маршрут по умолчанию — файл $T/iface;
#   * DNS для BLOCK_HOSTS — свой резолвер-скрипт.
# Ни одного запроса в интернет: всё на 127.0.0.1. Системный pf, маршруты и VPN не трогаются.
# Запуск: ./tests/run_macos.sh       (минуты три)
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
mkdir -p $T/www $T/state $T/pf $T/Fake.app/Contents/MacOS
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
iface() { print -r -- $1 > $T/iface }   # «маршрут по умолчанию»
iface utun9
# резолвер для BLOCK_HOSTS: публичные адреса берутся, служебные (127.*, 198.18/15, fe80::) — нет
# (адреса — не из встроенных HOSTS_SEED, иначе тест 19 ничего не доказывал бы); каждый вызов
# пишется в $T/resolver.calls — так видно, ходил ли демон в DNS
print -r -- '#!/bin/zsh
print -r -- "$1" >> '"$T"'/resolver.calls
print -r -- "name: $1"
print -r -- "ip_address: 203.0.113.10"
print -r -- "ip_address: 127.0.0.1"
print -r -- "ip_address: 198.18.0.7"
print -r -- "ipv6_address: 2001:db8::10"
print -r -- "ipv6_address: fe80::1"' > $T/resolver
chmod +x $T/resolver
FAKEPF=$PWD/tests/fake-pfctl
pf_reset() { rm -rf $T/pf; mkdir -p $T/pf; }
pf_rules_now() { cat $T/pf/anchor.rules 2>/dev/null }
pf_has_pass() { grep -q '^pass' $T/pf/anchor.rules 2>/dev/null }
pf_has_block() { grep -q '^block return out quick from any to <vpnguard>' $T/pf/anchor.rules 2>/dev/null }
calls() { cat $T/pf/calls.log 2>/dev/null }
st() { grep -q -- "$1" $T/state/status.json 2>/dev/null }

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
${CONF_EXTRA:-}
EOF
  chmod 600 $T/conf
}
countries() { print -rl -- "# test" "$@" > $T/countries; chmod 600 $T/countries }

start_daemon() {
  rm -f $T/state/status.json
  VPN_GUARD_TEST=1 VPN_GUARD_CONF=$T/conf VPN_GUARD_STATE=$T/state \
  VPN_GUARD_APPS=$T/no-apps-file VPN_GUARD_COUNTRIES=$T/countries \
  VPN_GUARD_GEO_URLS="http://127.0.0.1:$PORT/trace" VPN_GUARD_GEO_BIND=${GEO_BIND:-0} \
  VPN_GUARD_IFACE_FILE=$T/iface VPN_GUARD_PFCTL=$FAKEPF FAKE_PF_DIR=$T/pf \
  VPN_GUARD_RESOLVER=${RESOLVER:-$T/resolver} \
  VPN_GUARD_NET_MONITOR=${MONITOR:-"tail -n0 -F $T/events"} \
    zsh ./vpn-guard daemon >> $T/daemon.log 2>&1 &
  DPID=$!
  wait_status '"time"' 10 >/dev/null
  # подменный монитор (tail -F) должен успеть открыть файл, иначе первое событие теряется
  if [[ -z ${MONITOR:-} ]]; then
    local i=0
    while (( i++ < 30 )) && ! pgrep -f "tail -n0 -F $T/events" >/dev/null; do sleep 0.1; done
    sleep 0.2
  fi
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
check "нет ответа, но GEO_STALE=60 — «не уверен»" st '"state":"unsure"'
check "«не уверен»: приложение НЕ заморожено" test "$(fake_state)" != T
check "«не уверен»: сеть к адресам закрыта (pass нет, block есть)" eval '! pf_has_pass && pf_has_block'
geo DE; event
check "ответ вернулся — VPN поднят, пропуск через utun9" eval 'vpn_is true 5 && pf_has_pass'
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
      VPN_GUARD_GEO_URLS="http://127.0.0.1:$PORT/trace" VPN_GUARD_GEO_BIND=0 VPN_GUARD_IFACE_FILE=$T/iface \
      VPN_GUARD_PFCTL=$FAKEPF FAKE_PF_DIR=$T/pf zsh ./vpn-guard check)
print -r -- $out | sed 's/^/       /'
check "check видит BY и список стран" eval '[[ $out == *"страна выхода: BY"*"RU CN BY IR"* && $out == *"ВЫКЛЮЧЕН"* ]]'

# ---- 12. настоящий route -n monitor: демон не будит сам себя -----------------
print "12. настоящий route -n monitor, нагрузка"
countries RU CN BY IR; INTERVAL=1 GEO_TTL=1 GEO_TTL_DOWN=1 conf geo; geo DE   # как в конфиге по умолчанию
MONITOR="route -n monitor" start_daemon
h0=$(geo_hits)
cyc() { grep -o '"cycle":[0-9]*' $T/state/status.json 2>/dev/null | cut -d: -f2 }
c0=$(cyc); sleep 30; c1=$(cyc)
n=$(( c1 - c0 ))
# счётчик кругов из status.json: самоподбуживание дало бы больше 33 (метки времени — нет)
check "за 30 с кругов ${n} (ждём ~30 при INTERVAL=1, без самоподбуживания)" test $n -ge 25 -a $n -le 33
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

# ---- 14. pf: старт закрытым, затем пропуск только через туннель ---------------
print "14. pf: старт закрытым, if-bound, таблица Anthropic"
pf_reset; countries RU CN BY IR; iface utun9; conf route geo; geo DE; start_daemon
check "первая загрузка — без пропуска (закрыто до проверки)" eval '[[ $(calls | grep "^load" | head -1) == load-block ]]'
check "потом — пропуск только через utun9" vpn_is true
check "правило пропуска с keep state (if-bound)" grep -q '^pass out quick on utun9 from any to <vpnguard> .*(if-bound)' $T/pf/anchor.rules
check "в таблице 160.79.104.0/21 и 2607:6bc0::/32" eval 'grep -qx 160.79.104.0/21 $T/pf/anchor.table && grep -qx 2607:6bc0::/32 $T/pf/anchor.table'
check "status.json: net=via:utun9, net_ok=true, state=up" eval 'st "\"net\":\"via:utun9\"" && st "\"net_ok\":true" && st "\"state\":\"up\""'

# ---- 15. маршрут ушёл на en0 — сразу block, режима open нет ------------------
print "15. маршрут utun9 → en0: блок, а не снятие фильтра"
iface en0; event
check "VPN выключен" vpn_is false
check "в якоре block и нет pass" eval 'pf_has_block && ! pf_has_pass'
check "открытые соединения к адресам оборваны (pfctl -k)" eval 'calls | grep -q "^kill 0.0.0.0/0 160.79.104.0/21"'
check "приложение заморожено" test "$(fake_state)" = T
check "ни разу не было пустого якоря (open)" eval '! calls | grep -q flush-anchor'
iface utun9; event
check "туннель вернулся — снова через utun9" eval 'vpn_is true 5 && pf_has_pass'

# ---- 16. событие сети: сеть закрыта до ответа о стране ------------------------
print "16. событие сети при живом туннеле: hold до перепроверки"
: > $T/pf/calls.log
event NEWADDR; sleep 2
check "после события: загрузка без pass (hold), потом снова pass" eval '[[ "$(calls | grep "^load" | tr "\n" " ")" == "load-block load-pass " ]]'
check "в hold соединения не рвали" eval '! calls | grep -q "^kill"'
: > $T/pf/calls.log
geo RU; event
check "тот же utun9, но выход RU — блок" vpn_is false
check "порядок: hold, затем block с обрывом соединений" eval 'calls | grep -q "^kill" && ! pf_has_pass'
geo DE; event; vpn_is true 5

# ---- 17. pf сбили снаружи — демон чинит за круг -------------------------------
print "17. самопочинка pf"
INTERVAL=1 conf route geo; event; sleep 1.5   # INTERVAL=1 — чтобы проверка шла каждую секунду
vpn_is true 5
rm -f $T/pf/enabled                     # как pfctl -d у другого VPN-клиента
sleep 2.5
check "pfctl -d → pf снова включён" test -e $T/pf/enabled
grep -q 'защиту сбили снаружи (pf выключен)' $T/daemon.log && ok "в журнале — «сбили снаружи (pf выключен)»" || bad "нет записи о pfctl -d"
rm -f $T/pf/anchor.rules $T/pf/anchor.table   # очистили якорь
sleep 2.5
check "очищенный якорь восстановлен (pass через utun9)" pf_has_pass
: > $T/pf/main.rules                    # pfctl -F all — пропала точка com.apple/*
sleep 2.5
check "пустой основной набор → загружен /etc/pf.conf" eval 'calls | grep -q "^load-main /etc/pf.conf" && grep -qF "anchor \"com.apple/*\"" $T/pf/main.rules'
print -r -- 'anchor "mullvad" all' > $T/pf/main.rules   # чужой основной набор без com.apple/*
sleep 2.5
check "чужой основной набор не трогаем, но net_ok=false с причиной" eval 'st "\"net_ok\":false" && st "точка подключения com.apple"'
check "чужой основной набор остался как был" grep -q mullvad $T/pf/main.rules
print -r -- 'anchor "com.apple/*" all' > $T/pf/main.rules
sleep 2.5
check "точка вернулась — net_ok=true" st '"net_ok":true'

# ---- 18. правила не грузятся — честный статус и повтор -------------------------
print "18. загрузка pf падает"
touch $T/pf/fail-load; rm -f $T/pf/anchor.rules; sleep 2.5
check "net_ok=false, причина в net_error" eval 'st "\"net_ok\":false" && st "pfctl не принял правила"'
rm -f $T/pf/fail-load; sleep 2.5
check "загрузка снова проходит — net_ok=true" eval 'st "\"net_ok\":true" && pf_has_pass'
stop_daemon

# ---- 19. BLOCK_HOSTS: адреса из DNS в таблицу, служебные — никогда --------------
print "19. BLOCK_HOSTS"
pf_reset; INTERVAL=1 conf route geo; geo DE; iface utun9; rm -f $T/state/hosts.ips; start_daemon
vpn_is true 5; sleep 2
check "203.0.113.10 и 2001:db8::10 (из DNS) в таблице" eval 'grep -qx 203.0.113.10 $T/pf/anchor.table && grep -qx 2001:db8::10 $T/pf/anchor.table'
check "127.0.0.1, 198.18.0.7, fe80::1 в таблицу не попали" eval '! grep -qE "^(127\.0\.0\.1|198\.18\.0\.7|fe80::1)$" $T/pf/anchor.table'
check "кэш адресов записан с подписью списка имён" grep -q '^# hosts: downloads.claude.ai' $T/state/hosts.ips
stop_daemon
pf_reset; print -rl -- "$(grep '^# hosts:' $T/state/hosts.ips)" 203.0.113.11 > $T/state/hosts.ips
RESOLVER=false INTERVAL=1 conf route geo; RESOLVER=false start_daemon
vpn_is true 5
check "DNS не отвечает — адрес из кэша на диске (203.0.113.11) в таблице" grep -qx 203.0.113.11 $T/pf/anchor.table
check "и встроенные адреса имён (34.149.66.165 — Datadog) на месте" grep -qx 34.149.66.165 $T/pf/anchor.table
stop_daemon

# ---- 20. кривая запись BLOCK_NETS не роняет правила -----------------------------
print "20. кривые записи в конфиге"
pf_reset; CONF_EXTRA='BLOCK_NETS=( 160.79.104.0/21 999.1.1.1/8 2607:6bc0::/32 "a;b" )
BLOCK_HOSTS=( "bad host" ok.example )' INTERVAL=1 conf route geo; start_daemon
check "правила загружены, несмотря на кривые записи" eval 'vpn_is true 5 && pf_has_pass'
check "в таблице годные 160.79.104.0/21 и 2607:6bc0::/32" eval 'grep -qx 160.79.104.0/21 $T/pf/anchor.table && grep -qx 2607:6bc0::/32 $T/pf/anchor.table'
grep -q 'пропускаю непонятную запись «999.1.1.1/8»' $T/daemon.log && ok "999.1.1.1/8 — в журнале" || bad "нет записи о 999.1.1.1/8"
grep -q 'пропускаю непонятное имя «bad host»' $T/daemon.log && ok "«bad host» — в журнале" || bad "нет записи о «bad host»"
stop_daemon

# ---- 21. конфиг испорчен — защита не снимается -----------------------------------
print "21. конфиг небезопасный (доступен на запись всем)"
pf_reset; rm -f $T/sourced; CONF_EXTRA="touch $T/sourced
BLOCK_NETS=( 10.66.0.0/16 )" conf route geo; chmod 666 $T/conf; geo DE; start_daemon
check "сеть всё равно под охраной (умолчания: таблица Anthropic)" eval 'vpn_is true 5 && pf_has_pass && grep -qx 160.79.104.0/21 $T/pf/anchor.table'
check "небезопасный конфиг не исполнялся (метка не создана, 10.66.0.0/16 нет)" eval '! test -e $T/sourced && ! grep -qx 10.66.0.0/16 $T/pf/anchor.table'
grep -q 'доступен на запись группе или всем — не читаю' $T/daemon.log && ok "в журнале — «не читаю его»" || bad "нет записи «не читаю»"
iface en0; event
check "без конфига VPN выключен по маршруту (умолчание route geo)" eval 'vpn_is false 5 && ! pf_has_pass'
iface utun9; chmod 600 $T/conf
stop_daemon

# ---- 22. файл стран: «RU, CN» в строке и мусор ------------------------------------
print "22. файл стран"
pf_reset; countries 'RU, CN'; conf geo; geo CN; start_daemon
check "«RU, CN» в одной строке понят: из CN — блокировка" vpn_is false
stop_daemon
countries '???' 'x1'; conf geo; geo IR; start_daemon
check "мусор без годных кодов → список по умолчанию (IR блокируется)" vpn_is false
stop_daemon
countries; conf geo; geo IR; start_daemon
check "пустой выбор (только комментарий) → страну не проверяем" vpn_is true
stop_daemon
countries RU CN BY IR

# ---- 23. остановка демона оставляет сеть закрытой ----------------------------------
print "23. остановка демона (launchctl bootout при обновлении)"
pf_reset; conf route geo; geo DE; start_daemon; vpn_is true 5
stop_daemon
check "после остановки в якоре block без pass" eval 'pf_has_block && ! pf_has_pass'

# ---- 24. macOS не даёт снять +x — «заблокировано» не врём --------------------------
print "24. chmod запрещён (как «Управление приложениями»)"
pf_reset; INTERVAL=1 conf route geo; geo DE; start_daemon; vpn_is true 5
chflags uchg $T/Fake.app/Contents/MacOS/fake
geo RU; event; vpn_is false 5; sleep 1
check "приложение заморожено" test "$(fake_state)" = T
check "status.json: locked=false (chmod не прошёл)" st '"locked":false'
chflags nouchg $T/Fake.app/Contents/MacOS/fake
sleep 2
check "запрет сняли — теперь locked=true и +x снят" eval 'st "\"locked\":true" && ! test -x $T/Fake.app/Contents/MacOS/fake'
geo DE; event; vpn_is true 5
check "VPN вернулся — +x на месте" test -x $T/Fake.app/Contents/MacOS/fake
stop_daemon

# ---- 25. без туннеля страну не спрашиваем (ни одного запроса мимо VPN) -------------
print "25. маршрут не через туннель — запроса о стране нет"
pf_reset; iface en0; conf geo; geo DE; h0=$(geo_hits); GEO_BIND=1 start_daemon; sleep 3
check "VPN выключен" vpn_is false
check "за 3 с ни одного запроса к «Cloudflare»" test $(geo_hits) -eq $h0
stop_daemon; iface utun9

# ---- 26. загрузка с пропуском падает — в ядре не остаётся старого pass ---------------
print "26. сбой загрузки: запасной набор без pass (ревью: старый pass переживал «down»)"
pf_reset; countries RU CN BY IR; iface utun9; INTERVAL=1 conf route geo; geo DE; start_daemon; vpn_is true 5
touch $T/pf/fail-load-pass
CONF_EXTRA='BLOCK_NETS=( 160.79.104.0/21 2607:6bc0::/32 34.36.0.0/16 )' INTERVAL=1 conf route geo; event; sleep 2
check "pass из ядра ушёл, block на месте" eval 'pf_has_block && ! pf_has_pass'
check "net_ok=false, причина «pfctl не принял правила»" eval 'st "\"net_ok\":false" && st "pfctl не принял"'
check "status.json: net — режим, который пытались (via:utun9), а не пусто" st '"net":"via:utun9"'
check "соединения оборваны" eval 'calls | grep -q "^kill"'
rm -f $T/pf/fail-load-pass; sleep 2.5
check "сбой прошёл — снова via:utun9 с новой сетью 34.36.0.0/16" eval 'pf_has_pass && grep -qx 34.36.0.0/16 $T/pf/anchor.table && st "\"net_ok\":true"'

# ---- 27. таблица в ядре не совпала по числу адресов — тоже сбой -------------------------
print "27. сверка таблицы"
touch $T/pf/drop-table-entry
CONF_EXTRA='BLOCK_NETS=( 160.79.104.0/21 2607:6bc0::/32 )' INTERVAL=1 conf route geo; event; sleep 2
check "адрес «потерялся» — net_ok=false, причина в net_error" eval 'st "\"net_ok\":false" && st "в таблице pf"'
rm -f $T/pf/drop-table-entry; sleep 2.5
check "после — снова норма" st '"net_ok":true'
stop_daemon

# ---- 28. кривой IPv6 отсекается до pf (ревью: принимался и ронял загрузку) -------------
print "28. строгая проверка IPv6"
pf_reset; CONF_EXTRA='BLOCK_NETS=( 160.79.104.0/21 2607:6bc0:::/32 1::2::3 12345::1/64 2607:6bc0::/32 )
BLOCK_HOSTS=()' INTERVAL=1 conf route geo; start_daemon
check "правила загружены, в таблице ровно 2 годные сети" eval 'vpn_is true 5 && pf_has_pass && [[ $(grep -c . $T/pf/anchor.table) == 2 ]]'
for b in '2607:6bc0:::/32' '1::2::3' '12345::1/64'; do
  grep -qF "пропускаю непонятную запись «$b»" $T/daemon.log && ok "«$b» отсеян" || bad "«$b» не отсеян"
done
check "ни одной синтаксической ошибки pf" eval '! calls | grep -q load-syntax-error'
stop_daemon

# ---- 29. точка подключения — целая строка; чужой pass quick до неё ---------------------
print "29. основной набор pf: scrub-anchor и чужой pass quick"
pf_reset; INTERVAL=1 conf route geo; start_daemon; vpn_is true 5
print -rl -- 'scrub-anchor "com.apple/*" all fragment reassemble' 'anchor "mullvad" all' > $T/pf/main.rules; sleep 2.5
check "только scrub-anchor — это не подключение: net_ok=false" eval 'st "\"net_ok\":false" && st "точка подключения"'
print -rl -- 'pass out quick all flags S/SA keep state' 'anchor "com.apple/*" all' > $T/pf/main.rules; sleep 2.5
check "чужой pass quick до com.apple/* — net_ok=false" eval 'st "\"net_ok\":false" && st "чужой пропуск"'
print -r -- 'anchor "com.apple/*" all' > $T/pf/main.rules; sleep 2.5
check "штатный набор — net_ok=true" st '"net_ok":true'
stop_daemon

# ---- 30. вход в «не уверен» рвёт соединения через туннель один раз ---------------------
print "30. «не уверен»: открытые соединения рвутся при входе"
pf_reset; INTERVAL=1 GEO_STALE=60 GEO_TTL=1 conf route geo; geo DE; start_daemon; vpn_is true 5
: > $T/pf/calls.log
geo ''; sleep 3
check "state=unsure" st '"state":"unsure"'
check "при входе в unsure — pfctl -k" eval 'calls | grep -q "^kill"'
k1=$(calls | grep -c '^kill'); sleep 2; k2=$(calls | grep -c '^kill')
check "дальше в unsure не рвёт каждый круг (было $k1, стало $k2)" test $k1 -eq $k2
geo DE; sleep 2.5
check "Cloudflare ответил — up" vpn_is true 3
stop_daemon

# ---- 31. события сети: рвём соединения только если это событие туннеля --------------
print "31. событие чужого интерфейса не рвёт соединения; туннеля — рвёт"
pf_reset; print -r -- 'utun9|29|10.8.0.2' > $T/iface.id; conf route geo; geo DE; start_daemon; vpn_is true 5
: > $T/pf/calls.log; print -r -- "RTM_IFINFO: iface status change: len 112, if# 4, flags:<UP>" >> $T/events; sleep 1.5
check "IFINFO другого интерфейса (if# 4, awdl0/мост) — без обрыва" eval '! calls | grep -q "^kill"'
: > $T/pf/calls.log; event NEWADDR; sleep 1.5
check "NEWADDR (новый адрес IPv6) — без обрыва" eval '! calls | grep -q "^kill"'
: > $T/pf/calls.log; print -r -- "RTM_IFINFO: iface status change: len 112, if# 29, flags:<UP>" >> $T/events; sleep 1.5
check "IFINFO самого туннеля (if# 29) — обрыв" eval 'calls | grep -q "^kill"'
vpn_is true 3
: > $T/pf/calls.log; print -r -- 'utun9|29|10.8.0.77' > $T/iface.id; event CHANGE; sleep 1.5
check "у туннеля сменился адрес (переподключился) — обрыв" eval 'calls | grep -q "^kill"'
check "и снова via:utun9" eval 'vpn_is true 3 && pf_has_pass'
stop_daemon; rm -f $T/iface.id

# ---- 32. BLOCK_HOSTS: fake-IP при VPN; без туннеля — ни одного DNS-запроса ----------
print "32. BLOCK_HOSTS при fake-IP прокси и при упавшем VPN"
pf_reset; rm -f $T/state/hosts.ips $T/resolver.calls
print -r -- '198.18.0.9' > $T/dnsans
print -r -- '#!/bin/zsh
print -r -- "$1" >> '"$T"'/resolver.calls
print -r -- "name: $1"; print -r -- "ip_address: $(<'"$T"'/dnsans)"' > $T/resolver2; chmod +x $T/resolver2
INTERVAL=1 conf route geo; RESOLVER=$T/resolver2 start_daemon; vpn_is true 5; sleep 1
check "пока fake-IP — 198.18.* в таблицу не попал, встроенные адреса на месте" eval '! grep -q "^198\.18\." $T/pf/anchor.table && grep -qx 34.149.66.165 $T/pf/anchor.table'
iface en0; event; vpn_is false 5; sleep 0.5; : > $T/resolver.calls; sleep 12
check "VPN упал — за 12 с ни одного DNS-запроса мимо туннеля" test ! -s $T/resolver.calls
check "встроенные адреса телеметрии закрыты и без DNS" grep -qx 34.149.66.165 $T/pf/anchor.table
iface utun9; stop_daemon

# ---- 33. битый конфиг при старте не разблокирует приложения ------------------------------
print "33. старт с нечитаемым конфигом: приложения остаются заблокированными"
pf_reset; INTERVAL=1 conf route geo; geo RU; start_daemon; vpn_is false 5
check "заблокировано: +x снят" eval '! test -x $T/Fake.app/Contents/MacOS/fake'
stop_daemon
chmod 666 $T/conf; start_daemon; sleep 2
check "после рестарта с битым конфигом +x по-прежнему снят" eval '! test -x $T/Fake.app/Contents/MacOS/fake'
check "в журнале нет «убран из конфига»" eval '! grep -q "убран из конфига" $T/daemon.log'
check "приложение заморожено" test "$(fake_state)" = T
grep -q 'беру последний годный список приложений' $T/daemon.log && ok "список — из apps.last (в журнале)" || bad "нет записи об apps.last"
stop_daemon; chmod 600 $T/conf; geo DE

# ---- 34. путь со скобками: не «убран из конфига» при каждом сохранении ----------------
print "34. приложение со скобками в пути"
mkdir -p "$T/Beta (1).app/Contents/MacOS"; cp $T/Fake.app/Contents/MacOS/fake "$T/Beta (1).app/Contents/MacOS/beta"
chmod 755 "$T/Beta (1).app/Contents/MacOS/beta" $T/Fake.app/Contents/MacOS/fake   # 33-я оставила Fake без +x
pf_reset; : > $T/daemon.log
CONF_EXTRA="APPS=( \"$T/Fake.app\" \"$T/Beta (1).app\" )" INTERVAL=1 conf route geo; geo RU; start_daemon; vpn_is false 5; sleep 1
check "Beta (1).app заблокирован" eval '! test -x "$T/Beta (1).app/Contents/MacOS/beta"'
touch $T/conf; sleep 2
check "перечитали конфиг — Beta (1).app не «убран из конфига»" eval '! grep -q "Beta (1).app убран из конфига" $T/daemon.log && ! test -x "$T/Beta (1).app/Contents/MacOS/beta"'
geo DE; event; vpn_is true 5
check "VPN вернулся — +x у Beta (1).app вернули" test -x "$T/Beta (1).app/Contents/MacOS/beta"
stop_daemon

# ---- 35. LOCK_LAUNCH=yes и VPN «поднят» без туннеля --------------------------------------
print "35. кривой LOCK_LAUNCH; VPN по правилу proc: без туннеля"
pf_reset; : > $T/daemon.log; iface en0
CONF_EXTRA='LOCK_LAUNCH=yes' INTERVAL=1 conf 'proc:zsh'; start_daemon; sleep 2
grep -q 'LOCK_LAUNCH=yes — беру 1' $T/daemon.log && ok "LOCK_LAUNCH=yes → 1 (в журнале)" || bad "LOCK_LAUNCH=yes не исправлен"
check "VPN поднят (proc:zsh), маршрут en0 — сеть: block, не via" eval 'vpn_is true 5 && st "\"net\":\"block\"" && ! pf_has_pass'
check "режим pf — не дата из журнала (ревью: лог попадал в \$(…))" eval '! grep -q "pf: .*20[0-9][0-9]-" $T/daemon.log'
n=$(grep -c 'маршрут не через туннель' $T/daemon.log)
check "предупреждение «не через туннель» — один раз, а не каждый круг ($n)" test $n -eq 1
iface utun9; stop_daemon

# ---- 36. старый якорь com.apple/vpn-guard чистится при старте ----------------------------
print "36. переименование якоря"
pf_reset; print -r -- 'pass out quick on utun3 from any to <vpnguard> flags S/SA keep state' > "$T/pf/other.com.apple_vpn_guard.rules"
INTERVAL=1 conf route geo; start_daemon; vpn_is true 5
check "старый якорь очищен" test ! -e "$T/pf/other.com.apple_vpn_guard.rules"
stop_daemon

# ---- 37. дубли в канонической записи pf не роняют загрузку ------------------------
print "37. дубли: 160.79.105.0/21 ≡ 160.79.104.0/21, 34.149.66.165/32 ≡ встроенный адрес"
pf_reset; CONF_EXTRA='BLOCK_NETS=( 160.79.105.0/21 160.79.104.0/21 34.149.66.165/32 2607:6BC0::/32 )' INTERVAL=1 conf route geo; geo DE; start_daemon
check "правила загружены, net_ok=true, без запасного набора" eval 'vpn_is true 5 && st "\"net_ok\":true" && pf_has_pass'
check "160.79.104.0/21 в таблице один раз" eval '[[ $(grep -cx 160.79.104.0/21 $T/pf/anchor.table) == 1 ]]'
stop_daemon

# ---- 38. блок выключен (BLOCK_NETS=() и BLOCK_HOSTS=()) — старые правила снимаются ---
print "38. сетевой блок выключен в конфиге"
pf_reset; mkdir -p $T/pf; print -r -- 'block return out quick from any to <vpnguard>' > $T/pf/anchor.rules
CONF_EXTRA='BLOCK_NETS=()
BLOCK_HOSTS=()' INTERVAL=1 conf route geo; start_daemon; sleep 1
check "старые правила сняты" test ! -e $T/pf/anchor.rules
check "status.json: net=off" st '"net":"off"'
stop_daemon

# ---- 39. старый конфиг с BLOCK_NETS=() (без BLOCK_HOSTS) — имена тоже не трогать ------
print "39. старый конфиг «BLOCK_NETS=() — блок выключен»"
pf_reset; CONF_EXTRA='BLOCK_NETS=()' INTERVAL=1 conf route geo; start_daemon; sleep 1
check "блок выключен целиком (net=off), встроенные адреса не грузятся" eval 'st "\"net\":\"off\"" && test ! -e $T/pf/anchor.rules'
stop_daemon

# ---- 40. перенос BLOCK_NETS в install.sh (на копии конфига 2026-09) -------------------
print "40. install.sh: перенос старого списка сетей"
{ print '#!/bin/zsh'; print 'SRC=$1 CONF=$2 migrated=0'
  sed -n '/# >>> перенос BLOCK_NETS/,/# <<< перенос BLOCK_NETS/p' install.sh | sed -e 's/chown root:wheel \$tmp; //'
} > $T/migr.zsh
cp tests/fixtures/vpn-guard.conf.2026-09 $T/old.conf
zsh $T/migr.zsh $PWD $T/old.conf > $T/migr.out 2>&1
check "старый список заменён новым (160.79.104.0/21 есть, /23 нет)" eval 'grep -q "^  160.79.104.0/21" $T/old.conf && ! grep -q "160.79.104.0/23" $T/old.conf'
check "остальной конфиг не тронут (APPS, VPN_CHECK, NOTIFY)" eval 'diff <(grep -v "^  [0-9]" tests/fixtures/vpn-guard.conf.2026-09 | grep -v "^  2607") <(grep -v "^  [0-9]" $T/old.conf | grep -v "^  2607") >/dev/null'
check "резервная копия старого конфига" eval 'ls $T/old.conf.bak.* >/dev/null 2>&1'
check "новый конфиг — валидный zsh" zsh -n $T/old.conf
cp $T/old.conf $T/old2.conf; zsh $T/migr.zsh $PWD $T/old.conf > /dev/null 2>&1
check "второй прогон ничего не меняет" cmp -s $T/old.conf $T/old2.conf
{ cat tests/fixtures/vpn-guard.conf.2026-09; print 'BLOCK_NETS=( 10.99.0.0/16 )'; print 'GRACE=5'; } > $T/old3.conf; cp $T/old3.conf $T/old3b.conf
zsh $T/migr.zsh $PWD $T/old3.conf > /dev/null 2>&1
check "два BLOCK_NETS= в конфиге — не трогаем вообще" cmp -s $T/old3.conf $T/old3b.conf

# ---- 41. unlock (как аварийный выход) снимает всё -----------------------------------
print "41. vpn-guard unlock"
pf_reset; INTERVAL=1 conf route geo; geo RU; start_daemon; vpn_is false 5; sleep 1
stop_daemon
check "после остановки — закрыто (hold) и status state=stopped" eval 'pf_has_block && st "\"state\":\"stopped\""'
VPN_GUARD_TEST=1 VPN_GUARD_CONF=$T/conf VPN_GUARD_STATE=$T/state VPN_GUARD_APPS=$T/no-apps-file \
  VPN_GUARD_COUNTRIES=$T/countries VPN_GUARD_IFACE_FILE=$T/iface VPN_GUARD_PFCTL=$FAKEPF FAKE_PF_DIR=$T/pf \
  zsh ./vpn-guard unlock > $T/unlock.out 2>&1
check "unlock: правил в якоре нет" test ! -e $T/pf/anchor.rules
check "unlock: +x вернули" test -x $T/Fake.app/Contents/MacOS/fake
check "unlock: status.json без «hold» (щит не пугает)" eval '! st "\"net\":\"hold\""'
geo DE

# ---- 42. приложение убрали из списка, пока оно заморожено — разморозить ----------------
print "42. убрали из списка во время блокировки"
pf_reset; INTERVAL=1 conf route geo; geo RU; start_daemon; vpn_is false 5; sleep 1
check "заморожено" test "$(fake_state)" = T
CONF_EXTRA='APPS=()' INTERVAL=1 conf route geo; sleep 2.5
check "после удаления из списка — разморожено" test "$(fake_state)" != T
check "и +x вернули" test -x $T/Fake.app/Contents/MacOS/fake
stop_daemon; geo DE

print
print "итог: прошло $PASS, упало $FAIL"
(( FAIL == 0 ))
