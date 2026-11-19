# Vafa — карта проекта

Не даёт пользоваться выбранными приложениями (Claude.app, VLC…) и не пускает сеть к Anthropic,
пока не поднят VPN с выходом не из стран блокировки (RU CN BY IR). macOS и Windows.
GitHub: `k33ssa/vafa`. Задачи — [TODO.md](TODO.md), журнал — `docs/HISTORY_<год-месяц>.md`.

## ⚠ Правила работы (от пользователя)

* **Не отключать и не переподключать VPN. Ни одного сетевого запроса мимо туннеля**
  (с российского адреса): никаких `curl --interface en0`, `curl -6` «для проверки» и т.п.
  Тесты — только на локальных подменах (127.0.0.1, `tests/fake-pfctl`).
* **Живую систему правит только пользователь** (нужен sudo): `sudo ./install.sh`,
  `/usr/local/etc/vpn-guard.conf`, pf. Claude может подготовить и предложить команду.
* Windows-VM «Windows 11» в Parallels — тестовая; перед изменениями делать снимок.

## Где что

| путь | что |
|---|---|
| `vpn-guard` | macOS: демон (zsh, root, LaunchDaemon `local.vpnguard`). Подкоманды daemon/status/check/lock/unlock/uninstall |
| `vpn-guard.conf` | настройки по умолчанию; ставится в `/usr/local/etc/` **только если там нет** — дальше install.sh лишь мигрирует известные старые значения |
| `local.vpnguard.plist` | LaunchDaemon (`ProcessType=Interactive` — с Background круг шёл раз в 4 с) |
| `vpn-guard-bootlock`, `local.vpnguard.bootlock.plist` | загрузочный замок (sh, без zsh и конфига): при старте системы грузит в якорь pf набор «закрыто» из `boot.rules`, который пишет демон; «Охрана выключена»/удаление файл стирают |
| `install.sh`, `make-dmg.sh` | установка (sudo) и DMG. Релизы на GitHub: `Vafa-<версия>.dmg` + `Vafa-<версия>-windows.zip` (папка `windows/` как есть); Homebrew — cask `vafa` в `k33ssa/homebrew-tap` (версию и sha256 править там при новом релизе) |
| `app/main.swift`, `app/build.sh` | щит в строке меню; читает `/usr/local/var/vpn-guard/status.json` |
| `windows/` | PowerShell-служба (задача Планировщика от SYSTEM), трей, install.cmd |
| `tests/run_macos.sh`, `tests/fake-pfctl` | тесты демона без root и без интернета (~3 мин) |
| `tests/run_windows.ps1` | тесты Windows-службы — в VM «Windows 11» от администратора; цель — 9.9.9.9, не Anthropic. Передача файлов в VM: base64 кусками ≤3000 символов через `prlctl exec` + `certutil -decode` (длиннее — `prlctl exec` виснет; `\\Mac\Home` от SYSTEM недоступен) |
| `docs/ПОДРОБНО.md` | подробное описание, правила VPN_CHECK, что исправлялось и почему |

Живая система (macOS): `/usr/local/bin/vpn-guard`, конфиг `/usr/local/etc/vpn-guard.conf` (600 root),
выбор приложений `vpn-guard.apps`, стран `vpn-guard.countries`, состояние `/usr/local/var/vpn-guard/`
(`status.json`, `hosts.ips`, `perms/`), журнал `/usr/local/var/log/vpn-guard.log`.

## Как устроен демон (коротко)

Круг раз в `INTERVAL` (1 с) или сразу по событию `route -n monitor`. Один снимок маршрута на круг
(`CUR_IF`). Состояния: **up** (туннель + свежая страна) → pf `via:utunN`; **unsure** (страна не
подтверждена: после события сети, Cloudflare молчит ≤ `GEO_STALE`, GRACE) → pf `hold`, приложения
не трогаются; **down** → pf `block` первым делом, затем заморозка и `chmod a-x`. Режима «без правил»
нет. pf сверяется каждый круг (`pf_verify`) и чинится. Адреса: `BLOCK_NETS` + `BLOCK_HOSTS`
(резолв в фоне, кэш `hosts.ips`).

Медленное — в фоне (с 2026-11-19): `ps` и `codesign` демон в круге не ждёт дольше 0,15 с (`ps_snap`/`ps_take`,
`sig_pump`, очередь `SIG_Q`), опрос страны — независимые запросы раз в секунду (`GEO_JOBS`). Круг дольше 2 с пишется в
журнал по шагам (`cy_mark`/`cy_report`) и ставит `LOOP_STALLED`: страна перепроверяется, новые соединения закрыты
(hold), открытые не рвутся, пока перепроверка не провалилась (`GEO_SOFT`).

## Запуск тестов

```bash
./tests/run_macos.sh
```

## Грабли

* zsh-скрипт работает под `emulate -L zsh` **без extendedglob**: шаблоны с `#`/`##` молча не совпадают.
  Где нужны — `setopt local_options extended_glob` внутри функции (так было сломано `~/Applications`).
* BSD awk на macOS не принимает перевод строки в `awk -v` — многострочное передавать файлом.
* Claude.app: `chmod` запрещён защитой «Управление приложениями» — запуск не блокируется,
  работает только заморозка (пока пользователь не даст право `/bin/zsh`).
* Claude Code CLI **морозится** (с 2026-11-13, решение пользователя; до того — только сеть, решение
  2026-10-09): `FREEZE_CLI=1`, по подписи `Q6L2SF6YDW:com.anthropic.claude-code`, с потомками, +x снимается.
  **Тесты гонять с `FREEZE_CLI=0`** (так в `conf()`), и демон в `VPN_GUARD_TEST=1` настоящую подпись не
  трогает — иначе тесты заморозили бы живые сессии, в том числе ту, что их запускает.
* **Маршрут проверять к адресу, а не `route get default`.** Happ 4.5 (xray, utunN) default не
  трогает, туннель — кусками `1/8, 2/7 … 64/2, 128/1` без `0/8`: default и `0.0.0.0` на `en0`,
  всё остальное через туннель. Демон смотрит `route -n get 160.79.104.10` (`ROUTE_PROBE`), как
  Windows-версия (`$RouteProbes`). Проверено на живой таблице 2026-11-03.
* «Странные» записи журнала со «страна: ?» и долгими паузами — часто сон/DarkWake Мака:
  сверять с `pmset -g log`.
* Проверка безопасности Claude Code не пропускает `zsh -c "<подставленный текст>"` с rm —
  писать отдельный скрипт.
* **Тесты не гонять под `taskpolicy -b`** (2026-11-18): фоновый приоритет тормозит демон и подменный pfctl, и
  проверки «за N секунд» плавают (первый круг ~4 с вместо < 1, заморозка 1–5,5 с вместо 0,2; падали 16–18, 45, 49).
  Набор лёгкий (~20 % ядра, ~9 мин) — запускать как есть. Долгий круг демон сам пишет в журнал («круг N занял…»),
  в тестах — ещё и в `/tmp/vafa-slow-cycles.log`. Файлы `vpn-guard` и `tests/run_macos.sh` во время прогона не править:
  zsh читает скрипт по ходу.
