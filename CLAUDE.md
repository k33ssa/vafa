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
| `install.sh`, `make-dmg.sh` | установка (sudo) и DMG |
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
* Claude Code CLI (`~/Library/Application Support/Claude/claude-code/…`, npm) **не морозится** —
  решение пользователя 2026-10-09; защищает только сеть.
* «Странные» записи журнала со «страна: ?» и долгими паузами — часто сон/DarkWake Мака:
  сверять с `pmset -g log`.
* Проверка безопасности Claude Code не пропускает `zsh -c "<подставленный текст>"` с rm —
  писать отдельный скрипт.
