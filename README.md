# VPN Guard

# Quick install 

```bash
git clone https://github.com/k33ssa/vafa
cd vafa
./app/build.sh
sudo ./install.sh
```

Проверить:

```bash
sudo vpn-guard status
```
# О приложении 

Не даёт пользоваться выбранными приложениями на macOS, пока не включён VPN.

Системный демон (root) каждые 2 секунды проверяет VPN. Если VPN нет:

* **замораживает** процессы выбранных приложений (или закрывает — `ON_DOWN=kill`);
* **запрещает запуск** — снимает право на исполнение с файлов в `.app`;
* **режет сеть** к заданным адресам через файрвол pf (по умолчанию — Anthropic,
  чтобы claude.ai не открывался и в браузере).

Когда VPN возвращается, всё размораживается и открывается само.

**VPN Guard.app** — окно и значок в строке меню: статус
(`Claude — запуск: разблокировано, процессов: 20`) и галочки «какие приложения
охранять».

## Быстрая установка

**macOS** (нужны Xcode Command Line Tools: `xcode-select --install`):

```bash
cd ~
git clone https://github.com/k33ssa/vafa
cd vafa
./app/build.sh
sudo ./install.sh
```

Щит сразу появится в строке меню. Проверить: `sudo vpn-guard status`.

**Windows 10/11**: скачать репозиторий (Code → Download ZIP), распаковать, открыть
папку `windows` и дважды щёлкнуть `install.cmd` — он сам попросит права
администратора. Щит появится в трее (возможно, под стрелкой ^ у часов).
Подробнее — [INSTALL.md](INSTALL.md).

## Как понимается, что VPN включён

Правила в `/usr/local/etc/vpn-guard.conf`, по умолчанию оба сразу:

* `route` — весь трафик идёт через туннельный интерфейс (utun/tun/ppp/ipsec);
* `geo:!RU` — Cloudflare видит выход не из России.

Поэтому **подходит любой VPN, который гонит весь трафик через туннель**: Happ,
OpenVPN, WireGuard, Outline, AmneziaVPN, встроенный IKEv2 и т.п.

**Не подходит «как есть»**, если VPN работает как прокси (режим «системный
прокси» в Happ/V2Ray/Clash) или с раздельным туннелированием: маршрут остаётся на
Wi-Fi, и демон считает, что VPN нет. Для таких случаев есть правила
`nc:ИмяVPN`, `proc:имя_процесса`, `script:/путь` — см. [docs/ПОДРОБНО.md](docs/ПОДРОБНО.md).

## Файлы

| файл | что это |
|---|---|
| `vpn-guard` | демон и команды (`status`, `check`, `lock`, `unlock`, `uninstall`) |
| `vpn-guard.conf` | настройки по умолчанию (ставятся только при первой установке) |
| `local.vpnguard.plist` | автозапуск демона |
| `install.sh` | установка — см. [INSTALL.md](INSTALL.md) |
| `app/` | исходник VPN Guard.app и `build.sh` |
| `make-dmg.sh` | собрать `VPN-Guard.dmg` для другого Мака |
| `windows/` | версия для Windows: служба (PowerShell + Планировщик), трей, `install.cmd` |

Аварийно снять всю блокировку: `sudo vpn-guard unlock`.
