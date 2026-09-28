<p align="center"><img src="assets/logo.png" width="280" alt="Vafa"></p>

# Vafa (Verify access for apps) 

Не даёт пользоваться выбранными приложениями, пока не включён VPN.
Без VPN приложения **замораживаются** и **не запускаются**; когда VPN
возвращается — всё размораживается само. Значок-щит показывает статус
(`Claude — запуск: разблокировано, процессов: 20`), по клику — выбор приложений.

Щит: 🟢 VPN есть · 🔴 блокировка · ⭕ пустой контур — охрана выключена.

---

##  macOS

### Установка

Нужны Xcode Command Line Tools (один раз: `xcode-select --install`).

```bash
cd ~
git clone https://github.com/k33ssa/vafa
cd vafa
./app/build.sh
sudo ./install.sh
```

Щит сразу появится в строке меню. Проверить:

```bash
sudo vpn-guard status
```

### Как работает

Системный демон (root) каждые 2 секунды проверяет VPN. Если VPN нет:

* **замораживает** процессы приложений (или закрывает — `ON_DOWN=kill`);
* **запрещает запуск** — снимает право на исполнение с файлов в `.app`;
* **режет сеть** к заданным адресам через pf (по умолчанию — Anthropic).

Настройки: `/usr/local/etc/vpn-guard.conf`, журнал: `/usr/local/var/log/vpn-guard.log`.

### Команды

```bash
sudo vpn-guard status      # что сейчас происходит
sudo vpn-guard unlock      # аварийно снять всю блокировку
sudo vpn-guard uninstall   # удалить демон
```

Перенести на другой Мак без сборки: `./make-dmg.sh` → [INSTALL.md](INSTALL.md).

---

##  Windows 10/11

### Установка

1. Скачать репозиторий: **Code → Download ZIP**, распаковать.
2. Открыть папку `windows`, дважды щёлкнуть **`install.cmd`** → разрешить в окне UAC.

Щит появится в трее (в Windows 11 — возможно, под стрелкой **^** у часов).
Двойной щелчок по щиту — окно выбора приложений.

### Как работает

Служба (задача Планировщика от SYSTEM, стартует с Windows) каждые 2 секунды
проверяет VPN. Если VPN нет:

* **замораживает** процессы приложений (или закрывает — `"on_down": "kill"`);
* **запрещает запуск** — запрет выполнения на `.exe` в папке приложения;
* **режет сеть** к адресам из `block_nets` Брандмауэром Windows (по умолчанию выключено).

Настройки: `C:\ProgramData\VPNGuard\config.json`, журнал — там же, `vpn-guard.log`.

### Команды (PowerShell от администратора)

```powershell
& "C:\Program Files\VPNGuard\vpn-guard.ps1" status   # что сейчас происходит
& "C:\Program Files\VPNGuard\vpn-guard.ps1" unlock   # аварийно снять блокировку
```

Удалить: в распакованной папке `windows` —

```powershell
powershell -ExecutionPolicy Bypass -File .\uninstall.ps1
```

---

## Какой VPN подходит

Проверка по умолчанию на обеих системах: **весь трафик идёт через туннель** и
**Cloudflare видит выход не из России**.

*  Подходит любой VPN в режиме туннеля: Happ, OpenVPN, WireGuard, Outline,
  AmneziaVPN, встроенный IKEv2 и т.п.
*  Не подходит «как есть» VPN в режиме **системного прокси** (Happ/V2Ray/Clash)
  или с раздельным туннелированием — трафик идёт мимо туннеля, и охрана считает,
  что VPN нет. Для таких случаев есть правила `proc:`, `nc:`/`adapter:`, `script:` —
  см. [docs/ПОДРОБНО.md](docs/ПОДРОБНО.md).

## Файлы

| путь | что это |
|---|---|
| `vpn-guard`, `vpn-guard.conf`, `local.vpnguard.plist`, `install.sh` | macOS: демон, настройки, автозапуск, установка |
| `app/` | macOS: приложение-щит (Swift) и `build.sh` |
| `make-dmg.sh` | macOS: собрать `Vafa.dmg` |
| `windows/` | Windows: служба, трей, `install.cmd`, `uninstall.ps1` |
| `INSTALL.md` | подробная установка для обеих систем |
