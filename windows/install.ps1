# Установка Vafa для Windows. Запуск: правый клик по install.cmd → «Запуск
# от имени администратора» (или install.cmd сам попросит права).
#requires -RunAsAdministrator
$ErrorActionPreference = 'Stop'
# PowerShell 5.1 сериализует массивы в JSON как {value, Count} — убрать эту надстройку
# (как в vpn-guard.ps1 и трее: config.json здесь переписывается через ConvertTo-Json)
Remove-TypeData System.Array -ErrorAction SilentlyContinue
$Src  = $PSScriptRoot
$Dest = Join-Path $env:ProgramFiles 'VPNGuard'
$Root = Join-Path $env:ProgramData 'VPNGuard'

New-Item -ItemType Directory -Force -Path $Dest, $Root | Out-Null
Copy-Item "$Src\vpn-guard.ps1", "$Src\VPNGuard-Tray.ps1", "$Src\vafa.ico" $Dest -Force
Get-ChildItem $Dest -File | ForEach-Object { $_.IsReadOnly = $false }

# ProgramData\VPNGuard: писать могут только SYSTEM и администраторы, читать — все
# (иначе любой пользователь поменял бы список, а служба от SYSTEM его исполнила бы)
# (icacls — с ErrorActionPreference=Continue: его stderr при Stop стал бы исключением)
& { $ErrorActionPreference = 'Continue'
    & icacls.exe $Root /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' '*S-1-5-32-545:(OI)(CI)RX' 2>&1 | Out-Null
    if ($LASTEXITCODE) { throw "icacls $Root`: код $LASTEXITCODE" }
    # файлы внутри — только унаследованные права (старые ручные правки ACL убрать)
    & icacls.exe "$Root\*" /reset /T /Q 2>&1 | Out-Null }

$conf = Join-Path $Root 'config.json'
# запись через временный файл: служба не должна увидеть полузаписанный JSON
function Save-Conf($j) {
    (Get-Item $conf).IsReadOnly = $false
    $j | ConvertTo-Json -Depth 4 | Set-Content "$conf.tmp" -Encoding UTF8
    Move-Item "$conf.tmp" $conf -Force
}
if (-not (Test-Path $conf)) {
    Copy-Item "$Src\config.default.json" $conf
    (Get-Item $conf).IsReadOnly = $false   # из общей папки/архива файл может прийти «только чтение»
    Write-Host "Конфиг: $conf (новый)"
} else {
    Write-Host "Конфиг $conf уже был — оставил как есть."
    # обновление со старой версии: добавить страны блокировки (Китай, Беларусь, Иран
    # к прежнему geo:!RU), иначе служба так и проверяла бы только Россию
    $j = Get-Content $conf -Raw -Encoding UTF8 | ConvertFrom-Json
    if ($j.PSObject.Properties.Name -notcontains 'block_countries') {
        $old = @($j.checks) | Where-Object { "$_" -like 'geo:!*' } | ForEach-Object { "$_".Substring(5) -split ',' }
        $cc = @(@('RU', 'CN', 'BY', 'IR') + @($old) | ForEach-Object { "$_".Trim().ToUpper() } | Where-Object { $_ -match '^[A-Z]{2}$' } | Select-Object -Unique)
        $j | Add-Member -NotePropertyName block_countries -NotePropertyValue $cc
        Save-Conf $j
        Write-Host "Страны блокировки: $($cc -join ' ')"
    }
    # старые значения по умолчанию (опрос раз в 2 с, страна раз в 15 с) — на раз в секунду;
    # если их меняли руками, не трогать
    $j = Get-Content $conf -Raw -Encoding UTF8 | ConvertFrom-Json
    if ($j.interval -eq 2 -and $j.geo_ttl -eq 15) {
        $j.interval = 1; $j.geo_ttl = 1
        $j | Add-Member -NotePropertyName geo_ttl_down -NotePropertyValue 1 -Force
        Save-Conf $j
        Write-Host 'Конфиг: проверка VPN и страны — теперь каждую секунду.'
    }
    # Сетевой блок раньше по умолчанию был выключен (block_nets: []) — Claude Code и
    # браузер ничем не закрывались. Пустой, отсутствующий или прежний список (6 сетей)
    # заменить нынешним; свой список пользователя не трогать.
    $j = Get-Content $conf -Raw -Encoding UTF8 | ConvertFrom-Json
    $def = Get-Content "$Src\config.default.json" -Raw -Encoding UTF8 | ConvertFrom-Json
    $oldNets = @('160.79.104.0/23', '160.79.106.0/24', '209.249.57.0/24', '38.46.212.0/24', '38.84.152.0/24', '2607:6bc0::/32')
    $cur = @($j.block_nets | ForEach-Object { "$_".Trim() } | Where-Object { $_ })
    $changed = $false
    if (-not $cur.Count -or -not (Compare-Object @($cur | Sort-Object) @($oldNets | Sort-Object))) {
        $j | Add-Member -NotePropertyName block_nets -NotePropertyValue @($def.block_nets) -Force; $changed = $true
        Write-Host "Сетевой блок: сети Anthropic по умолчанию ($(@($def.block_nets).Count) шт.)"
    }
    # имена вне сетей Anthropic (её облачные адреса, Sentry, Datadog, Intercom)
    if ($j.PSObject.Properties.Name -notcontains 'block_hosts') {
        $j | Add-Member -NotePropertyName block_hosts -NotePropertyValue @($def.block_hosts); $changed = $true
        Write-Host "Сетевой блок: имена block_hosts ($(@($def.block_hosts).Count) шт.)"
    }
    if ($changed) { Save-Conf $j }
}

# служба = задача Планировщика от SYSTEM. Запускает сторожа (supervise): он держит
# демона и перезапускает его через 2 с. Триггеры: при загрузке и раз в минуту — если
# сторож жив, повтор ничего не делает (IgnoreNew), если умер — Планировщик поднимет снова.
$action  = New-ScheduledTaskAction -Execute 'powershell.exe' `
           -Argument "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$Dest\vpn-guard.ps1`" supervise"
$trigger = @((New-ScheduledTaskTrigger -AtStartup),
             (New-ScheduledTaskTrigger -Once -At (Get-Date) -RepetitionInterval (New-TimeSpan -Minutes 1)))
$princ   = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
# Priority 4 — обычный приоритет: по умолчанию у задачи 7 («ниже среднего»), и под нагрузкой
# круг демона отставал бы на секунды
$set     = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -Priority 4 `
           -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1) -ExecutionTimeLimit ([TimeSpan]::Zero) -MultipleInstances IgnoreNew
# переустановка: сначала остановить старую копию — Unregister её не убивает, а
# Stop-ScheduledTask убивает только сторожа, не демона
Stop-ScheduledTask -TaskName VPNGuard -ErrorAction SilentlyContinue
Get-CimInstance Win32_Process -Filter "Name='powershell.exe'" |
    Where-Object { $_.CommandLine -match 'vpn-guard\.ps1.*\s(daemon|supervise)\b' } | ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }
Unregister-ScheduledTask -TaskName VPNGuard -Confirm:$false -ErrorAction SilentlyContinue
Register-ScheduledTask -TaskName VPNGuard -Action $action -Trigger $trigger -Principal $princ -Settings $set | Out-Null
Start-ScheduledTask -TaskName VPNGuard

# трей: ярлык в «Пуск», автозапуск у текущего пользователя, запуск сразу
$trayCmd = 'conhost.exe'
$trayArg = "--headless powershell.exe -NoProfile -ExecutionPolicy Bypass -File `"$Dest\VPNGuard-Tray.ps1`""
$sh = New-Object -ComObject WScript.Shell
$lnk = $sh.CreateShortcut("$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Vafa.lnk")
$lnk.TargetPath = $trayCmd; $lnk.Arguments = $trayArg; $lnk.IconLocation = "$Dest\vafa.ico"; $lnk.Save()

# старый трей (прошлая версия) ещё работает — погасить: новый иначе упрётся в его мьютекс и
# выйдет, а пользователь до выхода из системы видел бы старый
Get-CimInstance Win32_Process -Filter "Name='powershell.exe'" |
    Where-Object { $_.CommandLine -like '*VPNGuard-Tray.ps1*' } | ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }

$user = (Get-CimInstance Win32_ComputerSystem).UserName     # вошедший пользователь, не «администратор UAC»
if ($user) {
    $sid = (New-Object Security.Principal.NTAccount $user).Translate([Security.Principal.SecurityIdentifier]).Value
    $run = "Registry::HKEY_USERS\$sid\Software\Microsoft\Windows\CurrentVersion\Run"
    if (Test-Path $run) { Set-ItemProperty $run -Name VPNGuard -Value "$trayCmd $trayArg" }
    # запустить трей в сессии пользователя — через одноразовую задачу от его имени
    $a = New-ScheduledTaskAction -Execute $trayCmd -Argument $trayArg
    # без этого задача от батареи (ноутбук, Parallels на MacBook) висит в очереди
    $ts = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit ([TimeSpan]::Zero)
    Register-ScheduledTask -TaskName VPNGuardTrayOnce -Action $a -User $user -Settings $ts -Force | Out-Null
    Start-ScheduledTask -TaskName VPNGuardTrayOnce
    Start-Sleep 2
    Unregister-ScheduledTask -TaskName VPNGuardTrayOnce -Confirm:$false
}

Write-Host ''
Write-Host "Установлено: $Dest"
Write-Host "Журнал:      $Root\vpn-guard.log"
Write-Host "Проверить:   powershell -ExecutionPolicy Bypass -File `"$Dest\vpn-guard.ps1`" status   (от администратора)"
Write-Host 'Щит — в трее (возможно, под стрелкой ^ рядом с часами).'
