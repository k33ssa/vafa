# Установка Vafa для Windows. Запуск: правый клик по install.cmd → «Запуск
# от имени администратора» (или install.cmd сам попросит права).
#requires -RunAsAdministrator
$ErrorActionPreference = 'Stop'
$Src  = $PSScriptRoot
$Dest = Join-Path $env:ProgramFiles 'VPNGuard'
$Root = Join-Path $env:ProgramData 'VPNGuard'

New-Item -ItemType Directory -Force -Path $Dest, $Root | Out-Null
Copy-Item "$Src\vpn-guard.ps1", "$Src\VPNGuard-Tray.ps1" $Dest -Force
Get-ChildItem $Dest -File | ForEach-Object { $_.IsReadOnly = $false }

# ProgramData\VPNGuard: писать могут только SYSTEM и администраторы, читать — все
# (иначе любой пользователь поменял бы список, а служба от SYSTEM его исполнила бы)
& icacls.exe $Root /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' '*S-1-5-32-545:(OI)(CI)RX' | Out-Null
# файлы внутри — только унаследованные права (старые ручные правки ACL убрать)
& icacls.exe "$Root\*" /reset /T /Q | Out-Null

$conf = Join-Path $Root 'config.json'
if (-not (Test-Path $conf)) {
    Copy-Item "$Src\config.default.json" $conf
    (Get-Item $conf).IsReadOnly = $false   # из общей папки/архива файл может прийти «только чтение»
    Write-Host "Конфиг: $conf (новый)"
} else { Write-Host "Конфиг $conf уже был — оставил как есть." }

# служба = задача Планировщика от SYSTEM: при загрузке, перезапуск при падении
$action  = New-ScheduledTaskAction -Execute 'powershell.exe' `
           -Argument "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$Dest\vpn-guard.ps1`" daemon"
$trigger = New-ScheduledTaskTrigger -AtStartup
$princ   = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
$set     = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
           -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1) -ExecutionTimeLimit ([TimeSpan]::Zero) -MultipleInstances IgnoreNew
# переустановка: сначала остановить старую копию — Unregister её не убивает
Stop-ScheduledTask -TaskName VPNGuard -ErrorAction SilentlyContinue
Get-CimInstance Win32_Process -Filter "Name='powershell.exe'" |
    Where-Object { $_.CommandLine -like '*vpn-guard.ps1*daemon*' } | ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }
Unregister-ScheduledTask -TaskName VPNGuard -Confirm:$false -ErrorAction SilentlyContinue
Register-ScheduledTask -TaskName VPNGuard -Action $action -Trigger $trigger -Principal $princ -Settings $set | Out-Null
Start-ScheduledTask -TaskName VPNGuard

# трей: ярлык в «Пуск», автозапуск у текущего пользователя, запуск сразу
$trayCmd = 'conhost.exe'
$trayArg = "--headless powershell.exe -NoProfile -ExecutionPolicy Bypass -File `"$Dest\VPNGuard-Tray.ps1`""
$sh = New-Object -ComObject WScript.Shell
$lnk = $sh.CreateShortcut("$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Vafa.lnk")
$lnk.TargetPath = $trayCmd; $lnk.Arguments = $trayArg; $lnk.IconLocation = 'imageres.dll,101'; $lnk.Save()

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
