# Удаление Vafa для Windows (от администратора).
#requires -RunAsAdministrator
$Dest = Join-Path $env:ProgramFiles 'VPNGuard'
Stop-ScheduledTask -TaskName VPNGuard -ErrorAction SilentlyContinue
Unregister-ScheduledTask -TaskName VPNGuard -Confirm:$false -ErrorAction SilentlyContinue
# Stop-ScheduledTask убивает только сторожа — демона погасить самим, иначе он вернёт блокировку
Get-CimInstance Win32_Process -Filter "Name='powershell.exe'" |
    Where-Object { $_.CommandLine -match 'vpn-guard\.ps1.*\s(daemon|supervise)\b' } | ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }
if (Test-Path "$Dest\vpn-guard.ps1") { & "$Dest\vpn-guard.ps1" unlock }
# на случай, если vpn-guard.ps1 уже нет: правила брандмауэра всех версий
Get-NetFirewallRule -DisplayName 'VPNGuard-Block' -ErrorAction SilentlyContinue | Remove-NetFirewallRule -ErrorAction SilentlyContinue
Get-CimInstance Win32_Process -Filter "Name='powershell.exe'" |
    Where-Object CommandLine -like '*VPNGuard-Tray.ps1*' | ForEach-Object { Stop-Process -Id $_.ProcessId -Force }
Remove-Item "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Vafa.lnk" -ErrorAction SilentlyContinue
Remove-Item "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\VPN Guard.lnk" -ErrorAction SilentlyContinue   # старое имя
Get-ChildItem Registry::HKEY_USERS | ForEach-Object {
    Remove-ItemProperty "Registry::$($_.Name)\Software\Microsoft\Windows\CurrentVersion\Run" -Name VPNGuard -ErrorAction SilentlyContinue
}
Remove-Item $Dest -Recurse -Force -ErrorAction SilentlyContinue
Write-Host "Удалено. Настройки и журнал остались в $env:ProgramData\VPNGuard — удалите вручную, если не нужны."
