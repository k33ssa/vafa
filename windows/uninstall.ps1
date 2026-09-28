# Удаление VPN Guard для Windows (от администратора).
#requires -RunAsAdministrator
$Dest = Join-Path $env:ProgramFiles 'VPNGuard'
Stop-ScheduledTask -TaskName VPNGuard -ErrorAction SilentlyContinue
Unregister-ScheduledTask -TaskName VPNGuard -Confirm:$false -ErrorAction SilentlyContinue
if (Test-Path "$Dest\vpn-guard.ps1") { & "$Dest\vpn-guard.ps1" unlock }
Get-CimInstance Win32_Process -Filter "Name='powershell.exe'" |
    Where-Object CommandLine -like '*VPNGuard-Tray.ps1*' | ForEach-Object { Stop-Process -Id $_.ProcessId -Force }
Remove-Item "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\VPN Guard.lnk" -ErrorAction SilentlyContinue
Get-ChildItem Registry::HKEY_USERS | ForEach-Object {
    Remove-ItemProperty "Registry::$($_.Name)\Software\Microsoft\Windows\CurrentVersion\Run" -Name VPNGuard -ErrorAction SilentlyContinue
}
Remove-Item $Dest -Recurse -Force -ErrorAction SilentlyContinue
Write-Host "Удалено. Настройки и журнал остались в $env:ProgramData\VPNGuard — удалите вручную, если не нужны."
