#requires -RunAsAdministrator
# Тесты Windows-версии vpn-guard без VPN и без единого обращения к Anthropic:
#   * «Cloudflare» — HttpListener на адресе самой виртуалки (маршрут к нему — через её
#     Ethernet, который демон считает туннелем; на 127.0.0.1 демон теперь не спросит: не
#     туннель), страну выхода тест меняет файлом;
#   * в block_nets вместо сетей Anthropic — 9.9.9.9/32 (Quad9), в block_hosts — dns.quad9.net;
#   * приложение — крошечный fake.exe, его морозит и размораживает демон;
#   * второй интерфейс — KM-TEST Loopback (драйвер netloop.inf есть в Windows): на нём
#     проверяется режим «только через» и пересборка правила при новом адаптере, а
#     маршруты к адресам Anthropic через него (в никуда, наружу ничего не уходит) — проверка route;
#   * основной Ethernet виртуалки демон считает туннелем (VPN_GUARD_TUNNEL_IFS), кроме
#     раздела 12a: там выход не через туннель, и страну спрашивать нельзя.
# Запуск (PowerShell от администратора; служба Vafa должна быть остановлена — тест сам
# создаёт и снимает правила «VPNGuard-Block»):
#   powershell -ExecutionPolicy Bypass -File tests\run_windows.ps1             # демон, минуты 3-4
#   powershell -ExecutionPolicy Bypass -File tests\run_windows.ps1 -Install    # плюс install.ps1 / uninstall.ps1
# Меняет на время теста: профиль брандмауэра Public (выключает на секунды, исключает из
# защиты KM-TEST и возвращает как было), лишний адрес 10.254.254.254/32 на основном адаптере,
# KM-TEST Loopback (с новым именем «Vafa Test* [1]»), время в
# виртуалке (на 10 минут назад и обратно).
param([switch]$Install, [switch]$NoLoopback)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
[Console]::OutputEncoding = [Text.Encoding]::UTF8
Remove-TypeData System.Array -ErrorAction SilentlyContinue
$Repo  = Split-Path $PSScriptRoot -Parent
$Win   = Join-Path $Repo 'windows'
$Guard = Join-Path $Win 'vpn-guard.ps1'
# не в C:\Windows\Temp: путь приложения под C:\Windows демон справедливо отвергает
$T     = 'C:\vafa-test-' + [guid]::NewGuid().ToString('N').Substring(0, 6)
$Port  = Get-Random -Minimum 20000 -Maximum 40000
$script:Pass = 0; $script:Fail = 0

function Ok([string]$m)  { Write-Host "  ok   $m"; $script:Pass++ }
function Bad([string]$m) { Write-Host "  FAIL $m"; $script:Fail++ }
# имена параметров необычные: блок видит переменные вызывающего, а $name/$b затенили бы их
function Check([string]$__name, [scriptblock]$__block) {
    $__ok = $false
    try { $__ok = [bool](& $__block) } catch { $__name += " (исключение: $_)" }
    if ($__ok) { Ok $__name } else { Bad $__name }
}
# ждать условия; вернуть, сколько секунд ждали (не меньше 0,1 — чтобы читалось как «да»), или $null
function WaitFor([scriptblock]$__cond, [double]$__sec = 10) {
    $__sw = [Diagnostics.Stopwatch]::StartNew()
    while ($__sw.Elapsed.TotalSeconds -lt $__sec) {
        try { if (& $__cond) { return [Math]::Max(0.1, [Math]::Round($__sw.Elapsed.TotalSeconds, 1)) } } catch {}
        Start-Sleep -Milliseconds 300
    }
    return $null
}
# демон заменяет файл (Replace) — чтение может попасть в миг замены: тогда ещё раз
# (чтение с FILE_SHARE_DELETE, как у трея: не мешает демону заменять файл)
function ReadShared([string]$f) {
    $fs = [IO.File]::Open($f, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]'ReadWrite, Delete')
    try { (New-Object IO.StreamReader($fs, [Text.Encoding]::UTF8)).ReadToEnd() } finally { $fs.Dispose() }
}
function St { for ($__i = 0; $__i -lt 3; $__i++) { try { return (ReadShared "$T\status.json" | ConvertFrom-Json) } catch { Start-Sleep -Milliseconds 50 } }; $null }
# status.json свежий: time — секунды Unix по UTC, расхождение в обе стороны не больше 3 с
function Fresh($s) { $s -and [Math]::Abs([DateTimeOffset]::UtcNow.ToUnixTimeSeconds() - [long]$s.time) -le 3 }
function GeoCount { @(Get-Content "$T\geo.log" -ErrorAction SilentlyContinue).Count }
function Rules { @(Get-NetFirewallRule -DisplayName 'VPNGuard-Block' -ErrorAction SilentlyContinue) }
# правило могут снять посреди чтения (демон как раз меняет режим) — тогда пусто, WaitFor повторит
function RuleAddrs { try { @(Rules | Get-NetFirewallAddressFilter | ForEach-Object { $_.RemoteAddress }) } catch { @() } }
# быстрая проверка через COM (~10 мс против ~400 мс у Get-NetFirewallRule): опрос
# через WMI сам тормозит демона, который тоже ходит в WMI
function FwLive { try { [bool]((New-Object -ComObject HNetCfg.FwPolicy2).Rules.Item('VPNGuard-Block').Enabled) } catch { $false } }
function RuleIfs { try { @(Rules | Get-NetFirewallInterfaceFilter | ForEach-Object { $_.InterfaceAlias }) } catch { @() } }
function Reach([string]$ip, [int]$port = 443) {
    $c = New-Object Net.Sockets.TcpClient
    try { return $c.ConnectAsync($ip, $port).Wait(3000) } catch { return $false } finally { $c.Close() }
}
function Geo([string]$v) { Set-Content "$T\trace" $v -Encoding ASCII -NoNewline }
function Conf([hashtable]$over = @{}) {
    $c = $script:BaseConf.Clone(); foreach ($k in $over.Keys) { $c[$k] = $over[$k] }
    ([pscustomobject]$c) | ConvertTo-Json -Depth 4 | Set-Content "$T\config.json.tmp" -Encoding UTF8
    Move-Item "$T\config.json.tmp" "$T\config.json" -Force
}
function Frozen {
    $p = Get-Process -Id $script:Fake.Id -ErrorAction SilentlyContinue
    [bool]($p -and $p.Threads.Count -and -not ($p.Threads | Where-Object { $_.ThreadState -ne 'Wait' -or "$($_.WaitReason)" -ne 'Suspended' }))
}
function LogLines { try { @(Get-Content "$T\vpn-guard.log" -Encoding UTF8) } catch { @() } }
function Guards([string]$what = 'daemon|supervise') {
    @(Get-CimInstance Win32_Process -Filter "Name='powershell.exe'" | Where-Object { $_.CommandLine -match "vpn-guard\.ps1.*\s($what)\b" })
}
function CanLaunch {
    try { $p = Start-Process "$T\FakeApp\fake.exe" -PassThru -WindowStyle Hidden -ErrorAction Stop; Stop-Process -Id $p.Id -Force; $true } catch { $false }
}
function Start-Daemon {
    Remove-Item "$T\status.json" -ErrorAction SilentlyContinue
    $script:D = Start-Process powershell.exe -PassThru -WindowStyle Hidden -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$Guard`" daemon" `
        -RedirectStandardOutput "$T\daemon.out" -RedirectStandardError "$T\daemon.err"
    [void](WaitFor { St } 30)
}
function Stop-Daemon { if ($script:D) { Stop-Process -Id $script:D.Id -Force -ErrorAction SilentlyContinue; $script:D = $null } }
# CPU процесса и всех WmiPrvSE (сумма), мс
function CpuMs([int]$id) { $p = Get-Process -Id $id -ErrorAction SilentlyContinue; if ($p) { $p.TotalProcessorTime.TotalMilliseconds } else { 0 } }
function WmiMs { $h = @{}; foreach ($p in @(Get-Process WmiPrvSE -ErrorAction SilentlyContinue)) { try { $h[$p.Id] = $p.TotalProcessorTime.TotalMilliseconds } catch {} }; $h }
function WmiDelta($a, $b) { $d = 0.0; foreach ($k in $b.Keys) { $d += $b[$k] - $(if ($a.ContainsKey($k)) { $a[$k] } else { 0 }) }; $d }

# Сетевой адаптер KM-TEST Loopback: SetupAPI, как devcon install netloop.inf *MSLOOP
$LoopCs = @'
using System; using System.Runtime.InteropServices; using System.Text;
public static class VGTestLoop {
    [StructLayout(LayoutKind.Sequential)] struct DEVINFO { public int cbSize; public Guid ClassGuid; public int DevInst; public IntPtr Reserved; }
    [DllImport("setupapi.dll", SetLastError=true)] static extern IntPtr SetupDiCreateDeviceInfoList(ref Guid cls, IntPtr hwnd);
    [DllImport("setupapi.dll", SetLastError=true, CharSet=CharSet.Unicode)] static extern bool SetupDiCreateDeviceInfoW(IntPtr set, string name, ref Guid cls, string desc, IntPtr hwnd, int flags, ref DEVINFO d);
    [DllImport("setupapi.dll", SetLastError=true)] static extern bool SetupDiSetDeviceRegistryPropertyW(IntPtr set, ref DEVINFO d, int prop, byte[] buf, int size);
    [DllImport("setupapi.dll", SetLastError=true)] static extern bool SetupDiCallClassInstaller(int fn, IntPtr set, ref DEVINFO d);
    [DllImport("setupapi.dll", SetLastError=true)] static extern bool SetupDiDestroyDeviceInfoList(IntPtr set);
    [DllImport("newdev.dll", SetLastError=true, CharSet=CharSet.Unicode)] static extern bool UpdateDriverForPlugAndPlayDevicesW(IntPtr hwnd, string hwid, string inf, int flags, out bool reboot);
    public static string Add(string inf) {
        Guid net = new Guid("4d36e972-e325-11ce-bfc1-08002be10318");
        IntPtr set = SetupDiCreateDeviceInfoList(ref net, IntPtr.Zero);
        try {
            DEVINFO d = new DEVINFO(); d.cbSize = Marshal.SizeOf(typeof(DEVINFO));
            if (!SetupDiCreateDeviceInfoW(set, "Net", ref net, null, IntPtr.Zero, 1, ref d)) return "create " + Marshal.GetLastWin32Error();
            byte[] hw = Encoding.Unicode.GetBytes("*MSLOOP\0\0");
            if (!SetupDiSetDeviceRegistryPropertyW(set, ref d, 1, hw, hw.Length)) return "hwid " + Marshal.GetLastWin32Error();
            if (!SetupDiCallClassInstaller(0x19, set, ref d)) return "register " + Marshal.GetLastWin32Error();
            bool rb;
            if (!UpdateDriverForPlugAndPlayDevicesW(IntPtr.Zero, "*MSLOOP", inf, 1, out rb)) return "driver " + Marshal.GetLastWin32Error();
            return "ok";
        } finally { SetupDiDestroyDeviceInfoList(set); }
    }
}
'@

# ---- проверки до начала --------------------------------------------------------
if (Guards) { Write-Host 'Работает служба vpn-guard. Останови: Disable-ScheduledTask VPNGuard; & "C:\Program Files\VPNGuard\vpn-guard.ps1" unlock'; exit 2 }
if (Rules) { Write-Host 'Есть правила брандмауэра «VPNGuard-Block» — сними их (vpn-guard.ps1 unlock) и запусти снова'; exit 2 }

Write-Host '== 0. синтаксис и кодировка'
foreach ($f in @(Get-ChildItem $Win -Filter *.ps1) + @(Get-ChildItem $PSScriptRoot -Filter *.ps1)) {
    $errs = $null
    [void][Management.Automation.Language.Parser]::ParseFile($f.FullName, [ref]$null, [ref]$errs)
    Check "разбор $($f.Name)" { -not $errs }
    foreach ($e in @($errs)) { if ($e) { Write-Host "      $($e.Extent.StartLineNumber): $($e.Message)" } }
    # без BOM PowerShell 5.1 читает файл как ANSI — русские строки ломают разбор
    $b = [IO.File]::ReadAllBytes($f.FullName)
    Check "$($f.Name): UTF-8 с BOM" { $b[0] -eq 0xEF -and $b[1] -eq 0xBB -and $b[2] -eq 0xBF }
}

Write-Host '== 1. трей: строки состояния (функции из VPNGuard-Tray.ps1)'
$tast = [Management.Automation.Language.Parser]::ParseFile((Join-Path $Win 'VPNGuard-Tray.ps1'), [ref]$null, [ref]$null)
Add-Type -AssemblyName System.Drawing
foreach ($n in $tast.FindAll({ param($x) $x -is [Management.Automation.Language.FunctionDefinitionAst] -and $x.Name -in 'State-Of', 'State-Text', 'Net-Text', 'New-ShieldIcon' }, $true)) { Invoke-Expression $n.Extent.Text }
Check 'via:Wintun, net_ok → «только через Wintun»' { (Net-Text ([pscustomobject]@{ state = 'up'; net = 'via:Wintun'; net_ok = $true; net_error = '' })) -eq 'Сеть к Anthropic: только через Wintun' }
Check 'block, net_ok → «закрыта»' { (Net-Text ([pscustomobject]@{ state = 'down'; net = 'block'; net_ok = $true; net_error = '' })) -eq 'Сеть к Anthropic: закрыта' }
Check 'net_ok=false → «НЕ ЗАЩИЩЕНА (причина)»' { (Net-Text ([pscustomobject]@{ state = 'up'; net = ''; net_ok = $false; net_error = 'правило брандмауэра не найдено' })) -eq 'Сеть к Anthropic: НЕ ЗАЩИЩЕНА (правило брандмауэра не найдено)' }
Check 'старая служба (только vpn): state=up, строки про сеть нет' { $o = [pscustomobject]@{ vpn = $true }; (State-Of $o) -eq 'up' -and $null -eq (Net-Text $o) }
Check 'unsure — своя строка' { (State-Text ([pscustomobject]@{ state = 'unsure' })) -match 'не подтверждена' }
Check 'значок с «!» рисуется' { (New-ShieldIcon ([Drawing.Color]::Orange) $true $true) -is [Drawing.Icon] }
$tips = @([regex]::Matches((Get-Content (Join-Path $Win 'VPNGuard-Tray.ps1') -Raw -Encoding UTF8), "'(Vafa: [^']*)'") | ForEach-Object { $_.Groups[1].Value })
Check "подсказки значка не длиннее 63 символов ($($tips.Count) шт., самая длинная $(($tips | Measure-Object Length -Maximum).Maximum))" { $tips.Count -ge 5 -and -not ($tips | Where-Object { $_.Length -gt 63 }) }
# Guard-On: Get-ScheduledTask (WMI) — не каждые 2 с, а раз в 30 с; -Fresh — сразу
foreach ($n in $tast.FindAll({ param($x) $x -is [Management.Automation.Language.AssignmentStatementAst] -and "$($x.Left)" -in '$GuardC', '$GuardSw' }, $false)) { Invoke-Expression $n.Extent.Text }
foreach ($n in $tast.FindAll({ param($x) $x -is [Management.Automation.Language.FunctionDefinitionAst] -and $x.Name -eq 'Guard-On' }, $true)) { Invoke-Expression $n.Extent.Text }
$script:SchedCalls = 0
function Get-ScheduledTask { $script:SchedCalls++; [pscustomobject]@{ State = 'Ready' } }
Check 'трей: Guard-On — один запрос к Планировщику на 5 вызовов (кэш), -Fresh — ещё один' {
    $r = @(1..5 | ForEach-Object { Guard-On }); $c1 = $script:SchedCalls; $f = Guard-On -Fresh
    $c1 -eq 1 -and $script:SchedCalls -eq 2 -and $f -and -not ($r -contains $false) }
Remove-Item Function:\Get-ScheduledTask

Write-Host '== 2. проверка адресов (функции из vpn-guard.ps1)'
$ast = [Management.Automation.Language.Parser]::ParseFile($Guard, [ref]$null, [ref]$null)
foreach ($n in $ast.FindAll({ param($x) $x -is [Management.Automation.Language.AssignmentStatementAst] -and "$($x.Left)" -in '$GeoIPs', '$NotPublic' }, $false)) { Invoke-Expression $n.Extent.Text }
foreach ($n in $ast.FindAll({ param($x) $x -is [Management.Automation.Language.FunctionDefinitionAst] -and $x.Name -in 'ConvertTo-Cidr', 'Test-InNet', 'Test-PublicIp' }, $true)) { Invoke-Expression $n.Extent.Text }
$cases = [ordered]@{ '160.79.104.5/21' = '160.79.104.0/21'; '2607:6bc0::10/32' = '2607:6bc0::/32'; '9.9.9.9/32' = '9.9.9.9'; '9.9.9.9' = '9.9.9.9'
                     '1.2.3.4/33' = $null; 'foo' = $null; '1' = $null; '10.0.0.0/7' = $null; '2607::/8' = $null; '1.2.3.4/x' = $null }
foreach ($k in $cases.Keys) { $want = $cases[$k]; $got = ConvertTo-Cidr $k; Check "ConvertTo-Cidr '$k' → '$want'" { "$got" -eq "$want" } }
foreach ($ip in '9.9.9.9', '2620:fe::fe', '34.36.57.103') { Check "Test-PublicIp $ip = да" { Test-PublicIp $ip } }
foreach ($ip in '10.1.2.3', '198.18.0.5', '100.64.1.1', '127.0.0.1', '1.1.1.1', '1.0.0.1', 'fe80::1', '::1', 'fd00::1') { Check "Test-PublicIp $ip = нет" { -not (Test-PublicIp $ip) } }
# VGNative (C# из vpn-guard.ps1): маршрут без WMI, время записи разделов реестра, снимок процессов
foreach ($n in $ast.FindAll({ param($x) $x -is [Management.Automation.Language.CommandAst] -and $x.GetCommandName() -eq 'Add-Type' -and $x.Extent.Text -match 'class VGNative' }, $true)) { Invoke-Expression $n.Extent.Text }
Check 'VGNative собирается' { 'VGNative' -as [type] }
foreach ($ip in '1.1.1.1', '9.9.9.9', '160.79.104.10') {
    $fr = (Find-NetRoute -RemoteIPAddress $ip | Where-Object InterfaceIndex | Select-Object -First 1).InterfaceIndex
    Check "BestIf $ip = Find-NetRoute ($fr)" { [VGNative]::BestIf($ip) -eq $fr }
}
Check 'BestIf: не адрес → 0' { [VGNative]::BestIf('foo') -eq 0 }
Check 'KeyStamp: раздел правил брандмауэра есть, несуществующий → 0' {
    [VGNative]::KeyStamp([string[]]@('SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules', 'SOFTWARE\VafaNope')) -match '^[1-9]\d+,0,$' }
Check 'VGNative.Now: монотонные секунды (за 1,2 с сна — 1,1–1,5 с)' { $a = [VGNative]::Now(); Start-Sleep -Milliseconds 1200; $d = [VGNative]::Now() - $a; $d -ge 1.1 -and $d -le 1.5 }

Write-Host '== 2a. что считать туннелем, адреса проверки страны, числа в конфиге (функции из vpn-guard.ps1)'
foreach ($n in $ast.FindAll({ param($x) $x -is [Management.Automation.Language.AssignmentStatementAst] -and "$($x.Left)" -in '$TunnelRx', '$NotTunnelRx', '$NoTime', '$ConfWriters', '$NetCacheTtl', '$TestTunnelIfs' }, $false)) { Invoke-Expression $n.Extent.Text }
foreach ($n in $ast.FindAll({ param($x) $x -is [Management.Automation.Language.FunctionDefinitionAst] -and $x.Name -in 'Test-Tunnel', 'Read-PbkVpn', 'Get-RasVpnNames', 'Get-GeoIp', 'Get-Num', 'Get-Flag', 'Update-NetCache', 'Test-ConfSafe', 'Normalize-Countries' }, $true)) { Invoke-Expression $n.Extent.Text }
$script:Warns = @()
function WarnOnce([string]$k, [string]$m) { $script:Warns += $m }
function Log([string]$m) { }
# VPN-подключение Windows «Work VPN» — как будто из телефонной книги
$script:RasC = @{ T = [VGNative]::Now(); Names = @('Work VPN') }
$tun = [ordered]@{
    'Высокоскоростное подключение||ras' = $false        # PPPoE провайдера (Ростелеком, Дом.ру)
    'Rostelecom||ras' = $false                          # PPPoE под своим именем — нет в списке VPN
    'Work VPN||ras' = $true                             # VPN-подключение Windows (IKEv2/L2TP/SSTP)
    'Local Area Connection* 5|WAN Miniport (PPPOE)' = $false
    'Network Bridge|Microsoft MAC Bridge Miniport' = $false
    'Team1|Microsoft Network Adapter Multiplexor Driver' = $false
    'Ethernet 3|Some Virtual Adapter' = $false          # раньше: «не железный» — значит, туннель
    'vEthernet (WSL)|Hyper-V Virtual Ethernet Adapter' = $false
    'Teredo Tunneling Pseudo-Interface|' = $false
    '6to4 Adapter|' = $false
    'Microsoft IP-HTTPS Platform Interface|' = $false
    'Tailscale|Tailscale Tunnel' = $false
    'Ethernet|Parallels VirtIO Ethernet Adapter' = $false
    'wg0|WireGuard Tunnel' = $true
    'Ethernet 2|TAP-Windows Adapter V9' = $true
    'AmneziaVPN|AmneziaWG Tunnel' = $true
    'singbox_tun|sing-box Tunnel' = $true
    'Подключение по локальной сети 3|Wintun Userspace Tunnel' = $true
    'OpenVPN Data Channel Offload|OpenVPN Data Channel Offload' = $true
    'NordLynx|NordLynx Tunnel' = $true
}
foreach ($k in $tun.Keys) {
    $alias, $desc, $ras = $k -split '\|'
    $o = [pscustomobject]@{ Index = 99; Alias = $alias; Desc = "$desc"; Adapter = ($ras -ne 'ras'); Tun = $null }
    $want = $tun[$k]
    Check "Test-Tunnel «$alias»$(if ($desc) { " ($desc)" })$(if ($ras -eq 'ras') { ' без адаптера' }) = $(if ($want) { 'туннель' } else { 'нет' })" { (Test-Tunnel $o) -eq $want }
}
$pbk = @('[Work VPN]', 'MEDIA=rastapi', 'Port=VPN2-0', 'Device=WAN Miniport (IKEv2)', 'Type=2', '',
         '[Высокоскоростное подключение]', 'Type=5', 'MEDIA=rastapi', 'Port=PPPoE5-0', 'Device=WAN Miniport (PPPOE)', '',
         '[Странное]', 'Type=2', 'Port=PPPoE5-0')
Check 'rasphone.pbk: VPN — только «Work VPN» (широкополосное и PPPoE — нет)' { $r = @(Read-PbkVpn $pbk); $r.Count -eq 1 -and $r[0] -eq 'Work VPN' }
$script:RasC = @{ T = $NoTime; Names = @() }
Check "Get-RasVpnNames на этой машине работает (VPN-подключений: $(@(Get-RasVpnNames).Count))" { $null -ne $script:RasC.Names -and $script:RasC.T -gt 0 }
$urls = [ordered]@{ 'https://1.1.1.1/cdn-cgi/trace' = '1.1.1.1'; 'http://10.211.55.50:3456/trace' = '10.211.55.50'
                    'https://www.cloudflare.com/cdn-cgi/trace' = ''; 'https://[2606:4700::1111]/cdn-cgi/trace' = ''; 'http://localhost:80/' = ''; 'мусор' = '' }
foreach ($k in $urls.Keys) { $want = $urls[$k]; Check "Get-GeoIp '$k' → '$want'" { "$(Get-GeoIp $k)" -eq $want } }
Check 'адреса проверки страны по умолчанию — только IPv4-литералы (без www.cloudflare.com)' {
    $g = @($ast.FindAll({ param($x) $x -is [Management.Automation.Language.AssignmentStatementAst] -and "$($x.Left)" -eq '$GeoUrls' }, $false))[0].Extent.Text
    $g -notmatch 'cloudflare\.com' -and $g -match '1\.1\.1\.1' }
Check "Get-Num: «5m» → по умолчанию (300) с предупреждением, «45» → 45, 10 при минимуме 30 → 300" {
    $script:Warns = @(); (Get-Num '5m' 300 30 300 'hosts_ttl') -eq 300 -and $script:Warns.Count -eq 1 -and (Get-Num '45' 300 30 300 'x') -eq 45 -and (Get-Num 10 300 30 300 'x') -eq 300 -and (Get-Num $null 7 0 0 'x') -eq 7 }
Check 'Get-Flag: false/«false»/0 → нет, «maybe» → по умолчанию' { -not (Get-Flag $false $true 'f') -and -not (Get-Flag 'false' $true 'f') -and -not (Get-Flag 0 $true 'f') -and (Get-Flag 'maybe' $true 'f') }
# испорченный block_countries раньше давал пустой список — страна молча не проверялась
$ccs = [ordered]@{
    'строка «RU,CN»' = @{ In = 'RU,CN'; Want = 'RU CN' }
    'строка «ru; by  ir»' = @{ In = 'ru; by  ir'; Want = 'RU BY IR' }
    '{"value": […], "Count": 2} (установщик d674bf9)' = @{ In = ('{"value":["RU","CN"],"Count":2}' | ConvertFrom-Json); Want = 'RU CN' }
    'массив ["RU","XX1","by"]' = @{ In = @('RU', 'XX1', 'by'); Want = 'RU BY' }
    'пустой массив' = @{ In = @(); Want = '' }
}
foreach ($k in $ccs.Keys) { $v = $ccs[$k]; Check "Normalize-Countries: $k → «$($v.Want)»" { (@(Normalize-Countries $v.In) -join ' ') -eq $v.Want } }
# разбор DNS-ответа (проверка fake-IP): запрос + ответ с одной записью A
$q = [VGNative]::DnsQueryA('dns.quad9.net', 0x1234)
$r = [byte[]]($q + @(0xC0, 0x0C, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 198, 18, 0, 7)); $r[2] = 0x81; $r[3] = 0x80; $r[7] = 1
Check "DnsQueryA/DnsAnswersA: запрос $($q.Length) байт, ответ → 198.18.0.7" { $q.Length -eq 31 -and $q[0] -eq 0x12 -and (@([VGNative]::DnsAnswersA($r)) -join ',') -eq '198.18.0.7' }
Check 'DnsAnswersA: мусор и обрезанный ответ — без исключения, пусто' { @([VGNative]::DnsAnswersA([byte[]]@(1, 2, 3))).Count -eq 0 -and @([VGNative]::DnsAnswersA([byte[]]$r[0..35])).Count -eq 0 }
# Get-NetAdapter упал или пуст — кэш интерфейсов прежний (раньше все становились «RAS — туннель»)
$script:NetC = @{ T = $NoTime; Ifs = @('old'); Info = @{ 999 = 'old' } }
function Get-NetAdapter { throw 'WMI не ответил' }
Update-NetCache -Force
Check 'Get-NetAdapter упал — кэш интерфейсов прежний' { $script:NetC.Info.Count -eq 1 -and $script:NetC.Info.ContainsKey(999) }
function Get-NetAdapter { }
Update-NetCache -Force
Check 'Get-NetAdapter пуст — кэш интерфейсов прежний' { $script:NetC.Info.Count -eq 1 -and $script:NetC.Info.ContainsKey(999) }
Remove-Item Function:\Get-NetAdapter
Update-NetCache -Force
$tuns = @($script:NetC.Info.Values | Where-Object { $_.Tun } | ForEach-Object Alias)
Check "настоящий список: интерфейсов $($script:NetC.Info.Count), туннелей нет (было бы: $($tuns -join ', '))" { $script:NetC.Info.Count -ge 2 -and -not $tuns.Count }

# ---- окружение -------------------------------------------------------------------
New-Item -ItemType Directory -Force "$T\FakeApp" | Out-Null
# как install.ps1: писать — только SYSTEM и администраторы (иначе демон конфиг не читает)
& icacls.exe $T /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' '*S-1-5-32-545:(OI)(CI)RX' | Out-Null
Add-Type -TypeDefinition 'public static class FakeMain { public static void Main() { System.Threading.Thread.Sleep(-1); } }' `
    -OutputAssembly "$T\FakeApp\fake.exe" -OutputType ConsoleApplication
$script:Fake = Start-Process "$T\FakeApp\fake.exe" -PassThru -WindowStyle Hidden
# exe, права на который icacls поменять не может (SYSTEM и администраторам запрещено менять
# права, владельцу — только чтение): так падает icacls на чужом или занятом файле
New-Item -ItemType Directory -Force "$T\FakeApp\sub" | Out-Null
Copy-Item "$T\FakeApp\fake.exe" "$T\FakeApp\sub\deny.exe"
& icacls.exe "$T\FakeApp\sub\deny.exe" /grant '*S-1-3-4:(R)' | Out-Null
& icacls.exe "$T\FakeApp\sub\deny.exe" /deny '*S-1-5-18:(WDAC)' '*S-1-5-32-544:(WDAC)' | Out-Null

Write-Host '== 2c. запрет запуска: запись — до icacls; снятие — со всех exe папки (функции из vpn-guard.ps1)'
foreach ($n in $ast.FindAll({ param($x) $x -is [Management.Automation.Language.FunctionDefinitionAst] -and $x.Name -in 'Load-State', 'Save-State', 'Lock-App', 'Unlock-App', 'App-Folder', 'Invoke-Native' }, $true)) { Invoke-Expression $n.Extent.Text }
$StatePath = "$T\locked-test.json"
New-Item -ItemType Directory -Force "$T\LockT\bin" | Out-Null
Copy-Item "$T\FakeApp\fake.exe" "$T\LockT\bin\a.exe"; Copy-Item "$T\FakeApp\fake.exe" "$T\LockT\bin\b.exe"
function Denied([string]$f) { [bool]@((Get-Acl $f).Access | Where-Object { "$($_.AccessControlType)" -eq 'Deny' -and $_.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value -eq 'S-1-1-0' }).Count }
Lock-App "$T\LockT\bin"
Check 'Lock-App: оба exe под запретом, оба в locked.json' { (Denied "$T\LockT\bin\a.exe") -and (Denied "$T\LockT\bin\b.exe") -and @((Load-State)."$T\LockT\bin").Count -eq 2 }
# прерванный проход: запрет на exe есть, а в записи его нет
Copy-Item "$T\FakeApp\fake.exe" "$T\LockT\bin\c.exe"; & icacls.exe "$T\LockT\bin\c.exe" /deny '*S-1-1-0:(X)' | Out-Null
Unlock-App "$T\LockT\bin"
Check 'Unlock-App: запрет снят со всех трёх (c.exe не был записан)' { -not (Denied "$T\LockT\bin\a.exe") -and -not (Denied "$T\LockT\bin\b.exe") -and -not (Denied "$T\LockT\bin\c.exe") }
& icacls.exe "$T\LockT\bin\c.exe" /deny '*S-1-1-0:(X)' | Out-Null
Unlock-App "$T\LockT\bin"
Check 'Unlock-App без записи — ничего не делает (дёшево в каждом круге up)' { Denied "$T\LockT\bin\c.exe" }
Unlock-App "$T\LockT\bin" -Sweep
Check 'Unlock-App -Sweep (unlock) — снимает и без записи' { -not (Denied "$T\LockT\bin\c.exe") }
New-Item -ItemType Directory -Force "$T\Приложение\bin" | Out-Null; Copy-Item "$T\FakeApp\fake.exe" "$T\Приложение\bin\x.exe"
Lock-App "$T\Приложение\bin"
Check 'путь с кириллицей: запись в locked.json (UTF-8 без BOM) читается обратно' { @((Load-State)."$T\Приложение\bin").Count -eq 1 -and (Denied "$T\Приложение\bin\x.exe") }
Unlock-App "$T\Приложение\bin"
Check 'путь с кириллицей: запрет снят, записи нет' { -not (Denied "$T\Приложение\bin\x.exe") -and -not (Load-State).PSObject.Properties["$T\Приложение\bin"] }
Remove-Item "$T\Приложение" -Recurse -Force -ErrorAction SilentlyContinue
Check 'locked.json пишется без временных файлов-остатков' { -not (Get-ChildItem $T -Filter 'locked-test.json.*.tmp') }
Remove-Item "$T\LockT", $StatePath -Recurse -Force -ErrorAction SilentlyContinue
Remove-Variable StatePath

Write-Host '== 2b. права на конфиг: сравниваются SID, а не имена (в русской Windows SYSTEM — «СИСТЕМА»)'
$cf = "$T\acl-test.json"; Set-Content $cf '{}'
& icacls.exe $cf /inheritance:r /grant:r '*S-1-5-18:F' '*S-1-5-32-544:F' '*S-1-5-32-545:RX' | Out-Null
Check 'SYSTEM, Администраторы — полный доступ, Пользователи — чтение: годится' { Test-ConfSafe $cf }
& icacls.exe $cf /grant '*S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464:F' '*S-1-1-0:R' | Out-Null
Check 'плюс TrustedInstaller (полный) и Все (чтение): годится' { Test-ConfSafe $cf }
& icacls.exe $cf /grant '*S-1-5-11:M' | Out-Null
Check '«Прошедшие проверку» могут менять: не годится' { -not (Test-ConfSafe $cf) }
& icacls.exe $cf /remove:g '*S-1-5-11' | Out-Null
& icacls.exe $cf /grant '*S-1-5-32-545:(WD)' | Out-Null
Check 'Пользователи могут дописывать (WD): не годится' { -not (Test-ConfSafe $cf) }
& icacls.exe $cf /inheritance:r /grant:r '*S-1-5-18:F' '*S-1-5-32-544:F' '*S-1-5-32-545:RX' | Out-Null
& icacls.exe $cf /setowner '*S-1-5-32-545' | Out-Null
Check 'владелец файла — Пользователи (права сами по себе безопасные): не годится' { -not (Test-ConfSafe $cf) }
& icacls.exe $cf /setowner '*S-1-5-32-544' | Out-Null
Check 'владелец — Администраторы: годится' { Test-ConfSafe $cf }
$cdir = "$T\acl-dir"; New-Item -ItemType Directory -Force $cdir | Out-Null; $cf2 = "$cdir\config.json"; Set-Content $cf2 '{}'
& icacls.exe $cdir /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' '*S-1-5-32-545:(OI)(CI)RX' | Out-Null
& icacls.exe $cf2 /reset | Out-Null
Check 'папка: Пользователи — только чтение: годится' { Test-ConfSafe $cf2 }
& icacls.exe $cdir /grant '*S-1-5-32-545:(WD)' | Out-Null
& icacls.exe $cf2 /inheritance:r /grant:r '*S-1-5-18:F' '*S-1-5-32-544:F' '*S-1-5-32-545:RX' | Out-Null
Check 'папка: Пользователи могут создавать файлы (файл сам безопасен): не годится' { -not (Test-ConfSafe $cf2) }
& icacls.exe $cdir /remove:g '*S-1-5-32-545' | Out-Null; & icacls.exe $cdir /grant '*S-1-5-32-545:(OI)(CI)RX' | Out-Null
& icacls.exe $cdir /setowner '*S-1-5-32-545' | Out-Null
Check 'владелец папки — Пользователи: не годится' { -not (Test-ConfSafe $cf2) }
& icacls.exe $cdir /setowner '*S-1-5-32-544' | Out-Null
Remove-Item $cdir -Recurse -Force
$names = @((Get-Acl $cf).Access | ForEach-Object { "$($_.IdentityReference)" })
Check "имена ACE на этой Windows ($($names -join ', ')) — проверка от них не зависит (в коде нет имён)" {
    $src = (Get-Command Test-ConfSafe).Definition
    ($names -match 'SYSTEM|СИСТЕМА') -and $src -notmatch 'SYSTEM\$|Administrators|Администраторы' }
Remove-Item $cf -Force

$egIdx = (Find-NetRoute -RemoteIPAddress 1.1.1.1 | Where-Object InterfaceIndex | Select-Object -First 1).InterfaceIndex
$egress = (Get-NetIPInterface -InterfaceIndex $egIdx | Select-Object -First 1).InterfaceAlias
# «Cloudflare» — на адресе самой виртуалки: маршрут к нему идёт через её Ethernet (туннель для демона)
$EgIp = (Get-NetIPAddress -InterfaceIndex $egIdx -AddressFamily IPv4 | Where-Object { $_.IPAddress -notlike '169.254.*' -and -not $_.SkipAsSource } | Select-Object -First 1).IPAddress
Geo 'DE'
$script:GeoJob = Start-Job -ArgumentList $T, $Port -ScriptBlock {
    param($T, $Port)
    $l = New-Object Net.HttpListener; $l.Prefixes.Add("http://+:$Port/"); $l.Start()
    while ($true) {
        $c = $l.GetContext()
        if ($c.Request.Url.AbsolutePath -eq '/dns-query') {
            # DNS через HTTPS (как https://1.1.1.1/dns-query): адреса dns.quad9.net
            $qn = $c.Request.QueryString['name']; $qt = $c.Request.QueryString['type']
            Add-Content "$T\doh.log" "$(Get-Date -Format 'HH:mm:ss.fff') $($c.Request.RemoteEndPoint) $qn $qt $($c.Request.Headers['Accept'])"
            $ans = if ($qn -ne 'dns.quad9.net') { '' } elseif ($qt -eq 'AAAA') { '{"name":"dns.quad9.net","type":28,"TTL":60,"data":"2620:fe::fe"}' } else { '{"name":"dns.quad9.net","type":1,"TTL":60,"data":"9.9.9.9"},{"name":"dns.quad9.net","type":1,"TTL":60,"data":"149.112.112.112"}' }
            $b = [Text.Encoding]::ASCII.GetBytes("{`"Status`":0,`"Answer`":[$ans]}")
            try { $c.Response.ContentType = 'application/dns-json'; $c.Response.OutputStream.Write($b, 0, $b.Length); $c.Response.Close() } catch {}
            continue
        }
        $v = try { "$(Get-Content "$T\trace" -Raw)".Trim() } catch { '' }
        if ($v -match '^HANG (\d+)') { Start-Sleep $Matches[1]; $v = '' }          # молчит, потом отвечает без страны
        if ($v -match '^DELAY (\d+) (\w+)') { Start-Sleep $Matches[1]; $v = $Matches[2] }
        Add-Content "$T\geo.log" "$(Get-Date -Format 'HH:mm:ss.fff') $($c.Request.RemoteEndPoint) $($c.Request.Url.Host) $v"
        $b = [Text.Encoding]::ASCII.GetBytes("fl=1`nip=203.0.113.1`n$(if ($v) { "loc=$v`n" })")
        try { $c.Response.OutputStream.Write($b, 0, $b.Length); $c.Response.Close() } catch {}
    }
}
# обычный DNS (UDP) на адресе виртуалки — для проверки fake-IP: отвечает адресом из файла fakedns
$DnsPort = Get-Random -Minimum 40001 -Maximum 50000
Set-Content "$T\fakedns" '9.9.9.9' -Encoding ASCII -NoNewline
$script:DnsJob = Start-Job -ArgumentList $T, $EgIp, $DnsPort -ScriptBlock {
    param($T, $EgIp, $DnsPort)
    $u = New-Object Net.Sockets.UdpClient -ArgumentList (New-Object Net.IPEndPoint -ArgumentList ([Net.IPAddress]::Parse($EgIp)), $DnsPort)
    while ($true) {
        $from = New-Object Net.IPEndPoint -ArgumentList ([Net.IPAddress]::Any), 0
        $q = $u.Receive([ref]$from)
        $ip = try { "$(Get-Content "$T\fakedns" -Raw)".Trim() } catch { '9.9.9.9' }
        Add-Content "$T\dnsudp.log" "$(Get-Date -Format 'HH:mm:ss.fff') $from $ip"
        $r = [byte[]]($q + @(0xC0, 0x0C, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4) + [byte[]]@($ip -split '\.' | ForEach-Object { [byte]$_ }))
        $r[2] = 0x81; $r[3] = 0x80; $r[7] = 1
        [void]$u.Send($r, $r.Length, $from)
    }
}
Clear-DnsClientCache
$env:VPN_GUARD_ROOT = $T
$env:VPN_GUARD_DOH_URL = "http://${EgIp}:$Port/dns-query"
$env:VPN_GUARD_DNS_PORT = "$DnsPort"
$env:VPN_GUARD_GEO_URLS = "http://${EgIp}:$Port/trace"
$script:BaseConf = @{
    apps = @("$T\FakeApp"); checks = @('geo'); block_countries = @('RU'); require = 'all'; on_down = 'freeze'; lock_launch = $true
    # 1.2.3.4/33 и foo — кривые; 1.0.0.0/8 закрыл бы проверку страны (1.1.1.1, 1.0.0.1)
    block_nets = @('9.9.9.9/32', '1.2.3.4/33', 'foo', '1.0.0.0/8'); block_hosts = @('dns.quad9.net'); hosts_ttl = 300
    interval = 1; geo_ttl = 1; geo_ttl_down = 1; geo_stale = 8; grace = 0; net_watch = $true
}
Conf
$loopId = $null; $loopAlias = $null; $addedIp = $false; $route4 = $null; $route6 = $null; $route1 = $null; $clock = $null
$env:VPN_GUARD_TUNNEL_IFS = $egress
$profOrig = (Get-NetFirewallProfile -Profile Public -PolicyStore PersistentStore).Enabled
$disOrig = @((Get-NetFirewallProfile -Profile Public -PolicyStore PersistentStore).DisabledInterfaceAliases)

try {
    Write-Host "== 3. VPN есть (страна DE); основной интерфейс: $egress"
    Start-Daemon
    $w = WaitFor { (St).state -eq 'up' } 20
    Check "state=up за $w с" { $w }
    $s = St
    Check 'status.json: поля state, vpn, net, net_ok, net_error' { $n = $s.PSObject.Properties.Name; @('state', 'vpn', 'net', 'net_ok', 'net_error' | Where-Object { $n -notcontains $_ }).Count -eq 0 }
    Check "net=via:$egress, net_ok=true, vpn=true" { $s.net -eq "via:$egress" -and $s.net_ok -eq $true -and $s.vpn -eq $true }
    Check '9.9.9.9:443 доступен через основной интерфейс' { Reach '9.9.9.9' }
    Check 'приложение не заморожено, запуск разрешён' { -not (Frozen) -and (CanLaunch) }
    $log = (LogLines) -join "`n"
    Check 'журнал: кривые block_nets пропущены (1.2.3.4/33, foo, 1.0.0.0/8)' { $log -match '1\.2\.3\.4/33' -and $log -match '«foo»' -and $log -match '1\.0\.0\.0/8.*проверку страны' }
    Check "status.json: time — секунды Unix по UTC ($($s.time) против $([DateTimeOffset]::UtcNow.ToUnixTimeSeconds()))" { Fresh (St) }
    Check 'VGNative.Procs: fake.exe найден, не заморожен' {
        $p = @([VGNative]::Procs([string[]]@("$T\FakeApp\"))); $p.Count -eq 1 -and $p[0].ProcessId -eq $script:Fake.Id -and $p[0].Name -eq 'fake.exe' -and -not $p[0].Frozen }

    if (-not $NoLoopback) {
        Write-Host '== 4. новый адаптер (KM-TEST Loopback): правило «только через» встаёт само'
        Add-Type -TypeDefinition $LoopCs
        $before = @(Get-NetAdapter -IncludeHidden | ForEach-Object ifIndex)
        $r = [VGTestLoop]::Add("$env:windir\INF\netloop.inf")
        $w0 = WaitFor { Get-NetAdapter | Where-Object { $_.ifIndex -notin $before -and $_.InterfaceDescription -match 'KM-TEST' } } 20
        $la = Get-NetAdapter | Where-Object { $_.ifIndex -notin $before -and $_.InterfaceDescription -match 'KM-TEST' } | Select-Object -First 1
        if ($r -eq 'ok' -and $la) {
            $loopId = (Get-PnpDevice -FriendlyName $la.InterfaceDescription -ErrorAction SilentlyContinue | Select-Object -First 1).InstanceId
            $loopAlias = $la.Name
            Write-Host "      адаптер: $loopAlias ($loopId), появился за $w0 с"
            # новый адаптер — это и событие сети: сначала block, потом снова via, уже с ним
            $w = WaitFor { (St).state -eq 'up' -and (St).net -eq "via:$egress" -and (RuleIfs) -contains $loopAlias } 25
            Check "up, правило «только через» закрывает $loopAlias ($w с)" { $w }
            # у нового адаптера ещё несколько секунд меняются адреса (APIPA) — это новые события
            # сети, и демон каждый раз закрывает сеть до свежего ответа geo. Дать успокоиться.
            Start-Sleep 8
            $w = WaitFor { $i = RuleIfs; (St).state -eq 'up' -and (St).net -eq "via:$egress" -and $i -contains $loopAlias -and $i -notcontains $egress } 25
            Check "в правиле $loopAlias, но не $egress — через него можно ($w с)" { $w }
            $w = WaitFor { Reach '9.9.9.9' } 15
            Check "9.9.9.9 доступен через основной интерфейс ($w с)" { $w }

            Write-Host '== 4a. маршрут к Anthropic мимо туннеля: по IPv4 — VPN не засчитан, по IPv6 — засчитан, только если брандмауэр точно закроет'
            # маршруты через KM-TEST — в никуда: наружу к Anthropic ничего не уходит
            $li = [int]$la.ifIndex
            Conf @{ checks = @('route', 'geo'); block_nets = @('9.9.9.9/32', '2607:6bc0::/32') }
            $w = WaitFor { (St).state -eq 'up' -and (St).net -eq "via:$egress" } 15
            Check "checks=route,geo: up ($w с)" { $w }
            New-NetRoute -DestinationPrefix '2607:6bc0::/32' -InterfaceIndex $li -NextHop '::' -PolicyStore ActiveStore | Out-Null; $route6 = $li
            Check "маршрут к 2607:6bc0::10 — через $loopAlias" { [VGNative]::BestIf('2607:6bc0::10') -eq $li }
            Start-Sleep 4
            Check 'IPv6 мимо туннеля: по-прежнему up, net=via' { $s = St; $s.state -eq 'up' -and $s.net -eq "via:$egress" }
            Check 'журнал: про IPv6 мимо туннеля — ровно одна строка' { @((LogLines) -match '2607:6bc0::10 \(Anthropic, IPv6\) идёт мимо туннеля').Count -eq 1 }
            Check "правило «только через»: 2607:6bc0::/32 закрыт на $loopAlias" { (@(RuleAddrs) -match '^2607:6bc0::').Count -ge 1 -and (RuleIfs) -contains $loopAlias -and (RuleIfs) -notcontains $egress }
            Check 'второе правило: IPv6-адреса закрыты на всех интерфейсах (без списка интерфейсов)' {
                $r6 = @(Rules | Where-Object { $i = @($_ | Get-NetFirewallInterfaceFilter | ForEach-Object { $_.InterfaceAlias }); -not $i.Count -or $i -contains 'Any' })
                $a6 = @(if ($r6.Count -eq 1) { $r6[0] | Get-NetFirewallAddressFilter | ForEach-Object { $_.RemoteAddress } })
                @(Rules).Count -eq 2 -and $a6.Count -ge 1 -and -not @($a6 | Where-Object { $_ -notmatch ':' }).Count }
            # брандмауэр правила не применяет — закрыть IPv6 нечем: VPN не засчитан (раньше засчитывался)
            try {
                Set-NetFirewallProfile -Profile Public -Enabled False
                $w = WaitFor { (St).state -eq 'down' } 10
                Check "профиль брандмауэра выключен, IPv6 мимо туннеля — VPN не засчитан ($w с)" { $w }
            } finally { Set-NetFirewallProfile -Profile Public -Enabled $profOrig }
            $w = WaitFor { (St).state -eq 'up' } 15
            Check "профиль включили — снова up ($w с)" { $w }
            # KM-TEST исключён из защиты брандмауэра («Защищённые сетевые подключения»): то же самое
            try {
                Set-NetFirewallProfile -Profile Public -DisabledInterfaceAliases $loopAlias
                $w = WaitFor { $s = St; $s.state -eq 'down' -and $s.net_ok -eq $false -and $s.net_error -match 'не защищает интерфейсы' } 10
                Check "$loopAlias исключён из защиты: net_ok=false («$((St).net_error)»), VPN не засчитан ($w с)" { $w }
            } finally { Set-NetFirewallProfile -Profile Public -DisabledInterfaceAliases $disOrig }
            $w = WaitFor { $s = St; $s.state -eq 'up' -and $s.net_ok } 15
            Check "исключение сняли — снова up, net_ok ($w с)" { $w }
            Check 'журнал: «закрыть его брандмауэром нельзя»' { ((LogLines) -join "`n") -match '2607:6bc0::10 \(Anthropic, IPv6\) идёт мимо туннеля.*закрыть его брандмауэром нельзя' }
            Conf @{ checks = @('route', 'geo'); block_nets = @('9.9.9.9/32') }
            $w = WaitFor { (St).state -eq 'down' } 10
            Check "без 2607:6bc0::/32 в block_nets закрыть нечем — VPN не засчитан ($w с)" { $w }
            Remove-NetRoute -DestinationPrefix '2607:6bc0::/32' -InterfaceIndex $li -PolicyStore ActiveStore -Confirm:$false; $route6 = $null
            Conf @{ checks = @('route', 'geo'); block_nets = @('9.9.9.9/32', '2607:6bc0::/32') }
            $w = WaitFor { (St).state -eq 'up' } 15
            Check "маршрут убран — снова up ($w с)" { $w }
            New-NetRoute -DestinationPrefix '160.79.104.10/32' -InterfaceIndex $li -NextHop '0.0.0.0' -PolicyStore ActiveStore | Out-Null; $route4 = $li
            $fr = (Find-NetRoute -RemoteIPAddress 160.79.104.10 | Where-Object InterfaceIndex | Select-Object -First 1).InterfaceIndex
            Check "маршрут к 160.79.104.10 — через $loopAlias (BestIf = Find-NetRoute = $fr)" { [VGNative]::BestIf('160.79.104.10') -eq $li -and $fr -eq $li }
            $w = WaitFor { (St).state -eq 'down' } 6
            Check "IPv4 мимо туннеля: down за $w с" { $w }
            Check 'журнал: «160.79.104.10 (Anthropic) идёт мимо туннеля … VPN не засчитан»' { ((LogLines) -join "`n") -match '160\.79\.104\.10 \(Anthropic\) идёт мимо туннеля.*VPN не засчитан' }
            Remove-NetRoute -DestinationPrefix '160.79.104.10/32' -InterfaceIndex $li -PolicyStore ActiveStore -Confirm:$false; $route4 = $null
            # выход (1.1.1.1) не через туннель при checks=route,geo: route — «нет» первым, до geo
            # дело не доходит, но страна туннеля всё равно забывается (было: «интерфейс: Ethernet,
            # страна: FR» в статусе и щите — замер с sing-box)
            $w = WaitFor { $s = St; $s.state -eq 'up' -and $s.country -eq 'DE' } 15
            New-NetRoute -DestinationPrefix '1.1.1.1/32' -InterfaceIndex $li -NextHop '0.0.0.0' -PolicyStore ActiveStore | Out-Null; $route1 = $li
            $w2 = WaitFor { $s = St; $s.state -eq 'down' -and $s.iface -eq $loopAlias } 8
            $s = St
            Check "checks=route,geo, выход через $loopAlias (не туннель): down, страны туннеля в статусе нет (country='$($s.country)'; $w / $w2 с)" { $w -and $w2 -and $s.country -eq '' }
            Remove-NetRoute -DestinationPrefix '1.1.1.1/32' -InterfaceIndex $li -PolicyStore ActiveStore -Confirm:$false; $route1 = $null
            Conf
            $w = WaitFor { (St).state -eq 'up' -and -not (Frozen) } 15
            Check "маршрут убран, checks=geo — снова up, приложение разморожено ($w с)" { $w }

            Write-Host '== 4b. адрес проверки страны не через туннель или имя вместо адреса — туда не спрашиваем'
            # 127.0.0.1 — маршрут через Loopback Pseudo-Interface, не через туннель; «Cloudflare»
            # слушает и там, так что спроси демон туда — запрос попал бы в geo.log (так и было
            # в прежних тестах: «Cloudflare» был на 127.0.0.1)
            $w = WaitFor { Reach '127.0.0.1' $Port } 5
            Check "«Cloudflare» отвечает и на 127.0.0.1 ($w с), маршрут к нему — #$([VGNative]::BestIf('127.0.0.1')), не туннель #$egIdx" { $w -and [VGNative]::BestIf('127.0.0.1') -ne $egIdx }
            Stop-Daemon; $n0 = GeoCount
            $env:VPN_GUARD_GEO_URLS = "http://127.0.0.1:$Port/trace,http://localhost:$Port/trace,http://${EgIp}:$Port/trace"
            Start-Daemon
            $w = WaitFor { (St).state -eq 'up' } 20
            Check "первые два адреса пропущены, up по третьему ($w с)" { $w }
            $hosts = @(Get-Content "$T\geo.log" | Select-Object -Skip $n0 | ForEach-Object { ($_ -split ' ')[2] } | Select-Object -Unique)
            Check "к «Cloudflare» — только через туннель (адреса запросов: $($hosts -join ', '))" { $hosts.Count -eq 1 -and $hosts[0] -eq $EgIp }
            $log = (LogLines) -join "`n"
            Check 'журнал: 127.0.0.1 — не через туннель, localhost — не IPv4-литерал' { $log -match 'маршрут к 127\.0\.0\.1 \(проверка страны\) идёт не через туннель' -and $log -match 'localhost.*не IPv4-литерал' }
            Stop-Daemon; $n0 = GeoCount
            $env:VPN_GUARD_GEO_URLS = "http://127.0.0.1:$Port/trace,http://localhost:$Port/trace"
            Start-Daemon
            $w = WaitFor { (St).state -eq 'down' } 20
            Check "годных адресов нет — «нет ответа», down после geo_stale ($w с), запросов 0 ($((GeoCount) - $n0))" { $w -and (GeoCount) -eq $n0 }
            Stop-Daemon
            $env:VPN_GUARD_GEO_URLS = "http://${EgIp}:$Port/trace"
            Start-Daemon
            $w = WaitFor { (St).state -eq 'up' -and -not (Frozen) } 20
            Check "адрес вернули — up, приложение разморожено ($w с)" { $w }

            Write-Host '== 4c. имя интерфейса со знаками шаблона («Vafa Test* [1]», как «Local Area Connection* 1»)'
            Rename-NetAdapter -Name $loopAlias -NewName 'Vafa Test* [1]'
            $loopAlias = 'Vafa Test* [1]'
            $w = WaitFor { $i = RuleIfs; (St).state -eq 'up' -and (St).net -eq "via:$egress" -and $i -contains $loopAlias -and $i -notcontains $egress } 25
            Check "правило «только через» закрывает «$loopAlias» ($w с; в правиле: $((RuleIfs) -join ', '))" { $w }
            Check 'журнал: правило «только через» не падало' { -not (((LogLines) -join "`n") -match 'не смог поставить правило') }
        } else { Bad "не удалось добавить KM-TEST Loopback: $r" }
    }
    Check 'адреса правила: 9.9.9.9 есть, 1.2.3.4 нет' { $a = RuleAddrs; if (-not $a) { $true } else { ($a -match '^9\.9\.9\.9') -and -not ($a -match '1\.2\.3\.4') } }

    # в установившемся up демон не должен жечь процессор: было 8–15 % ядра и 13–15 % в WmiPrvSE,
    # стало ~4 % и ~3 % (замер 2026-10-09). Сразу после запуска и смены конфига — всплеск
    # (догружается .NET), поэтому сначала 30 с покоя, потом 20 с замера. WmiPrvSE — сумма по
    # всем его процессам: это его нагрузку в основном и создают запросы WMI демона.
    [void](WaitFor { (St).state -eq 'up' } 15)
    Start-Sleep 30
    $sw = [Diagnostics.Stopwatch]::StartNew(); $c0 = CpuMs $script:D.Id; $w0 = WmiMs
    Start-Sleep 20
    $c1 = CpuMs $script:D.Id; $w1 = WmiMs; $el = $sw.Elapsed.TotalSeconds
    $cpu = ($c1 - $c0) / 10 / $el; $wmi = (WmiDelta $w0 $w1) / 10 / $el
    Check ("CPU демона в up: {0:N1} % ядра за {1:N0} с (нужно < 6 %)" -f $cpu, $el) { $cpu -lt 6 -and (St).state -eq 'up' }
    Check ("CPU WmiPrvSE (все процессы) за то же время: {0:N1} % ядра (нужно < 6 %)" -f $wmi) { $wmi -lt 6 }

    Write-Host '== 5. страна RU → down'
    Geo 'RU'
    $w = WaitFor { (St).state -eq 'down' } 10
    Check "state=down за $w с" { $w }
    Check 'net=block, net_ok=true, vpn=false' { $s = St; $s.net -eq 'block' -and $s.net_ok -eq $true -and $s.vpn -eq $false }
    Check 'правило без привязки к интерфейсам' { $i = RuleIfs; @(Rules).Count -eq 1 -and (-not $i -or $i -contains 'Any') }
    Check '9.9.9.9:443 закрыт' { -not (Reach '9.9.9.9') }
    $w = WaitFor { (RuleAddrs) -match '^149\.112\.112\.112' } 15
    Check "block_hosts: адрес dns.quad9.net (149.112.112.112) в правиле за $w с" { $w }
    Check '149.112.112.112:443 закрыт' { -not (Reach '149.112.112.112') }
    $w = WaitFor { Frozen } 10
    Check "приложение заморожено за $w с" { $w }
    Check 'VGNative.Procs: Frozen=true' { @([VGNative]::Procs([string[]]@("$T\FakeApp\")))[0].Frozen }
    Check 'icacls не смог (deny.exe): заморозка всё равно сделана, в журнале — предупреждение, а не «ошибка в цикле»' {
        $l = (LogLines) -join "`n"; (Frozen) -and $l -match 'не смог запретить запуск .*deny\.exe' -and $l -notmatch 'ошибка в цикле' }
    $w = WaitFor { -not (CanLaunch) } 10
    Check "запуск запрещён ($w с)" { $w -ne $null }
    $L = LogLines
    $iv = -1; for ($i = $L.Count - 1; $i -ge 0; $i--) { if ($L[$i] -match 'VPN не обнаружен') { $iv = $i; break } }
    $ifz = -1; for ($i = [Math]::Max(0, $iv); $i -lt $L.Count; $i++) { if ($L[$i] -match 'заморожен процесс') { $ifz = $i; break } }
    $ic = -1; for ($i = $ifz; $i -ge 0; $i--) { if ($L[$i] -match 'сеть к Anthropic: ЗАКРЫТА') { $ic = $i; break }; if ($L[$i] -match 'только через') { break } }
    Check "порядок в журнале: сеть закрыта (стр. $ic) раньше заморозки (стр. $ifz)" { $ic -ge 0 -and $ifz -gt $ic }

    Check 'block_hosts: резолв через DoH по туннелю (doh.log: A и AAAA, accept: application/dns-json), системный DNS не спрошен' {
        $d = @(Get-Content "$T\doh.log" -ErrorAction SilentlyContinue)
        ($d -match 'dns\.quad9\.net A application/dns-json').Count -and ($d -match 'dns\.quad9\.net AAAA').Count -and -not (Get-DnsClientCache -Entry 'dns.quad9.net' -ErrorAction SilentlyContinue) }

    Write-Host '== 5a. VPN-клиент с fake-IP (DNS через туннель отвечает 198.18.x.x): в down закрыта и 198.18.0.0/15, в up — нет'
    Set-Content "$T\fakedns" '198.18.0.7' -Encoding ASCII -NoNewline
    Conf                                       # перечитать конфиг — резолв заново
    $w = WaitFor { (RuleAddrs) -contains '198.18.0.0/255.254.0.0' } 15
    Check "fake-IP замечен: 198.18.0.0/15 в правиле за $w с (запросов к DNS: $(@(Get-Content "$T\dnsudp.log" -ErrorAction SilentlyContinue).Count))" { $w }
    Check 'журнал: «подменяет адреса DNS (fake-IP»' { ((LogLines) -join "`n") -match 'подменяет адреса DNS \(fake-IP' }
    Geo 'DE'
    $w = WaitFor { (St).state -eq 'up' -and -not ((RuleAddrs) -contains '198.18.0.0/255.254.0.0') -and (RuleAddrs) -match '^9\.9\.9\.9' } 15
    Check "up: в правиле «только через» 198.18.0.0/15 нет ($w с)" { $w }
    Set-Content "$T\fakedns" '9.9.9.9' -Encoding ASCII -NoNewline
    Conf
    $w = WaitFor { ((LogLines) -join "`n") -match 'больше не подменяет' } 15
    Geo 'RU'
    $w2 = WaitFor { (St).state -eq 'down' -and (RuleAddrs) -match '^9\.9\.9\.9' -and -not ((RuleAddrs) -contains '198.18.0.0/255.254.0.0') } 15
    Check "fake-IP пропал: в down 198.18.0.0/15 уже не закрыт ($w / $w2 с)" { $w -and $w2 }
    [void](WaitFor { Frozen } 10)

    Write-Host '== 6. самопочинка правила'
    Remove-NetFirewallRule -DisplayName 'VPNGuard-Block' -ErrorAction SilentlyContinue
    $w = WaitFor { FwLive } 6
    Check "удалённое правило вернулось за $w с (нужно ≤ 2,5)" { $w -ne $null -and $w -le 2.5 }
    Disable-NetFirewallRule -DisplayName 'VPNGuard-Block' -ErrorAction SilentlyContinue
    $w = WaitFor { @(Rules | Where-Object { "$($_.Enabled)" -eq 'True' }).Count -ge 1 } 8
    Check "выключенное правило заменено за $w с" { $w -ne $null -and $w -le 2.5 }
    Check '9.9.9.9 снова закрыт' { -not (Reach '9.9.9.9') }
    Check 'журнал: «восстанавливаю»' { ((LogLines) -join "`n") -match 'пропало или выключено' }
    Check 'старое (выключенное) правило снято — правило одно' { (WaitFor { @(Rules).Count -eq 1 } 5) -ne $null }

    Write-Host '== 7. сломанный и пропавший конфиг'
    Set-Content "$T\config.json" '{ broken' -Encoding UTF8
    Start-Sleep 3
    Check 'битый JSON: статус свежий, state=down, правило на месте, приложение заморожено' {
        $s = St; (Fresh $s) -and $s.state -eq 'down' -and @(Rules).Count -ge 1 -and (Frozen) }
    Check 'журнал: «конфиг не читается»' { ((LogLines) -join "`n") -match 'конфиг не читается' }
    Remove-Item "$T\config.json"
    Start-Sleep 3
    Check 'нет конфига: статус свежий, правило на месте, приложение заморожено' {
        $s = St; (Fresh $s) -and @(Rules).Count -ge 1 -and (Frozen) -and -not (Reach '9.9.9.9') }
    Conf
    Start-Sleep 2

    Write-Host '== 7a. конфиг не читается при старте: сеть закрыта сразу, настройки по умолчанию, попытка каждый круг'
    Stop-Daemon
    # выход — не туннель: с настройками по умолчанию демон иначе резолвил бы имена Anthropic
    # из block_hosts по умолчанию, а тесту к Anthropic обращаться нельзя даже через DNS
    Remove-Item Env:VPN_GUARD_TUNNEL_IFS -ErrorAction SilentlyContinue
    & icacls.exe "$T\config.json" /grant '*S-1-5-11:(M)' | Out-Null      # «Прошедшие проверку» могут писать — не читать
    $mt0 = (Get-Item "$T\config.json").LastWriteTimeUtc
    Start-Daemon
    $w = WaitFor { $s = St; $s -and $s.state -eq 'down' -and @($s.apps).Count -eq 0 } 15
    Check "небезопасный конфиг: настройки по умолчанию — приложений нет, state=down ($w с)" { $w }
    Check 'сеть закрыта сразу — сетями Anthropic по умолчанию (160.79.104.0/21)' { (RuleAddrs) -contains '160.79.104.0/255.255.248.0' }
    Check 'журнал: «могут писать не только администраторы»' { ((LogLines) -join "`n") -match 'могут писать не только администраторы' }
    & icacls.exe "$T\config.json" /remove:g '*S-1-5-11' | Out-Null
    Check 'права починили, время записи конфига прежнее' { (Get-Item "$T\config.json").LastWriteTimeUtc -eq $mt0 }
    $w = WaitFor { $s = St; @($s.apps).Count -eq 1 -and ((RuleAddrs) -match '^9\.9\.9\.9') -and -not ((RuleAddrs) -match '^160\.79\.') } 10
    Check "конфиг прочитан без перезапуска: приложение под охраной, в правиле block_nets из конфига ($w с)" { $w }
    Stop-Daemon
    Conf @{ hosts_ttl = '5m'; grace = 'x'; interval = 'fast'; lock_launch = 'maybe' }
    Start-Daemon
    Start-Sleep 3
    Check 'кривые числа в конфиге: демон жив, статус свежий, state=down' { (Get-Process -Id $script:D.Id -ErrorAction SilentlyContinue) -and (Fresh (St)) -and (St).state -eq 'down' }
    Check 'журнал: «hosts_ttl = «5m» — не число»' { ((LogLines) -join "`n") -match 'hosts_ttl = «5m» — не число' }
    Stop-Daemon
    $env:VPN_GUARD_TUNNEL_IFS = $egress
    Conf
    Start-Daemon
    Start-Sleep 2

    Write-Host '== 8. брандмауэр выключен → net_ok=false'
    try {
        Set-NetFirewallProfile -Profile Public -Enabled False
        $w = WaitFor { (St).net_ok -eq $false } 6
        Check "net_ok=false за $w с: «$((St).net_error)»" { $w -ne $null -and (St).net_error -match 'брандмауэр выключен' }
    } finally { Set-NetFirewallProfile -Profile Public -Enabled $profOrig }
    $w = WaitFor { (St).net_ok -eq $true } 6
    Check "профиль вернули ($profOrig) — net_ok=true за $w с" { $w -ne $null }

    Write-Host '== 9. Cloudflare молчит: unsure (сеть закрыта, приложения не трогаем), потом down'
    Geo 'DE'
    $w = WaitFor { (St).state -eq 'up' -and -not (Frozen) } 15
    Check "up и разморожено за $w с" { $w }
    Check 'запуск снова разрешён' { CanLaunch }
    Geo ''
    $w = WaitFor { (St).state -eq 'unsure' } 15
    Check "state=unsure за $w с (свежесть ответа ~7 с)" { $w }
    Check 'unsure: net=block, vpn=false, приложение не заморожено' { $s = St; $s.net -eq 'block' -and $s.vpn -eq $false -and -not (Frozen) }
    Check 'unsure: 9.9.9.9 закрыт' { -not (Reach '9.9.9.9') }
    $w = WaitFor { (St).state -eq 'down' } 15
    Check "state=down после geo_stale=8 с (ещё $w с)" { $w }
    Check 'приложение заморожено' { (WaitFor { Frozen } 5) -ne $null }

    Write-Host '== 10. Cloudflare висит — круг не ждёт ответа'
    Geo 'DE'
    [void](WaitFor { (St).state -eq 'up' } 15)
    Geo 'HANG 8'
    Start-Sleep 1
    # без перемен демон пишет status.json раз в 2 с — за 5 с метка обязана сдвинуться на 2+
    $t1 = (St).time; Start-Sleep 5; $t2 = (St).time
    Check "status.json обновляется, пока geo висит ($t1 → $t2)" { $t2 - $t1 -ge 2 }
    Geo 'DE'
    $w = WaitFor { (St).state -eq 'up' } 30
    Check "снова up за $w с" { $w }

    Write-Host '== 10a. status.json держит читатель — запись не удалась, но сеть из-за этого не закрывается'
    # «Cloudflare» теста однопоточный: после HANG 8 из раздела 10 он ещё отвечает с задержкой, и
    # демон мог уйти в unsure/down посреди проверки (так было в прогоне на русской Windows)
    Start-Sleep 8
    [void](WaitFor { (St).state -eq 'up' } 15)
    $n0 = @((LogLines) -match 'сеть к Anthropic: ЗАКРЫТА').Count; $net0 = (St).net
    # без FILE_SHARE_DELETE (как Get-Content) — Replace у демона не проходит
    $fs = [IO.File]::Open("$T\status.json", [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite)
    try { Start-Sleep 5; $ifsHeld = @(RuleIfs) } finally { $fs.Dispose() }
    Check 'журнал: «не смог записать …status.json»' { ((LogLines) -join "`n") -match 'не смог записать .*status\.json' }
    Check "пока файл был занят, сеть не закрывалась (было $net0, новых «ЗАКРЫТА» нет)" {
        $net0 -like 'via:*' -and @((LogLines) -match 'сеть к Anthropic: ЗАКРЫТА').Count -eq $n0 -and ($NoLoopback -or ($ifsHeld.Count -and $ifsHeld -notcontains 'Any')) }
    Check 'status.json снова свежий' { (WaitFor { Fresh (St) } 5) -ne $null }

    Write-Host '== 11. событие сети: сначала закрыть, открыть после свежего ответа'
    Geo 'DELAY 3 DE'
    [void](WaitFor { (St).state -eq 'up' } 15)
    Start-Sleep 2
    New-NetIPAddress -InterfaceAlias $egress -IPAddress 10.254.254.254 -PrefixLength 32 -SkipAsSource $true | Out-Null
    $addedIp = $true
    # событие приходит, когда адрес прошёл проверку на дубликат (в VM ~4 с, замер 2026-10-09);
    # ответ geo идёт 3 с, так что «закрыто» надо успеть увидеть до свежего ответа
    $w = WaitFor { (St).net -eq 'block' } 8
    Check "после события сети net=block за $w с" { $w -ne $null }
    Check 'state=unsure, приложение не заморожено' { (St).state -eq 'unsure' -and -not (Frozen) }
    $w = WaitFor { (St).state -eq 'up' } 20
    Check "снова up после свежего ответа (geo отвечает за 3 с) за $w с" { $w }
    Remove-NetIPAddress -IPAddress 10.254.254.254 -Confirm:$false; $addedIp = $false
    Geo 'DE'
    $ports = @(Get-Content "$T\geo.log" | Select-Object -Last 10 | ForEach-Object { ($_ -split ' ')[1] })
    Check "geo: каждый запрос — новое соединение ($(@($ports | Select-Object -Unique).Count) разных портов из $($ports.Count))" { @($ports | Select-Object -Unique).Count -eq $ports.Count }

    Write-Host '== 11a. часы перевели на 10 минут назад: проверка страны не встаёт'
    [void](WaitFor { (St).state -eq 'up' } 15)
    $clock = @{ Utc = [DateTime]::UtcNow; Sw = [Diagnostics.Stopwatch]::StartNew() }
    try {
        Set-Date -Adjust ([TimeSpan]::FromMinutes(-10)) | Out-Null
        Start-Sleep 2
        Geo 'RU'
        $w = WaitFor { (St).state -eq 'down' } 10
        Check "часы назад, страна RU — down за $w с (на местном времени демон не спрашивал бы страну 10 минут)" { $w }
    } finally { Set-Date -Date ($clock.Utc + $clock.Sw.Elapsed).ToLocalTime() | Out-Null; $clock = $null }
    Geo 'DE'
    $w = WaitFor { (St).state -eq 'up' } 15
    Check "снова up ($w с)" { $w }

    Write-Host '== 11b. перерыв между кругами дольше geo_stale (как сон VM): «не уверен», а не сразу down'
    [void](WaitFor { (St).state -eq 'up' } 15)
    [void][VGNative]::Suspend($script:D.Id); Start-Sleep 12; [void][VGNative]::Resume($script:D.Id)
    $seen = @(); $sw = [Diagnostics.Stopwatch]::StartNew()
    while ($sw.Elapsed.TotalSeconds -lt 6) { $s = St; if ($s) { $seen += $s.state }; Start-Sleep -Milliseconds 100 }
    Check "после паузы 12 с (geo_stale=8): $(@($seen | Select-Object -Unique) -join ' → '), down не было, снова up" { $seen -notcontains 'down' -and $seen[-1] -eq 'up' -and $seen -contains 'unsure' }
    Check 'журнал: «перерыв … между кругами»' { ((LogLines) -join "`n") -match 'перерыв \d+ с между кругами' }
    Check 'приложение не заморожено' { -not (Frozen) }

    Write-Host '== 12. пустые block_nets и block_hosts'
    Geo 'RU'
    [void](WaitFor { (St).state -eq 'down' } 10)
    Conf @{ block_nets = @(); block_hosts = @() }
    $w = WaitFor { (St).net_error -match 'BLOCK_NETS пуст' } 10
    Check "net_ok=false, «$((St).net_error)» за $w с" { $w -ne $null -and (St).net_ok -eq $false }
    Check 'правил нет' { (WaitFor { -not (Rules) } 5) -ne $null }
    Conf
    $w = WaitFor { @(Rules).Count -ge 1 -and (St).net_ok } 10
    Check "список вернули — правило снова есть ($w с)" { $w }
    # пустой block_hosts вычистил кэш адресов — дождаться, пока dns.quad9.net снова в hosts.json
    $w = WaitFor { (ReadShared "$T\hosts.json") -match '149\.112\.112\.112' } 20
    Check "адрес dns.quad9.net снова в кэше hosts.json ($w с)" { $w }

    Write-Host '== 12a. выход не через туннель: страну не спрашиваем вовсе (запрос ушёл бы с настоящего адреса)'
    Stop-Daemon
    Geo 'DE'                                   # спроси демон страну — VPN засчитался бы
    Remove-Item Env:VPN_GUARD_TUNNEL_IFS -ErrorAction SilentlyContinue
    $n0 = GeoCount
    Clear-DnsClientCache
    Start-Daemon
    $w = WaitFor { $s = St; $s.state -eq 'down' -and $s.net -eq 'block' -and $s.country -eq '' -and (LogLines) -match 'не туннель' } 15
    Check "state=down, net=block, страны нет ($w с)" { $w }
    Start-Sleep 4                              # и дальше — ни одного запроса
    Check "к «Cloudflare» ни одного запроса ($($(GeoCount) - $n0) новых)" { (GeoCount) -eq $n0 }
    Check 'журнал: «не туннель: страну не спрашиваю»' { ((LogLines) -join "`n") -match 'не туннель: страну не спрашиваю' }
    Check 'DNS тоже не трогаем: dns.quad9.net не резолвился (в кэше DNS нет), в журнале «не резолвлю»' {
        -not (Get-DnsClientCache -Entry 'dns.quad9.net' -ErrorAction SilentlyContinue) -and ((LogLines) -join "`n") -match 'имена block_hosts не резолвлю' }
    Check 'в правиле — адрес dns.quad9.net из кэша (149.112.112.112)' { (RuleAddrs) -match '^149\.112\.112\.112' }
    $out = (& powershell.exe -NoProfile -ExecutionPolicy Bypass -File $Guard check 2>&1) -join "`n"
    Check 'vpn-guard.ps1 check: geo — «нет», без запроса' { $out -match '\[ нет\] geo' -and $out -match 'не спрашиваю — выход не через туннель' -and $out -match 'VPN: ВЫКЛЮЧЕН' -and (GeoCount) -eq $n0 }

    Write-Host '== 12b. VPN засчитан не туннелем (checks=proc:) — «только через» Ethernet не ставится, сеть закрыта везде'
    Stop-Daemon
    Conf @{ checks = @('proc:fake') }
    Start-Daemon
    $w = WaitFor { $s = St; $s.state -eq 'up' -and $s.net -eq 'block' } 15
    Check "state=up, net=block ($w с)" { $w }
    Check 'правило без привязки к интерфейсам, 9.9.9.9 закрыт' { $i = RuleIfs; @(Rules).Count -ge 1 -and (-not $i -or $i -contains 'Any') -and -not (Reach '9.9.9.9') }
    Check 'журнал: «не туннель: сеть к Anthropic закрыта везде»' { ((LogLines) -join "`n") -match 'не туннель: сеть к Anthropic закрыта везде' }
    Conf
    $env:VPN_GUARD_TUNNEL_IFS = $egress
    Geo 'RU'

    Write-Host '== 13. демон убит — правило остаётся'
    Stop-Daemon
    Start-Sleep 1
    Check 'правило на месте, 9.9.9.9 закрыт' { @(Rules).Count -ge 1 -and -not (Reach '9.9.9.9') }

    Write-Host '== 14. сторож перезапускает демона'
    $sup = Start-Process powershell.exe -PassThru -WindowStyle Hidden -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$Guard`" supervise"
    $w = WaitFor { @(Guards 'daemon').Count -eq 1 } 30
    Check "сторож запустил демона ($w с)" { $w }
    $d1 = @(Guards 'daemon')[0].ProcessId
    Stop-Process -Id $d1 -Force
    $w = WaitFor { $g = @(Guards 'daemon'); $g.Count -eq 1 -and $g[0].ProcessId -ne $d1 } 20
    Check "убитый демон перезапущен за $w с" { $w -ne $null -and $w -le 10 }
    $d1 = @(Guards 'daemon')[0].ProcessId
    Check 'приоритет демона — обычный (от сторожа досталось бы «ниже среднего»)' { "$((Get-Process -Id $d1).PriorityClass)" -eq 'Normal' }
    # завис (WMI не отвечает) — для сторожа выглядит так же, как приостановленный процесс:
    # status.json не обновляется
    [void][VGNative]::Suspend($d1)
    $w = WaitFor { $g = @(Guards 'daemon'); $g.Count -eq 1 -and $g[0].ProcessId -ne $d1 } 55
    Check "зависший демон убит сторожем и заменён за $w с (порог 30 с)" { $w -ne $null -and $w -ge 25 -and -not (Get-Process -Id $d1 -ErrorAction SilentlyContinue) }
    Check 'журнал: «зависла, перезапускаю»' { ((LogLines) -join "`n") -match 'зависла, перезапускаю' }
    Stop-Process -Id $sup.Id -Force
    Start-Sleep 1
    Check 'сторож убит — демон продолжает работать' { @(Guards 'daemon').Count -eq 1 }
    $d2 = @(Guards 'daemon')[0].ProcessId
    $sup2 = Start-Process powershell.exe -PassThru -WindowStyle Hidden -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$Guard`" supervise"
    Start-Sleep 6
    Check 'новый сторож не плодит второго демона' { $g = @(Guards 'daemon'); $g.Count -eq 1 -and $g[0].ProcessId -eq $d2 }
    # осиротевший демон завис — новый сторож его тоже видит: убивает и запускает свой
    [void][VGNative]::Suspend($d2)
    $w = WaitFor { $g = @(Guards 'daemon'); $g.Count -eq 1 -and $g[0].ProcessId -ne $d2 } 55
    Check "новый сторож: зависший осиротевший демон убит и заменён за $w с" { $w -ne $null -and -not (Get-Process -Id $d2 -ErrorAction SilentlyContinue) }

    Write-Host '== 15. unlock'
    $out = & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $Guard unlock 2>&1
    Check 'служба и сторож остановлены' { (WaitFor { -not (Guards) } 5) -ne $null }
    Check 'правил нет' { -not (Rules) }
    Check 'приложение разморожено, запуск разрешён' { -not (Frozen) -and (CanLaunch) }
    Check '9.9.9.9 доступен' { Reach '9.9.9.9' }
} finally {
    Get-CimInstance Win32_Process -Filter "Name='powershell.exe'" | Where-Object { $_.CommandLine -match 'vpn-guard\.ps1.*\s(daemon|supervise)\b' } |
        ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }
    Get-NetFirewallRule -DisplayName 'VPNGuard-Block' -ErrorAction SilentlyContinue | Remove-NetFirewallRule
    if ($addedIp) { Remove-NetIPAddress -IPAddress 10.254.254.254 -Confirm:$false -ErrorAction SilentlyContinue }
    if ($route6) { Remove-NetRoute -DestinationPrefix '2607:6bc0::/32' -InterfaceIndex $route6 -PolicyStore ActiveStore -Confirm:$false -ErrorAction SilentlyContinue }
    if ($route4) { Remove-NetRoute -DestinationPrefix '160.79.104.10/32' -InterfaceIndex $route4 -PolicyStore ActiveStore -Confirm:$false -ErrorAction SilentlyContinue }
    if ($loopId) { & pnputil.exe /remove-device $loopId | Out-Null; Write-Host "      KM-TEST Loopback удалён ($loopId)" }
    Set-NetFirewallProfile -Profile Public -Enabled $profOrig -DisabledInterfaceAliases $disOrig
    if ($clock) { Set-Date -Date ($clock.Utc + $clock.Sw.Elapsed).ToLocalTime() | Out-Null }
    Get-Process -Id $script:Fake.Id -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
    Stop-Job $script:GeoJob, $script:DnsJob -ErrorAction SilentlyContinue; Remove-Job $script:GeoJob, $script:DnsJob -Force -ErrorAction SilentlyContinue
    if ($route1) { Remove-NetRoute -DestinationPrefix '1.1.1.1/32' -InterfaceIndex $route1 -PolicyStore ActiveStore -Confirm:$false -ErrorAction SilentlyContinue }
    Remove-Item Env:VPN_GUARD_ROOT, Env:VPN_GUARD_GEO_URLS, Env:VPN_GUARD_TUNNEL_IFS, Env:VPN_GUARD_DOH_URL, Env:VPN_GUARD_DNS_PORT -ErrorAction SilentlyContinue
    if ($script:Fail -eq 0) { Remove-Item $T -Recurse -Force -ErrorAction SilentlyContinue } else { Write-Host "      файлы теста оставлены: $T" }
}

if ($Install) {
    $PD = Join-Path $env:ProgramData 'VPNGuard'
    $PF = Join-Path $env:ProgramFiles 'VPNGuard'
    $hadPD = Test-Path $PD
    if ($hadPD) { Write-Host "Уже есть $PD — установку не проверяю, чтобы не трогать настоящие настройки"; $Install = $false }
}
if ($Install) {
    # установщик — отдельным powershell.exe, как из install.cmd: со своей (не убранной)
    # надстройкой массивов для JSON; его stderr не должен ронять тест
    function RunPs([string]$file, [string]$log, [string[]]$extra = @()) {
        $ErrorActionPreference = 'Continue'
        & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $file @extra *> $log
        return $LASTEXITCODE
    }
    function Trays { @(Get-CimInstance Win32_Process -Filter "Name='powershell.exe'" | Where-Object { $_.CommandLine -match 'VPNGuard-Tray\.ps1' } | ForEach-Object { $_.ProcessId }) }
    $hasUser = [bool](Get-CimInstance Win32_ComputerSystem).UserName
    try {
        Write-Host '== 16. установка поверх старого конфига (block_nets пуст, block_hosts и block_countries нет)'
        New-Item -ItemType Directory -Force $PD | Out-Null
        [pscustomobject]@{ apps = @(); checks = @('route', 'geo:!RU'); require = 'all'; on_down = 'freeze'
            lock_launch = $true; block_nets = @(); interval = 1; geo_ttl = 1; geo_ttl_down = 1; net_watch = $true; geo_stale = 60; grace = 0 } |
            ConvertTo-Json -Depth 4 | Set-Content "$PD\config.json" -Encoding UTF8
        $rc = RunPs (Join-Path $Win 'install.ps1') "$T-install1.log"
        Check "install.ps1 отработал (код $rc)" { $rc -eq 0 }
        $raw = Get-Content "$PD\config.json" -Raw -Encoding UTF8; $j = $raw | ConvertFrom-Json
        Check "block_nets = сети Anthropic по умолчанию ($(@($j.block_nets).Count) шт.)" { @($j.block_nets).Count -eq 7 -and @($j.block_nets) -contains '160.79.104.0/21' -and @($j.block_nets) -contains '2607:6bc0::/32' }
        Check "block_hosts добавлены ($(@($j.block_hosts).Count) шт.), это строки" { @($j.block_hosts).Count -eq 10 -and $j.block_hosts[0] -is [string] }
        Check "block_countries добавлены ($(@($j.block_countries) -join ' ')), это строки" { @($j.block_countries).Count -eq 4 -and $j.block_countries[0] -is [string] -and @($j.block_countries) -contains 'CN' }
        Check 'в config.json нет {value, Count}' { $raw -notmatch '"(value|Count)"\s*:' }
        $task = Get-ScheduledTask -TaskName VPNGuard
        Check 'задача: действие supervise' { $task.Actions[0].Arguments -match 'vpn-guard\.ps1" supervise' }
        Check 'задача: при загрузке и раз в минуту' { @($task.Triggers).Count -eq 2 -and @($task.Triggers | Where-Object { $_.Repetition.Interval -eq 'PT1M' }).Count -eq 1 }
        Check "задача: обычный приоритет (Priority=$($task.Settings.Priority))" { $task.Settings.Priority -eq 4 }
        $w = WaitFor { $s = ReadShared "$PD\status.json" | ConvertFrom-Json; $s.state -and (Fresh $s) } 60
        Check "служба пишет status.json ($w с)" { $w }
        $s = ReadShared "$PD\status.json" | ConvertFrom-Json
        Check "без VPN: state=$($s.state), net=$($s.net), net_ok=$($s.net_ok)" { $s.state -eq 'down' -and $s.net -eq 'block' -and $s.net_ok -eq $true }
        Check 'в правиле сети Anthropic (v4 и v6) и встроенные адреса block_hosts' { $a = RuleAddrs; ($a -contains '160.79.104.0/255.255.248.0') -and ($a -match '^2607:6bc0::') -and ($a -contains '34.149.66.165') }
        $st = (& powershell.exe -NoProfile -ExecutionPolicy Bypass -File "$PF\vpn-guard.ps1" status 2>&1) -join "`n"
        Check 'status показывает правило и состояние брандмауэра' { $st -match 'VPNGuard-[0-9a-f]{8}: включено=True' -and $st -match 'брандмауэр включён' -and $st -match 'состояние down' }
        $d1 = @(Guards 'daemon')[0].ProcessId
        Check 'демон службы — с обычным приоритетом' { "$((Get-Process -Id $d1).PriorityClass)" -eq 'Normal' }
        Stop-Process -Id $d1 -Force
        $w = WaitFor { $g = @(Guards 'daemon'); $g.Count -eq 1 -and $g[0].ProcessId -ne $d1 } 20
        Check "убитый демон службы перезапущен за $w с" { $w -ne $null -and $w -le 10 }
        $tray1 = @()
        if ($hasUser) {
            # трей запускается в сеансе пользователя; живой через 10 с — значит, не упал на старте
            Start-Sleep 8
            $tray1 = @(Trays)
            Check "трей запущен и жив ($($tray1 -join ', '))" { $tray1.Count -ge 1 }
        }

        Write-Host '== 17. обновление: свой список block_nets не трогается, старый трей заменён новым'
        $j.block_nets = @('9.9.9.9/32'); $j | ConvertTo-Json -Depth 4 | Set-Content "$PD\config.json" -Encoding UTF8
        $rc = RunPs (Join-Path $Win 'install.ps1') "$T-install2.log"
        $j = Get-Content "$PD\config.json" -Raw -Encoding UTF8 | ConvertFrom-Json
        Check "block_nets = 9.9.9.9/32 (install.ps1: код $rc)" { $rc -eq 0 -and @($j.block_nets).Count -eq 1 -and $j.block_nets[0] -eq '9.9.9.9/32' }
        Check 'служба снова работает (одна копия демона и сторожа)' { (WaitFor { @(Guards 'daemon').Count -eq 1 -and @(Guards 'supervise').Count -eq 1 } 30) -ne $null }
        if ($hasUser) {
            Start-Sleep 8
            $tray2 = @(Trays)
            Check "старый трей погашен, новый запущен (было $($tray1 -join ', '), стало $($tray2 -join ', '))" { $tray2.Count -eq 1 -and $tray1 -notcontains $tray2[0] }
        }

        Write-Host '== 18. убиты и сторож, и демон — задачу поднимает повтор раз в минуту'
        Get-CimInstance Win32_Process -Filter "Name='powershell.exe'" | Where-Object { $_.CommandLine -match 'vpn-guard\.ps1.*\s(daemon|supervise)\b' } |
            ForEach-Object { Stop-Process -Id $_.ProcessId -Force }
        $w = WaitFor { @(Guards 'daemon').Count -eq 1 } 80
        Check "служба поднялась сама за $w с (повтор задачи — 1 мин)" { $w -ne $null }

        Write-Host '== 19. unlock сам выключает задачу (повтор раз в минуту её не поднимает); включить — как «Охрана включена» в трее'
        $out = (& powershell.exe -NoProfile -ExecutionPolicy Bypass -File "$PF\vpn-guard.ps1" unlock) -join "`n"
        Check 'unlock: задача выключена' { "$((Get-ScheduledTask -TaskName VPNGuard).State)" -eq 'Disabled' }
        Check 'unlock: процессов службы нет, правил нет' { (WaitFor { -not (Guards) } 5) -ne $null -and -not (Rules) }
        Check 'unlock: подсказка, как включить снова' { $out -match 'Enable-ScheduledTask' -and $out -match 'Охрана включена' }
        Start-Sleep 65
        Check 'через 65 с (повтор задачи — раз в минуту) служба так и не поднялась' { -not (Guards) -and -not (Rules) }
        Enable-ScheduledTask -TaskName VPNGuard | Out-Null; Start-ScheduledTask -TaskName VPNGuard
        Check 'включили: служба работает, правило снова есть' { (WaitFor { @(Guards 'daemon').Count -eq 1 -and @(Rules).Count -ge 1 } 40) -ne $null }
    } finally {
        Write-Host '== 20. удаление'
        $rc = RunPs (Join-Path $Win 'uninstall.ps1') "$T-uninstall.log"
        Check "задачи нет (uninstall.ps1: код $rc)" { -not (Get-ScheduledTask -TaskName VPNGuard -ErrorAction SilentlyContinue) }
        Check 'процессов службы нет' { (WaitFor { -not (Guards) } 5) -ne $null }
        Check 'правил нет' { -not (Rules) }
        Check "$PF удалён" { -not (Test-Path $PF) }
        if ($hasUser) { Check 'трея нет' { (WaitFor { -not (Trays) } 5) -ne $null } }
        Remove-Item $PD -Recurse -Force -ErrorAction SilentlyContinue
        if ($script:Fail -eq 0) { Remove-Item "$T-install1.log", "$T-install2.log", "$T-uninstall.log" -ErrorAction SilentlyContinue }
    }
}

Write-Host ''
Write-Host "итого: ok $($script:Pass), FAIL $($script:Fail)"
exit $(if ($script:Fail) { 1 } else { 0 })
