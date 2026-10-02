# vpn-guard.ps1 — Windows-версия vpn-guard: не даёт пользоваться выбранными
# приложениями, пока не включён VPN.
#
# Работает как задача Планировщика от SYSTEM (ставит install.ps1). Если VPN нет:
#   * приостанавливает процессы приложений (NtSuspendProcess) или закрывает их;
#   * запрещает запуск: ACE «Все: запрет выполнения» на .exe в папке приложения;
#   * (если задан block_nets) блокирует сеть к этим адресам Брандмауэром Windows.
# Когда VPN возвращается — всё снимается.
#
# Команды: daemon | status | check | unlock | set-apps <файл.json> | set-countries <файл.json>

param([string]$Command = 'status', [string]$Arg = '')

$ErrorActionPreference = 'Stop'
# PowerShell 5.1 сериализует массивы в JSON как {value, Count} — убрать эту надстройку
Remove-TypeData System.Array -ErrorAction SilentlyContinue
# PowerShell 5.1 по умолчанию не включает TLS 1.2 — без этого Cloudflare не отвечает
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$Root      = Join-Path $env:ProgramData 'VPNGuard'
$ConfPath  = Join-Path $Root 'config.json'
$StatePath = Join-Path $Root 'locked.json'
$StatusPath= Join-Path $Root 'status.json'
$LogPath   = Join-Path $Root 'vpn-guard.log'
$FwRule    = 'VPNGuard-Block'
$TunnelRx  = '(?i)wintun|wireguard|tap-windows|tap-|\btun\b|openvpn|vpn|ppp|wan miniport|amnezia|outline|sing-?box|happ|v2ray|xray|clash|hiddify|nekoray|tailscale|zerotier'

# ---- служебное --------------------------------------------------------------
function Log([string]$m) {
    $line = '{0} {1}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $m
    try {
        if ((Test-Path $LogPath) -and (Get-Item $LogPath).Length -gt 1MB) {
            Move-Item $LogPath "$LogPath.1" -Force
        }
        Add-Content -Path $LogPath -Value $line -Encoding UTF8
    } catch {}
    Write-Host $line
}
$script:Warned = @{}
function WarnOnce([string]$key, [string]$m) {
    if (-not $script:Warned.ContainsKey($key)) { $script:Warned[$key] = 1; Log $m }
}

Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class VGNative {
    [DllImport("kernel32.dll", SetLastError=true)] static extern IntPtr OpenProcess(int a, bool i, int pid);
    [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr h);
    [DllImport("ntdll.dll")] static extern int NtSuspendProcess(IntPtr h);
    [DllImport("ntdll.dll")] static extern int NtResumeProcess(IntPtr h);
    const int PROCESS_SUSPEND_RESUME = 0x0800;
    public static bool Suspend(int pid) { return Call(pid, true); }
    public static bool Resume(int pid)  { return Call(pid, false); }
    static bool Call(int pid, bool s) {
        IntPtr h = OpenProcess(PROCESS_SUSPEND_RESUME, false, pid);
        if (h == IntPtr.Zero) return false;
        try { return (s ? NtSuspendProcess(h) : NtResumeProcess(h)) == 0; } finally { CloseHandle(h); }
    }
}
'@ -ErrorAction SilentlyContinue

# ---- конфиг -----------------------------------------------------------------
# Страны, из которых VPN считается выключенным: Россия, Китай, Беларусь, Иран
$DefaultCountries = @('RU', 'CN', 'BY', 'IR')

function Normalize-Countries($list) {
    @(@($list) | ForEach-Object { "$_".Trim().ToUpper() } | Where-Object { $_ -match '^[A-Z]{2}$' } | Select-Object -Unique)
}

function Default-Conf {
    [pscustomobject]@{
        apps = @(); checks = @('route', 'geo'); require = 'all'; on_down = 'freeze'
        lock_launch = $true; block_nets = @(); interval = 1; geo_ttl = 1; geo_ttl_down = 1; geo_stale = 60; grace = 0
        block_countries = $DefaultCountries; net_watch = $true
    }
}

# Путь приложения опасен, если под ним системные процессы: заморозить C:\Windows
# значит повесить машину. Разрешаем только папки глубже корня диска и не системные.
function Test-SafeAppPath([string]$p) {
    if ([string]::IsNullOrWhiteSpace($p)) { return $false }
    try { $full = [IO.Path]::GetFullPath($p).TrimEnd('\') } catch { return $false }
    if ($full -match '\.\.') { return $false }
    if (($full -split '\\').Count -lt 3) { return $false }          # C:\X — слишком широко
    $deny = @($env:windir, $env:ProgramFiles, ${env:ProgramFiles(x86)}, $env:ProgramData,
              (Join-Path $env:SystemDrive 'Users'), $PSScriptRoot) | Where-Object { $_ }
    foreach ($d in $deny) {
        $d = $d.TrimEnd('\')
        if ($full -ieq $d) { return $false }
        if ($d -ieq $env:windir -and $full.StartsWith("$d\", 'OrdinalIgnoreCase')) { return $false }
        if ($d -ieq $PSScriptRoot -and $full.StartsWith("$d\", 'OrdinalIgnoreCase')) { return $false }
    }
    if ($full -match '^[A-Za-z]:\\Users\\[^\\]+$') { return $false }  # профиль целиком
    return $true
}

# Папка приложения: для .exe — его каталог (у Claude, Discord и т.п. рядом лежат
# app-x.y.z\ с настоящим бинарём и помощниками).
function App-Folder([string]$p) {
    if ($p -match '\.exe$') { return (Split-Path $p -Parent) }
    return $p.TrimEnd('\')
}

# Конфиг читается, только если писать в него могут лишь SYSTEM и администраторы —
# иначе любой пользователь мог бы заставить SYSTEM заморозить что угодно.
function Test-ConfSafe([string]$f) {
    if (-not (Test-Path $f)) { return $false }
    $bad = (Get-Acl $f).Access | Where-Object {
        $_.AccessControlType -eq 'Allow' -and
        # только биты записи: WriteData, AppendData, WriteEA, WriteAttributes, Delete,
        # ChangePermissions, TakeOwnership (у Modify/FullControl они есть, у ReadAndExecute — нет)
        ([int]$_.FileSystemRights -band 0xD0116) -and
        $_.IdentityReference.Value -notmatch '(?i)SYSTEM$|Administrators$|Администраторы$|TrustedInstaller$|CREATOR OWNER$'
    }
    return -not $bad
}

function Load-Conf {
    $c = Default-Conf
    if (-not (Test-Path $ConfPath)) { WarnOnce 'noconf' "нет $ConfPath — сторожить нечего"; return $c }
    if (-not (Test-ConfSafe $ConfPath)) { WarnOnce 'unsafe' "в $ConfPath могут писать не только администраторы — не читаю"; return $c }
    # файл могли поймать посреди записи — тогда вернуть $null, и демон оставит прежний конфиг
    try { $j = Get-Content $ConfPath -Raw -Encoding UTF8 | ConvertFrom-Json } catch { Log "конфиг не читается: $_"; return $null }
    if (-not $j) { return $null }
    foreach ($k in $c.PSObject.Properties.Name) { if ($null -ne $j.$k) { $c.$k = $j.$k } }
    # старый конфиг без block_countries: список берётся из правила geo:!RU,…
    if ($j.PSObject.Properties.Name -notcontains 'block_countries') {
        $legacy = @($c.checks) | Where-Object { "$_" -like 'geo:!*' } | Select-Object -First 1
        if ($legacy) { $c.block_countries = @("$legacy".Substring(5) -split ',') }
    }
    $c.block_countries = Normalize-Countries $c.block_countries
    if ([int]$c.geo_ttl -lt 1) { $c.geo_ttl = 1 }
    if ([int]$c.geo_ttl_down -lt 1) { $c.geo_ttl_down = 1 }
    $c.apps = @($c.apps | ForEach-Object { $_ } | ForEach-Object { "$_" } | Where-Object {
        if (Test-SafeAppPath $_) { $true } else { WarnOnce "bad:$_" "пропускаю недопустимый путь: $_"; $false }
    })
    if ($c.require -notin 'all', 'any') { $c.require = 'all' }
    if ($c.on_down -notin 'freeze', 'kill') { $c.on_down = 'freeze' }
    if ([int]$c.interval -lt 1) { $c.interval = 1 }
    if (@($c.checks).Count -eq 0) { $c.checks = @('route') }
    return $c
}

# ---- определение VPN --------------------------------------------------------
# Интерфейс, через который реально уйдёт пакет в интернет. Find-NetRoute учитывает
# и маршруты 0.0.0.0/1 + 128.0.0.0/1, которые ставят OpenVPN/WireGuard.
function Get-EgressAdapter {
    try {
        $r = Find-NetRoute -RemoteIPAddress 1.1.1.1 -ErrorAction Stop | Where-Object { $_.InterfaceIndex } | Select-Object -First 1
    } catch { return $null }
    if (-not $r) { return $null }
    $a = Get-NetAdapter -InterfaceIndex $r.InterfaceIndex -IncludeHidden -ErrorAction SilentlyContinue
    $alias = (Get-NetIPInterface -InterfaceIndex $r.InterfaceIndex -ErrorAction SilentlyContinue | Select-Object -First 1).InterfaceAlias
    [pscustomobject]@{
        Index = $r.InterfaceIndex; Alias = $alias
        Desc = if ($a) { $a.InterfaceDescription } else { '' }
        Hardware = if ($a) { [bool]$a.HardwareInterface } else { $false }
        Adapter = [bool]$a
    }
}

function Test-Tunnel($e) {
    if (-not $e) { return $false }
    if (-not $e.Adapter) { return $true }                 # RAS/PPP-подключение без NetAdapter
    if ("$($e.Alias) $($e.Desc)" -match $TunnelRx) { return $true }
    if (-not $e.Hardware -and "$($e.Alias) $($e.Desc)" -notmatch '(?i)hyper-v|vethernet|vmware|virtualbox|loopback|parallels') { return $true }
    return $false
}

$script:Geo = @{ T = [datetime]::MinValue; If = ''; CC = ''; GoodT = [datetime]::MinValue; GoodCC = '' }
$script:GuardDown = $false
function Fetch-Geo([string]$url) {
    try {
        $r = Invoke-WebRequest -Uri $url -UseBasicParsing -TimeoutSec 4
        foreach ($l in ($r.Content -split "`n")) { if ($l -match '^loc=(\w+)') { return $Matches[1] } }
    } catch {}
    return ''
}
# Как на Маке: три попытки, при полном молчании на том же интерфейсе ещё geo_stale
# секунд верим последнему ответу — иначе каждый таймаут Cloudflare = ложная блокировка.
# Как часто: раз в geo_ttl с (по умолчанию каждую секунду; geo_ttl_down — при блокировке)
# и сразу — по событию сети (см. Wait-Tick).
function Refresh-Geo($conf) {
    $e = Get-EgressAdapter; $if = if ($e) { "$($e.Index)" } else { '' }
    $now = Get-Date
    $ttl = if ($script:GuardDown) { $conf.geo_ttl_down } else { $conf.geo_ttl }
    if (($now - $script:Geo.T).TotalSeconds -lt $ttl -and $if -eq $script:Geo.If) { return }
    $cc = ''
    foreach ($u in 'https://www.cloudflare.com/cdn-cgi/trace', 'https://1.1.1.1/cdn-cgi/trace', 'https://www.cloudflare.com/cdn-cgi/trace') {
        $cc = Fetch-Geo $u; if ($cc) { break }
    }
    if ($if -ne $script:Geo.If) { $script:Geo.GoodT = [datetime]::MinValue }
    if ($cc) { $script:Geo.GoodT = $now; $script:Geo.GoodCC = $cc }
    elseif (($now - $script:Geo.GoodT).TotalSeconds -lt $conf.geo_stale) {
        $cc = $script:Geo.GoodCC
        WarnOnce "stale:$($script:Geo.GoodT)" "Cloudflare не ответил — пока верю прошлой стране $cc"
    }
    $script:Geo.CC = $cc; $script:Geo.T = $now; $script:Geo.If = $if
}

function Test-Check([string]$rule, $conf) {
    switch -Regex ($rule) {
        '^route$'      { return (Test-Tunnel (Get-EgressAdapter)) }
        # geo, geo:!RU — страна выхода не из block_countries (пустой список — не проверять)
        '^geo(:!.*)?$' {
            $bad = @($conf.block_countries)
            if ($bad.Count -eq 0) { return $true }
            Refresh-Geo $conf; $cc = $script:Geo.CC
            if (-not $cc) { return $false }
            return -not ($bad -contains $cc)
        }
        # geo:FR,NL — страна выхода из списка
        '^geo:([^!].*)$' {
            $spec = $Matches[1]; Refresh-Geo $conf; $cc = $script:Geo.CC
            if (-not $cc) { return $false }
            return (($spec -split ',') -contains $cc)
        }
        '^adapter:(.+)$' { return [bool](Get-NetAdapter -Name $Matches[1] -IncludeHidden -ErrorAction SilentlyContinue | Where-Object Status -eq 'Up') }
        '^proc:(.+)$'  { return [bool](Get-Process -Name $Matches[1] -ErrorAction SilentlyContinue) }
        '^script:(.+)$' { & $Matches[1] *> $null; return ($LASTEXITCODE -eq 0) }
        default        { WarnOnce "rule:$rule" "неизвестное правило: $rule — считаю невыполненным"; return $false }
    }
}

function Test-VpnUp($conf) {
    if ($conf.require -eq 'all') {
        foreach ($r in $conf.checks) { if (-not (Test-Check $r $conf)) { return $false } }
        return $true
    }
    foreach ($r in $conf.checks) { if (Test-Check $r $conf) { return $true } }
    return $false
}

# ---- процессы ---------------------------------------------------------------
function Get-AppProcs([string]$app, $all) {
    $dir = (App-Folder $app) + '\'
    @($all | Where-Object { $_.ExecutablePath -and $_.ExecutablePath.StartsWith($dir, 'OrdinalIgnoreCase') -and $_.ProcessId -ne $PID })
}

# Процесс считается замороженным, если все его потоки ждут с причиной Suspended.
function Test-Frozen([int]$procId) {
    $p = Get-Process -Id $procId -ErrorAction SilentlyContinue
    if (-not $p -or $p.Threads.Count -eq 0) { return $false }
    foreach ($t in $p.Threads) {
        if ($t.ThreadState -ne 'Wait' -or "$($t.WaitReason)" -ne 'Suspended') { return $false }
    }
    return $true
}

function Freeze-App([string]$app, $all) {
    foreach ($p in (Get-AppProcs $app $all)) {
        if (Test-Frozen $p.ProcessId) { continue }             # NtSuspend копит счётчик — не повторять
        if ([VGNative]::Suspend([int]$p.ProcessId)) { Log "заморожен процесс $($p.ProcessId) ($($p.Name))" }
    }
}
function Resume-App([string]$app, $all) {
    foreach ($p in (Get-AppProcs $app $all)) {
        $n = 0
        while ((Test-Frozen $p.ProcessId) -and $n -lt 10) { [void][VGNative]::Resume([int]$p.ProcessId); $n++ }
        if ($n) { Log "разморожен процесс $($p.ProcessId) ($($p.Name))" }
    }
}
function Kill-App([string]$app, $all) {
    foreach ($p in (Get-AppProcs $app $all)) {
        Stop-Process -Id $p.ProcessId -Force -ErrorAction SilentlyContinue
        Log "закрыт процесс $($p.ProcessId) ($($p.Name))"
    }
}

# ---- запрет запуска ---------------------------------------------------------
function Load-State { if (Test-Path $StatePath) { try { return (Get-Content $StatePath -Raw | ConvertFrom-Json) } catch {} }; [pscustomobject]@{} }
function Save-State($s) { $s | ConvertTo-Json -Depth 4 | Set-Content $StatePath -Encoding UTF8 }

function Lock-App([string]$app) {
    $dir = App-Folder $app
    if (-not (Test-Path $dir)) { WarnOnce "nodir:$app" "не нашёл $dir — проверь путь"; return }
    $st = Load-State
    $done = @(); if ($st.PSObject.Properties[$app]) { $done = @($st.$app) }
    $exes = @(Get-ChildItem -Path $dir -Filter *.exe -Recurse -Depth 2 -File -ErrorAction SilentlyContinue | ForEach-Object FullName)
    $new = @($exes | Where-Object { $done -notcontains $_ })
    if (-not $new) { return }
    foreach ($f in $new) {
        & icacls.exe $f /deny '*S-1-1-0:(X)' *> $null
        if ($LASTEXITCODE -eq 0) { $done += $f } else { WarnOnce "acl:$f" "не смог запретить запуск $f" }
    }
    $st | Add-Member -NotePropertyName $app -NotePropertyValue $done -Force
    Save-State $st
    Log "заблокирован запуск: $app ($($done.Count) exe)"
}

function Unlock-App([string]$app) {
    $st = Load-State
    if (-not $st.PSObject.Properties[$app]) { return }
    foreach ($f in @($st.$app)) { if (Test-Path $f) { & icacls.exe $f /remove:d '*S-1-1-0' *> $null } }
    $st.PSObject.Properties.Remove($app); Save-State $st
    Log "снята блокировка запуска: $app"
}

# ---- брандмауэр -------------------------------------------------------------
$script:FwMode = ''
function Set-Firewall([string]$mode, $conf, $egress) {
    if (@($conf.block_nets).Count -eq 0) {
        if ($script:FwMode -ne 'none') { Remove-NetFirewallRule -DisplayName $FwRule -ErrorAction SilentlyContinue; $script:FwMode = 'none' }
        return
    }
    $key = $mode; if ($mode -eq 'up' -and $egress) { $key = "up:$($egress.Alias)" }
    if ($key -eq $script:FwMode) { return }
    Remove-NetFirewallRule -DisplayName $FwRule -ErrorAction SilentlyContinue
    $p = @{ DisplayName = $FwRule; Direction = 'Outbound'; Action = 'Block'; RemoteAddress = @($conf.block_nets); Profile = 'Any' }
    if ($mode -eq 'up') {
        # VPN есть — блок только на всех НЕ туннельных интерфейсах: трафик к этим
        # адресам пойдёт лишь через туннель, и падение VPN режется сразу.
        $others = @(Get-NetAdapter -IncludeHidden -ErrorAction SilentlyContinue | Where-Object { $_.ifIndex -ne $egress.Index } | ForEach-Object Name)
        if (-not $others) { $script:FwMode = $key; return }
        $p.InterfaceAlias = $others
    }
    New-NetFirewallRule @p | Out-Null
    $script:FwMode = $key
    if ($mode -eq 'up') { Log "сеть к заблокированным адресам: только через $($egress.Alias)" } else { Log 'сеть к заблокированным адресам: ЗАКРЫТА' }
}

# ---- состояние для трея -----------------------------------------------------
function Write-Status($conf, [bool]$vpn, $all) {
    $e = Get-EgressAdapter
    $st = Load-State
    $apps = foreach ($a in $conf.apps) {
        $ps = @(Get-AppProcs $a $all)
        $fz = @($ps | Where-Object { Test-Frozen $_.ProcessId }).Count
        [pscustomobject]@{ path = $a; locked = [bool]$st.PSObject.Properties[$a]; procs = $ps.Count; frozen = $fz }
    }
    $o = [pscustomobject]@{
        time = [int][double]::Parse((Get-Date -UFormat %s)); vpn = $vpn
        iface = if ($e) { "$($e.Alias)" } else { '' }; country = $script:Geo.CC; on_down = $conf.on_down
        countries = @($conf.block_countries)
        geo = [bool](@($conf.checks) | Where-Object { "$_" -match '^geo(:|$)' })
        apps = @($apps)
    }
    $tmp = "$StatusPath.$PID.tmp"
    [IO.File]::WriteAllText($tmp, ($o | ConvertTo-Json -Depth 4 -Compress), (New-Object Text.UTF8Encoding $false))
    # Replace — атомарно, трей никогда не увидит пустой или полузаписанный файл
    if (Test-Path $StatusPath) { [IO.File]::Replace($tmp, $StatusPath, [NullString]::Value) } else { [IO.File]::Move($tmp, $StatusPath) }
}

# ---- ожидание: таймер или событие сети ---------------------------------------
# NetworkAddressChanged приходит, когда у адаптера меняется адрес: VPN поднялся,
# упал, переподключился. Пока сеть не меняется, служба просто спит interval секунд.
$script:NetWatch = $false
function Start-NetWatch($conf) {
    if (-not $conf.net_watch -or $script:NetWatch) { return }
    try {
        Register-ObjectEvent -InputObject ([Net.NetworkInformation.NetworkChange]) `
            -EventName NetworkAddressChanged -SourceIdentifier VafaNet | Out-Null
        $script:NetWatch = $true
    } catch { WarnOnce 'netwatch' "не удалось подписаться на события сети — работаю по таймеру: $_" }
}

# true — проснулись по событию сети (тогда страну надо спросить заново)
function Wait-Tick($conf) {
    if (-not $script:NetWatch) { Start-Sleep -Seconds $conf.interval; return $false }
    $ev = Wait-Event -SourceIdentifier VafaNet -Timeout $conf.interval
    if (-not $ev) { return $false }
    $n = 0
    # VPN при подключении шлёт пачку событий — дождаться тишины и забрать все
    do {
        Remove-Event -SourceIdentifier VafaNet -ErrorAction SilentlyContinue
        $more = Wait-Event -SourceIdentifier VafaNet -Timeout 1
    } while ($more -and ++$n -lt 10)
    Remove-Event -SourceIdentifier VafaNet -ErrorAction SilentlyContinue
    return $true
}

# ---- команды ----------------------------------------------------------------
function Cmd-Daemon {
    New-Item -ItemType Directory -Force -Path $Root | Out-Null
    # ровно одна копия: две дерутся за status.json и дублируют действия
    $script:Mutex = New-Object Threading.Mutex($false, 'Global\VPNGuardDaemon')
    try { $got = $script:Mutex.WaitOne(0) } catch [Threading.AbandonedMutexException] { $got = $true }
    if (-not $got) { Write-Host 'vpn-guard уже запущен'; return }
    $conf = Load-Conf; if ($null -eq $conf) { $conf = Default-Conf }
    $mt = if (Test-Path $ConfPath) { (Get-Item $ConfPath).LastWriteTimeUtc } else { $null }
    Log "vpn-guard запущен: правила=[$($conf.checks -join ' ')] ($($conf.require)), при падении VPN=$($conf.on_down), приложений: $(@($conf.apps).Count), страны блокировки: $(if ($conf.block_countries) { $conf.block_countries -join ' ' } else { 'не заданы' })"
    Start-NetWatch $conf
    $last = 'init'; $downSince = $null; $lastLock = [datetime]::MinValue
    while ($true) {
        try {
            $m = if (Test-Path $ConfPath) { (Get-Item $ConfPath).LastWriteTimeUtc } else { $null }
            if ($m -ne $mt) {
                $mt = $m; Log 'конфиг изменился — перечитываю'
                $old = @($conf.apps); $new = Load-Conf
                if ($null -eq $new) { $mt = $null; Start-Sleep 1; continue }   # повторить на следующем круге
                $conf = $new; $last = 'init'; $script:FwMode = ''
                foreach ($a in $old) { if ($conf.apps -notcontains $a) { Log "$a убран из списка — снимаю блокировку"; Unlock-App $a; Resume-App $a (Get-CimInstance Win32_Process) } }
            }
            $all = Get-CimInstance Win32_Process -Property ProcessId, Name, ExecutablePath
            if (Test-VpnUp $conf) {
                if ($last -ne 'up') { Log 'VPN поднят — снимаю блокировку'; $last = 'up' }
                $downSince = $null; $script:GuardDown = $false
                foreach ($a in $conf.apps) { Unlock-App $a; Resume-App $a $all }
                Set-Firewall 'up' $conf (Get-EgressAdapter)
                Write-Status $conf $true $all
            } else {
                if (-not $downSince) { $downSince = Get-Date }
                if (((Get-Date) - $downSince).TotalSeconds -ge $conf.grace) {
                    if ($last -ne 'down') {
                        $e = Get-EgressAdapter
                        Log "VPN не обнаружен (интерфейс: $($e.Alias), страна: $(if ($script:Geo.CC) { $script:Geo.CC } else { '?' })) — блокирую"
                        $last = 'down'; $lastLock = [datetime]::MinValue
                    }
                    $script:GuardDown = $true
                    foreach ($a in $conf.apps) {
                        # проход по exe — раз в 30 с: ловит файлы, появившиеся после обновления
                        if ($conf.lock_launch -and ((Get-Date) - $lastLock).TotalSeconds -ge 30) { Lock-App $a }
                        if ($conf.on_down -eq 'kill') { Kill-App $a $all } else { Freeze-App $a $all }
                    }
                    if (((Get-Date) - $lastLock).TotalSeconds -ge 30) { $lastLock = Get-Date }
                    Set-Firewall 'down' $conf $null
                }
                Write-Status $conf $false $all
            }
        } catch { WarnOnce "err:$_" "ошибка в цикле: $_" }
        # сеть поменялась — на следующем круге страну спросить заново, не ждать geo_ttl
        if (Wait-Tick $conf) { $script:Geo.T = [datetime]::MinValue }
    }
}

function Cmd-Check {
    $conf = Load-Conf; if ($null -eq $conf) { $conf = Default-Conf }
    foreach ($r in $conf.checks) {
        $ok = Test-Check $r $conf
        $note = if ($ok) { "  [ да ] $r" } else { "  [ нет] $r" }
        if ($r -match '^geo(:|$)') { $note += "   (страна выхода: $(if ($script:Geo.CC) { $script:Geo.CC } else { 'нет ответа' }); блокировать: $(if ($conf.block_countries) { $conf.block_countries -join ' ' } else { 'ничего' }))" }
        Write-Host $note
    }
    $e = Get-EgressAdapter
    Write-Host "  интерфейс выхода: $($e.Alias) — $($e.Desc)"
    if (Test-VpnUp $conf) { Write-Host "VPN: ПОДНЯТ ($($conf.require))" } else { Write-Host "VPN: ВЫКЛЮЧЕН ($($conf.require))" }
}

function Cmd-Status {
    Cmd-Check
    $conf = Load-Conf; if ($null -eq $conf) { $conf = Default-Conf }; $all = Get-CimInstance Win32_Process -Property ProcessId, Name, ExecutablePath; $st = Load-State
    Write-Host "`nПриложения под охраной:"
    if (-not $conf.apps) { Write-Host '  (список пуст)' }
    foreach ($a in $conf.apps) {
        $ps = @(Get-AppProcs $a $all)
        $fz = @($ps | Where-Object { Test-Frozen $_.ProcessId }).Count
        $lk = if ($st.PSObject.Properties[$a]) { 'ЗАБЛОКИРОВАНО' } else { 'разблокировано' }
        Write-Host "  $a"
        Write-Host "      запуск: $lk, процессов: $($ps.Count)$(if ($fz) { ", заморожено: $fz" })"
    }
    $t = Get-ScheduledTask -TaskName VPNGuard -ErrorAction SilentlyContinue
    Write-Host "`nЗадача: $(if ($t) { $t.State } else { 'НЕ установлена' })"
}

# аварийный выход: вернуть всё как было
function Cmd-Unlock {
    $st = Load-State
    foreach ($a in $st.PSObject.Properties.Name) { Unlock-App $a }
    $conf = Load-Conf; if ($null -eq $conf) { $conf = Default-Conf }; $all = Get-CimInstance Win32_Process -Property ProcessId, Name, ExecutablePath
    foreach ($a in $conf.apps) { Resume-App $a $all }
    Remove-NetFirewallRule -DisplayName $FwRule -ErrorAction SilentlyContinue
    Write-Host 'готово: запуск разрешён, процессы разморожены, правило брандмауэра снято'
}

# вызывается треем через «Запуск от имени администратора»: заменить список приложений
function Cmd-SetApps([string]$file) {
    # ConvertFrom-Json в 5.1 отдаёт массив одним объектом — развернуть
    $list = @(Get-Content $file -Raw -Encoding UTF8 | ConvertFrom-Json | ForEach-Object { $_ })
    $ok = @($list | Where-Object { Test-SafeAppPath $_ })
    $conf = if (Test-Path $ConfPath) { Get-Content $ConfPath -Raw -Encoding UTF8 | ConvertFrom-Json } else { Default-Conf }
    $conf.apps = $ok
    if (Test-Path $ConfPath) { (Get-Item $ConfPath).IsReadOnly = $false }
    # запись через временный файл: демон не должен увидеть полузаписанный JSON
    $conf | ConvertTo-Json -Depth 4 | Set-Content "$ConfPath.tmp" -Encoding UTF8
    Move-Item "$ConfPath.tmp" $ConfPath -Force
    Write-Host "сохранено приложений: $($ok.Count)"
}

# вызывается треем через «Запуск от имени администратора»: заменить список стран
function Cmd-SetCountries([string]$file) {
    $ok = Normalize-Countries (Get-Content $file -Raw -Encoding UTF8 | ConvertFrom-Json | ForEach-Object { $_ })
    $conf = if (Test-Path $ConfPath) { Get-Content $ConfPath -Raw -Encoding UTF8 | ConvertFrom-Json } else { Default-Conf }
    $conf | Add-Member -NotePropertyName block_countries -NotePropertyValue @($ok) -Force
    if (Test-Path $ConfPath) { (Get-Item $ConfPath).IsReadOnly = $false }
    $conf | ConvertTo-Json -Depth 4 | Set-Content "$ConfPath.tmp" -Encoding UTF8
    Move-Item "$ConfPath.tmp" $ConfPath -Force
    Write-Host "страны блокировки: $(if ($ok) { $ok -join ' ' } else { 'не заданы' })"
}

switch ($Command) {
    'daemon'   { Cmd-Daemon }
    'status'   { Cmd-Status }
    'check'    { Cmd-Check }
    'unlock'   { Cmd-Unlock }
    'set-apps' { Cmd-SetApps $Arg }
    'set-countries' { Cmd-SetCountries $Arg }
    default    { Write-Host 'использование: vpn-guard.ps1 {daemon|status|check|unlock|set-apps <файл>|set-countries <файл>}'; exit 1 }
}
