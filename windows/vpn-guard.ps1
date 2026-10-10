# vpn-guard.ps1 — Windows-версия vpn-guard: не даёт пользоваться выбранными
# приложениями и ходить к серверам Anthropic, пока не включён VPN.
#
# Работает как задача Планировщика от SYSTEM (ставит install.ps1): задача запускает
# сторожа (supervise), сторож — сам демон и перезапускает его через 2 с, если тот умер.
# Состояния (те же, что на macOS, поле state в status.json):
#   up     — маршрут через туннель И свежий ответ geo из разрешённой страны: сеть к
#            адресам Anthropic открыта только через туннель, приложения работают;
#   unsure — маршрут через туннель, но страна не подтверждена свежим ответом (сразу
#            после события сети, Cloudflare молчит меньше geo_stale): сеть к Anthropic
#            закрыта, приложения не трогаем — ни морозим, ни размораживаем;
#   down   — VPN нет: сеть закрыта (первой), процессы приостановлены (NtSuspendProcess)
#            или закрыты, запуск запрещён (ACE «Все: запрет выполнения» на .exe).
# Сеть режет Брандмауэр Windows: block_nets (сети Anthropic) и адреса block_hosts.
#
# Команды: daemon | supervise | status | check | unlock | set-apps <файл.json> | set-countries <файл.json>

param([string]$Command = 'status', [string]$Arg = '')

$ErrorActionPreference = 'Stop'
# PowerShell 5.1 сериализует массивы в JSON как {value, Count} — убрать эту надстройку
Remove-TypeData System.Array -ErrorAction SilentlyContinue
# PowerShell 5.1 по умолчанию не включает TLS 1.2 — без этого Cloudflare не отвечает
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
Add-Type -AssemblyName System.Net.Http
# VPN_GUARD_ROOT и VPN_GUARD_GEO_URLS — только для tests/run_windows.ps1
$Root      = if ($env:VPN_GUARD_ROOT) { $env:VPN_GUARD_ROOT } else { Join-Path $env:ProgramData 'VPNGuard' }
$ConfPath  = Join-Path $Root 'config.json'
$StatePath = Join-Path $Root 'locked.json'
$StatusPath= Join-Path $Root 'status.json'
$HostsPath = Join-Path $Root 'hosts.json'
$LogPath   = Join-Path $Root 'vpn-guard.log'
$FwRule    = 'VPNGuard-Block'      # DisplayName всех наших правил (и старых версий)
$FwGroup   = 'VPNGuard'
# Туннель — только адаптер, похожий на VPN по имени или описанию. Раньше туннелем считался
# любой «не железный» адаптер и любое RAS-подключение без адаптера — а это и PPPoE провайдера
# («Высокоскоростное подключение», WAN Miniport (PPPOE)), и сетевой мост, и NIC Teaming:
# тогда страна спрашивалась с настоящего адреса.
$TunnelRx  = '(?i)wintun|wireguard|nordlynx|tap-windows|tap-|\btun\d*\b|\btunnel\b|openvpn|vpn|amnezia|outline|sing-?box|happ|v2ray|xray|clash|hiddify|nekoray|nekobox|\bwarp\b|anyconnect|pangp|globalprotect|forti|juniper|pulse secure|softether'
# Не туннель, даже если имя похоже: Tailscale и ZeroTier — оверлейные сети, «подключены»
# всегда; PPPoE и широкополосные подключения провайдера; мост и объединение адаптеров;
# туннели перехода на IPv6 (Teredo, 6to4, ISATAP, IP-HTTPS) идут с настоящего адреса;
# виртуальные коммутаторы и петли
$NotTunnelRx = '(?i)tailscale|zerotier|pppoe|broadband|широкополос|высокоскоростн|bridge|сетевой мост|multiplexor|мультиплексор|\bteam\b|teredo|isatap|6to4|ip-https|iphttps|hyper-v|vethernet|vmware|virtualbox|parallels|loopback|wi-fi direct|bluetooth|kernel debug'
# Адреса Anthropic (claude.ai, api.anthropic.com): маршрут к ним тоже должен идти в туннель
$RouteProbes = @('160.79.104.10', '2607:6bc0::10')
# Только IPv4-литералы: без DNS (запрос к DNS ушёл бы мимо туннеля, и до 15 с в PowerShell
# 5.1) и без IPv6 (у имени есть AAAA, и IPv6 часто идёт мимо IPv4-туннеля). Перед каждым
# запросом — маршрут к этому адресу через проверенный туннель (Test-GeoPath).
$GeoUrls   = @(if ($env:VPN_GUARD_GEO_URLS) { $env:VPN_GUARD_GEO_URLS -split '[,\s]+' | Where-Object { $_ } } else {
    'https://1.1.1.1/cdn-cgi/trace', 'https://1.0.0.1/cdn-cgi/trace' })
$GeoIPs    = @('1.1.1.1', '1.0.0.1')   # их нельзя закрывать — иначе страну не узнать никогда
$GeoTimeout = 4
$HostsMax  = 256
# VPN_GUARD_TUNNEL_IFS — только для tests/run_windows.ps1: эти интерфейсы (InterfaceAlias)
# считать туннелем (в виртуалке без VPN выход — обычный Ethernet)
$TestTunnelIfs = @("$env:VPN_GUARD_TUNNEL_IFS" -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ })
# Дорогое (WMI) — не каждый круг. Замер 2026-10-09 в VM (ARM64, 4 ядра): Get-NetFirewallRule
# ~160 мс (115 мс CPU в WmiPrvSE), Get-NetIPInterface/Get-NetAdapter/Find-NetRoute по 10–20 мс;
# демон тратил 11–15 % ядра и столько же WmiPrvSE.
$NetCacheTtl   = 5    # с: список интерфейсов и адаптеров (и сразу — по событию сети)
$FwVerifyEvery = 5    # с: полная проверка правила и брандмауэра (и сразу — по изменению реестра брандмауэра)
$ProcScanEvery = 5    # с: обход процессов в up/unsure (в down и при смене состояния — каждый круг)
# Разделы реестра брандмауэра: правило удалили или выключили, выключили профиль, пришла
# групповая политика — меняется время записи раздела (проверка — доли миллисекунды)
$FwKeys = [string[]]@(
    @('FirewallRules', 'DomainProfile', 'StandardProfile', 'PublicProfile') | ForEach-Object { "SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\$_" }
    @('FirewallRules', 'DomainProfile', 'PrivateProfile', 'PublicProfile') | ForEach-Object { "SOFTWARE\Policies\Microsoft\WindowsFirewall\$_" })

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
# конфиг снова прочитан — предупреждения о нём можно повторить, если он опять сломается
function Reset-Warn([string]$prefix) {
    foreach ($k in @($script:Warned.Keys)) { if ($k.StartsWith($prefix)) { $script:Warned.Remove($k) } }
}

try { Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
public class VGProc { public int ProcessId; public string Name; public string ExecutablePath; public bool Frozen; }
public static class VGNative {
    [DllImport("kernel32.dll", SetLastError=true)] static extern IntPtr OpenProcess(int a, bool i, int pid);
    [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr h);
    [DllImport("ntdll.dll")] static extern int NtSuspendProcess(IntPtr h);
    [DllImport("ntdll.dll")] static extern int NtResumeProcess(IntPtr h);
    [DllImport("kernel32.dll", CharSet=CharSet.Unicode)] static extern bool QueryFullProcessImageNameW(IntPtr h, int flags, StringBuilder name, ref int size);
    [DllImport("iphlpapi.dll")] static extern int GetBestInterfaceEx(byte[] addr, out int index);
    [DllImport("advapi32.dll", CharSet=CharSet.Unicode)] static extern int RegOpenKeyExW(UIntPtr key, string sub, int opt, int sam, out IntPtr res);
    [DllImport("advapi32.dll")] static extern int RegQueryInfoKeyW(IntPtr h, IntPtr cls, IntPtr clsLen, IntPtr res, IntPtr subKeys, IntPtr maxSub,
        IntPtr maxCls, IntPtr values, IntPtr maxName, IntPtr maxVal, IntPtr sd, out long lastWrite);
    [DllImport("advapi32.dll")] static extern int RegCloseKey(IntPtr h);
    [DllImport("kernel32.dll")] static extern ulong GetTickCount64();
    const int PROCESS_SUSPEND_RESUME = 0x0800, PROCESS_QUERY_LIMITED_INFORMATION = 0x1000;

    // Монотонные секунды с загрузки (со временем сна): все интервалы демона — по ним, а не по
    // Get-Date. Местное время прыгает при смене часового пояса и при подводке часов, и тогда
    // «ответ из будущего» выглядел свежим часами, а новый запрос страны не шёл.
    public static double Now() { return GetTickCount64() / 1000.0; }
    public static bool Suspend(int pid) { return Call(pid, true); }
    public static bool Resume(int pid)  { return Call(pid, false); }
    static bool Call(int pid, bool s) {
        IntPtr h = OpenProcess(PROCESS_SUSPEND_RESUME, false, pid);
        if (h == IntPtr.Zero) return false;
        try { return (s ? NtSuspendProcess(h) : NtResumeProcess(h)) == 0; } finally { CloseHandle(h); }
    }

    // Интерфейс, через который ядро отправит пакет к адресу: то же, что Find-NetRoute
    // (учитывает и 0.0.0.0/1 + 128.0.0.0/1), но микросекунды вместо 10 мс WMI. 0 — маршрута нет.
    public static int BestIf(string ip) {
        IPAddress a;
        if (!IPAddress.TryParse(ip, out a)) return 0;
        byte[] sa;
        if (a.AddressFamily == AddressFamily.InterNetwork) { sa = new byte[16]; sa[0] = 2; Buffer.BlockCopy(a.GetAddressBytes(), 0, sa, 4, 4); }
        else { sa = new byte[28]; sa[0] = 23; Buffer.BlockCopy(a.GetAddressBytes(), 0, sa, 8, 16); }
        int idx;
        return GetBestInterfaceEx(sa, out idx) == 0 ? idx : 0;
    }

    // Время последней записи разделов HKLM (FILETIME через запятую; 0 — раздела нет)
    public static string KeyStamp(string[] subs) {
        StringBuilder r = new StringBuilder();
        foreach (string sub in subs) {
            long t = 0; IntPtr h;
            if (RegOpenKeyExW(new UIntPtr(0x80000002u), sub, 0, 0x20119, out h) == 0) {
                try { if (RegQueryInfoKeyW(h, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, out t) != 0) t = -1; }
                finally { RegCloseKey(h); }
            }
            r.Append(t).Append(',');
        }
        return r.ToString();
    }

    // Событие сети (сменился адрес у адаптера): счётчик и пробуждение спящего круга —
    // круг ждёт на WaitOne, а не опрашивает очередь событий 10 раз в секунду
    static int addrSeq;
    static bool watching;
    public static readonly AutoResetEvent Wake = new AutoResetEvent(false);
    public static int AddrSeq { get { return Thread.VolatileRead(ref addrSeq); } }
    public static void WatchNet() {
        if (watching) return;
        NetworkChange.NetworkAddressChanged += OnAddr;
        watching = true;
    }
    static void OnAddr(object s, EventArgs e) { Interlocked.Increment(ref addrSeq); Wake.Set(); }

    // Процессы, чей exe лежит в одной из папок dirs (с «\» на конце): один снимок процессов
    // и потоков вместо Get-CimInstance Win32_Process и Get-Process на каждый процесс.
    // Frozen — все потоки ждут с причиной Suspended (как Test-Frozen).
    public static VGProc[] Procs(string[] dirs) {
        List<VGProc> res = new List<VGProc>();
        if (dirs == null || dirs.Length == 0) return res.ToArray();
        foreach (Process p in Process.GetProcesses()) {
            try {
                int id = p.Id;
                if (id == 0 || id == 4) continue;
                string path = ImagePath(id);
                if (path == null) continue;
                bool hit = false;
                foreach (string d in dirs) { if (!String.IsNullOrEmpty(d) && path.StartsWith(d, StringComparison.OrdinalIgnoreCase)) { hit = true; break; } }
                if (!hit) continue;
                ProcessThreadCollection th = p.Threads;
                bool fz = th.Count > 0;
                foreach (ProcessThread t in th) {
                    if (t.ThreadState != System.Diagnostics.ThreadState.Wait || t.WaitReason != ThreadWaitReason.Suspended) { fz = false; break; }
                }
                VGProc o = new VGProc();
                o.ProcessId = id; o.Name = System.IO.Path.GetFileName(path); o.ExecutablePath = path; o.Frozen = fz;
                res.Add(o);
            } catch { } finally { p.Dispose(); }
        }
        return res.ToArray();
    }
    static string ImagePath(int pid) {
        IntPtr h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid);
        if (h == IntPtr.Zero) return null;
        try {
            foreach (int cap in new int[] { 1024, 32768 }) {
                StringBuilder sb = new StringBuilder(cap); int n = cap;
                if (QueryFullProcessImageNameW(h, 0, sb, ref n)) return sb.ToString(0, n);
            }
            return null;
        } finally { CloseHandle(h); }
    }

    // Запросы к 1.1.1.1 (страна, DNS через HTTPS) — с адреса туннеля: такой пакет Windows
    // (модель strong host) отправит только через туннель. Туннель пропал между проверкой
    // маршрута и SYN — запрос не уйдёт вовсе, а не уйдёт с настоящего адреса. Адреса нет или
    // привязка не удалась — исключение (запрос не идёт), а не null (null — «как обычно»).
    public static IPAddress BindAddr;
    public static IPEndPoint BindEP(ServicePoint sp, IPEndPoint remote, int retry) {
        IPAddress a = BindAddr;
        if (a == null || retry > 0) throw new InvalidOperationException("tunnel address unavailable");
        return new IPEndPoint(a, 0);
    }
    public static void BindTo(string url) { ServicePointManager.FindServicePoint(new Uri(url)).BindIPEndPointDelegate = new BindIPEndPoint(BindEP); }
    // первый IPv4-адрес интерфейса с этим индексом; null — нет
    public static string IfAddr4(int index) {
        foreach (NetworkInterface n in NetworkInterface.GetAllNetworkInterfaces()) {
            try {
                IPInterfaceProperties ip = n.GetIPProperties();
                IPv4InterfaceProperties p = ip.GetIPv4Properties();
                if (p == null || p.Index != index) continue;
                foreach (UnicastIPAddressInformation u in ip.UnicastAddresses)
                    if (u.Address.AddressFamily == AddressFamily.InterNetwork) return u.Address.ToString();
            } catch { }
        }
        return null;
    }

    // DNS-запрос A (UDP) и разбор ответа — для проверки, не подменяет ли VPN-клиент адреса
    // (fake-IP: mihomo/Clash/Hiddify/sing-box отвечают адресами из 198.18.0.0/15)
    public static byte[] DnsQueryA(string name, int id) {
        List<byte> b = new List<byte>(new byte[] { (byte)(id >> 8), (byte)id, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0 });
        foreach (string l in name.TrimEnd('.').Split('.')) { byte[] s = Encoding.ASCII.GetBytes(l); b.Add((byte)s.Length); b.AddRange(s); }
        b.AddRange(new byte[] { 0, 0, 1, 0, 1 });
        return b.ToArray();
    }
    static int SkipName(byte[] r, int i) {
        while (i < r.Length) {
            int n = r[i];
            if (n == 0) return i + 1;
            if ((n & 0xC0) == 0xC0) return i + 2;
            i += n + 1;
        }
        return r.Length;
    }
    public static string[] DnsAnswersA(byte[] r) {
        List<string> res = new List<string>();
        if (r == null || r.Length < 12) return res.ToArray();
        int qd = (r[4] << 8) | r[5], an = (r[6] << 8) | r[7], i = 12;
        for (int k = 0; k < qd; k++) i = SkipName(r, i) + 4;
        for (int k = 0; k < an && i + 10 <= r.Length; k++) {
            i = SkipName(r, i);
            if (i + 10 > r.Length) break;
            int type = (r[i] << 8) | r[i + 1], len = (r[i + 8] << 8) | r[i + 9];
            i += 10;
            if (i + len > r.Length) break;
            if (type == 1 && len == 4) res.Add(r[i] + "." + r[i + 1] + "." + r[i + 2] + "." + r[i + 3]);
            i += len;
        }
        return res.ToArray();
    }
}
'@ -ErrorAction Stop } catch {
    # без VGNative служба работать не может: причину — в журнал (раньше молча падала снова и снова)
    if (-not ('VGNative' -as [type])) { Log "не компилируется встроенный код C# — служба не запустится: $($_.Exception.Message)"; throw }
}
$NoTime = -1e15        # «никогда» для меток [VGNative]::Now()

# Внешняя программа (icacls и т.п.) без исключений: при $ErrorActionPreference = 'Stop' её
# stderr в PowerShell 5.1 становится исключением и обрывает всё вокруг — например, заморозку
# остальных приложений. Возвращает код выхода.
function Invoke-Native([string]$exe, [string[]]$argv) {
    $ErrorActionPreference = 'Continue'
    & $exe @argv 2>&1 | Out-Null
    return $LASTEXITCODE
}

# ---- адреса и подсети -------------------------------------------------------
# «160.79.104.5/21» → «160.79.104.0/21»; не адрес, кривая маска или шире /8 (/16 для
# IPv6) → $null. Одна кривая строка не должна ломать всё правило: New-NetFirewallRule
# отвергает список целиком.
function ConvertTo-Cidr([string]$s) {
    $ip, $len = "$s".Trim() -split '/', 2
    $a = $null
    if (-not [Net.IPAddress]::TryParse($ip, [ref]$a)) { return $null }
    $v6 = "$($a.AddressFamily)" -eq 'InterNetworkV6'
    # TryParse принимает и «1» (= 0.0.0.1) — требуем полную запись
    if ($v6) { if ($ip -notmatch ':') { return $null } } elseif ($ip -notmatch '^\d{1,3}(\.\d{1,3}){3}$') { return $null }
    $max = if ($v6) { 128 } else { 32 }
    if ($null -eq $len) { $n = $max } elseif ($len -match '^\d{1,3}$' -and [int]$len -le $max) { $n = [int]$len } else { return $null }
    if ($n -lt $(if ($v6) { 16 } else { 8 })) { return $null }
    $b = $a.GetAddressBytes()
    for ($i = 0; $i -lt $b.Length; $i++) {
        $keep = [Math]::Max(0, [Math]::Min(8, $n - 8 * $i))
        $b[$i] = [byte]($b[$i] -band ((0xFF -shl (8 - $keep)) -band 0xFF))
    }
    $net = (New-Object Net.IPAddress -ArgumentList (, $b)).ToString()
    if ($n -eq $max) { return $net }
    return "$net/$n"
}

function Test-InNet([string]$ip, [string]$cidr) {
    $net, $n = $cidr -split '/', 2
    $a = ([Net.IPAddress]::Parse($ip)).GetAddressBytes(); $b = ([Net.IPAddress]::Parse($net)).GetAddressBytes()
    if ($a.Length -ne $b.Length) { return $false }
    if ($null -eq $n) { $n = 8 * $a.Length }
    for ($i = 0; $i -lt $a.Length -and 8 * $i -lt [int]$n; $i++) {
        $m = (0xFF -shl (8 - [Math]::Min(8, [int]$n - 8 * $i))) -band 0xFF
        if (($a[$i] -band $m) -ne ($b[$i] -band $m)) { return $false }
    }
    return $true
}

# Адрес из DNS годится в правило, только если он публичный: частные, CGNAT, fake-IP
# прокси-клиентов (198.18/15), служебные и адреса проверки страны — нет.
$NotPublic = @('0.0.0.0/8', '10.0.0.0/8', '100.64.0.0/10', '127.0.0.0/8', '169.254.0.0/16', '172.16.0.0/12',
               '192.0.0.0/24', '192.168.0.0/16', '198.18.0.0/15', '224.0.0.0/4', '240.0.0.0/4',
               '::/127', 'fe80::/10', 'fc00::/7', 'ff00::/8', '::ffff:0:0/96') + $GeoIPs
function Test-PublicIp([string]$ip) {
    $a = $null
    if (-not [Net.IPAddress]::TryParse($ip, [ref]$a) -or $ip -match '%') { return $false }
    foreach ($n in $NotPublic) { if (Test-InNet $ip $n) { return $false } }
    return $true
}

function Test-HostName([string]$h) {
    $h -match '^(?=.{1,253}$)([A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z][A-Za-z0-9-]{0,62}$'
}

# ---- конфиг -----------------------------------------------------------------
# Страны, из которых VPN считается выключенным: Россия, Китай, Беларусь, Иран
$DefaultCountries = @('RU', 'CN', 'BY', 'IR')
# Сети Anthropic (проверено 2026-10-09: ARIN AP-2440 «Anthropic, PBC», RIPEstat,
# https://platform.claude.com/docs/en/api/ip-addresses). Сюда ходят claude.ai, claude.com,
# api.anthropic.com (160.79.104.10 / 2607:6bc0::10). Аренда у Cogent/Zayo — перепроверять.
$DefaultNets = @('160.79.104.0/21', '2607:6bc0::/32', '153.61.0.0/16', '216.73.216.0/22',
                 '38.46.212.0/24', '38.84.152.0/24', '209.249.57.0/24')
# Имена вне этих сетей: облачные адреса Anthropic и её телеметрия (Sentry, Datadog,
# Intercom). Резолвятся в фоне раз в hosts_ttl с, адреса копятся (не больше 256).
# Цена: пока VPN нет, Datadog, Sentry и Intercom недоступны и другим программам.
$DefaultHosts = @('downloads.claude.ai', 'assets.claude.ai', 'pivot.claude.ai', 'a-cdn.anthropic.com',
                  's-cdn.anthropic.com', 'o1158394.ingest.us.sentry.io', 'http-intake.logs.us5.datadoghq.com',
                  'browser-intake-us5-datadoghq.com', 'logs.browser-intake-us5-datadoghq.com', 'api-iam.intercom.io')
# Встроенные адреса этих имён (как HOSTS_SEED на macOS): в правиле с первой секунды, даже
# если DNS ещё не ответил или резолвить нельзя (выход не через туннель). Берутся только для
# имён, которые есть в block_hosts.
$HostsSeed = @{
    'downloads.claude.ai' = @('35.190.46.17'); 'assets.claude.ai' = @('34.120.108.227')
    'pivot.claude.ai' = @('34.50.145.103'); 'a-cdn.anthropic.com' = @('34.36.57.103')
    's-cdn.anthropic.com' = @('34.54.194.141'); 'o1158394.ingest.us.sentry.io' = @('34.160.81.0', '2600:1901:0:5e8a::')
    'http-intake.logs.us5.datadoghq.com' = @('34.149.66.165', '2600:1901:0:9e23::')
    'browser-intake-us5-datadoghq.com' = @('34.149.66.163', '2600:1901:0:5ae7::')
    'logs.browser-intake-us5-datadoghq.com' = @('34.149.66.163')
}

# Принимает и испорченное: строку «RU,CN» (или через ; и пробелы) и {"value": [...], "Count": N} —
# так PowerShell 5.1 записывал массив установщиком d674bf9. Раньше такое давало пустой список,
# и страна молча не проверялась.
function Normalize-Countries($list) {
    $flat = foreach ($x in @($list)) {
        if ($null -eq $x) { continue }
        if ($x -isnot [string] -and $x.PSObject.Properties['value']) { $x = $x.value }
        foreach ($y in @($x)) { "$y" -split '[,;\s]+' }
    }
    @(@($flat) | ForEach-Object { "$_".Trim().ToUpper() } | Where-Object { $_ -match '^[A-Z]{2}$' } | Select-Object -Unique)
}

function Default-Conf {
    [pscustomobject]@{
        apps = @(); checks = @('route', 'geo'); require = 'all'; on_down = 'freeze'
        lock_launch = $true; block_nets = $DefaultNets; block_hosts = $DefaultHosts; hosts_ttl = 300
        interval = 1; geo_ttl = 1; geo_ttl_down = 1; geo_stale = 60; grace = 0
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
# Сравниваются SID, а не имена: в русской Windows SYSTEM называется «NT AUTHORITY\СИСТЕМА»,
# и проверка по именам считала безопасный конфиг чужим (а локальный пользователь с именем
# на «...SYSTEM» прошёл бы её).
$ConfWriters = @('S-1-5-18',            # SYSTEM
                 'S-1-5-32-544',        # Администраторы
                 'S-1-3-0',             # CREATOR OWNER
                 'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464')   # TrustedInstaller
# Проверяются и владелец (он может переписать права в любой момент — так было, если папку
# заранее создал обычный пользователь), и права папки: кто может создавать и удалять в ней
# файлы, тот подменит config.json целиком.
function Test-ConfSafe([string]$f) {
    if (-not (Test-Path $f)) { return $false }
    foreach ($p in @($f, (Split-Path $f -Parent))) {
        $acl = Get-Acl $p
        if ($ConfWriters -notcontains $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value) { return $false }
        # только биты записи: WriteData (у папки — создание файлов), AppendData (создание папок),
        # WriteEA, WriteAttributes, Delete, ChangePermissions, TakeOwnership, GENERIC_WRITE,
        # GENERIC_ALL, у папки ещё DeleteChild (у Modify/FullControl они есть, у ReadAndExecute — нет)
        $mask = if ($p -eq $f) { 0x500D0116 } else { 0x500D0156 }
        $bad = @($acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier]) | Where-Object {
            "$($_.AccessControlType)" -eq 'Allow' -and
            # «только для вложенных» (наследуемое) к самой папке не относится
            -not ("$($_.PropagationFlags)" -match 'InheritOnly') -and
            ([int]$_.FileSystemRights -band $mask) -and
            $ConfWriters -notcontains $_.IdentityReference.Value
        })
        if ($bad.Count) { return $false }
    }
    return $true
}

# Числа и флаги из конфига: не число («5m», «off») — значение по умолчанию с предупреждением,
# меньше допустимого — $low. Раньше [int]"5m" бросало исключение, и демон падал при старте
# снова и снова.
function Get-Num($v, [double]$def, [double]$min, [double]$low, [string]$name) {
    $d = 0.0
    if ($null -eq $v) { return $def }
    if ($v -is [bool] -or -not [double]::TryParse("$v", [Globalization.NumberStyles]::Float, [Globalization.CultureInfo]::InvariantCulture, [ref]$d) -or
        [double]::IsNaN($d) -or [double]::IsInfinity($d)) {
        WarnOnce "conf:num:${name}:$v" "конфиг: $name = «$v» — не число, беру $def"
        return $def
    }
    if ($d -lt $min) { return $low }
    return $d
}
function Get-Flag($v, [bool]$def, [string]$name) {
    if ($v -is [bool]) { return $v }
    if ($null -eq $v) { return $def }
    $s = "$v".Trim()
    if ($s -match '^(?i:true|1|yes|да)$') { return $true }
    if ($s -match '^(?i:false|0|no|нет)$') { return $false }
    WarnOnce "conf:flag:${name}:$v" "конфиг: $name = «$v» — не true/false, беру $def"
    return $def
}

# $null — конфиг не годится (нет файла, чужие права, битый JSON): демон тогда работает
# по прежним настройкам, а при старте — по Default-Conf (сеть к Anthropic закрыта).
# Раньше в этих случаях снималась вся блокировка.
function Load-Conf {
    $c = Default-Conf
    if (-not (Test-Path $ConfPath)) { WarnOnce 'conf:none' "нет $ConfPath — работаю по прежним настройкам"; return $null }
    if (-not (Test-ConfSafe $ConfPath)) { WarnOnce 'conf:unsafe' "в $ConfPath могут писать не только администраторы — не читаю, работаю по прежним настройкам"; return $null }
    # файл могли поймать посреди записи — тогда вернуть $null, и демон оставит прежний конфиг
    try { $j = Get-Content $ConfPath -Raw -Encoding UTF8 | ConvertFrom-Json } catch { WarnOnce "conf:bad:$_" "конфиг не читается: $_ — работаю по прежним настройкам"; return $null }
    if (-not $j) { WarnOnce 'conf:empty' "конфиг пуст — работаю по прежним настройкам"; return $null }
    Reset-Warn 'conf:'
    foreach ($k in $c.PSObject.Properties.Name) { if ($null -ne $j.$k) { $c.$k = $j.$k } }
    # старый конфиг без block_countries: список берётся из правила geo:!RU,…
    if ($j.PSObject.Properties.Name -notcontains 'block_countries') {
        $legacy = @($c.checks) | Where-Object { "$_" -like 'geo:!*' } | Select-Object -First 1
        if ($legacy) { $c.block_countries = @("$legacy".Substring(5) -split ',') }
    }
    $rawCc = @(@($c.block_countries) | Where-Object { $null -ne $_ -and "$_".Trim() })
    $c.block_countries = Normalize-Countries $c.block_countries
    # список был, но ни одной годной страны — не «не проверять», а по умолчанию ([] — не проверять)
    if ($rawCc.Count -and -not @($c.block_countries).Count) {
        WarnOnce "conf:cc:$($rawCc -join ',')" "block_countries: «$($rawCc -join ', ')» — ни одной страны (нужны коды вида RU), беру по умолчанию: $($DefaultCountries -join ' ')"
        $c.block_countries = $DefaultCountries
    }
    $c.interval    = Get-Num $c.interval 1 1 1 'interval'
    $c.geo_ttl      = Get-Num $c.geo_ttl 1 1 1 'geo_ttl'
    $c.geo_ttl_down = Get-Num $c.geo_ttl_down 1 1 1 'geo_ttl_down'
    $c.geo_stale    = Get-Num $c.geo_stale 60 0 60 'geo_stale'
    $c.hosts_ttl    = Get-Num $c.hosts_ttl 300 30 300 'hosts_ttl'
    $c.grace        = Get-Num $c.grace 0 0 0 'grace'
    $c.lock_launch  = Get-Flag $c.lock_launch $true 'lock_launch'
    $c.net_watch    = Get-Flag $c.net_watch $true 'net_watch'
    $c.checks = @(@($c.checks) | ForEach-Object { $_ } | ForEach-Object { "$_".Trim() } | Where-Object { $_ })
    $c.require = "$($c.require)"; $c.on_down = "$($c.on_down)"
    $c.apps = @($c.apps | ForEach-Object { $_ } | ForEach-Object { "$_" } | Where-Object {
        if (Test-SafeAppPath $_) { $true } else { WarnOnce "bad:$_" "пропускаю недопустимый путь: $_"; $false }
    })
    # сети: кривые строки — мимо, с предупреждением; пустой список ([]) — блок выключен
    $raw = @($c.block_nets | ForEach-Object { $_ } | ForEach-Object { "$_".Trim() } | Where-Object { $_ })
    $nets = @(foreach ($n in $raw) {
        $v = ConvertTo-Cidr $n
        if (-not $v) { WarnOnce "badnet:$n" "block_nets: «$n» — не адрес/подсеть или шире /8 — пропускаю"; continue }
        $geo = @($GeoIPs | Where-Object { Test-InNet $_ $v })
        if ($geo) { WarnOnce "geonet:$n" "block_nets: «$n» закрыл бы проверку страны ($($geo -join ', ')) — пропускаю"; continue }
        $v
    })
    if ($raw.Count -and -not $nets.Count) {
        WarnOnce 'nonets' 'block_nets: ни одной годной строки — беру сети Anthropic по умолчанию'
        $nets = $DefaultNets
    }
    $c.block_nets = @($nets | Select-Object -Unique)
    $c.block_hosts = @($c.block_hosts | ForEach-Object { $_ } | ForEach-Object { "$_".Trim().ToLower() } | Where-Object {
        if (Test-HostName $_) { $true } else { WarnOnce "badhost:$_" "block_hosts: «$_» — не имя хоста, пропускаю"; $false }
    } | Select-Object -Unique)
    if ($c.require -notin 'all', 'any') { $c.require = 'all' }
    if ($c.on_down -notin 'freeze', 'kill') { $c.on_down = 'freeze' }
    if (@($c.checks).Count -eq 0) { $c.checks = @('route') }
    return $c
}

# ---- определение VPN --------------------------------------------------------
# Интерфейс, через который реально уйдёт пакет к адресу (GetBestInterfaceEx — как
# Find-NetRoute, с маршрутами 0.0.0.0/1 + 128.0.0.0/1 от OpenVPN/WireGuard). Дёшево —
# поэтому каждый круг, без кэша. $null — маршрута нет (например, IPv6 нет вовсе).
function Get-RouteIf([string]$ip) {
    $i = [VGNative]::BestIf($ip)
    if ($i -gt 0) { return $i }
    return $null
}

# Интерфейсы (Get-NetIPInterface, в том числе RAS/PPP) и адаптеры (Get-NetAdapter) — через
# WMI, поэтому кэш: не старше $NetCacheTtl с, сбрасывается событием сети; маршрут через
# индекс, которого в кэше нет, — перечитать сразу (не чаще раза за круг).
$script:NetC = @{ T = $NoTime; Ifs = @(); Info = @{} }
$script:TickT = [double]::MaxValue        # начало круга; вне демона (check/status) — без ограничения
function Update-NetCache([switch]$Force) {
    $C = $script:NetC; $now = [VGNative]::Now(); $age = $now - $C.T
    if (-not $Force -and $age -ge 0 -and $age -lt $NetCacheTtl) { return }
    $C.T = $now                            # и при ошибке: не долбить WMI каждый круг
    try { $ifs = @(Get-NetIPInterface -ErrorAction Stop) }
    catch { WarnOnce "netif:$($_.Exception.Message)" "не удалось получить список интерфейсов: $($_.Exception.Message)"; return }
    # Без списка адаптеров каждый интерфейс выглядел бы подключением без адаптера (RAS) —
    # при ошибке или пустом ответе оставить прежний кэш
    try { $adl = @(Get-NetAdapter -IncludeHidden -ErrorAction SilentlyContinue) }
    catch { WarnOnce "netad:$($_.Exception.Message)" "не удалось получить список адаптеров: $($_.Exception.Message) — оставляю прежний"; return }
    if (-not $adl.Count -and @($ifs | Where-Object { "$($_.InterfaceAlias)" -notlike 'Loopback Pseudo-Interface*' }).Count) {
        WarnOnce 'netad:empty' 'список адаптеров пуст, а интерфейсы есть — оставляю прежний'
        return
    }
    $ads = @{}
    foreach ($a in $adl) { $ads[[int]$a.ifIndex] = $a }
    $info = @{}
    foreach ($i in $ifs) {
        $x = [int]$i.InterfaceIndex
        if ($info.ContainsKey($x)) { continue }
        $a = $ads[$x]
        $info[$x] = [pscustomobject]@{
            Index = $x; Alias = "$($i.InterfaceAlias)"
            Desc = if ($a) { "$($a.InterfaceDescription)" } else { '' }
            Hardware = if ($a) { [bool]$a.HardwareInterface } else { $false }
            Adapter = [bool]$a                 # нет NetAdapter — RAS/PPP-подключение
            Tun = $null
        }
        $info[$x].Tun = Test-Tunnel $info[$x]  # вывод «туннель или нет» — тоже раз на обновление списка
    }
    $C.Ifs = $ifs; $C.Info = $info
}

function Get-AdapterInfo([int]$idx) {
    $C = $script:NetC; $t = $script:TickT
    # быстрый путь круга: индекс известен, список свежий
    if ($C.T -le $t -and ($t - $C.T) -lt $NetCacheTtl -and $C.Info.ContainsKey($idx)) { return $C.Info[$idx] }
    Update-NetCache
    if (-not $script:NetC.Info.ContainsKey($idx) -and $script:NetC.T -lt $script:TickT) { Update-NetCache -Force }
    if ($script:NetC.Info.ContainsKey($idx)) { return $script:NetC.Info[$idx] }
    # интерфейса нет даже в свежем списке (WMI не ответил) — не туннель: лучше закрыть,
    # чем принять неизвестно что за VPN (раньше такой считался RAS-подключением, то есть туннелем)
    return [pscustomobject]@{ Index = $idx; Alias = "#$idx"; Desc = ''; Hardware = $true; Adapter = $true }
}

function Get-EgressAdapter {
    $i = Get-RouteIf '1.1.1.1'
    if ($null -eq $i) { return $null }
    return (Get-AdapterInfo $i)
}

# Имена VPN-подключений Windows (RAS): общие (Get-VpnConnection -AllUserConnection) и из
# телефонных книг пользователей (rasphone.pbk, Type=2 — VPN; 5 — широкополосное, то есть
# PPPoE). Нужны, только когда у интерфейса нет NetAdapter; кэш на 30 с.
$script:RasC = @{ T = $NoTime; Names = @() }
function Read-PbkVpn([string[]]$lines) {
    $r = @(); $name = $null; $type = ''; $pppoe = $false
    foreach ($l in @($lines) + @('[]')) {
        if ($l -match '^\s*\[(.*)\]\s*$') {
            if ($name -and $type -eq '2' -and -not $pppoe) { $r += $name }
            $name = $Matches[1]; $type = ''; $pppoe = $false
        } elseif (-not $type -and $l -match '^\s*Type\s*=\s*(\d+)') { $type = $Matches[1] }
        elseif ($l -match '(?i)pppoe') { $pppoe = $true }
    }
    return $r
}
function Get-RasVpnNames {
    $C = $script:RasC; $now = [VGNative]::Now(); $age = $now - $C.T
    if ($age -ge 0 -and $age -lt 30) { return $C.Names }
    $C.T = $now
    $n = @()
    try { $n += @(Get-VpnConnection -AllUserConnection -ErrorAction Stop | ForEach-Object { "$($_.Name)" }) } catch {}
    $pbk = @(Join-Path $env:ProgramData 'Microsoft\Network\Connections\Pbk\rasphone.pbk') +
           @(Get-ChildItem (Join-Path $env:SystemDrive 'Users') -Directory -ErrorAction SilentlyContinue |
             ForEach-Object { Join-Path $_.FullName 'AppData\Roaming\Microsoft\Network\Connections\Pbk\rasphone.pbk' })
    foreach ($f in $pbk) {
        try { if ([IO.File]::Exists($f)) { $n += @(Read-PbkVpn ([IO.File]::ReadAllLines($f))) } } catch {}
    }
    $C.Names = @($n | Where-Object { $_ } | Select-Object -Unique)
    return $C.Names
}

function Test-Tunnel($e) {
    if (-not $e) { return $false }
    if ($e.Tun -is [bool]) { return $e.Tun }
    if ($TestTunnelIfs.Count -and $TestTunnelIfs -contains "$($e.Alias)") { return $true }
    $s = "$($e.Alias) $($e.Desc)"
    if ($s -match $NotTunnelRx) { return $false }
    # подключение без NetAdapter (RAS): туннель, только если это VPN-подключение Windows,
    # а не PPPoE провайдера
    if (-not $e.Adapter) { return (@(Get-RasVpnNames) -contains "$($e.Alias)") }
    return ($s -match $TunnelRx)
}

# route: в туннель идёт не только 1.1.1.1, но и адрес Anthropic по IPv4. Split-tunnel,
# при котором 160.79.104.0/21 идёт мимо, — это VPN выключен. Нет маршрута к адресу
# вообще — не утечка.
# IPv6 мимо туннеля VPN не выключает: у многих провайдеров в России IPv6 свой, а VPN
# только IPv4. В режиме up IPv6-адреса из списка закрываются отдельным правилом на ВСЕХ
# интерфейсах (Set-Firewall 'via', $script:V6Bypass), а остальное — правилом на всех
# интерфейсах, кроме туннеля. Но только если закрыть точно получится: адрес покрыт
# block_nets, брандмауэр правила применяет (Test-FwEnforced, в том числе ни один интерфейс
# не исключён из защиты), правило ставится без ошибки и интерфейс известен (есть в списке
# интерфейсов, значит, и в правиле «только через»). Иначе VPN не засчитан, как раньше.
function Test-RouteCheck($e, $conf) {
    if (-not (Test-Tunnel $e)) { return $false }
    foreach ($ip in $RouteProbes) {
        $i = Get-RouteIf $ip
        if ($null -eq $i -or $i -eq $e.Index) { continue }
        $o = Get-AdapterInfo $i
        if (Test-Tunnel $o) { continue }
        if ($ip -match ':' -and @(@($conf.block_nets) | Where-Object { "$_" -match ':' -and (Test-InNet $ip "$_") }).Count) {
            $why = if ($null -eq $script:FwEnf) { 'брандмауэр ещё не проверен' } elseif ($script:FwEnf) { $script:FwEnf }
                   elseif ($script:Fw.Err) { $script:Fw.Err }
                   elseif (-not $script:NetC.Info.ContainsKey([int]$i) -or "$($o.Alias)" -like 'Loopback Pseudo-Interface*') { "интерфейс #$i не найден в списке интерфейсов" }
                   else { '' }
            if (-not $why) {
                $script:V6Bypass = $true
                WarnOnce "rt6:${ip}:$i" "маршрут к $ip (Anthropic, IPv6) идёт мимо туннеля, через $($o.Alias) — не помеха: IPv6-адреса Anthropic закрыты брандмауэром на всех интерфейсах"
                continue
            }
            WarnOnce "rt6no:${ip}:${i}:$why" "маршрут к $ip (Anthropic, IPv6) идёт мимо туннеля, через $($o.Alias), а закрыть его брандмауэром нельзя ($why) — VPN не засчитан"
            return $false
        }
        WarnOnce "rt:${ip}:$i" "маршрут к $ip (Anthropic) идёт мимо туннеля, через $($o.Alias) — VPN не засчитан$(if ($ip -match ':') { ': этого адреса нет в block_nets. Верни туда 2607:6bc0::/32, включи IPv6 в VPN или выключи IPv6 на этом адаптере' })"
        return $false
    }
    return $true
}

# ---- страна выхода (geo) ------------------------------------------------------
# Запрос не держит круг: HttpClient асинхронный, круг только забирает готовый ответ.
# Каждый раз новое соединение (Connection: close): по старому keep-alive проба могла
# бы ехать через прежний узел прокси и показывать прежнюю страну.
# Адреса по очереди. Ответ на запрос, начатый до события сети, не в счёт.
$script:StartT = [VGNative]::Now()
$script:Geo = @{
    Req = $null; LastRoundT = $NoTime; LastOk = $false
    GoodT = $NoTime; GoodCC = ''; GoodIf = ''
    EventT = $script:StartT; LastIf = $null; Sync = $false
}
$script:GuardDown = $false
$script:ResumeT = $NoTime     # круг после перерыва дольше $GapSec с (сон, гибернация)
$GapSec = 10

# IPv4 из URL проверки страны; $null — в URL имя или IPv6
function Get-GeoIp([string]$url) {
    $u = $null
    if (-not [Uri]::TryCreate($url, [UriKind]::Absolute, [ref]$u)) { return $null }
    if ("$($u.HostNameType)" -ne 'IPv4') { return $null }
    return $u.Host
}
# Запрос страны уходит, только если пакет к этому адресу пойдёт через проверенный туннель $e:
# при split-tunnel или запасном адресе вне туннеля он ушёл бы с настоящего адреса
function Test-GeoPath([int]$idx, $e) {
    $ip = Get-GeoIp $GeoUrls[$idx]
    if (-not $ip) { WarnOnce "geourl:$($GeoUrls[$idx])" "адрес проверки страны $($GeoUrls[$idx]) — не IPv4-литерал: не спрашиваю (DNS и IPv6 ушли бы мимо туннеля)"; return $false }
    if (-not $e) { return $false }
    $i = [VGNative]::BestIf($ip)
    if ($i -ne $e.Index) {
        WarnOnce "geort:${ip}:${i}:$($e.Index)" "маршрут к $ip (проверка страны) идёт не через туннель $($e.Alias) (интерфейс #$i) — этот адрес не спрашиваю"
        return $false
    }
    return $true
}
# Запрос к $url — с адреса туннеля $e (VGNative.BindEP): Windows отправит его только через
# туннель, даже если маршрут успел смениться после проверки. $false — у туннеля нет IPv4.
function Set-TunnelBind([string]$url, $e) {
    $a = if ($e) { [VGNative]::IfAddr4([int]$e.Index) } else { $null }
    if (-not $a) { WarnOnce "bind:$($e.Alias)" "у туннеля $($e.Alias) нет IPv4-адреса — к $url не обращаюсь"; return $false }
    [VGNative]::BindAddr = [Net.IPAddress]::Parse($a)
    [VGNative]::BindTo($url)
    return $true
}
# HttpClient без системного прокси (он увёл бы запрос мимо туннеля) и без переадресаций
function New-DirectClient([int]$sec) {
    $h = New-Object Net.Http.HttpClientHandler
    $h.UseProxy = $false; $h.AllowAutoRedirect = $false
    $c = New-Object Net.Http.HttpClient -ArgumentList $h
    $c.Timeout = [TimeSpan]::FromSeconds($sec)
    return $c
}
# Запрос к первому годному адресу, начиная с $idx; $null — годных нет (это «нет ответа»).
# Без системного прокси (он увёл бы запрос мимо туннеля) и без переадресаций.
function New-GeoRequest([int]$idx, $e) {
    for (; $idx -lt $GeoUrls.Count; $idx++) {
        if (-not (Test-GeoPath $idx $e)) { continue }
        if (-not (Set-TunnelBind $GeoUrls[$idx] $e)) { continue }
        $c = New-DirectClient $GeoTimeout
        $c.DefaultRequestHeaders.ConnectionClose = $true
        return @{ Client = $c; Task = $c.GetStringAsync($GeoUrls[$idx]); Idx = $idx; If = "$($e.Index)"; Start = [VGNative]::Now() }
    }
    return $null
}
function Fail-GeoRound($now) {
    $G = $script:Geo
    $G.LastOk = $false; $G.LastRoundT = $now
    WarnOnce "geofail:$($G.GoodT)" "Cloudflare не ответил — сеть к Anthropic закрыта до ответа$(if ($G.GoodCC) { " (прошлая страна $($G.GoodCC))" })"
}
function Read-GeoReply($r) {
    $cc = ''
    if ($r.Task.IsCompleted -and "$($r.Task.Status)" -eq 'RanToCompletion') {
        foreach ($l in ($r.Task.Result -split "`n")) { if ($l -match '^loc=([A-Za-z]{2})\s*$') { $cc = $Matches[1].ToUpper(); break } }
    }
    try { $r.Client.Dispose() } catch {}     # недождавшийся запрос этим и отменяется
    return $cc
}

# Вызывается каждый круг, пока проверка geo вообще нужна. Ничего не ждёт.
function Pump-Geo($conf, $e) {
    $G = $script:Geo
    if ($G.Sync) { return }                  # check/status: уже спросили синхронно (Sync-Geo)
    $now = [VGNative]::Now()
    $if = if ($e) { "$($e.Index)" } else { '' }
    if ($null -ne $G.LastIf -and $if -ne $G.LastIf) { $G.EventT = $now }   # сменился интерфейс — как событие сети
    $G.LastIf = $if
    if ($G.Req) {
        $r = $G.Req; $age = $now - $r.Start
        if ($r.Task.IsCompleted -or $age -gt $GeoTimeout + 1 -or $age -lt 0) {
            $cc = Read-GeoReply $r; $G.Req = $null
            if ($r.Start -le $G.EventT -or $r.If -ne $if) { $G.LastRoundT = $NoTime }   # устарел — спросить заново
            elseif ($cc) { $G.GoodT = $now; $G.GoodCC = $cc; $G.GoodIf = $if; $G.LastOk = $true; $G.LastRoundT = $now }
            else {
                # следующий адрес — тоже только через туннель
                $G.Req = New-GeoRequest ($r.Idx + 1) $e
                if (-not $G.Req) { Fail-GeoRound $now }
            }
        }
    }
    if (-not $G.Req -and $e) {
        $ttl = if ($script:GuardDown) { $conf.geo_ttl_down } else { $conf.geo_ttl }
        $age = $now - $G.LastRoundT
        if ($G.LastRoundT -le $G.EventT -or $age -lt 0 -or $age -ge $ttl) {
            $G.Req = New-GeoRequest 0 $e
            if (-not $G.Req) { Fail-GeoRound $now }
        }
    }
}

# Для check/status: один синхронный опрос (по тем же правилам: только через туннель)
function Sync-Geo($e) {
    $G = $script:Geo; $if = if ($e) { "$($e.Index)" } else { '' }
    $G.EventT = $NoTime; $G.LastIf = $if; $G.LastOk = $false; $G.Sync = $true
    $i = 0
    while ($null -ne ($r = New-GeoRequest $i $e)) {
        try { [void]$r.Task.Wait(($GeoTimeout + 1) * 1000) } catch {}
        $cc = Read-GeoReply $r
        if ($cc) { $G.GoodT = [VGNative]::Now(); $G.GoodCC = $cc; $G.GoodIf = $if; $G.LastOk = $true; break }
        $i = $r.Idx + 1
    }
    $G.LastRoundT = [VGNative]::Now()
}

# Выход (маршрут к 1.1.1.1) не через туннель: страну не спрашивать вовсе — запрос ушёл бы
# с настоящего адреса (в России — с российского), а ответ и так ясен: VPN нет. Так же
# делает демон на macOS. Начатый раньше запрос отменяется; туннель вернётся — Pump-Geo
# увидит смену интерфейса и засчитает только свежий ответ.
function Stop-Geo($e) {
    $G = $script:Geo
    if ($G.Req) { [void](Read-GeoReply $G.Req); $G.Req = $null }
    # GoodIf тоже забыть: туннель вернётся с тем же индексом — до свежего ответа страны нет
    $G.LastRoundT = $NoTime; $G.LastIf = ''; $G.LastOk = $false; $G.GoodIf = ''
    $k = if ($e) { "$($e.Alias)" } else { '' }
    WarnOnce "nogeo:$k" "выход $(if ($e) { "через $($e.Alias)" } else { 'не найден' }) — не туннель: страну не спрашиваю (запрос ушёл бы с настоящего адреса), VPN не засчитан"
}
# страна для журнала и статуса: только ответ, полученный через нынешний выход
function Geo-Shown {
    $G = $script:Geo
    if ($G.GoodCC -and $G.GoodIf -and $G.GoodIf -eq $G.LastIf) { return $G.GoodCC }
    return ''
}

# $true — страна свежая и разрешённая; $false — запрещённая (или молчание дольше
# geo_stale); $null — «не уверен»: ответа после события сети ещё нет / Cloudflare молчит.
function Get-GeoVerdict($conf, [string[]]$list, [bool]$allow) {
    $G = $script:Geo; $now = [VGNative]::Now()
    $ttl = if ($script:GuardDown) { $conf.geo_ttl_down } else { $conf.geo_ttl }
    $cc = $G.GoodCC
    $good = if (-not $cc) { $false } elseif ($allow) { $list -contains $cc } else { -not ($list -contains $cc) }
    if ($cc -and -not $good) { return $false }   # последняя известная страна — запрещённая
    # возраст ответа меньше нуля (метка «из будущего») — не свежий
    $age = $now - $G.GoodT
    $fresh = $G.LastOk -and $G.GoodT -gt $G.EventT -and $G.GoodIf -eq $G.LastIf -and $age -ge 0 -and $age -le $ttl + $GeoTimeout + 2
    if ($fresh -and $good) { return $true }
    # отсчёт geo_stale — от последнего ответа, старта или пробуждения после сна (ResumeT): иначе
    # после сна дольше geo_stale сразу down и заморозка, хотя свежий ответ придёт через секунду
    $ref = [Math]::Max([Math]::Max($G.GoodT, $script:StartT), $script:ResumeT)
    $since = $now - $ref
    if ($since -ge 0 -and $since -lt $conf.geo_stale) { return $null }
    return $false
}

# $true / $false / $null (не уверен)
function Test-Check([string]$rule, $conf, $e) {
    if ($rule -eq 'route') { return (Test-RouteCheck $e $conf) }   # частые случаи — без перебора шаблонов
    switch -Regex ($rule) {
        '^route$'      { return (Test-RouteCheck $e $conf) }
        # geo, geo:!RU — страна выхода не из block_countries (пустой список — не проверять)
        '^geo(:!.*)?$' {
            $bad = @($conf.block_countries)
            if ($bad.Count -eq 0) { return $true }
            if (-not (Test-Tunnel $e)) { Stop-Geo $e; return $false }
            Pump-Geo $conf $e
            return (Get-GeoVerdict $conf $bad $false)
        }
        # geo:FR,NL — страна выхода из списка
        '^geo:([^!].*)$' {
            $spec = @(Normalize-Countries ($Matches[1] -split ','))
            if (-not (Test-Tunnel $e)) { Stop-Geo $e; return $false }
            Pump-Geo $conf $e
            return (Get-GeoVerdict $conf $spec $true)
        }
        '^adapter:(.+)$' { return [bool](Get-NetAdapter -Name $Matches[1] -IncludeHidden -ErrorAction SilentlyContinue | Where-Object Status -eq 'Up') }
        '^proc:(.+)$'  { return [bool](Get-Process -Name $Matches[1] -ErrorAction SilentlyContinue) }
        '^script:(.+)$' { return ((Invoke-Native $Matches[1] @()) -eq 0) }
        default        { WarnOnce "rule:$rule" "неизвестное правило: $rule — считаю невыполненным"; return $false }
    }
}

# require=all: любое «нет» — нет, иначе любое «не уверен» — не уверен.
# require=any: любое «да» — да, иначе любое «не уверен» — не уверен.
function Get-VpnVerdict($conf, $e) {
    $unsure = $false
    foreach ($r in $conf.checks) {
        $x = Test-Check $r $conf $e
        if ($null -eq $x) { $unsure = $true; continue }
        if ($conf.require -eq 'all' -and -not $x) { return $false }
        if ($conf.require -eq 'any' -and $x) { return $true }
    }
    if ($unsure) { return $null }
    return ($conf.require -eq 'all')
}

# ---- процессы ---------------------------------------------------------------
# Процессы из папок приложений $apps — один снимок (VGNative.Procs): ProcessId, Name,
# ExecutablePath и Frozen. Раньше — Get-CimInstance Win32_Process (WMI) и Get-Process
# на каждый процесс по два раза за круг.
function Get-ProcsIn($apps) {
    $dirs = [string[]]@(@($apps) | Where-Object { $_ } | ForEach-Object { (App-Folder "$_") + '\' })
    if (-not $dirs.Count) { return @() }
    return [VGNative]::Procs($dirs)
}
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

# $all — снимок Get-ProcsIn этого круга; Frozen в нём правится по ходу, чтобы статус
# показывал уже сделанное
function Freeze-App([string]$app, $all) {
    foreach ($p in (Get-AppProcs $app $all)) {
        if ($p.Frozen) { continue }                            # NtSuspend копит счётчик — не повторять
        if ([VGNative]::Suspend([int]$p.ProcessId)) { $p.Frozen = $true; Log "заморожен процесс $($p.ProcessId) ($($p.Name))" }
    }
}
function Resume-App([string]$app, $all) {
    foreach ($p in (Get-AppProcs $app $all)) {
        if (-not $p.Frozen) { continue }
        $n = 0
        do { [void][VGNative]::Resume([int]$p.ProcessId); $n++ } while ((Test-Frozen $p.ProcessId) -and $n -lt 10)
        $p.Frozen = $false
        Log "разморожен процесс $($p.ProcessId) ($($p.Name))"
    }
}
function Kill-App([string]$app, $all) {
    foreach ($p in (Get-AppProcs $app $all)) {
        Stop-Process -Id $p.ProcessId -Force -ErrorAction SilentlyContinue
        Log "закрыт процесс $($p.ProcessId) ($($p.Name))"
    }
}

# ---- запрет запуска ---------------------------------------------------------
# -Encoding UTF8: Save-State пишет UTF-8 без BOM — иначе PowerShell 5.1 прочёл бы пути с кириллицей как ANSI
function Load-State { if (Test-Path $StatePath) { try { return (Get-Content $StatePath -Raw -Encoding UTF8 | ConvertFrom-Json) } catch {} }; [pscustomobject]@{} }
# через временный файл: оборванная запись не должна потерять список заблокированных exe
function Save-State($s) {
    $tmp = "$StatePath.$PID.tmp"
    [IO.File]::WriteAllText($tmp, ($s | ConvertTo-Json -Depth 4), (New-Object Text.UTF8Encoding $false))
    if (Test-Path $StatePath) { [IO.File]::Replace($tmp, $StatePath, [NullString]::Value) } else { [IO.File]::Move($tmp, $StatePath) }
}

function Lock-App([string]$app) {
    $dir = App-Folder $app
    if (-not (Test-Path $dir)) { WarnOnce "nodir:$app" "не нашёл $dir — проверь путь"; return }
    $st = Load-State
    $done = @(); if ($st.PSObject.Properties[$app]) { $done = @($st.$app) }
    $exes = @(Get-ChildItem -Path $dir -Filter *.exe -Recurse -Depth 2 -File -ErrorAction SilentlyContinue | ForEach-Object FullName)
    $new = @($exes | Where-Object { $done -notcontains $_ })
    if (-not $new) { return }
    # сначала записать, потом icacls: демона убьют посреди прохода — Unlock-App всё равно снимет
    # запрет (раньше запись шла после, и запрет на часть exe мог остаться навсегда)
    $st | Add-Member -NotePropertyName $app -NotePropertyValue @($done + $new) -Force
    Save-State $st
    foreach ($f in $new) {
        $rc = Invoke-Native 'icacls.exe' @($f, '/deny', '*S-1-1-0:(X)')
        if ($rc -eq 0) { $done += $f } else { WarnOnce "acl:$f" "не смог запретить запуск $f (icacls: код $rc)" }
    }
    # не получившиеся — из записи вон: следующий проход попробует снова
    $st | Add-Member -NotePropertyName $app -NotePropertyValue $done -Force
    Save-State $st
    Log "заблокирован запуск: $app ($($done.Count) exe)"
}

# Снимает запрет «Все: выполнение» с записанных exe и со всех exe папки (те, что появились
# после записи или остались от прерванного прохода). -Sweep — даже без записи (unlock).
function Unlock-App([string]$app, [switch]$Sweep) {
    $st = Load-State
    $has = [bool]$st.PSObject.Properties[$app]
    if (-not $has -and -not $Sweep) { return }
    $dir = App-Folder $app
    $files = @(@(if ($has) { $st.$app }) + @(if (Test-Path $dir) { Get-ChildItem -Path $dir -Filter *.exe -Recurse -Depth 2 -File -ErrorAction SilentlyContinue | ForEach-Object FullName }) |
               Where-Object { $_ } | Select-Object -Unique)
    foreach ($f in $files) { if (Test-Path $f) { [void](Invoke-Native 'icacls.exe' @($f, '/remove:d', '*S-1-1-0')) } }
    if ($has) { $st.PSObject.Properties.Remove($app); Save-State $st; Log "снята блокировка запуска: $app" }
}

# ---- block_hosts: имена → адреса, в фоне ---------------------------------------
# DNS через HTTPS к 1.1.1.1 ($DohUrl) тем же путём, что и страна: маршрут через проверенный
# туннель (как Test-GeoPath) и сокет с адреса туннеля. Системный резолвер не годится: его
# DNS-сервер (роутер, IPv6-DNS провайдера, после 1 с — DNS всех адаптеров) может быть мимо
# туннеля, и имена Anthropic ушли бы провайдеру. Круг не ждёт ответа, а забирает готовое на
# следующих кругах. Адреса копятся (объединение, не больше 256, вытесняются давно не
# виденные) и хранятся в hosts.json — чтобы после перезагрузки правило было полным
# ещё до первого ответа DNS. Резолвить — только пока выход через туннель: иначе запрос к
# DNS ушёл бы с настоящего адреса; тогда в правиле адреса из кэша и встроенные ($HostsSeed).
# VPN_GUARD_DOH_URL и VPN_GUARD_DNS_PORT — только для tests/run_windows.ps1
$DohUrl  = if ($env:VPN_GUARD_DOH_URL) { $env:VPN_GUARD_DOH_URL } else { 'https://1.1.1.1/dns-query' }
$DnsPort = if ($env:VPN_GUARD_DNS_PORT) { [int]$env:VPN_GUARD_DNS_PORT } else { 53 }
# fake-IP: VPN-клиент (mihomo/Clash/Hiddify/sing-box fakeip) отвечает на обычный DNS адресами
# из этой сети, и приложения ходят к Anthropic по ним — через туннель, мимо правила по
# настоящим адресам. Проверка: обычный DNS-запрос (UDP 53) к тому же 1.1.1.1 через туннель —
# такой клиент его перехватит. Подменяет — эта сеть закрыта в режимах block и hold (не в via).
$FakeNet = '198.18.0.0/15'
$script:FakeIp = $false
$script:HostIps = @{}      # адрес → @{ T = когда видели (UTC); H = имя }
$script:HostVer = 0        # растёт, когда меняется набор адресов (Get-BlockAddrs пересобирает список)
$script:Dns = @{ Tasks = @(); Start = $NoTime; LastT = $NoTime; Want = $true; Client = $null; Probe = $null }

function Load-HostIps($conf) {
    $script:HostIps = @{}
    if (-not (Test-Path $HostsPath)) { return }
    try {
        foreach ($x in @(Get-Content $HostsPath -Raw -Encoding UTF8 | ConvertFrom-Json | ForEach-Object { $_ })) {
            if ($conf.block_hosts -contains "$($x.host)" -and (Test-PublicIp "$($x.ip)")) {
                $script:HostIps["$($x.ip)"] = @{ T = [datetime]::FromFileTimeUtc([long]$x.t); H = "$($x.host)" }
            }
        }
    } catch { WarnOnce 'hostsbad' "не читается $HostsPath — начинаю список адресов заново" }
    $script:HostVer++
}
function Save-HostIps {
    $list = @(foreach ($k in $script:HostIps.Keys) { [pscustomobject]@{ ip = $k; host = $script:HostIps[$k].H; t = $script:HostIps[$k].T.ToFileTimeUtc() } })
    $tmp = "$HostsPath.$PID.tmp"
    try {
        [IO.File]::WriteAllText($tmp, (ConvertTo-Json -InputObject $list -Compress), (New-Object Text.UTF8Encoding $false))
        if (Test-Path $HostsPath) { [IO.File]::Replace($tmp, $HostsPath, [NullString]::Value) } else { [IO.File]::Move($tmp, $HostsPath) }
    } catch { WarnOnce 'hostssave' "не смог записать $HostsPath`: $_" }
}
# имя убрали из block_hosts — его адреса больше не нужны
function Prune-HostIps($conf) {
    $gone = @($script:HostIps.Keys | Where-Object { $conf.block_hosts -notcontains $script:HostIps[$_].H })
    foreach ($k in $gone) { $script:HostIps.Remove($k) }
    if ($gone) { $script:HostVer++; Save-HostIps }
}

# ответ DoH (application/dns-json) → адреса A и AAAA
function Read-DohIps([string]$json) {
    try { $j = $json | ConvertFrom-Json } catch { return @() }
    @(@($j.Answer) | Where-Object { $_ -and ($_.type -eq 1 -or $_.type -eq 28) } | ForEach-Object { "$($_.data)" })
}
# ответ на проверку fake-IP: сменилось — в журнал (сменится и ключ правила — Set-Firewall пересоберёт)
function Read-FakeProbe {
    $P = $script:Dns.Probe
    if ("$($P.Task.Status)" -eq 'RanToCompletion') {
        $ips = @([VGNative]::DnsAnswersA($P.Task.Result.Buffer))
        if ($ips.Count) {
            $fake = [bool]@($ips | Where-Object { Test-InNet $_ $FakeNet }).Count
            if ($fake -ne $script:FakeIp) {
                $script:FakeIp = $fake
                Log $(if ($fake) { "VPN-клиент подменяет адреса DNS (fake-IP: $($P.Host) → $($ips -join ', ')) — в режимах «закрыто» и «не уверен» закрываю и $FakeNet" }
                      else { "VPN-клиент больше не подменяет адреса DNS ($($P.Host) → $($ips -join ', ')) — $FakeNet не закрываю" })
            }
        }
    }
    try { $P.Udp.Close() } catch {}
    $script:Dns.Probe = $null
}
function Pump-Dns($conf, $e) {
    $D = $script:Dns; $now = [VGNative]::Now()
    if ($D.Probe) {
        $pa = $now - $D.Start
        if ($D.Probe.Task.IsCompleted -or $pa -lt 0 -or $pa -ge 5) { Read-FakeProbe }
    }
    if ($D.Tasks.Count) {
        $pending = @($D.Tasks | Where-Object { -not $_.Task.IsCompleted }).Count
        $age = $now - $D.Start
        if ($pending -and $age -ge 0 -and $age -lt 30) { return }
        $added = 0; $utc = [datetime]::UtcNow
        foreach ($t in $D.Tasks) {
            if ("$($t.Task.Status)" -ne 'RanToCompletion') { continue }
            foreach ($s in (Read-DohIps $t.Task.Result)) {
                if (-not (Test-PublicIp $s)) { continue }
                if (-not $script:HostIps.ContainsKey($s)) { $added++ }
                $script:HostIps[$s] = @{ T = $utc; H = $t.Host }
            }
        }
        try { $D.Client.Dispose() } catch {}
        $D.Tasks = @(); $D.Client = $null; $D.LastT = $now
        if ($script:HostIps.Count -gt $HostsMax) {
            $old = @($script:HostIps.Keys | Sort-Object { $script:HostIps[$_].T } | Select-Object -First ($script:HostIps.Count - $HostsMax))
            foreach ($k in $old) { $script:HostIps.Remove($k) }
            $script:HostVer++
        }
        if ($added) { $script:HostVer++; Save-HostIps; Log "block_hosts: новых адресов $added, всего $($script:HostIps.Count)" }
        return
    }
    if (-not @($conf.block_hosts).Count) { return }
    $age = $now - $D.LastT
    if ($D.Want -or $age -lt 0 -or $age -ge $conf.hosts_ttl) {
        # выход не через туннель — DNS не трогать (Want остаётся: туннель вернётся — резолвим)
        if (-not (Test-Tunnel $e)) {
            WarnOnce "dnsnotun:$(if ($e) { $e.Alias })" "выход $(if ($e) { "через $($e.Alias)" } else { 'не найден' }) — не туннель: имена block_hosts не резолвлю (запрос к DNS ушёл бы с настоящего адреса), в правиле адреса из кэша и встроенные"
            return
        }
        $ip = Get-GeoIp $DohUrl
        $i = if ($ip) { [VGNative]::BestIf($ip) } else { 0 }
        if (-not $ip -or $i -ne $e.Index) {
            WarnOnce "dohrt:${ip}:${i}:$($e.Index)" "маршрут к $(if ($ip) { $ip } else { $DohUrl }) (DNS через HTTPS) идёт не через туннель $($e.Alias) — имена block_hosts не резолвлю"
            return
        }
        if (-not (Set-TunnelBind $DohUrl $e)) { return }
        $D.Want = $false; $D.Start = $now
        $c = New-DirectClient 10
        [void]$c.DefaultRequestHeaders.Accept.TryParseAdd('application/dns-json')
        $D.Client = $c
        $D.Tasks = @(foreach ($h in $conf.block_hosts) {
            foreach ($ty in 'A', 'AAAA') { try { @{ Host = $h; Task = $c.GetStringAsync("$DohUrl`?name=$h&type=$ty") } } catch {} }
        })
        if (-not $D.Tasks.Count) { $D.LastT = $now; try { $c.Dispose() } catch {}; $D.Client = $null }
        # проверка fake-IP: обычный DNS к тому же адресу, тоже с адреса туннеля
        if (-not $D.Probe) {
            try {
                $h0 = "$(@($conf.block_hosts)[0])"
                $u = New-Object Net.Sockets.UdpClient -ArgumentList (New-Object Net.IPEndPoint -ArgumentList ([VGNative]::BindAddr), 0)
                $u.Connect($ip, $DnsPort)
                $q = [VGNative]::DnsQueryA($h0, (Get-Random -Maximum 65535))
                [void]$u.Send($q, $q.Length)
                $D.Probe = @{ Udp = $u; Task = $u.ReceiveAsync(); Host = $h0 }
            } catch { WarnOnce "probe:$($_.Exception.Message)" "проверка fake-IP не удалась: $($_.Exception.Message)" }
        }
    }
}

# ---- брандмауэр -------------------------------------------------------------
# Блок в Брандмауэре Windows всегда сильнее разрешения, поэтому «пускать только через
# туннель» = правило Block на ВСЕХ IP-интерфейсах, кроме туннеля (Get-NetIPInterface —
# в том числе RAS/PPP). Список интерфейсов входит в ключ: новый адаптер — новое правило.
# IPv6 к Anthropic идёт мимо туннеля ($script:V6Bypass) — IPv6-адреса ещё и вторым
# правилом, без списка интерфейсов: блок не зависит от того, полон ли список.
# Смена правила: сначала новое под новым именем, потом снять старые — ни мгновения без
# правила. Правило есть в ActiveStore и включено, иначе — заново: проверка (~160 мс WMI)
# раз в $FwVerifyEvery с и сразу, когда изменился реестр брандмауэра ($FwKeys: правило
# удалили, выключили, выключили профиль) и после события сети.
$script:Fw = @{ Key = ''; Names = @(); Mode = ''; Err = ''; Note = ''; ViaFail = ''; ViaFailT = $NoTime; Due = $true; VerifyT = $NoTime; Stamp = ''; RepairLogT = $NoTime; ModeLog = '' }
$script:IfsC = @{ T = $null; Idx = $null; Ifs = @(); HasE = $false }
$script:FwEnf = $null       # Test-FwEnforced: '' — правила действуют; $null — ещё не проверяли
$script:FwBlind = $false    # ActiveStore наших правил не покажет (MpsSvc стоит, политика без локальных правил)
$script:V6Bypass = $false   # на этом круге: IPv6 к Anthropic мимо туннеля, и это допустимо (Test-RouteCheck)

# Пора ли полной проверки на этом круге (результат — в $script:Fw.Due)
function Test-FwDue {
    $F = $script:Fw; $now = [VGNative]::Now(); $age = $now - $F.VerifyT
    $s = [VGNative]::KeyStamp($FwKeys)
    if ($s -ne $F.Stamp -or $age -lt 0 -or $age -ge $FwVerifyEvery) {
        $F.Stamp = $s; $F.VerifyT = $now
        return $true
    }
    return $false
}

# список адресов правила — пересобирается, только когда сменился конфиг или набор адресов block_hosts
$script:AddrC = @{ Nets = $null; Ver = -1; List = @(); Join = '' }
function Get-BlockAddrs($conf) {
    $C = $script:AddrC; $sig = (@($conf.block_nets) -join ',') + '|' + (@($conf.block_hosts) -join ',')
    if ($C.Nets -ne $sig -or $C.Ver -ne $script:HostVer) {
        $seed = @(foreach ($h in @($conf.block_hosts)) { $HostsSeed["$h"] })
        $C.List = @(@(@($conf.block_nets) + @(@($script:HostIps.Keys) + $seed | Sort-Object)) | Where-Object { $_ } | Select-Object -Unique)
        $C.Join = $C.List -join ','; $C.Nets = $sig; $C.Ver = $script:HostVer
    }
    return $C.List
}
function Remove-FwRules([string[]]$Keep = @()) {
    Get-NetFirewallRule -DisplayName $FwRule -ErrorAction SilentlyContinue |
        Where-Object { $Keep -notcontains $_.Name } | Remove-NetFirewallRule -ErrorAction SilentlyContinue
}
# в действующей политике (ActiveStore) — ровно наши правила, и все включены: пропавшее,
# выключенное или лишнее (не снятое старое) — повод пересобрать. Когда ActiveStore локальных
# правил не показывает (служба брандмауэра стоит, групповая политика их не применяет) —
# сверять с PersistentStore: иначе «восстанавливаю» каждую секунду.
function Test-FwRules([string[]]$names) {
    $store = if ($script:FwBlind) { 'PersistentStore' } else { 'ActiveStore' }
    $live = @(Get-NetFirewallRule -Group $FwGroup -PolicyStore $store -ErrorAction SilentlyContinue)
    if ($live.Count -ne @($names).Count) { return $false }
    foreach ($r in $live) {
        if (@($names) -notcontains $r.Name -or "$($r.Enabled)" -ne 'True' -or "$($r.Action)" -ne 'Block' -or "$($r.Direction)" -ne 'Outbound') { return $false }
    }
    return $true
}
function New-FwRule($addr, $ifs, [string]$desc) {
    $name = 'VPNGuard-' + [guid]::NewGuid().ToString('N').Substring(0, 8)
    $p = @{ Name = $name; DisplayName = $FwRule; Group = $FwGroup; Direction = 'Outbound'; Action = 'Block'
            RemoteAddress = @($addr); Profile = 'Any'; ErrorAction = 'Stop'; Description = $desc }
    # -InterfaceAlias — шаблон: «Local Area Connection* 1» иначе расползётся на чужие имена
    if (@($ifs).Count) { $p.InterfaceAlias = @(@($ifs) | ForEach-Object { [Management.Automation.WildcardPattern]::Escape($_) }) }
    New-NetFirewallRule @p | Out-Null
    return $name
}

# $mode: 'via' — только через туннель $e; 'block' — закрыто везде
function Set-Firewall([string]$mode, $conf, $e) {
    $F = $script:Fw
    try {
        $addrs = @(Get-BlockAddrs $conf)
        if (-not $addrs.Count) {
            if ($F.Key -ne 'none') { Remove-FwRules; $F.Key = 'none'; $F.Names = @(); Log 'block_nets и block_hosts пусты — правило брандмауэра снято' }
            $F.Mode = ''; $F.Err = 'BLOCK_NETS пуст — сеть не защищена'
            return
        }
        $ifs = @(); $via = ''
        if ($mode -ne 'via') { $F.Note = '' }
        # «только через» — только через туннель. Без него (VPN засчитан правилами proc:, adapter:,
        # script: или require=any) «только через Wi-Fi» открыло бы прямой выход к Anthropic с
        # настоящего адреса: закрыть везде (приложениям за системным прокси это не мешает)
        if ($mode -eq 'via' -and $e -and -not (Test-Tunnel $e)) {
            WarnOnce "vianotun:$($e.Alias)" "VPN засчитан, но выход через $($e.Alias) — не туннель: сеть к Anthropic закрыта везде, а не «только через» него"
            $mode = 'block'
        }
        if ($mode -eq 'via' -and $e) {
            # интерфейсы, кроме выхода, — пересчитать, только когда перечитан их список или сменился выход
            Update-NetCache
            $IC = $script:IfsC
            if ($IC.T -ne $script:NetC.T -or $IC.Idx -ne $e.Index) {
                $all = @($script:NetC.Ifs)
                $IC.Ifs = @($all | Where-Object { $_.InterfaceIndex -ne $e.Index -and $_.InterfaceAlias -notlike 'Loopback Pseudo-Interface*' } |
                            ForEach-Object InterfaceAlias | Sort-Object -Unique)
                $IC.HasE = [bool]($all | Where-Object InterfaceIndex -eq $e.Index)
                $IC.T = $script:NetC.T; $IC.Idx = $e.Index
            }
            $ifs = @($IC.Ifs)
            # в списке нет самого выхода — список не получен как следует: закрыть всё
            if ($IC.HasE) { $via = "$($e.Alias)" } else { $mode = 'block'; $ifs = @() }
        } else { $mode = 'block' }
        $v6 = @(); if ($mode -eq 'via' -and $script:V6Bypass) { $v6 = @($addrs | Where-Object { "$_" -match ':' }) }
        # VPN-клиент с fake-IP: в режиме «закрыто» (и «не уверен») — ещё и его сеть адресов
        $fake = if ($script:FakeIp) { @($FakeNet) } else { @() }
        $blockKey = "block|||$($script:AddrC.Join)|v6:0|fake:$($fake.Count)"
        $key = if ($mode -eq 'via') { "$mode|$via|$($ifs -join ';')|$($script:AddrC.Join)|v6:$($v6.Count)|fake:0" } else { $blockKey }
        # с этим набором интерфейсов правило уже не создалось — не долбить каждый круг, но
        # через минуту попробовать снова (раньше — только после смены конфига)
        $fa = [VGNative]::Now() - $F.ViaFailT
        if ($mode -eq 'via' -and $key -eq $F.ViaFail -and $fa -ge 0 -and $fa -lt 60) { $mode = 'block'; $ifs = @(); $via = ''; $v6 = @(); $key = $blockKey }
        if ($key -eq $F.Key) {
            if (-not $F.Due) { return }
            if (Test-FwRules $F.Names) { $F.Err = ''; return }
            # в журнал — не чаще раза в минуту: если правило пропадает снова и снова, журнал не забивать
            $now = [VGNative]::Now()
            if ($now - $F.RepairLogT -ge 60 -or $now -lt $F.RepairLogT) { Log 'правило брандмауэра пропало или выключено — восстанавливаю'; $F.RepairLogT = $now }
        }
        $specs = @()
        if ($mode -eq 'via') {
            if ($ifs.Count) { $specs += @{ Addr = $addrs; Ifs = $ifs; Desc = "Vafa: сеть к Anthropic только через $via" } }
            if ($v6.Count) { $specs += @{ Addr = $v6; Ifs = @(); Desc = "Vafa: IPv6 к Anthropic идёт мимо туннеля $via — IPv6-адреса закрыты везде" } }
        } else { $specs += @{ Addr = @($addrs + $fake); Ifs = @(); Desc = 'Vafa: сеть к Anthropic закрыта' } }
        if (-not $specs.Count) {
            # кроме выхода, интерфейсов нет (так бывает, когда в checks нет route и выход —
            # сам адаптер): закрывать нечего. Появится новый — сменится ключ, и правило встанет.
            Remove-FwRules
            $F.Key = $key; $F.Names = @(); $F.Err = ''
            if ($F.Mode -ne "via:$via") { Log "сеть к Anthropic: только через $via (других интерфейсов нет — правило не нужно)" }
            $F.Mode = "via:$via"; $F.ModeLog = ''
            return
        }
        $names = @()
        try { foreach ($sp in $specs) { $names += New-FwRule $sp.Addr $sp.Ifs $sp.Desc } }
        catch {
            if ($mode -ne 'via') { throw }
            foreach ($n in $names) { Remove-NetFirewallRule -Name $n -ErrorAction SilentlyContinue }
            WarnOnce "fwvia:$($ifs -join ';')" "не смог поставить правило «только через $via» ($($ifs -join ', ')): $($_.Exception.Message) — сеть к Anthropic закрыта полностью"
            $F.ViaFail = $key; $F.ViaFailT = [VGNative]::Now()
            $F.Note = "не смог поставить правило «только через $via» — сеть к Anthropic закрыта полностью, повтор через минуту"
            $mode = 'block'; $via = ''; $v6 = @(); $key = $blockKey
            $names = @(New-FwRule @($addrs + $fake) @() 'Vafa: сеть к Anthropic закрыта')
        }
        if ($mode -eq 'via') { $F.Note = '' }
        # новое на месте — теперь снять всё прежнее (и правила старых версий Vafa)
        Remove-FwRules $names
        $F.Key = $key; $F.Names = $names; $F.Err = ''
        # своя правка реестра брандмауэра — не повод для внеочередной проверки (иначе после
        # каждой починки — снова проверка и снова починка); плановая — через $FwVerifyEvery с
        $F.Stamp = [VGNative]::KeyStamp($FwKeys); $F.VerifyT = [VGNative]::Now()
        $m = if ($mode -eq 'via') { "via:$via" } else { 'block' }
        $ms = "$m|$($v6.Count -gt 0)"
        if ($ms -ne $F.ModeLog) {
            if ($mode -eq 'via') { Log "сеть к Anthropic: только через $via (закрыта на: $(if ($ifs.Count) { $ifs -join ', ' } else { '—' })$(if ($v6.Count) { '; IPv6-адреса — на всех интерфейсах' }))" }
            else { Log "сеть к Anthropic: ЗАКРЫТА ($($addrs.Count) адрес(ов) и сетей)" }
        }
        $F.Mode = $m; $F.ModeLog = $ms
    } catch {
        # прежнее правило не тронуто: New-NetFirewallRule падает раньше, чем снимается старое
        $F.Err = "не удалось поставить правило брандмауэра: $($_.Exception.Message)"
        WarnOnce "fw:$($_.Exception.Message)" $F.Err
        if (-not $F.Names -or -not (Test-FwRules $F.Names)) { $F.Mode = ''; $F.ModeLog = '' }
    }
}

# '' — Брандмауэр Windows правила применяет; иначе — почему нет. Правило создаётся и
# при выключенном профиле, и когда групповая политика запрещает локальные правила, и когда
# интерфейс исключён из защиты («Защищённые сетевые подключения», DisabledInterfaceAliases).
function Test-FwEnforced {
    $script:FwBlind = $false
    try {
        $svc = Get-Service MpsSvc -ErrorAction SilentlyContinue
        if (-not $svc -or "$($svc.Status)" -ne 'Running') { $script:FwBlind = $true; return 'служба брандмауэра (MpsSvc) не работает' }
        $p = @(Get-NetFirewallProfile -PolicyStore ActiveStore -ErrorAction Stop)
        $off = @($p | Where-Object { "$($_.Enabled)" -ne 'True' } | ForEach-Object Name)
        if ($off) { return "брандмауэр выключен (профиль: $($off -join ', '))" }
        $nolocal = @($p | Where-Object { "$($_.AllowLocalFirewallRules)" -eq 'False' } | ForEach-Object Name)
        if ($nolocal) { $script:FwBlind = $true; return "групповая политика не применяет локальные правила (профиль: $($nolocal -join ', '))" }
        $dis = @(foreach ($x in $p) {
            $l = @(@($x.DisabledInterfaceAliases) | Where-Object { $_ -and "$_" -ne 'NotConfigured' })
            if ($l.Count) { "$($x.Name): $($l -join ', ')" }
        })
        if ($dis) { return "брандмауэр не защищает интерфейсы ($($dis -join '; '))" }
        return ''
    } catch { return "не удалось проверить брандмауэр: $($_.Exception.Message)" }
}

# ---- состояние для трея -----------------------------------------------------
# $scan — на этом круге был обход процессов ($all — его снимок); иначе приложения в
# статусе — с прошлого обхода (не старше $ProcScanEvery с).
# Файл пишется сразу, если что-то изменилось, а если нет — раз в $StatusEvery с (метка time
# для трея: служба жива). Каждая запись — это ещё и проверка Защитником, ~1 % ядра в секунду.
# Запись не удалась (файл держит читатель без FILE_SHARE_DELETE) — не беда: в журнал один
# раз, на следующем круге — снова. Сеть из-за этого не закрывается.
$script:AppSum = $null; $script:AppSig = ''; $script:StatusSig = ''; $script:StatusT = $NoTime
$StatusEvery = 2
function Write-Status($conf, [string]$state, $all, [bool]$scan, $e, [string]$enfErr) {
    $tmp = "$StatusPath.$PID.tmp"
    try {
        if ($scan -or $null -eq $script:AppSum) {
            $st = Load-State
            $script:AppSum = @(foreach ($a in $conf.apps) {
                $ps = @(Get-AppProcs $a $all)
                [pscustomobject]@{ path = $a; locked = [bool]$st.PSObject.Properties[$a]; procs = $ps.Count; frozen = @($ps | Where-Object { $_.Frozen }).Count }
            })
            $script:AppSig = (@($script:AppSum | ForEach-Object { "$($_.path)*$($_.locked)*$($_.procs)*$($_.frozen)" }) -join '|')
        }
        $netErr = if ($script:Fw.Err) { $script:Fw.Err } elseif (-not $script:Fw.Mode) { 'правило брандмауэра не найдено' } else { $enfErr }
        # не ошибка защиты (сеть закрыта даже сильнее), но объяснение для щита и status
        $netNote = if ($netErr) { $netErr } else { $script:Fw.Note }
        $G = $script:Geo; $cc = Geo-Shown; $now = [VGNative]::Now()
        $iface = if ($e) { "$($e.Alias)" } else { '' }
        $ga = $now - $G.GoodT
        $country = if ($cc -and $ga -ge 0 -and $ga -lt [Math]::Max(60, $conf.geo_stale)) { $cc } else { '' }
        $geo = [bool](@($conf.checks) -match '^geo(:|$)')
        $sig = "$state|$iface|$country|$($script:Fw.Mode)|$netErr|$netNote|$($conf.on_down)|$(@($conf.block_countries) -join ',')|$geo|$($script:AppSig)"
        $sa = $now - $script:StatusT
        if ($sig -eq $script:StatusSig -and $sa -ge 0 -and $sa -lt $StatusEvery) { return }
        $o = [pscustomobject]@{
            # секунды Unix по UTC, как ждут трей и status: Get-Date -UFormat %s в PowerShell 5.1
            # считает от местного времени (в Москве — на 3 ч вперёд), и трей не видел, что служба умерла
            time = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds(); vpn = ($state -eq 'up'); state = $state
            iface = $iface; country = $country
            on_down = $conf.on_down
            countries = @($conf.block_countries)
            geo = $geo
            net = $script:Fw.Mode; net_ok = (-not $netErr); net_error = "$netNote"
            apps = @($script:AppSum)
        }
        [IO.File]::WriteAllText($tmp, ($o | ConvertTo-Json -Depth 4 -Compress), (New-Object Text.UTF8Encoding $false))
        # Replace — атомарно, трей никогда не увидит пустой или полузаписанный файл
        if (Test-Path $StatusPath) { [IO.File]::Replace($tmp, $StatusPath, [NullString]::Value) } else { [IO.File]::Move($tmp, $StatusPath) }
        $script:StatusSig = $sig; $script:StatusT = $now
    } catch {
        WarnOnce "status:$($_.Exception.Message)" "не смог записать $StatusPath`: $($_.Exception.Message) — повторю на следующем круге"
        try { [IO.File]::Delete($tmp) } catch {}
    }
}

# ---- ожидание: таймер или событие сети ---------------------------------------
# NetworkAddressChanged приходит, когда у адаптера меняется адрес: VPN поднялся,
# упал, переподключился. Пока сеть не меняется, служба просто спит до следующего круга.
$script:NetWatch = $false; $script:AddrSeen = 0
function Start-NetWatch($conf) {
    if (-not $conf.net_watch -or $script:NetWatch) { return }
    try {
        [VGNative]::WatchNet()
        $script:AddrSeen = [VGNative]::AddrSeq
        $script:NetWatch = $true
    } catch { WarnOnce 'netwatch' "не удалось подписаться на события сети — работаю по таймеру: $_" }
}

# true — проснулись по событию сети (или оно пришло, пока шёл круг). Круг длится interval
# секунд вместе с работой, но спим не меньше 0,5 с. Спим на WaitOne — без опроса. Пачку
# событий собирает Cmd-Daemon: после события — пауза 0,3 с, и всё пришедшее за неё — один круг.
function Wait-Tick($conf, [double]$spentMs) {
    $ms = [Math]::Max(500, [double]$conf.interval * 1000 - $spentMs)
    if (-not $script:NetWatch) { Start-Sleep -Milliseconds ([int]$ms); return $false }
    [void][VGNative]::Wake.WaitOne([int]$ms)
    $s = [VGNative]::AddrSeq
    if ($s -ne $script:AddrSeen) { $script:AddrSeen = $s; return $true }
    return $false
}

# ---- команды ----------------------------------------------------------------
function Get-ConfTime { if ([IO.File]::Exists($ConfPath)) { [IO.File]::GetLastWriteTimeUtc($ConfPath) } else { $null } }

# конфиг или $null; исключение внутри (кривое значение, файл занят) — тоже $null
function Try-LoadConf {
    try { return (Load-Conf) } catch { WarnOnce "conf:ex:$($_.Exception.Message)" "конфиг не читается: $($_.Exception.Message) — работаю по прежним настройкам"; return $null }
}

function Cmd-Daemon {
    New-Item -ItemType Directory -Force -Path $Root | Out-Null
    # ровно одна копия: две дерутся за status.json и дублируют действия
    $script:Mutex = New-Object Threading.Mutex($false, 'Global\VPNGuardDaemon')
    try { $got = $script:Mutex.WaitOne(0) } catch [Threading.AbandonedMutexException] { $got = $true }
    if (-not $got) { Write-Host 'vpn-guard уже запущен'; exit 3 }
    # приоритет обычный: от задачи Планировщика достаётся «ниже среднего», и под нагрузкой
    # круг отстаёт на секунды (та же грабля, что ProcessType=Background на macOS)
    try { [Diagnostics.Process]::GetCurrentProcess().PriorityClass = [Diagnostics.ProcessPriorityClass]::Normal } catch {}
    # первым делом закрыть сеть к Anthropic — по настройкам по умолчанию, ещё до чтения
    # конфига: что бы с ним ни было, сеть закрыта
    try { Set-Firewall 'block' (Default-Conf) $null } catch { WarnOnce "fw0:$_" "не удалось закрыть сеть при старте: $_" }
    # не прочитался — настройки по умолчанию (приложений нет) и попытка каждый круг, пока не
    # прочитается: права могли починить без смены времени записи файла
    $confBad = $false
    $conf = Try-LoadConf
    if ($null -eq $conf) { $conf = Default-Conf; $confBad = $true; Log 'конфиг не прочитан — беру настройки по умолчанию (сети Anthropic закрыты, приложений нет), пробую снова каждый круг' }
    $mt = Get-ConfTime
    Log "vpn-guard запущен: правила=[$($conf.checks -join ' ')] ($($conf.require)), при падении VPN=$($conf.on_down), приложений: $(@($conf.apps).Count), страны блокировки: $(if ($conf.block_countries) { $conf.block_countries -join ' ' } else { 'не заданы' }), сетей: $(@($conf.block_nets).Count), имён: $(@($conf.block_hosts).Count)"
    Load-HostIps $conf
    Start-NetWatch $conf
    # закрыто, пока не доказано обратное: первая проверка страны может идти секунды
    Set-Firewall 'block' $conf $null
    $last = 'init'; $downSince = $null; $lastLock = $NoTime; $blocked = $false
    $state = 'init'; $scanT = $NoTime; $scanState = ''
    $sw = New-Object Diagnostics.Stopwatch
    $prevT = $null
    while ($true) {
        $sw.Restart(); $t0 = [VGNative]::Now(); $script:TickT = $t0
        # перерыв между кругами (сон, гибернация): страну ждать заново с «не уверен», а не сразу
        # down по geo_stale — свежий ответ придёт через секунду (Get-GeoVerdict, ResumeT)
        if ($null -ne $prevT -and ($t0 - $prevT -gt $GapSec -or $t0 -lt $prevT)) {
            $script:ResumeT = $t0
            Log "перерыв $([int]($t0 - $prevT)) с между кругами (сон?) — страну спрашиваю заново"
        }
        $prevT = $t0
        try {
            $m = Get-ConfTime
            if ($m -ne $mt -or $confBad) {
                if ($m -ne $mt) { Log 'конфиг изменился — перечитываю'; $mt = $m }
                $new = Try-LoadConf
                # не читается — работаем по прежнему (все проверки идут) и пробуем снова на следующем круге
                $wasBad = $confBad; $confBad = ($null -eq $new)
                if (-not $confBad) {
                    $old = @($conf.apps); $conf = $new; $last = 'init'; $script:Fw.Key = ''; $script:Fw.ViaFail = ''
                    $scanState = ''; $script:AppSum = $null
                    # кэш адресов при старте был отфильтрован по именам из настроек по умолчанию — перечитать
                    if ($wasBad) { Load-HostIps $conf } else { Prune-HostIps $conf }
                    $script:Dns.Want = $true
                    foreach ($a in $old) {
                        if ($conf.apps -notcontains $a) {
                            Log "$a убран из списка — снимаю блокировку"
                            try { Unlock-App $a; Resume-App $a @(Get-ProcsIn @($a)) } catch { WarnOnce "unl:${a}:$_" "не смог снять блокировку $a`: $_" }
                        }
                    }
                }
            }
            $script:Fw.Due = Test-FwDue
            # состояние брандмауэра — до проверки VPN: от него зависит, можно ли пустить IPv6 мимо туннеля
            if ($script:Fw.Due -or $null -eq $script:FwEnf) { $script:FwEnf = Test-FwEnforced }
            $e = Get-EgressAdapter
            # выход не через туннель: страну туннеля забыть и начатый запрос отменить, даже если
            # до проверки geo дело не дойдёт (route — «нет» первым): иначе в статусе и щите
            # «интерфейс: Ethernet, страна: FR» (замер с sing-box 2026-10-10)
            if ((@($conf.checks) -match '^geo(:|$)') -and -not (Test-Tunnel $e)) { Stop-Geo $e }
            $D = $script:Dns; $da = $t0 - $D.LastT
            if ($D.Tasks.Count -or $D.Probe -or (@($conf.block_hosts).Count -and ($D.Want -or $da -lt 0 -or $da -ge $conf.hosts_ttl))) { Pump-Dns $conf $e }
            # проверка упала — «не уверен»: сеть закрыта, приложения не трогаем, статус пишется
            $script:V6Bypass = $false
            try { $v = Get-VpnVerdict $conf $e } catch { WarnOnce "verdict:$_" "ошибка проверки VPN: $_ — считаю «не уверен»"; $v = $null }
            if ($v -eq $true) { $downSince = $null; $state = 'up' }
            elseif ($null -eq $v) { $state = 'unsure' }
            else {
                if ($null -eq $downSince) { $downSince = [VGNative]::Now() }
                $dn = [VGNative]::Now() - $downSince
                $state = if ($dn -lt 0 -or $dn -ge $conf.grace) { 'down' } else { 'unsure' }
            }
            # обход процессов: в down — каждый круг (морозить новые), при смене состояния — сразу,
            # иначе (up, unsure: морозить нечего) — раз в $ProcScanEvery с
            $now = [VGNative]::Now(); $sa = $now - $scanT
            $scan = (@($conf.apps).Count -gt 0) -and ($state -eq 'down' -or $state -ne $scanState -or $sa -lt 0 -or $sa -ge $ProcScanEvery)
            $all = @()
            if ($scan) { $all = @(Get-ProcsIn $conf.apps); $scanT = $now; $scanState = $state }
            switch ($state) {
                'up' {
                    Set-Firewall 'via' $conf $e                    # сеть — до разморозки
                    if ($last -ne 'up') {
                        Log $(if ($blocked -or $last -eq 'init') { 'VPN поднят — снимаю блокировку' } else { "страна выхода подтверждена ($($script:Geo.GoodCC)) — сеть к Anthropic снова через туннель" })
                        $last = 'up'; $blocked = $false
                    }
                    $script:GuardDown = $false
                    if ($scan) {
                        foreach ($a in $conf.apps) { try { Unlock-App $a; Resume-App $a $all } catch { WarnOnce "unl:${a}:$_" "не смог снять блокировку $a`: $_" } }
                    }
                }
                'unsure' {
                    Set-Firewall 'block' $conf $null               # приложения не трогаем — ни морозим, ни размораживаем
                    if ($last -ne 'unsure') { Log "страна выхода не подтверждена (интерфейс: $($e.Alias), страна: $(if (Geo-Shown) { Geo-Shown } else { '?' })) — сеть к Anthropic закрыта, приложения не трогаю"; $last = 'unsure' }
                }
                'down' {
                    Set-Firewall 'block' $conf $null               # сеть — первой, до заморозки
                    if ($last -ne 'down') {
                        Log "VPN не обнаружен (интерфейс: $($e.Alias), страна: $(if (Geo-Shown) { Geo-Shown } else { '?' })) — блокирую"
                        $last = 'down'; $lastLock = $NoTime; $blocked = $true
                    }
                    $script:GuardDown = $true
                    # сначала заморозить (или закрыть), потом запрет запуска: ошибка icacls не
                    # должна оставить приложения работать
                    foreach ($a in $conf.apps) {
                        try { if ($conf.on_down -eq 'kill') { Kill-App $a $all } else { Freeze-App $a $all } }
                        catch { WarnOnce "frz:${a}:$_" "не смог остановить $a`: $_" }
                    }
                    # проход по exe — раз в 30 с: ловит файлы, появившиеся после обновления
                    $la = [VGNative]::Now() - $lastLock
                    if ($la -lt 0 -or $la -ge 30) {
                        if ($conf.lock_launch) {
                            foreach ($a in $conf.apps) { try { Lock-App $a } catch { WarnOnce "lock:${a}:$_" "не смог запретить запуск $a`: $_" } }
                        }
                        $lastLock = [VGNative]::Now()
                    }
                }
            }
            Write-Status $conf $state $all $scan $e $script:FwEnf
        } catch {
            WarnOnce "err:$_" "ошибка в цикле: $_"
            # что-то пошло не так — лучше закрыть, чем оставить открытым
            if ($script:Fw.Mode -like 'via:*') { Set-Firewall 'block' $conf $null }
        }
        $spent = $sw.Elapsed.TotalMilliseconds
        if ($env:VPN_GUARD_DEBUG) { Log ('круг: {0:N0} мс, состояние {1}, сеть {2}' -f $spent, $state, $script:Fw.Mode) }
        if (Wait-Tick $conf $spent) {
            # сеть поменялась: страна могла смениться в том же туннеле — сначала закрыть,
            # открыть снова только после свежего ответа geo; интерфейсы перечитать, правило проверить
            $script:Dns.Want = $true
            $script:NetC.T = $NoTime; $script:Fw.VerifyT = $NoTime
            if ($script:Fw.Mode -like 'via:*') { Set-Firewall 'block' $conf $null }
            # пачка событий (VPN подключается, Wi-Fi переключается, адаптер мигает) — один круг:
            # переждать 0,3 с и забрать всё, что пришло за это время
            Start-Sleep -Milliseconds 300
            [void][VGNative]::Wake.Reset(); $script:AddrSeen = [VGNative]::AddrSeq
            $script:Geo.EventT = [VGNative]::Now()
        }
    }
}

# Метка time из status.json (как есть, без разбора JSON); $null — файла или метки нет.
# Читается с FILE_SHARE_DELETE — не мешает демону заменять файл.
function Get-StatusStamp {
    try {
        $fs = [IO.File]::Open($StatusPath, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]'ReadWrite, Delete')
        try { $txt = (New-Object IO.StreamReader($fs)).ReadToEnd() } finally { $fs.Dispose() }
        if ($txt -match '"time"\s*:\s*(\d+)') { return $Matches[1] }
    } catch {}
    return $null
}

# Сторож демона. Планировщик перезапускает упавшую задачу не раньше чем через минуту,
# а когда процесс просто вышел — может и не перезапустить. Здесь: демон вышел — через
# 2 с новый. Демон завис (WMI не ответил, и status.json не обновляется $HangSec с) —
# убить: новый первым делом закроет сеть. Самого сторожа поднимает повторяющийся раз в
# минуту триггер задачи. Время — монотонное: метка в status.json сравнивается сама с собой
# (меняется ли), так что подводка часов сторожа не обманет.
$HangSec = 30
function Cmd-Supervise {
    New-Item -ItemType Directory -Force -Path $Root | Out-Null
    $script:SupMutex = New-Object Threading.Mutex($false, 'Global\VPNGuardSupervisor')
    try { $got = $script:SupMutex.WaitOne(0) } catch [Threading.AbandonedMutexException] { $got = $true }
    if (-not $got) { return }
    try { [Diagnostics.Process]::GetCurrentProcess().PriorityClass = [Diagnostics.ProcessPriorityClass]::Normal } catch {}
    $ps = Join-Path $PSHOME 'powershell.exe'
    $argv = "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$PSCommandPath`" daemon"
    $oSeen = $null; $oSeenT = [VGNative]::Now(); $oPoll = $oSeenT
    while ($true) {
        # демон ещё жив (осиротел после убитого сторожа) — не плодить копии, ждать; но и
        # за ним смотреть: status.json не меняется $HangSec с — убить
        $m = $null
        if ([Threading.Mutex]::TryOpenExisting('Global\VPNGuardDaemon', [ref]$m)) {
            $m.Dispose()
            $t = Get-StatusStamp; $now = [VGNative]::Now()
            # между опросами прошло много больше 2 с — машина спала: отсчёт заново (как ниже)
            if ($t -ne $oSeen -or $now - $oSeenT -lt 0 -or $now - $oPoll -gt 15 -or $now -lt $oPoll) { $oSeen = $t; $oSeenT = $now }
            elseif ($now - $oSeenT -ge $HangSec) {
                Log "служба не обновляет status.json $([int]($now - $oSeenT)) с — зависла, перезапускаю"
                Stop-Daemons -DaemonOnly
                $oSeen = $null; $oSeenT = $now
            }
            $oPoll = $now
            Start-Sleep 2; continue
        }
        try {
            $p = Start-Process $ps -ArgumentList $argv -WindowStyle Hidden -PassThru
            [void]$p.Handle                    # без этого ExitCode у вышедшего процесса пуст
            $seen = Get-StatusStamp; $seenT = [VGNative]::Now(); $poll = $seenT
            while (-not $p.WaitForExit(5000)) {
                $t = Get-StatusStamp; $now = [VGNative]::Now()
                # между опросами прошло много больше 5 с — машина спала: отсчёт заново
                if ($t -ne $seen -or $now - $poll -gt 15 -or $now - $poll -lt 0) { $seen = $t; $seenT = $now }
                elseif ($now - $seenT -ge $HangSec) {
                    Log "служба не обновляет status.json $([int]($now - $seenT)) с — зависла, перезапускаю"
                    try { $p.Kill() } catch {}
                    [void]$p.WaitForExit(5000)
                    break
                }
                $poll = $now
            }
            $code = $p.ExitCode
        } catch { $code = "$_" }
        if ("$code" -ne '3') { Log "служба остановилась (код $code) — перезапуск через 2 с" }
        Start-Sleep 2
        $oSeen = $null; $oSeenT = [VGNative]::Now()
    }
}

# Процессы демона и сторожа (кроме себя). Stop-ScheduledTask убивает только сторожа —
# демон-потомок остаётся жить, поэтому unlock, uninstall и «выключить охрану» гасят их сами.
function Stop-Daemons([switch]$DaemonOnly) {
    $rx = if ($DaemonOnly) { 'vpn-guard\.ps1.*\sdaemon\b' } else { 'vpn-guard\.ps1.*\s(daemon|supervise)\b' }
    Get-CimInstance Win32_Process -Filter "Name='powershell.exe'" -ErrorAction SilentlyContinue |
        Where-Object { $_.ProcessId -ne $PID -and $_.CommandLine -match $rx } |
        ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }
}

function Cmd-Check {
    $conf = Try-LoadConf; if ($null -eq $conf) { $conf = Default-Conf }
    $script:FwEnf = Test-FwEnforced
    $e = Get-EgressAdapter
    # выход не через туннель — страну не спрашивать (см. Stop-Geo)
    $tun = Test-Tunnel $e
    if ((@($conf.checks) -match '^geo(:|$)') -and $tun) { Sync-Geo $e }
    foreach ($r in $conf.checks) {
        $ok = Test-Check $r $conf $e
        $note = if ($null -eq $ok) { "  [ ?? ] $r" } elseif ($ok) { "  [ да ] $r" } else { "  [ нет] $r" }
        if ($r -match '^geo(:|$)') { $note += "   (страна выхода: $(if (-not $tun) { 'не спрашиваю — выход не через туннель' } elseif ($script:Geo.LastOk) { $script:Geo.GoodCC } else { 'нет ответа' }); блокировать: $(if ($conf.block_countries) { $conf.block_countries -join ' ' } else { 'ничего' }))" }
        Write-Host $note
    }
    Write-Host "  интерфейс выхода: $($e.Alias) — $($e.Desc)"
    $v = Get-VpnVerdict $conf $e
    $s = if ($v -eq $true) { 'ПОДНЯТ' } elseif ($null -eq $v) { 'НЕ УВЕРЕН (страна не подтверждена)' } else { 'ВЫКЛЮЧЕН' }
    Write-Host "VPN: $s ($($conf.require))"
}

function Cmd-Status {
    Cmd-Check
    $conf = Try-LoadConf; if ($null -eq $conf) { $conf = Default-Conf }; $all = @(Get-ProcsIn $conf.apps); $st = Load-State
    Write-Host "`nПриложения под охраной:"
    if (-not $conf.apps) { Write-Host '  (список пуст)' }
    foreach ($a in $conf.apps) {
        $ps = @(Get-AppProcs $a $all)
        $fz = @($ps | Where-Object { $_.Frozen }).Count
        $lk = if ($st.PSObject.Properties[$a]) { 'ЗАБЛОКИРОВАНО' } else { 'разблокировано' }
        Write-Host "  $a"
        Write-Host "      запуск: $lk, процессов: $($ps.Count)$(if ($fz) { ", заморожено: $fz" })"
    }
    Write-Host "`nБрандмауэр (правила «$FwRule»):"
    $rules = @(Get-NetFirewallRule -DisplayName $FwRule -ErrorAction SilentlyContinue)
    if (-not $rules) { Write-Host '  правил нет — сеть к Anthropic НЕ закрыта' }
    foreach ($r in $rules) {
        $af = @($r | Get-NetFirewallAddressFilter).RemoteAddress
        $if = @($r | Get-NetFirewallInterfaceFilter).InterfaceAlias
        Write-Host "  $($r.Name): включено=$($r.Enabled), $($r.Direction)/$($r.Action), адресов и сетей: $(@($af).Count)"
        Write-Host "      интерфейсы: $(if (-not $if -or "$($if[0])" -eq 'Any') { 'все' } else { $if -join ', ' })"
    }
    $enf = Test-FwEnforced
    Write-Host $(if ($enf) { "  ВНИМАНИЕ: $enf" } else { '  брандмауэр включён во всех профилях, локальные правила действуют' })
    try {
        $fs = [IO.File]::Open($StatusPath, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]'ReadWrite, Delete')
        try { $s = (New-Object IO.StreamReader($fs)).ReadToEnd() | ConvertFrom-Json } finally { $fs.Dispose() }
        $age = [int]([DateTimeOffset]::UtcNow.ToUnixTimeSeconds() - $s.time)
        if ($age -gt 20) { Write-Host "  по данным службы: status.json не обновлялся $age с — служба не отвечает" }
        else { Write-Host "  по данным службы: состояние $($s.state), режим «$($s.net)», $(if ($s.net_ok) { 'фильтр работает' } else { "НЕ РАБОТАЕТ: $($s.net_error)" })" }
    } catch { Write-Host '  по данным службы: status.json нет' }
    $t = Get-ScheduledTask -TaskName VPNGuard -ErrorAction SilentlyContinue
    Write-Host "`nЗадача: $(if ($t) { $t.State } else { 'НЕ установлена' })"
}

# аварийный выход: вернуть всё как было. Сначала выключить задачу (её повтор раз в минуту
# поднял бы службу снова), потом погасить демона и сторожа — иначе через секунду всё
# заблокировалось бы снова.
function Cmd-Unlock {
    $task = $false
    try {
        if (Get-ScheduledTask -TaskName VPNGuard -ErrorAction Stop) {
            Disable-ScheduledTask -TaskName VPNGuard -ErrorAction Stop | Out-Null; $task = $true
            Stop-ScheduledTask -TaskName VPNGuard -ErrorAction SilentlyContinue
        }
    } catch {}
    Stop-Daemons
    $st = Load-State
    $conf = Try-LoadConf; if ($null -eq $conf) { $conf = Default-Conf }
    $apps = @(@($conf.apps) + @($st.PSObject.Properties.Name) | Where-Object { $_ } | Select-Object -Unique)
    foreach ($a in $apps) { Unlock-App $a -Sweep }
    $all = @(Get-ProcsIn $apps)
    foreach ($a in $apps) { Resume-App $a $all }
    Remove-FwRules
    Get-NetFirewallRule -Group $FwGroup -ErrorAction SilentlyContinue | Remove-NetFirewallRule -ErrorAction SilentlyContinue
    Write-Host 'готово: служба остановлена, запуск разрешён, процессы разморожены, правила брандмауэра сняты'
    if ($task) {
        Write-Host 'Задача VPNGuard выключена — сама охрана не вернётся (и после перезагрузки тоже).'
        Write-Host 'Включить снова: трей → «Охрана включена» или от администратора:'
        Write-Host '  Enable-ScheduledTask -TaskName VPNGuard; Start-ScheduledTask -TaskName VPNGuard'
    }
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
    'daemon'    { Cmd-Daemon }
    'supervise' { Cmd-Supervise }
    'status'    { Cmd-Status }
    'check'     { Cmd-Check }
    'unlock'    { Cmd-Unlock }
    'set-apps'  { Cmd-SetApps $Arg }
    'set-countries' { Cmd-SetCountries $Arg }
    default     { Write-Host 'использование: vpn-guard.ps1 {daemon|supervise|status|check|unlock|set-apps <файл>|set-countries <файл>}'; exit 1 }
}
