# VPNGuard-Tray.ps1 — значок-щит в трее для vpn-guard (Windows).
# Статус читает из C:\ProgramData\VPNGuard\status.json. Список приложений и
# включение/выключение охраны меняются через запрос прав администратора (UAC).
# Автозапуск — ключ HKCU\...\Run, прав администратора не нужно.

Add-Type -AssemblyName System.Windows.Forms, System.Drawing
# PowerShell 5.1 сериализует массивы в JSON как {value, Count} — убрать эту надстройку
Remove-TypeData System.Array -ErrorAction SilentlyContinue
[Windows.Forms.Application]::EnableVisualStyles()

$Root       = Join-Path $env:ProgramData 'VPNGuard'
$StatusPath = Join-Path $Root 'status.json'
$Daemon     = Join-Path $PSScriptRoot 'vpn-guard.ps1'
$RunKey     = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'
$RunName    = 'VPNGuard'

# одна копия трея на пользователя
$mutex = New-Object Threading.Mutex($false, "Local\VPNGuardTray")
if (-not $mutex.WaitOne(0)) { exit }

# Чтение с FILE_SHARE_DELETE: не мешает службе заменять файл (Get-Content такой доли не
# даёт, и замена status.json у службы срывалась)
function Read-Status {
    try {
        $fs = [IO.File]::Open($StatusPath, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]'ReadWrite, Delete')
        try { return ((New-Object IO.StreamReader($fs, [Text.Encoding]::UTF8)).ReadToEnd() | ConvertFrom-Json) } finally { $fs.Dispose() }
    } catch { return $null }
}
function Is-Stale($s) { -not $s -or (([DateTimeOffset]::UtcNow.ToUnixTimeSeconds()) - $s.time) -gt 20 }
# up | unsure | down; старая служба без поля state — по vpn
function State-Of($s) { if ($s.state) { "$($s.state)" } elseif ($s.vpn) { 'up' } else { 'down' } }
function State-Text($s) {
    switch (State-Of $s) {
        'up'     { 'VPN: поднят' }
        'unsure' { 'VPN: страна не подтверждена — сеть закрыта, приложения работают' }
        default  { 'VPN: ВЫКЛЮЧЕН — блокировка' }
    }
}
# строка про сеть; $null — служба старая, поля net нет
function Net-Text($s) {
    if ($null -eq $s.net_ok) { return $null }
    if (-not $s.net_ok) { return "Сеть к Anthropic: НЕ ЗАЩИЩЕНА ($(if ($s.net_error) { $s.net_error } else { 'причина неизвестна' }))" }
    if ("$($s.net)" -like 'via:*') { return "Сеть к Anthropic: только через $("$($s.net)".Substring(4))" }
    return 'Сеть к Anthropic: закрыта'
}
function App-Name([string]$p) { $leaf = Split-Path $p -Leaf; if ($leaf -match '\.exe$') { $leaf = $leaf -replace '\.exe$' }; $leaf }

# Щит рисуем сами: залитый (зелёный/оранжевый/красный) или пустой контур (охрана
# выключена); с «!» — служба не отвечает.
function New-ShieldIcon([Drawing.Color]$c, [bool]$filled, [bool]$mark = $false) {
    $bmp = New-Object Drawing.Bitmap 32, 32
    $g = [Drawing.Graphics]::FromImage($bmp)
    $g.SmoothingMode = 'AntiAlias'
    $pts = [Drawing.PointF[]]@(
        (New-Object Drawing.PointF 16, 2), (New-Object Drawing.PointF 28, 7), (New-Object Drawing.PointF 27, 17),
        (New-Object Drawing.PointF 16, 30), (New-Object Drawing.PointF 5, 17), (New-Object Drawing.PointF 4, 7))
    if ($filled) { $g.FillPolygon((New-Object Drawing.SolidBrush $c), $pts) }
    $g.DrawPolygon((New-Object Drawing.Pen $c, 3), $pts)
    if ($mark) {
        $w = New-Object Drawing.SolidBrush ([Drawing.Color]::White)
        $g.FillRectangle($w, 14, 8, 4, 11); $g.FillRectangle($w, 14, 21, 4, 4)
    }
    $g.Dispose()
    [Drawing.Icon]::FromHandle($bmp.GetHicon())
}
$IconUp   = New-ShieldIcon ([Drawing.Color]::FromArgb(40, 180, 70)) $true
$IconDown = New-ShieldIcon ([Drawing.Color]::FromArgb(220, 50, 50)) $true
$IconOff  = New-ShieldIcon ([Drawing.Color]::FromArgb(40, 180, 70)) $false
$IconWarn = New-ShieldIcon ([Drawing.Color]::FromArgb(240, 140, 20)) $true
$IconDead = New-ShieldIcon ([Drawing.Color]::FromArgb(240, 140, 20)) $true $true

# Включена ли задача VPNGuard. Get-ScheduledTask — запрос WMI: раз в 2 с по таймеру он
# грузил WmiPrvSE. Поэтому кэш на 30 с; свежий ответ — при открытии меню и после
# переключения «Охрана включена».
$GuardC = @{ T = $null; V = $false }
$GuardSw = [Diagnostics.Stopwatch]::StartNew()
function Guard-On([switch]$Fresh) {
    $now = $GuardSw.Elapsed.TotalSeconds
    if (-not $Fresh -and $null -ne $GuardC.T -and $now - $GuardC.T -lt 30) { return $GuardC.V }
    $t = Get-ScheduledTask -TaskName VPNGuard -ErrorAction SilentlyContinue
    $GuardC.V = [bool]($t -and $t.State -ne 'Disabled'); $GuardC.T = $now
    return $GuardC.V
}

function Run-Elevated([string]$script) {
    $enc = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($script))
    try {
        Start-Process powershell.exe -Verb RunAs -WindowStyle Hidden -Wait `
            -ArgumentList "-NoProfile -ExecutionPolicy Bypass -EncodedCommand $enc"
        return $true
    } catch { return $false }   # отказались в UAC
}

# ---- окно выбора приложений ------------------------------------------------
# Кандидаты: ярлыки из меню «Пуск» (общего и пользователя) → папка их .exe.
function Get-Candidates {
    $sh = New-Object -ComObject WScript.Shell
    $dirs = @("$env:ProgramData\Microsoft\Windows\Start Menu\Programs", "$env:APPDATA\Microsoft\Windows\Start Menu\Programs")
    $seen = @{}
    foreach ($d in $dirs) {
        Get-ChildItem $d -Recurse -Filter *.lnk -ErrorAction SilentlyContinue | ForEach-Object {
            try { $t = $sh.CreateShortcut($_.FullName).TargetPath } catch { return }
            if ($t -notmatch '\.exe$' -or -not (Test-Path $t)) { return }
            if ($t -match '(?i)\\Windows\\|unins|setup|update\.exe$') { return }
            $folder = Split-Path $t -Parent
            if (-not $seen.ContainsKey($folder.ToLower())) {
                $seen[$folder.ToLower()] = 1
                [pscustomobject]@{ Name = $_.BaseName; Path = $folder }
            }
        }
    }
}

function Show-Picker {
    $s = Read-Status
    $current = @(); if ($s) { $current = @($s.apps | ForEach-Object path) }

    $f = New-Object Windows.Forms.Form
    $f.Text = 'Vafa'; $f.Size = New-Object Drawing.Size 520, 640; $f.StartPosition = 'CenterScreen'
    $f.Font = New-Object Drawing.Font 'Segoe UI', 10
    $ico = Join-Path $PSScriptRoot 'vafa.ico'; if (Test-Path $ico) { $f.Icon = New-Object Drawing.Icon $ico }

    $status = New-Object Windows.Forms.Label
    $status.Dock = 'Top'; $status.Height = 130; $status.Padding = New-Object Windows.Forms.Padding 10
    $f.Controls.Add($status)

    $list = New-Object Windows.Forms.CheckedListBox
    $list.Dock = 'Fill'; $list.CheckOnClick = $true; $list.IntegralHeight = $false
    $items = New-Object Collections.ArrayList
    $cands = @(Get-Candidates)
    foreach ($p in $current) { if (-not ($cands | Where-Object { $_.Path -ieq $p })) { $cands += [pscustomobject]@{ Name = App-Name $p; Path = $p } } }
    foreach ($c in ($cands | Sort-Object Name)) {
        [void]$items.Add($c)
        $i = $list.Items.Add("$($c.Name)   —   $($c.Path)")
        if ($current | Where-Object { $_ -ieq $c.Path }) { $list.SetItemChecked($i, $true) }
    }

    $bottom = New-Object Windows.Forms.FlowLayoutPanel
    $bottom.Dock = 'Bottom'; $bottom.Height = 44; $bottom.FlowDirection = 'RightToLeft'; $bottom.Padding = New-Object Windows.Forms.Padding 6
    $save = New-Object Windows.Forms.Button; $save.Text = 'Сохранить'; $save.Width = 120
    $add  = New-Object Windows.Forms.Button; $add.Text = 'Добавить .exe…'; $add.Width = 140
    $bottom.Controls.AddRange(@($save, $add))

    $hdr = New-Object Windows.Forms.Label
    $hdr.Text = 'Приложения, которые блокируются без VPN:'; $hdr.Dock = 'Top'; $hdr.Height = 26
    $hdr.Padding = New-Object Windows.Forms.Padding 10, 4, 0, 0
    $f.Controls.Add($list); $f.Controls.Add($hdr); $f.Controls.Add($bottom)
    $hdr.BringToFront(); $list.BringToFront()

    $add.Add_Click({
        $d = New-Object Windows.Forms.OpenFileDialog
        $d.Filter = 'Программы (*.exe)|*.exe'
        if ($d.ShowDialog() -eq 'OK') {
            $folder = Split-Path $d.FileName -Parent
            $c = [pscustomobject]@{ Name = [IO.Path]::GetFileNameWithoutExtension($d.FileName); Path = $folder }
            [void]$items.Add($c)
            $i = $list.Items.Add("$($c.Name)   —   $($c.Path)"); $list.SetItemChecked($i, $true)
        }
    })
    $save.Add_Click({
        $sel = @(); foreach ($i in $list.CheckedIndices) { $sel += $items[$i].Path }
        $tmp = Join-Path $env:TEMP "vpnguard-apps-$PID.json"
        ConvertTo-Json -InputObject @($sel) | Set-Content $tmp -Encoding UTF8
        # временный файл пользователя — только данные; SYSTEM-скрипт их проверяет сам
        if (Run-Elevated "& '$Daemon' set-apps '$tmp'") { $f.Close() }
        Remove-Item $tmp -ErrorAction SilentlyContinue
    })

    $upd = {
        $s = Read-Status
        if (Is-Stale $s) {
            $status.Text = if (Guard-On) { "Служба не отвечает`n(охрана включена, но status.json не обновляется)" } else { "Охрана выключена`n(служба не работает)" }
            $status.ForeColor = 'DarkOrange'; return
        }
        $t = State-Text $s
        $t += "`nинтерфейс: $($s.iface), страна: $(if ($s.country) { $s.country } else { 'нет ответа' })"
        if (@($s.countries).Count) { $t += "; блокировать из: $(@($s.countries) -join ', ')" }
        $nt = Net-Text $s; if ($nt) { $t += "`n$nt" }
        foreach ($a in $s.apps) {
            $t += "`n$(App-Name $a.path) — запуск: $(if ($a.locked) { 'ЗАБЛОКИРОВАНО' } else { 'разблокировано' }), процессов: $($a.procs)"
            if ($a.frozen) { $t += ", заморожено: $($a.frozen)" }
        }
        $st = State-Of $s
        $status.Text = $t
        $status.ForeColor = if ($st -eq 'down') { 'Red' } elseif ($st -eq 'unsure' -or $s.net_ok -eq $false) { 'DarkOrange' } else { 'Green' }
    }
    & $upd
    $tm = New-Object Windows.Forms.Timer; $tm.Interval = 2000; $tm.Add_Tick($upd); $tm.Start()
    $f.Add_FormClosed({ $tm.Stop() })
    [void]$f.ShowDialog()
}

# ---- окно выбора стран --------------------------------------------------------
$DefaultCountries = @('RU', 'CN', 'BY', 'IR')

# Все страны, какие знает Windows: код ISO и название на языке системы
function Get-Countries {
    $seen = @{}
    foreach ($c in [Globalization.CultureInfo]::GetCultures([Globalization.CultureTypes]::SpecificCultures)) {
        try { $r = New-Object Globalization.RegionInfo $c.Name } catch { continue }
        $code = $r.TwoLetterISORegionName
        if ($code -match '^[A-Z]{2}$' -and -not $seen.ContainsKey($code)) {
            $seen[$code] = 1
            [pscustomobject]@{ Code = $code; Name = $r.DisplayName }
        }
    }
}

function Show-Countries {
    $s = Read-Status
    $cur = if ($s -and $null -ne $s.countries) { @($s.countries) } else { $DefaultCountries }
    $st = @{ Sel = @{}; Busy = $false }
    foreach ($c in $cur) { $st.Sel["$c"] = $true }
    $all = @(Get-Countries)
    foreach ($c in $cur) { if (-not ($all | Where-Object Code -eq $c)) { $all += [pscustomobject]@{ Code = "$c"; Name = "$c" } } }
    $all = @($all | Sort-Object Name)

    $f = New-Object Windows.Forms.Form
    $f.Text = 'Vafa — страны'; $f.Size = New-Object Drawing.Size 460, 620; $f.StartPosition = 'CenterScreen'
    $f.Font = New-Object Drawing.Font 'Segoe UI', 10
    $ico = Join-Path $PSScriptRoot 'vafa.ico'; if (Test-Path $ico) { $f.Icon = New-Object Drawing.Icon $ico }

    $hdr = New-Object Windows.Forms.Label
    $hdr.Dock = 'Top'; $hdr.Height = 64; $hdr.Padding = New-Object Windows.Forms.Padding 10, 6, 10, 0
    $hdr.Text = "Страны, из которых VPN считается выключенным.`nЕсли интернет видит тебя из отмеченной страны — приложения блокируются."
    if ($s -and $s.geo -eq $false) { $hdr.Text += "`nПроверка страны выключена в config.json: добавь geo в checks."; $hdr.ForeColor = 'DarkOrange' }

    $search = New-Object Windows.Forms.TextBox
    $search.Dock = 'Top'

    $list = New-Object Windows.Forms.CheckedListBox
    $list.Dock = 'Fill'; $list.CheckOnClick = $true; $list.IntegralHeight = $false
    $shown = New-Object Collections.ArrayList

    $bottom = New-Object Windows.Forms.FlowLayoutPanel
    $bottom.Dock = 'Bottom'; $bottom.Height = 44; $bottom.FlowDirection = 'RightToLeft'; $bottom.Padding = New-Object Windows.Forms.Padding 6
    $save = New-Object Windows.Forms.Button; $save.Text = 'Сохранить'; $save.Width = 120
    $def  = New-Object Windows.Forms.Button; $def.Text = 'По умолчанию'; $def.Width = 130
    $count = New-Object Windows.Forms.Label; $count.AutoSize = $true; $count.Padding = New-Object Windows.Forms.Padding 0, 8, 0, 0
    $bottom.Controls.AddRange(@($save, $def, $count))

    $f.Controls.Add($list); $f.Controls.Add($search); $f.Controls.Add($hdr); $f.Controls.Add($bottom)
    $list.BringToFront()

    # выбранные — сверху; поиск по названию или коду
    $fill = {
        $st.Busy = $true
        $list.BeginUpdate(); $list.Items.Clear(); $shown.Clear()
        $q = $search.Text.Trim()
        $match = @($all | Where-Object { -not $q -or $_.Name -like "*$q*" -or $_.Code -eq $q })
        foreach ($c in (@($match | Where-Object { $st.Sel[$_.Code] }) + @($match | Where-Object { -not $st.Sel[$_.Code] }))) {
            [void]$shown.Add($c)
            $i = $list.Items.Add("$($c.Name)   $($c.Code)")
            if ($st.Sel[$c.Code]) { $list.SetItemChecked($i, $true) }
        }
        $list.EndUpdate()
        $count.Text = "Выбрано: $($st.Sel.Count)"
        $st.Busy = $false
    }
    $list.Add_ItemCheck({
        param($sender, $e)
        if ($st.Busy) { return }
        $code = $shown[$e.Index].Code
        if ($e.NewValue -eq 'Checked') { $st.Sel[$code] = $true } else { $st.Sel.Remove($code) }
        $count.Text = "Выбрано: $($st.Sel.Count)"
    })
    $search.Add_TextChanged($fill)
    $def.Add_Click({ $st.Sel.Clear(); foreach ($c in $DefaultCountries) { $st.Sel[$c] = $true }; & $fill })
    $save.Add_Click({
        $tmp = Join-Path $env:TEMP "vpnguard-countries-$PID.json"
        ConvertTo-Json -InputObject @($st.Sel.Keys | Sort-Object) | Set-Content $tmp -Encoding UTF8
        if (Run-Elevated "& '$Daemon' set-countries '$tmp'") { $f.Close() }
        Remove-Item $tmp -ErrorAction SilentlyContinue
    })
    & $fill
    [void]$f.ShowDialog()
}

# ---- журнал: новые записи сверху --------------------------------------------
function Get-ReversedLog {
    $p = Join-Path $Root 'vpn-guard.log'
    if (-not (Test-Path $p)) { return 'Журнал пуст' }
    $lines = @(Get-Content $p -Tail 2000 -Encoding UTF8)
    [array]::Reverse($lines)
    $lines -join "`r`n"
}
function Show-Log {
    $f = New-Object Windows.Forms.Form
    $f.Text = 'Vafa — журнал (новые сверху)'; $f.Size = New-Object Drawing.Size 820, 560; $f.StartPosition = 'CenterScreen'
    $tb = New-Object Windows.Forms.TextBox
    $tb.Multiline = $true; $tb.ReadOnly = $true; $tb.ScrollBars = 'Both'; $tb.WordWrap = $false; $tb.Dock = 'Fill'
    $tb.Font = New-Object Drawing.Font 'Consolas', 9
    $tb.Text = Get-ReversedLog; $tb.SelectionStart = 0
    $f.Controls.Add($tb)
    $tm = New-Object Windows.Forms.Timer; $tm.Interval = 2000
    $tm.Add_Tick({ $t = Get-ReversedLog; if ($tb.Text -ne $t) { $tb.Text = $t; $tb.SelectionStart = 0 } }); $tm.Start()
    $f.Add_FormClosed({ $tm.Stop() })
    [void]$f.ShowDialog()
}

# ---- трей -------------------------------------------------------------------
$ni = New-Object Windows.Forms.NotifyIcon
$ni.Visible = $true
$menu = New-Object Windows.Forms.ContextMenuStrip
$ni.ContextMenuStrip = $menu

function Rebuild-Menu {
    $menu.Items.Clear()
    $s = Read-Status
    $on = Guard-On -Fresh
    if (Is-Stale $s) { [void]$menu.Items.Add($(if ($on) { 'Служба не отвечает — состояние неизвестно' } else { 'Охрана выключена' })) }
    else {
        [void]$menu.Items.Add((State-Text $s))
        $nt = Net-Text $s; if ($nt) { [void]$menu.Items.Add($nt) }
        [void]$menu.Items.Add("интерфейс: $($s.iface), страна: $(if ($s.country) { $s.country } else { 'нет ответа' })")
        if ($null -ne $s.countries) {
            [void]$menu.Items.Add($(if ($s.geo -eq $false) { 'проверка страны выключена в конфиге' }
                elseif (@($s.countries).Count) { "блокировать из: $(@($s.countries) -join ', ')" } else { 'страны блокировки не выбраны' }))
        }
        foreach ($a in $s.apps) {
            $l = "$(App-Name $a.path) — запуск: $(if ($a.locked) { 'ЗАБЛОКИРОВАНО' } else { 'разблокировано' }), процессов: $($a.procs)"
            if ($a.frozen) { $l += ", заморожено: $($a.frozen)" }
            [void]$menu.Items.Add($l)
        }
    }
    foreach ($i in $menu.Items) { $i.Enabled = $false }
    [void]$menu.Items.Add('-')
    $menu.Items.Add('Выбрать приложения…').Add_Click({ Show-Picker })
    $menu.Items.Add('Выбрать страны…').Add_Click({ Show-Countries })

    $g = New-Object Windows.Forms.ToolStripMenuItem 'Охрана включена'
    $g.Checked = $on
    $g.Add_Click({
        if (Guard-On -Fresh) {
            # сначала выключить задачу (её повтор раз в минуту поднял бы службу снова), потом
            # остановить; unlock гасит и демона — Stop-ScheduledTask убивает только сторожа
            Run-Elevated "Disable-ScheduledTask -TaskName VPNGuard; Stop-ScheduledTask -TaskName VPNGuard; & '$Daemon' unlock" | Out-Null
        } else {
            Run-Elevated "Enable-ScheduledTask -TaskName VPNGuard; Start-ScheduledTask -TaskName VPNGuard" | Out-Null
        }
        [void](Guard-On -Fresh); & $refresh
    })
    [void]$menu.Items.Add($g)

    $li = New-Object Windows.Forms.ToolStripMenuItem 'Запускать при входе в Windows'
    $li.Checked = [bool](Get-ItemProperty $RunKey -Name $RunName -ErrorAction SilentlyContinue)
    $li.Add_Click({
        if (Get-ItemProperty $RunKey -Name $RunName -ErrorAction SilentlyContinue) {
            Remove-ItemProperty $RunKey -Name $RunName
        } else {
            $cmd = "conhost.exe --headless powershell.exe -NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`""
            Set-ItemProperty $RunKey -Name $RunName -Value $cmd
        }
    })
    [void]$menu.Items.Add($li)
    [void]$menu.Items.Add('-')
    $menu.Items.Add('Открыть журнал').Add_Click({ Show-Log })
    $menu.Items.Add('Выход').Add_Click({ $ni.Visible = $false; [Windows.Forms.Application]::Exit() })
}
$menu.Add_Opening({ Rebuild-Menu })
$ni.Add_DoubleClick({ Show-Picker })

# Спокойный зелёный — только когда VPN подтверждён и сеть к Anthropic под фильтром.
# Служба молчит при включённой охране — не контур «выключено», а оранжевый с «!».
# (Подсказка NotifyIcon — не длиннее 63 символов.)
$refresh = {
    $s = Read-Status
    if (-not (Guard-On)) { $ni.Icon = $IconOff; $ni.Text = 'Vafa: охрана выключена' }
    elseif (Is-Stale $s) { $ni.Icon = $IconDead; $ni.Text = 'Vafa: служба не отвечает' }
    else {
        $st = State-Of $s
        if ($st -eq 'down') { $ni.Icon = $IconDown; $ni.Text = $(if ($s.net_ok -eq $false) { 'Vafa: блокировка; сеть НЕ ЗАЩИЩЕНА' } else { 'Vafa: блокировка' }) }
        elseif ($st -eq 'unsure') { $ni.Icon = $IconWarn; $ni.Text = 'Vafa: страна не подтверждена — сеть закрыта' }
        elseif ($s.net_ok -eq $false) { $ni.Icon = $IconWarn; $ni.Text = 'Vafa: VPN поднят, сеть НЕ ЗАЩИЩЕНА' }
        else { $ni.Icon = $IconUp; $ni.Text = 'Vafa: VPN поднят' }
    }
}
& $refresh
Rebuild-Menu
$timer = New-Object Windows.Forms.Timer; $timer.Interval = 2000; $timer.Add_Tick($refresh); $timer.Start()
[Windows.Forms.Application]::Run()
