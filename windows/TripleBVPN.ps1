# TripleBVPN.ps1 — small WinForms front-end for hvpn.exe (Windows client).
#
# Run:  powershell -ExecutionPolicy Bypass -File .\TripleBVPN.ps1
# Needs hvpn.exe and wintun.dll in the same folder, and admin approval once per
# connect (the tunnel adapter is a driver view).
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

$root = Split-Path -Parent $MyInvocation.MyCommand.Definition
$exe  = Join-Path $root 'hvpn.exe'
$key  = Join-Path $root 'psk.txt'
$log  = Join-Path $env:TEMP 'tripleb-vpn.log'
$err  = Join-Path $env:TEMP 'tripleb-vpn.err'

if (-not (Test-Path $exe)) {
    [System.Windows.Forms.MessageBox]::Show("hvpn.exe is missing next to this script.", "Triple B VPN")
    exit 1
}

# First run: make a key (the exit node must use the same one).
if (-not (Test-Path $key)) {
    & $exe keygen -o $key | Out-Null
}

$form = New-Object System.Windows.Forms.Form
$form.Text = "Triple B VPN"
$form.Size = New-Object System.Drawing.Size(460, 420)
$form.StartPosition = "CenterScreen"
$form.FormBorderStyle = "FixedSingle"
$form.MaximizeBox = $false
$form.BackColor = [System.Drawing.Color]::FromArgb(24, 26, 34)
$form.ForeColor = [System.Drawing.Color]::White
$form.Font = New-Object System.Drawing.Font("Segoe UI", 9)

function Add-Label($text, $x, $y, $w = 120) {
    $l = New-Object System.Windows.Forms.Label
    $l.Text = $text; $l.Location = New-Object System.Drawing.Point($x, $y)
    $l.Size = New-Object System.Drawing.Size($w, 20)
    $l.ForeColor = [System.Drawing.Color]::FromArgb(170, 176, 190)
    $form.Controls.Add($l); return $l
}

$title = New-Object System.Windows.Forms.Label
$title.Text = "TRIPLE B VPN"
$title.Font = New-Object System.Drawing.Font("Segoe UI", 13, [System.Drawing.FontStyle]::Bold)
$title.Location = New-Object System.Drawing.Point(18, 14)
$title.Size = New-Object System.Drawing.Size(300, 28)
$form.Controls.Add($title)

Add-Label "Peer host:port" 18 56 | Out-Null
$peer = New-Object System.Windows.Forms.TextBox
$peer.Location = New-Object System.Drawing.Point(18, 78)
$peer.Size = New-Object System.Drawing.Size(410, 24)
$peer.Text = "127.0.0.1:51820"
$form.Controls.Add($peer)

Add-Label "Mode" 18 112 | Out-Null
$mode = New-Object System.Windows.Forms.ComboBox
$mode.Location = New-Object System.Drawing.Point(18, 134)
$mode.Size = New-Object System.Drawing.Size(160, 24)
$mode.DropDownStyle = "DropDownList"
[void]$mode.Items.Add("Full tunnel")
[void]$mode.Items.Add("Split tunnel")
$mode.SelectedIndex = 0
$form.Controls.Add($mode)

Add-Label "Split routes (cidr,cidr)" 190 112 240 | Out-Null
$routes = New-Object System.Windows.Forms.TextBox
$routes.Location = New-Object System.Drawing.Point(190, 134)
$routes.Size = New-Object System.Drawing.Size(238, 24)
$routes.Text = "1.1.1.1/32"
$form.Controls.Add($routes)

$connect = New-Object System.Windows.Forms.Button
$connect.Text = "Connect"
$connect.Location = New-Object System.Drawing.Point(18, 174)
$connect.Size = New-Object System.Drawing.Size(196, 34)
$connect.BackColor = [System.Drawing.Color]::FromArgb(11, 111, 250)
$connect.ForeColor = [System.Drawing.Color]::White
$connect.FlatStyle = "Flat"
$form.Controls.Add($connect)

$disconnect = New-Object System.Windows.Forms.Button
$disconnect.Text = "Disconnect"
$disconnect.Location = New-Object System.Drawing.Point(232, 174)
$disconnect.Size = New-Object System.Drawing.Size(196, 34)
$disconnect.FlatStyle = "Flat"
$form.Controls.Add($disconnect)

$status = New-Object System.Windows.Forms.Label
$status.Text = "Idle"
$status.Location = New-Object System.Drawing.Point(18, 216)
$status.Size = New-Object System.Drawing.Size(410, 20)
$status.ForeColor = [System.Drawing.Color]::FromArgb(140, 220, 160)
$form.Controls.Add($status)

$box = New-Object System.Windows.Forms.TextBox
$box.Location = New-Object System.Drawing.Point(18, 240)
$box.Size = New-Object System.Drawing.Size(410, 120)
$box.Multiline = $true
$box.ReadOnly = $true
$box.ScrollBars = "Vertical"
$box.BackColor = [System.Drawing.Color]::FromArgb(14, 16, 22)
$box.ForeColor = [System.Drawing.Color]::FromArgb(190, 196, 210)
$box.Font = New-Object System.Drawing.Font("Consolas", 8)
$form.Controls.Add($box)

$script:running = $false

function Tail-Log {
    if (Test-Path $log) {
        try {
            $lines = Get-Content $log -Tail 12 -ErrorAction Stop
            $box.Text = ($lines -join "`r`n")
        } catch { }
    }
}

$timer = New-Object System.Windows.Forms.Timer
$timer.Interval = 1000
$timer.Add_Tick({
    Tail-Log
    $alive = Get-Process -Name hvpn -ErrorAction SilentlyContinue
    if ($alive) {
        $status.Text = "Connected (hvpn.exe pid $($alive.Id))"
    } elseif ($script:running) {
        $status.Text = "Stopped"
        $script:running = $false
        $connect.Enabled = $true
    }
})
$timer.Start()

$connect.Add_Click({
    $argList = @("up", "--key", "`"$key`"", "--peer", $peer.Text)
    if ($mode.SelectedIndex -eq 0) {
        $argList += "--default"
    } else {
        foreach ($r in ($routes.Text -split ',')) {
            $t = $r.Trim()
            if ($t) { $argList += @("--route", $t) }
        }
    }
    $inner = "& '$exe' " + ($argList -join ' ') + " *> '$log'"
    try {
        Start-Process -FilePath "powershell" -Verb RunAs -WindowStyle Hidden `
            -ArgumentList @("-NoProfile", "-Command", $inner) | Out-Null
        $script:running = $true
        $connect.Enabled = $false
        $status.Text = "Starting (approve the admin prompt)…"
    } catch {
        $status.Text = "Not started: $($_.Exception.Message)"
    }
})

$disconnect.Add_Click({
    try {
        Start-Process -FilePath "powershell" -Verb RunAs -WindowStyle Hidden `
            -ArgumentList @("-NoProfile", "-Command", "& '$exe' down; Stop-Process -Name hvpn -Force -ErrorAction SilentlyContinue") | Out-Null
        $status.Text = "Disconnecting…"
        $connect.Enabled = $true
        $script:running = $false
    } catch {
        $status.Text = "Not stopped: $($_.Exception.Message)"
    }
})

[void]$form.ShowDialog()
