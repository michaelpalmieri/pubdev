# =========================
# ESXi Audit - Selection-Friendly Version
# =========================

# --- USER INPUT (auto-prompt if not set) ---
if (-not $InputCsvPath) {
    $InputCsvPath = Read-Host "Enter path to CSV (e.g. ./My-hosts.csv)"
}

if (-not $Credential) {
    $Credential = Get-Credential
}

$IgnoreInvalidCert = $true  # change to $false if needed

# --- LOAD MODULE ---
Import-Module VMware.PowerCLI -ErrorAction Stop | Out-Null

if ($IgnoreInvalidCert) {
    Set-PowerCLIConfiguration -InvalidCertificateAction Ignore -Confirm:$false | Out-Null
}

# --- LOG FUNCTION ---
function Write-LogLine {
    param($HostName, $Step, $Status, $Message)

    $statusText = "{0,-8}" -f $Status

    $statusColor = switch ($Status) {
        'Success' { 'Cyan' }
        'Failed'  { 'Red' }
        'Skipped' { 'Yellow' }
        'Warning' { 'Magenta' }
        default   { 'Gray' }
    }

    Write-Host "[$HostName]" -NoNewline -ForegroundColor Gray
    Write-Host " [$Step] " -NoNewline -ForegroundColor White
    Write-Host $statusText -NoNewline -ForegroundColor $statusColor
    Write-Host " - $Message" -ForegroundColor Gray
}

# --- CSV HELPER ---
function Get-RowValue {
    param($Row, $Names, $Default = $null)

    foreach ($name in $Names) {
        if ($Row.PSObject.Properties.Name -contains $name) {
            $value = $Row.$name
            if ($value -and "$value".Trim() -ne "") {
                return "$value".Trim()
            }
        }
    }
    return $Default
}

# --- VALIDATE CSV ---
if (-not (Test-Path -LiteralPath $InputCsvPath)) {
    throw "CSV file not found: $InputCsvPath"
}

$rows = Import-Csv -LiteralPath $InputCsvPath

# --- MAIN LOOP ---
foreach ($row in $rows) {

    $connectTarget = Get-RowValue -Row $row -Names @(
        'IP','IpAddress','IPAddress',
        'HostName','Host','FQDN','Name'
    )

    if ([string]::IsNullOrWhiteSpace($connectTarget)) {
        Write-Host "Skipping row (no host/IP)" -ForegroundColor Yellow
        continue
    }

    $vi = $null

    try {
        $vi = Connect-VIServer -Server $connectTarget -Credential $Credential -ErrorAction Stop
        Write-LogLine $connectTarget 'Connect' 'Success' "Connected"

        $vmHost = Get-VMHost -Server $vi | Select-Object -First 1

        # --- SSH CHECK ---
        try {
            $sshSvc = Get-VMHostService -VMHost $vmHost | Where-Object { $_.Key -eq 'TSM-SSH' }

            if ($sshSvc.Running -and $sshSvc.Policy -eq 'on') {
                Write-LogLine $connectTarget 'SSH' 'Success' 'SSH enabled'
            } else {
                Write-LogLine $connectTarget 'SSH' 'Warning' "Running=$($sshSvc.Running), Policy=$($sshSvc.Policy)"
            }
        } catch {
            Write-LogLine $connectTarget 'SSH' 'Failed' $_.Exception.Message
        }

        # --- NTP CHECK ---
        try {
            $ntp = @(Get-VMHostNtpServer -VMHost $vmHost)
            $text = if ($ntp) { $ntp -join ', ' } else { '<none>' }

            Write-LogLine $connectTarget 'NTP' 'Success' $text
        } catch {
            Write-LogLine $connectTarget 'NTP' 'Failed' $_.Exception.Message
        }

        # --- DNS CHECK ---
        try {
            $net = Get-VMHostNetwork -VMHost $vmHost
            Write-LogLine $connectTarget 'DNS' 'Success' "DNS: $($net.DnsAddress -join ', ')"
        } catch {
            Write-LogLine $connectTarget 'DNS' 'Failed' $_.Exception.Message
        }

        Write-LogLine $connectTarget 'Overall' 'Success' 'Done'
    }
    catch {
        Write-LogLine $connectTarget 'Connect' 'Failed' $_.Exception.Message
    }
    finally {
        if ($vi) {
            Disconnect-VIServer -Server $vi -Confirm:$false | Out-Null
        }
    }
}# =========================
# ESXi Audit - Selection-Friendly Version
# =========================

# --- USER INPUT (auto-prompt if not set) ---
if (-not $InputCsvPath) {
    $InputCsvPath = Read-Host "Enter path to CSV (e.g. ./My-hosts.csv)"
}

if (-not $Credential) {
    $Credential = Get-Credential
}

$IgnoreInvalidCert = $true  # change to $false if needed

# --- LOAD MODULE ---
Import-Module VMware.PowerCLI -ErrorAction Stop | Out-Null

if ($IgnoreInvalidCert) {
    Set-PowerCLIConfiguration -InvalidCertificateAction Ignore -Confirm:$false | Out-Null
}

# --- LOG FUNCTION ---
function Write-LogLine {
    param($HostName, $Step, $Status, $Message)

    $statusText = "{0,-8}" -f $Status

    $statusColor = switch ($Status) {
        'Success' { 'Cyan' }
        'Failed'  { 'Red' }
        'Skipped' { 'Yellow' }
        'Warning' { 'Magenta' }
        default   { 'Gray' }
    }

    Write-Host "[$HostName]" -NoNewline -ForegroundColor Gray
    Write-Host " [$Step] " -NoNewline -ForegroundColor White
    Write-Host $statusText -NoNewline -ForegroundColor $statusColor
    Write-Host " - $Message" -ForegroundColor Gray
}

# --- CSV HELPER ---
function Get-RowValue {
    param($Row, $Names, $Default = $null)

    foreach ($name in $Names) {
        if ($Row.PSObject.Properties.Name -contains $name) {
            $value = $Row.$name
            if ($value -and "$value".Trim() -ne "") {
                return "$value".Trim()
            }
        }
    }
    return $Default
}

# --- VALIDATE CSV ---
if (-not (Test-Path -LiteralPath $InputCsvPath)) {
    throw "CSV file not found: $InputCsvPath"
}

$rows = Import-Csv -LiteralPath $InputCsvPath

# --- MAIN LOOP ---
foreach ($row in $rows) {

    $connectTarget = Get-RowValue -Row $row -Names @(
        'IP','IpAddress','IPAddress',
        'HostName','Host','FQDN','Name'
    )

    if ([string]::IsNullOrWhiteSpace($connectTarget)) {
        Write-Host "Skipping row (no host/IP)" -ForegroundColor Yellow
        continue
    }

    $vi = $null

    try {
        $vi = Connect-VIServer -Server $connectTarget -Credential $Credential -ErrorAction Stop
        Write-LogLine $connectTarget 'Connect' 'Success' "Connected"

        $vmHost = Get-VMHost -Server $vi | Select-Object -First 1

        # --- SSH CHECK ---
        try {
            $sshSvc = Get-VMHostService -VMHost $vmHost | Where-Object { $_.Key -eq 'TSM-SSH' }

            if ($sshSvc.Running -and $sshSvc.Policy -eq 'on') {
                Write-LogLine $connectTarget 'SSH' 'Success' 'SSH enabled'
            } else {
                Write-LogLine $connectTarget 'SSH' 'Warning' "Running=$($sshSvc.Running), Policy=$($sshSvc.Policy)"
            }
        } catch {
            Write-LogLine $connectTarget 'SSH' 'Failed' $_.Exception.Message
        }

        # --- NTP CHECK ---
        try {
            $ntp = @(Get-VMHostNtpServer -VMHost $vmHost)
            $text = if ($ntp) { $ntp -join ', ' } else { '<none>' }

            Write-LogLine $connectTarget 'NTP' 'Success' $text
        } catch {
            Write-LogLine $connectTarget 'NTP' 'Failed' $_.Exception.Message
        }

        # --- DNS CHECK ---
        try {
            $net = Get-VMHostNetwork -VMHost $vmHost
            Write-LogLine $connectTarget 'DNS' 'Success' "DNS: $($net.DnsAddress -join ', ')"
        } catch {
            Write-LogLine $connectTarget 'DNS' 'Failed' $_.Exception.Message
        }

        Write-LogLine $connectTarget 'Overall' 'Success' 'Done'
    }
    catch {
        Write-LogLine $connectTarget 'Connect' 'Failed' $_.Exception.Message
    }
    finally {
        if ($vi) {
            Disconnect-VIServer -Server $vi -Confirm:$false | Out-Null
        }
    }
}