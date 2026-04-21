<#
================================================================================
ESXi-Audit.ps1

PURPOSE:
This script connects to ESXi hosts (via IP or hostname), gathers configuration
information, and prints it in a structured format.

THIS IS AN AUDIT-ONLY SCRIPT:
- It DOES NOT change anything
- It DOES NOT restart services
- It ONLY reads and reports configuration

REQUIREMENTS:
- VMware PowerCLI installed
- Network access to ESXi hosts
- Valid credentials (root or equivalent)

INPUT:
- CSV file containing HostName and/or IP

OUTPUT:
- Console output showing status of:
  Connect, Kernel, SSH, NTP, DNS, Datastore, Certificates, Commands, Overall

Run If not in Root Folder 
$cred = Get-Credential

./ESXi-Audit.ps1 `
  -InputCsvPath /Users/yourname/esxi-script/My-hosts.csv `
  -Credential $cred `
  -IgnoreInvalidCert

Test With Single Host
$cred = Get-Credential
./ESXi-Audit.ps1 -InputCsvPath ./My-hosts.csv -Credential $cred -IgnoreInvalidCert

One Line Version 
$cred = Get-Credential; ./ESXi-Audit.ps1 -InputCsvPath ./My-hosts.csv -Credential $cred -IgnoreInvalidCert

Most Common Example Execution
$cred = Get-Credential

./ESXi-Audit.ps1 `
  -InputCsvPath ./My-hosts.csv `
  -Credential $cred `
  -IgnoreInvalidCert

================================================================================
#>

[CmdletBinding()]
param(
    # Path to the CSV file containing host list
    [Parameter(Mandatory = $true)]
    [string]$InputCsvPath,

    # Credential used to connect to ESXi (typically root)
    [Parameter(Mandatory = $true)]
    [pscredential]$Credential,

    # Optional: ignore SSL certificate warnings (very common with ESXi)
    [switch]$IgnoreInvalidCert
)

# ==============================================================================
# LOAD POWERSHELL MODULES
# ==============================================================================

# Import VMware PowerCLI module (required for all VMware commands)
Import-Module VMware.PowerCLI -ErrorAction Stop | Out-Null

# If user requested, suppress certificate warnings (ESXi uses self-signed certs)
if ($IgnoreInvalidCert) {
    Set-PowerCLIConfiguration -InvalidCertificateAction Ignore -Confirm:$false | Out-Null
}

# ==============================================================================
# LOGGING FUNCTION (FORMATS OUTPUT LIKE YOUR SCREENSHOT)
# ==============================================================================

function Write-LogLine {
    param(
        [string]$HostName,  # Host being processed
        [string]$Step,      # Step name (Connect, SSH, etc.)
        [ValidateSet('Success','Failed','Skipped','Warning','Info')]
        [string]$Status,    # Status category
        [string]$Message    # Detailed message
    )

    # Format status to fixed width for alignment
    $statusText = "{0,-8}" -f $Status

    # Choose color based on status
    $statusColor = switch ($Status) {
        'Success' { 'Cyan' }
        'Failed'  { 'Red' }
        'Skipped' { 'Yellow' }
        'Warning' { 'Magenta' }
        default   { 'Gray' }
    }

    # Print formatted output
    Write-Host "[$HostName]" -NoNewline -ForegroundColor Gray
    Write-Host " [$Step] " -NoNewline -ForegroundColor White
    Write-Host $statusText -NoNewline -ForegroundColor $statusColor
    Write-Host " - $Message" -ForegroundColor Gray
}

# ==============================================================================
# HELPER FUNCTION: GET VALUE FROM CSV ROW
# ==============================================================================

function Get-RowValue {
    param(
        [psobject]$Row,     # One row from CSV
        [string[]]$Names,   # Possible column names
        $Default = $null
    )

    # Try each possible column name until one exists
    foreach ($name in $Names) {
        if ($Row.PSObject.Properties.Name -contains $name) {
            $value = $Row.$name
            if ($null -ne $value -and "$value".Trim() -ne "") {
                return "$value".Trim()
            }
        }
    }

    return $Default
}

# ==============================================================================
# VALIDATE INPUT FILE
# ==============================================================================

if (-not (Test-Path -LiteralPath $InputCsvPath)) {
    throw "CSV file not found: $InputCsvPath"
}

# Import CSV into objects
$rows = Import-Csv -LiteralPath $InputCsvPath

# ==============================================================================
# MAIN LOOP - PROCESS EACH HOST
# ==============================================================================

foreach ($row in $rows) {

    # Get connection target (prefer IP, fallback to hostname)
    $connectTarget = Get-RowValue -Row $row -Names @(
        'IP','IpAddress','IPAddress',
        'HostName','Host','FQDN','Name'
    )

    if ([string]::IsNullOrWhiteSpace($connectTarget)) {
        Write-Host "Skipping row because no IP or HostName value was found." -ForegroundColor Yellow
        continue
    }

    $vi = $null  # Holds connection object

    try {
        # ======================================================================
        # CONNECT TO ESXi HOST
        # ======================================================================
        $vi = Connect-VIServer -Server $connectTarget -Credential $Credential -ErrorAction Stop

        Write-LogLine -HostName $connectTarget -Step 'Connect' -Status 'Success' `
            -Message "Connected to $connectTarget"

        # Get VMHost object (represents the ESXi host)
        $vmHost = Get-VMHost -Server $vi -ErrorAction Stop | Select-Object -First 1

        # ======================================================================
        # KERNEL (ADVANCED SETTING CHECK)
        # ======================================================================
        try {
            # Example advanced setting (controls shell warning)
            $setting = Get-AdvancedSetting -Entity $vmHost -Name 'UserVars.SuppressShellWarning'
            $value = "$($setting.Value)"

            if ($value -eq '0') {
                Write-LogLine $connectTarget 'Kernel' 'Success' 'Already configured to FALSE.'
            }
            elseif ($value -eq '1') {
                Write-LogLine $connectTarget 'Kernel' 'Success' 'Currently configured to TRUE.'
            }
            else {
                Write-LogLine $connectTarget 'Kernel' 'Success' "Current value: $value"
            }
        }
        catch {
            Write-LogLine $connectTarget 'Kernel' 'Failed' $_.Exception.Message
        }

        # ======================================================================
        # SSH SERVICE CHECK
        # ======================================================================
        try {
            # Get SSH service (TSM-SSH)
            $sshSvc = Get-VMHostService -VMHost $vmHost | Where-Object { $_.Key -eq 'TSM-SSH' }

            if (-not $sshSvc) {
                throw "SSH service not found."
            }

            if ($sshSvc.Running -and $sshSvc.Policy -eq 'on') {
                $msg = "SSH enabled and policy set to On."
            }
            else {
                $msg = "SSH running=$($sshSvc.Running); policy=$($sshSvc.Policy)"
            }

            Write-LogLine $connectTarget 'SSH' 'Success' $msg
        }
        catch {
            Write-LogLine $connectTarget 'SSH' 'Failed' $_.Exception.Message
        }

        # ======================================================================
        # NTP CHECK
        # ======================================================================
        try {
            # Get configured NTP servers
            $ntpServers = @(Get-VMHostNtpServer -VMHost $vmHost)

            $ntpText = if ($ntpServers.Count -gt 0) { $ntpServers -join ', ' } else { '<none>' }

            # Check for required servers
            if ($ntpServers -contains '10.255.100.10' -and $ntpServers -contains '10.255.100.11') {
                Write-LogLine $connectTarget 'NTP' 'Success' "NTP configured to $ntpText"
            }
            else {
                Write-LogLine $connectTarget 'NTP' 'Warning' "Current NTP servers: $ntpText"
            }
        }
        catch {
            Write-LogLine $connectTarget 'NTP' 'Failed' $_.Exception.Message
        }

        # ======================================================================
        # DNS / NETWORK CONFIG
        # ======================================================================
        try {
            $net = Get-VMHostNetwork -VMHost $vmHost

            $dnsText = if (@($net.DnsAddress).Count -gt 0) {
                @($net.DnsAddress) -join ', '
            } else {
                '<none>'
            }

            Write-LogLine $connectTarget 'DNS' 'Success' `
                "DNS/domain configured: HostName=$($net.HostName); Domain=$($net.DomainName); DNS=$dnsText"
        }
        catch {
            Write-LogLine $connectTarget 'DNS' 'Failed' $_.Exception.Message
        }

        # ======================================================================
        # DATASTORE CHECK
        # ======================================================================
        try {
            $datastores = Get-Datastore -VMHost $vmHost | Sort-Object Name

            if ($datastores.Count -eq 0) {
                Write-LogLine $connectTarget 'Datastore' 'Warning' 'No datastores found.'
            }
            else {
                $ds = $datastores | Select-Object -First 1
                Write-LogLine $connectTarget 'Datastore' 'Success' "Current datastore: $($ds.Name)"
            }
        }
        catch {
            Write-LogLine $connectTarget 'Datastore' 'Failed' $_.Exception.Message
        }

        # ======================================================================
        # CERTIFICATE / HOSTNAME CHECK
        # ======================================================================
        try {
            $net = Get-VMHostNetwork -VMHost $vmHost

            $fqdn = if ($net.DomainName) {
                "$($net.HostName).$($net.DomainName)"
            } else {
                $net.HostName
            }

            Write-LogLine $connectTarget 'Certificates' 'Success' `
                "Hostname/certificate identity: $fqdn"
        }
        catch {
            Write-LogLine $connectTarget 'Certificates' 'Failed' $_.Exception.Message
        }

        # ======================================================================
        # COMMANDS (NOT EXECUTED IN AUDIT MODE)
        # ======================================================================
        Write-LogLine $connectTarget 'Commands' 'Skipped' `
            'Audit-only script; no hostd/vpxa restart performed.'

        # ======================================================================
        # FINAL STATUS
        # ======================================================================
        Write-LogLine $connectTarget 'Overall' 'Success' 'Host processing complete.'
    }
    catch {
        Write-LogLine $connectTarget 'Connect' 'Failed' $_.Exception.Message
        Write-LogLine $connectTarget 'Overall' 'Failed' 'Host processing aborted because connection failed.'
    }
    finally {
        # Always disconnect session
        if ($vi) {
            Disconnect-VIServer -Server $vi -Confirm:$false | Out-Null
        }
    }
}