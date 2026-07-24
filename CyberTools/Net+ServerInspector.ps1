<#
.SYNOPSIS
    Enterprise PowerShell Audit & Network Performance Toolkit

.DESCRIPTION
    Menu-driven toolkit for auditing Windows systems and performing
    network performance testing.

    Features:
        - Full System Audit
        - Disk Space Analysis
        - CPU and Memory Inventory
        - Network Adapter Reporting
        - Share Enumeration
        - Service Inventory
        - Domain Trust Verification
        - TLS/SCHANNEL Auditing
        - Latency and Jitter Testing
        - SMB Throughput Testing
        - iPerf3 Bandwidth Testing
        - iPerf3 Server Mode

.USAGE
    STEP 1 - Save Script

        Save this script as:

            Audit-NetworkToolkit.ps1

    STEP 2 - Open PowerShell

        Run PowerShell as Administrator.

    STEP 3 - Allow Script Execution, if required

        Set-ExecutionPolicy RemoteSigned -Scope CurrentUser

    STEP 4 - Navigate to Script Location

        cd C:\Scripts

    STEP 5 - Execute Script

        .\Audit-NetworkToolkit.ps1

    STEP 6 - Select Menu Option

        1 = Full System Audit
        2 = Latency / Jitter Test
        3 = SMB Bandwidth Test
        4 = iPerf3 Bandwidth Test
        5 = Start iPerf3 Server Mode
        6 = Show Help
        7 = Exit

    OPTIONAL - Load Functions Only

        . .\Audit-NetworkToolkit.ps1

    Then run:

        Get-BulkInfo -ComputerName SERVER01
        Test-NetworkQuality -ComputerName SERVER01
        Test-SMBBandwidth -RemoteShare "\\FILESERVER\TEST"
        Test-IperfBandwidth -Server SERVER01

.IPERF3 SETUP
    Download iPerf3 from:

        https://iperf.fr

    On the destination server:

        iperf3.exe -s

    On the source system:

        iperf3.exe -c SERVER01 -t 30

.REQUIREMENTS
    - Administrative rights on remote systems
    - WinRM enabled for remoting-based checks
    - PowerShell 2.0 or newer
    - iPerf3 installed for iPerf bandwidth testing
    - Writable SMB share for SMB bandwidth testing

.NOTES
    Author      : MP
    Version     : 2.0
    Created     : June 2026
    Compatibility:
        Windows PowerShell 2.0+
        Windows PowerShell 5.1
        PowerShell 7+

    Disclaimer:
        This software is provided AS-IS with no warranty expressed or implied.
        Use at your own risk.

.EXAMPLE
    .\Audit-NetworkToolkit.ps1

    Starts the interactive menu.

.EXAMPLE
    Get-BulkInfo -ComputerName SERVER01

    Performs a complete audit of SERVER01.

.EXAMPLE
    Get-BulkInfo -ComputerName SERVER01,SERVER02

    Performs a complete audit of multiple systems.

.EXAMPLE
    Test-NetworkQuality -ComputerName SERVER01 -Count 50

    Tests latency and jitter.

.EXAMPLE
    Test-SMBBandwidth -RemoteShare "\\FILESERVER\TEST" -FileSizeMB 500

    Measures SMB throughput.

.EXAMPLE
    Test-IperfBandwidth -Server SERVER01 -Duration 60

    Measures bandwidth using iPerf3.
#>

$Script:ToolkitVersion = "2.0"

function Test-IsAdmin {
    try {
        $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = New-Object Security.Principal.WindowsPrincipal($identity)
        return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    }
    catch {
        return $false
    }
}

function Show-Banner {
    Clear-Host
    Write-Host "=======================================" -ForegroundColor Cyan
    Write-Host " PowerShell Audit & Bandwidth Toolkit" -ForegroundColor Cyan
    Write-Host " Version: $Script:ToolkitVersion" -ForegroundColor Cyan
    Write-Host " Author : MP" -ForegroundColor Cyan
    Write-Host "=======================================" -ForegroundColor Cyan
    Write-Host "User        : $env:USERNAME"
    Write-Host "Computer    : $env:COMPUTERNAME"
    Write-Host "PowerShell  : $($PSVersionTable.PSVersion)"
    Write-Host "Admin Mode  : $(Test-IsAdmin)"
    Write-Host "Date        : $(Get-Date)"
    Write-Host "======================================="
    Write-Host ""
}

function Pause-Menu {
    Write-Host ""
    Read-Host "Press Enter to continue"
}

function Get-RemoteData {
<#
.SYNOPSIS
    Queries remote WMI/CIM data.

.DESCRIPTION
    Uses Get-CimInstance when available and falls back to Get-WmiObject
    for compatibility with older Windows PowerShell versions.

.EXAMPLE
    Get-RemoteData -Computer SERVER01 -ClassName Win32_ComputerSystem
#>
    param(
        [Parameter(Mandatory = $true)]
        [string]$Computer,

        [Parameter(Mandatory = $true)]
        [string]$ClassName,

        [string]$Filter
    )

    try {
        if (Get-Command Get-CimInstance -ErrorAction SilentlyContinue) {
            if ($Filter) {
                Get-CimInstance -ClassName $ClassName -ComputerName $Computer -Filter $Filter -ErrorAction Stop
            }
            else {
                Get-CimInstance -ClassName $ClassName -ComputerName $Computer -ErrorAction Stop
            }
        }
        else {
            if ($Filter) {
                Get-WmiObject -Class $ClassName -ComputerName $Computer -Filter $Filter -ErrorAction Stop
            }
            else {
                Get-WmiObject -Class $ClassName -ComputerName $Computer -ErrorAction Stop
            }
        }
    }
    catch {
        Write-Warning "[$Computer] Failed to query $ClassName. $($_.Exception.Message)"
        return $null
    }
}

function Test-NetworkQuality {
<#
.SYNOPSIS
    Tests latency and jitter.

.DESCRIPTION
    Uses Test-Connection to measure average, minimum, and maximum latency.
    Jitter is calculated as MaxLatency minus MinLatency.

.EXAMPLE
    Test-NetworkQuality -ComputerName SERVER01

.EXAMPLE
    Test-NetworkQuality -ComputerName SERVER01 -Count 50
#>
    param(
        [Parameter(Mandatory = $true)]
        [string]$ComputerName,

        [int]$Count = 20
    )

    try {
        $results = Test-Connection -ComputerName $ComputerName -Count $Count -ErrorAction Stop

        $avg = ($results | Measure-Object ResponseTime -Average).Average
        $min = ($results | Measure-Object ResponseTime -Minimum).Minimum
        $max = ($results | Measure-Object ResponseTime -Maximum).Maximum

        [PSCustomObject]@{
            ComputerName   = $ComputerName
            Count          = $Count
            AverageLatency = [math]::Round($avg, 2)
            MinLatency     = $min
            MaxLatency     = $max
            Jitter         = [math]::Round(($max - $min), 2)
        }
    }
    catch {
        Write-Warning "Network quality test failed for $ComputerName. $($_.Exception.Message)"
    }
}

function Test-SMBBandwidth {
<#
.SYNOPSIS
    Tests SMB file transfer throughput.

.DESCRIPTION
    Creates a temporary test file, copies it to a remote SMB share,
    measures transfer time, calculates Mbps, and removes the test files.

.EXAMPLE
    Test-SMBBandwidth -RemoteShare "\\SERVER\Share"

.EXAMPLE
    Test-SMBBandwidth -RemoteShare "\\SERVER\Share" -FileSizeMB 500
#>
    param(
        [Parameter(Mandatory = $true)]
        [string]$RemoteShare,

        [int]$FileSizeMB = 100
    )

    $localName = "BandwidthTest_$([guid]::NewGuid()).bin"
    $remoteName = "BandwidthTest_$([guid]::NewGuid()).bin"

    $testFile = Join-Path $env:TEMP $localName
    $destination = Join-Path $RemoteShare $remoteName

    try {
        if (-not (Test-Path $RemoteShare)) {
            throw "Remote share is not reachable or does not exist: $RemoteShare"
        }

        Write-Host "Creating $FileSizeMB MB test file..." -ForegroundColor Yellow

        $bytes = $FileSizeMB * 1MB
        $fs = [System.IO.File]::Create($testFile)
        $fs.SetLength($bytes)
        $fs.Close()

        Write-Host "Copying test file to $RemoteShare..." -ForegroundColor Yellow

        $sw = [System.Diagnostics.Stopwatch]::StartNew()
        Copy-Item -Path $testFile -Destination $destination -Force -ErrorAction Stop
        $sw.Stop()

        $mbps = ($FileSizeMB * 8) / $sw.Elapsed.TotalSeconds

        [PSCustomObject]@{
            RemoteShare = $RemoteShare
            FileSizeMB  = $FileSizeMB
            Seconds     = [math]::Round($sw.Elapsed.TotalSeconds, 2)
            Mbps        = [math]::Round($mbps, 2)
        }
    }
    catch {
        Write-Warning "SMB bandwidth test failed. $($_.Exception.Message)"
    }
    finally {
        if (Test-Path $testFile) {
            Remove-Item $testFile -Force -ErrorAction SilentlyContinue
        }

        if (Test-Path $destination) {
            Remove-Item $destination -Force -ErrorAction SilentlyContinue
        }
    }
}

function Test-IperfBandwidth {
<#
.SYNOPSIS
    Runs an iPerf3 bandwidth test.

.DESCRIPTION
    Uses iperf3.exe to test network throughput against a remote iPerf3 server.

.EXAMPLE
    Test-IperfBandwidth -Server SERVER01

.EXAMPLE
    Test-IperfBandwidth -Server SERVER01 -Duration 60 -IperfPath "C:\Tools\iperf3.exe"
#>
    param(
        [Parameter(Mandatory = $true)]
        [string]$Server,

        [int]$Duration = 30,

        [string]$IperfPath = "iperf3.exe"
    )

    try {
        $iperf = Get-Command $IperfPath -ErrorAction SilentlyContinue

        if (-not $iperf) {
            Write-Warning "iperf3.exe was not found. Install iPerf3 or provide the full path."
            return
        }

        Write-Host "Running iPerf3 test against $Server for $Duration seconds..." -ForegroundColor Yellow
        & $IperfPath -c $Server -t $Duration
    }
    catch {
        Write-Warning "iPerf3 bandwidth test failed. $($_.Exception.Message)"
    }
}

function Start-IperfServer {
<#
.SYNOPSIS
    Starts iPerf3 in server mode.

.DESCRIPTION
    Starts iperf3.exe using the -s parameter. Use CTRL+C to stop.

.EXAMPLE
    Start-IperfServer

.EXAMPLE
    Start-IperfServer -IperfPath "C:\Tools\iperf3.exe"
#>
    param(
        [string]$IperfPath = "iperf3.exe"
    )

    try {
        $iperf = Get-Command $IperfPath -ErrorAction SilentlyContinue

        if (-not $iperf) {
            Write-Warning "iperf3.exe was not found."
            return
        }

        Write-Host "Starting iPerf3 server mode. Press CTRL+C to stop." -ForegroundColor Yellow
        & $IperfPath -s
    }
    catch {
        Write-Warning "Failed to start iPerf3 server mode. $($_.Exception.Message)"
    }
}

function Get-BulkInfo {
<#
.SYNOPSIS
    Performs a full Windows system audit.

.DESCRIPTION
    Audits one or more Windows computers for:
        - Connectivity
        - Latency
        - Computer model
        - Memory
        - Disk space
        - CPU
        - Network adapters
        - Shares
        - Services
        - Domain trust
        - TLS / SCHANNEL registry settings

.EXAMPLE
    Get-BulkInfo -ComputerName SERVER01

.EXAMPLE
    Get-BulkInfo -ComputerName SERVER01,SERVER02
#>
    param(
        [Parameter(Mandatory = $true)]
        [Alias("Server")]
        [string[]]$ComputerName
    )

    foreach ($Computer in $ComputerName) {

        Write-Host ""
        Write-Host "======================================" -ForegroundColor Cyan
        Write-Host " Auditing $Computer" -ForegroundColor Cyan
        Write-Host "======================================" -ForegroundColor Cyan

        try {
            Test-Connection -ComputerName $Computer -Count 1 -ErrorAction Stop | Out-Null
            Write-Host "Ping: Online" -ForegroundColor Green
        }
        catch {
            Write-Warning "[$Computer] Host is unreachable. $($_.Exception.Message)"
            continue
        }

        Write-Host "`n--- LATENCY TEST ---" -ForegroundColor Magenta
        Test-NetworkQuality -ComputerName $Computer -Count 10 | Format-List

        Write-Host "`n--- SYSTEM MODEL / MEMORY ---" -ForegroundColor Magenta
        $cs = Get-RemoteData -Computer $Computer -ClassName Win32_ComputerSystem

        if ($cs) {
            $cs | Select-Object Name, Manufacturer, Model,
                @{Name = "MemoryGB"; Expression = { [math]::Round($_.TotalPhysicalMemory / 1GB, 2) } } |
                Format-List
        }

        Write-Host "`n--- OPERATING SYSTEM ---" -ForegroundColor Magenta
        $os = Get-RemoteData -Computer $Computer -ClassName Win32_OperatingSystem

        if ($os) {
            $os | Select-Object Caption, Version, BuildNumber,
                @{Name = "LastBootUpTime"; Expression = { $_.LastBootUpTime } } |
                Format-List
        }

        Write-Host "`n--- DISK REPORT ---" -ForegroundColor Magenta
        $disks = Get-RemoteData -Computer $Computer -ClassName Win32_LogicalDisk -Filter "DriveType = 3"

        if ($disks) {
            $disks | Select-Object DeviceID, VolumeName,
                @{Name = "SizeGB"; Expression = { [math]::Round($_.Size / 1GB, 2) } },
                @{Name = "FreeGB"; Expression = { [math]::Round($_.FreeSpace / 1GB, 2) } },
                @{Name = "FreePercent"; Expression = {
                    if ($_.Size -gt 0) {
                        [math]::Round(($_.FreeSpace / $_.Size) * 100, 2)
                    }
                    else {
                        0
                    }
                } } |
                Format-Table -AutoSize
        }

        Write-Host "`n--- CPU INFO ---" -ForegroundColor Magenta
        $cpu = Get-RemoteData -Computer $Computer -ClassName Win32_Processor

        if ($cpu) {
            $totalCores = ($cpu | Measure-Object NumberOfCores -Sum).Sum

            $cpu | Select-Object Name, Caption, NumberOfCores, NumberOfLogicalProcessors |
                Format-Table -AutoSize

            Write-Host "Total cores: $totalCores" -ForegroundColor Green
        }

        Write-Host "`n--- NETWORK ADAPTERS ---" -ForegroundColor Magenta
        $nics = Get-RemoteData -Computer $Computer -ClassName Win32_NetworkAdapterConfiguration -Filter "IPEnabled = True"

        if ($nics) {
            $nics | Select-Object Description, MACAddress,
                @{Name = "IPAddress"; Expression = { $_.IPAddress -join ", " } },
                @{Name = "Gateway"; Expression = { $_.DefaultIPGateway -join ", " } },
                @{Name = "DNS"; Expression = { $_.DNSServerSearchOrder -join ", " } } |
                Format-Table -AutoSize
        }

        Write-Host "`n--- SHARES ---" -ForegroundColor Magenta
        $shares = Get-RemoteData -Computer $Computer -ClassName Win32_Share

        if ($shares) {
            $shares | Select-Object Name, Path, Description |
                Format-Table -AutoSize
        }

        Write-Host "`n--- SERVICES COUNT ---" -ForegroundColor Magenta
        $services = Get-RemoteData -Computer $Computer -ClassName Win32_Service

        if ($services) {
            Write-Host "Found $($services.Count) services." -ForegroundColor Green

            Write-Host "`nStopped automatic services:" -ForegroundColor Yellow
            $services |
                Where-Object { $_.StartMode -eq "Auto" -and $_.State -ne "Running" } |
                Select-Object Name, DisplayName, State, StartMode |
                Format-Table -AutoSize
        }

        Write-Host "`n--- DOMAIN TRUST / TLS INFO ---" -ForegroundColor Magenta

        try {
            Invoke-Command -ComputerName $Computer -ScriptBlock {

                Write-Host "Domain Trust:" -ForegroundColor Cyan

                try {
                    if (Get-Command Test-ComputerSecureChannel -ErrorAction SilentlyContinue) {
                        Test-ComputerSecureChannel
                    }
                    else {
                        "Test-ComputerSecureChannel not available."
                    }
                }
                catch {
                    "Domain trust check failed: $($_.Exception.Message)"
                }

                Write-Host "`nTLS / .NET Registry Checks:" -ForegroundColor Cyan

                $paths = @(
                    "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client",
                    "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server",
                    "HKLM:\SOFTWARE\Microsoft\.NETFramework\v2.0.50727",
                    "HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v2.0.50727",
                    "HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319",
                    "HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v4.0.30319"
                )

                foreach ($path in $paths) {
                    try {
                        $props = Get-ItemProperty -Path $path -ErrorAction Stop

                        [PSCustomObject]@{
                            Path                     = $path
                            Enabled                  = $props.Enabled
                            DisabledByDefault        = $props.DisabledByDefault
                            SystemDefaultTlsVersions = $props.SystemDefaultTlsVersions
                        }
                    }
                    catch {
                        [PSCustomObject]@{
                            Path  = $path
                            Error = $_.Exception.Message
                        }
                    }
                }
            } -ErrorAction Stop
        }
        catch {
            Write-Warning "[$Computer] Remote command failed. $($_.Exception.Message)"
        }
    }
}

function Show-HelpMenu {
    Write-Host ""
    Write-Host "HELP / EXAMPLES" -ForegroundColor Cyan
    Write-Host "==============="
    Write-Host ""
    Write-Host "Run the script:"
    Write-Host "    .\Audit-NetworkToolkit.ps1"
    Write-Host ""
    Write-Host "Load functions only:"
    Write-Host "    . .\Audit-NetworkToolkit.ps1"
    Write-Host ""
    Write-Host "Full audit:"
    Write-Host "    Get-BulkInfo -ComputerName SERVER01"
    Write-Host "    Get-BulkInfo -ComputerName SERVER01,SERVER02"
    Write-Host ""
    Write-Host "Latency / jitter:"
    Write-Host "    Test-NetworkQuality -ComputerName SERVER01 -Count 50"
    Write-Host ""
    Write-Host "SMB bandwidth:"
    Write-Host "    Test-SMBBandwidth -RemoteShare `"\\FILESERVER\TEST`" -FileSizeMB 500"
    Write-Host ""
    Write-Host "iPerf3 bandwidth:"
    Write-Host "    Test-IperfBandwidth -Server SERVER01 -Duration 30"
    Write-Host ""
    Write-Host "iPerf3 server mode:"
    Write-Host "    Start-IperfServer"
    Write-Host ""
}

function Show-MainMenu {
    Show-Banner

    Write-Host "1. Full system audit"
    Write-Host "2. Latency / jitter test"
    Write-Host "3. SMB bandwidth test"
    Write-Host "4. iPerf3 bandwidth test"
    Write-Host "5. Start iPerf3 server mode"
    Write-Host "6. Show help"
    Write-Host "7. Exit"
    Write-Host ""
}

do {
    Show-MainMenu
    $choice = Read-Host "Choose an option"

    switch ($choice) {

        "1" {
            $servers = Read-Host "Enter server name(s), comma separated"
            $serverList = $servers -split "," | ForEach-Object { $_.Trim() } | Where-Object { $_ }

            if ($serverList.Count -gt 0) {
                Get-BulkInfo -ComputerName $serverList
            }
            else {
                Write-Warning "No server names entered."
            }

            Pause-Menu
        }

        "2" {
            $server = Read-Host "Enter server name or IP"
            $count = Read-Host "Enter ping count. Default is 20"

            if (-not $count) {
                $count = 20
            }

            Test-NetworkQuality -ComputerName $server -Count ([int]$count) |
                Format-List

            Pause-Menu
        }

        "3" {
            $share = Read-Host "Enter remote SMB share, example \\server\share"
            $size = Read-Host "Enter test file size in MB. Default is 100"

            if (-not $size) {
                $size = 100
            }

            Test-SMBBandwidth -RemoteShare $share -FileSizeMB ([int]$size) |
                Format-List

            Pause-Menu
        }

        "4" {
            $server = Read-Host "Enter iPerf3 server name or IP"
            $duration = Read-Host "Enter test duration in seconds. Default is 30"
            $path = Read-Host "Enter iperf3.exe path or press Enter for default"

            if (-not $duration) {
                $duration = 30
            }

            if (-not $path) {
                $path = "iperf3.exe"
            }

            Test-IperfBandwidth -Server $server -Duration ([int]$duration) -IperfPath $path
            Pause-Menu
        }

        "5" {
            $path = Read-Host "Enter iperf3.exe path or press Enter for default"

            if (-not $path) {
                $path = "iperf3.exe"
            }

            Start-IperfServer -IperfPath $path
            Pause-Menu
        }

        "6" {
            Show-HelpMenu
            Pause-Menu
        }

        "7" {
            Write-Host "Exiting..." -ForegroundColor Cyan
        }

        default {
            Write-Warning "Invalid selection."
            Pause-Menu
        }
    }

} while ($choice -ne "7")