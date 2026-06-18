function Get-BulkInfo {
<#
.SYNOPSIS
    Host inventory audit.

.DESCRIPTION
    Gathers system, disk, memory, CPU, network, share, service, domain,
    and TLS/.NET Schannel information from one or more remote Windows hosts.

.NOTES
    Compatible with older Windows PowerShell versions by using WMI fallbacks.

.Usage
   Get-BulkInfo -ComputerName Server01 | ConvertTo-Json -Depth 6

   Get-BulkInfo -ComputerName Server01, Server02

   Disclaimer:
        This software is provided AS-IS with no warranty expressed or implied.
        Use at your own risk.

#>

    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [Alias("ComputerName", "Server")]
        [string[]]$ComputerName
    )

    begin {
        function Get-RemoteData {
            param(
                [string]$Computer,
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
                $null
            }
        }

        function Invoke-RemoteSafe {
            param(
                [string]$Computer,
                [scriptblock]$ScriptBlock
            )

            try {
                Invoke-Command -ComputerName $Computer -ScriptBlock $ScriptBlock -ErrorAction Stop
            }
            catch {
                Write-Warning "[$Computer] PowerShell remoting failed. $($_.Exception.Message)"
                $null
            }
        }
    }

    process {
        foreach ($Computer in $ComputerName) {

            Write-Host "`n===============================" -ForegroundColor Cyan
            Write-Host " Auditing $Computer" -ForegroundColor Cyan
            Write-Host "===============================" -ForegroundColor Cyan

            $result = [ordered]@{
                ComputerName     = $Computer
                Online           = $false
                LatencyMs        = $null
                Model            = $null
                TotalMemoryGB    = $null
                TotalCores       = $null
                CPU              = $null
                Disks            = @()
                NetworkAdapters  = @()
                Shares           = @()
                ServicesCount    = $null
                DomainTrust      = $null
                TLS              = $null
                Errors           = @()
            }

            # Ping / latency check
            try {
                $ping = Test-Connection -ComputerName $Computer -Count 1 -ErrorAction Stop

                $latency = if ($ping.ResponseTime -ne $null) {
                    $ping.ResponseTime
                }
                else {
                    $ping.Latency
                }

                $result.Online = $true
                $result.LatencyMs = $latency

                if ($latency -lt 100) {
                    Write-Host "Latency: GOOD - $latency ms" -ForegroundColor Green
                }
                elseif ($latency -lt 200) {
                    Write-Host "Latency: ACCEPTABLE - $latency ms" -ForegroundColor Yellow
                }
                else {
                    Write-Host "Latency: SUBOPTIMAL - $latency ms" -ForegroundColor Red
                }
            }
            catch {
                $msg = "Ping failed: $($_.Exception.Message)"
                Write-Warning "[$Computer] $msg"
                $result.Errors += $msg
            }

            if (-not $result.Online) {
                [pscustomobject]$result
                continue
            }

            # Computer model
            $cs = Get-RemoteData -Computer $Computer -ClassName Win32_ComputerSystem
            if ($cs) {
                $result.Model = $cs.Model
                $result.TotalMemoryGB = [math]::Round(($cs.TotalPhysicalMemory / 1GB), 2)
            }

            # Disks
            $disks = Get-RemoteData -Computer $Computer -ClassName Win32_LogicalDisk -Filter "DriveType = 3"
            if ($disks) {
                foreach ($disk in $disks) {
                    $freeGB = [math]::Round(($disk.FreeSpace / 1GB), 2)
                    $sizeGB = [math]::Round(($disk.Size / 1GB), 2)
                    $freePct = if ($disk.Size -gt 0) {
                        [math]::Round((($disk.FreeSpace / $disk.Size) * 100), 2)
                    }
                    else {
                        0
                    }

                    $status = if ($freeGB -lt 5) {
                        "Critical"
                    }
                    elseif ($freeGB -lt 10) {
                        "Warning"
                    }
                    else {
                        "OK"
                    }

                    $result.Disks += [pscustomobject]@{
                        Drive      = $disk.DeviceID
                        VolumeName = $disk.VolumeName
                        SizeGB     = $sizeGB
                        FreeGB     = $freeGB
                        FreePct    = $freePct
                        Status     = $status
                    }
                }
            }

            # CPU
            $cpus = Get-RemoteData -Computer $Computer -ClassName Win32_Processor
            if ($cpus) {
                $result.TotalCores = ($cpus | Measure-Object -Property NumberOfCores -Sum).Sum
                $result.CPU = ($cpus | Select-Object -First 1).Name
            }

            # Network adapters
            $adapters = Get-RemoteData -Computer $Computer -ClassName Win32_NetworkAdapterConfiguration -Filter "IPEnabled = True"
            if ($adapters) {
                foreach ($adapter in $adapters) {
                    $result.NetworkAdapters += [pscustomobject]@{
                        Description = $adapter.Description
                        MACAddress  = $adapter.MACAddress
                        IPAddress   = ($adapter.IPAddress -join ", ")
                        Gateway     = ($adapter.DefaultIPGateway -join ", ")
                        DNS         = ($adapter.DNSServerSearchOrder -join ", ")
                    }
                }
            }

            # Shares - WMI compatible
            $shares = Get-RemoteData -Computer $Computer -ClassName Win32_Share
            if ($shares) {
                $result.Shares = $shares | Select-Object Name, Path, Description
            }

            # Services count
            $services = Get-RemoteData -Computer $Computer -ClassName Win32_Service
            if ($services) {
                $result.ServicesCount = ($services | Measure-Object).Count
            }

            # Domain trust and TLS info through remoting
            $remoteInfo = Invoke-RemoteSafe -Computer $Computer -ScriptBlock {
                $output = [ordered]@{
                    DomainTrust = $null
                    TLS         = @()
                }

                try {
                    if (Get-Command Test-ComputerSecureChannel -ErrorAction SilentlyContinue) {
                        $output.DomainTrust = Test-ComputerSecureChannel
                    }
                }
                catch {
                    $output.DomainTrust = "Failed: $($_.Exception.Message)"
                }

                $registryChecks = @(
                    "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client",
                    "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server",
                    "HKLM:\SOFTWARE\Microsoft\.NETFramework\v2.0.50727",
                    "HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v2.0.50727",
                    "HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319",
                    "HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v4.0.30319"
                )

                foreach ($path in $registryChecks) {
                    try {
                        $props = Get-ItemProperty -Path $path -ErrorAction Stop
                        $output.TLS += [pscustomobject]@{
                            Path                     = $path
                            Enabled                  = $props.Enabled
                            DisabledByDefault        = $props.DisabledByDefault
                            SystemDefaultTlsVersions = $props.SystemDefaultTlsVersions
                        }
                    }
                    catch {
                        $output.TLS += [pscustomobject]@{
                            Path                     = $path
                            Enabled                  = $null
                            DisabledByDefault        = $null
                            SystemDefaultTlsVersions = $null
                            Error                    = $_.Exception.Message
                        }
                    }
                }

                [pscustomobject]$output
            }

            if ($remoteInfo) {
                $result.DomainTrust = $remoteInfo.DomainTrust
                $result.TLS = $remoteInfo.TLS
            }

            [pscustomobject]$result
        }
    }
}