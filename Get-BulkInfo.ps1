Function Get-bulkinfo {
<#
    .SYNOPSIS
        Host Inventory     
    .DESCRIPTION
        Connect to remote system and gather inventory through cimsession 
    .NOTES
        Author:  Michael Palmieri
    .PARAMATER Server
        Host is a MANDATORY parameter
    .EXAMPLE
        Get-bulkinfo -server servername 
        https://adamtheautomator.com/powershell-get-ip-address/

#>

 [CmdletBinding()]
    param(
    [parameter(Mandatory = $true)]
    [string[]] $server)
        #Create CimSession
        $cimSession = New-CimSession -ComputerName $server
        #Test Latency
        Write-host -----------------LATENCY TESTING----------------- -BackgroundColor DarkMagenta `n
        $ping = Test-NetConnection -ComputerName "$server"
        ForEach ($Result in $Ping) {
            If  ($Result.PingReplyDetails.RoundtripTime -lt 100) {
            Write-Host Latency on $server is GOOD $Result.PingReplyDetails.RoundtripTime ms  -ForegroundColor Green `n
        }
            If  ( ($Result.PingReplyDetails.RoundtripTime -ge 100) -and ($Result.PingReplyDetails.RoundtripTime -lt 200) ) {
            Write-Host Latency on $server is ACCEPTABLE $Result.PingReplyDetails.RoundtripTime ms -ForegroundColor Yellow `n
        }
            If  ($Result.PingReplyDetails.RoundtripTime -ge 200) {
            Write-Host Latency on $server is SUBOPTIMAL $Result.PingReplyDetails.RoundtripTime ms  -ForegroundColor Red `n
        }
}
        #Disk Info
        #$cimsld= Get-CimInstance -ClassName Win32_LogicalDisk -ComputerName $server
        Write-host -----------------Disk Checks----------------- -BackgroundColor DarkMagenta `n
        $cimsld = Get-CimInstance -ClassName Win32_LogicalDisk -ComputerName $server -Filter "Drivetype = 3" | Select DeviceID, VolumeName, Size, FreeSpace
        write-host Total Disk Space on $cimsld.VolumeName Drive $cimsld.DeviceID is ($cimsld.Size/1GB) Remaining Space ($cimsld.FreeSpace/1GB) `n
        if ($cimsld.FreeSpace -gt 10){
        Write-Host Free Space Chacks Passed. -ForegroundColor Green
        if ($cimsld.FreeSpace -lt 5){
        Write-Host Free Space Chacks Failed. -ForegroundColor Red
                                    }
        }

        Write-host -----------------DISK REPORT------------------ -BackgroundColor DarkMagenta
        Get-CimInstance -ClassName Win32_LogicalDisk -ComputerName $server | Select-Object @{Name="Size(GB)";Expression={$_.size/1gb}}, @{Name="Free Space(GB)";Expression={$_.freespace/1gb}}, @{Name="Free (%)";Expression={"{0,6:P0}" -f(($_.freespace/1gb) / ($_.size/1gb))}}, DeviceID, DriveType | Where-Object DriveType -EQ '3'
        #Model Check
        Write-host -----------------MODEL CHECK----------------- -BackgroundColor DarkMagenta `n
        $cimsmod= Get-CimInstance -ClassName Win32_ComputerSystem -ComputerName $server | select Model
        write-host Platform Model Reported = $cimsmod.Model
        #Physical Memory
        Write-host -----------------MEMORY CHECK----------------- -BackgroundColor DarkMagenta `n
        $cimsph= Get-CimInstance -ClassName Win32_PhysicalMemory -ComputerName $server | select Capacity
        write-host Physical Memory Reported $cimsph
        #Network Adapter
        Write-host -----------------NETWORK ADAPTERS----------------- -BackgroundColor DarkMagenta `n
        $cimsna= Get-CimInstance -ClassName Win32_NetworkAdapter -ComputerName $server
        $cimsna | Format-Table | Out-String|% {Write-Host $_}
        #Get Shares
        Write-host -----------------SYSTEM SHARES----------------- -BackgroundColor DarkMagenta `n
        Get-SmbShare -CimSession $cimSession |ft         
        #Get-SmbShareAccess -CimSession $cimSession 
        Write-host -----------------CPU INFO----------------- -BackgroundColor DarkMagenta `n
        $TotalCores = 0
        Get-CimInstance -class  CIM_processor -ComputerName $server | ForEach {$TotalCores = $TotalCores + $_.numberofcores}
        Write-host The server $server has TotalCores $TotalCores | Format-Table | Out-String|% {Write-Host $_} 
        $cimscpu=Get-CimInstance -class  CIM_processor -ComputerName $server
        Write-host Found the following CPU `n $cimscpu.Name, $cimscpu.Caption -ForegroundColor Green `n
        
        Write-host -----------------DOMAIN INFO/TRUST TESTS----------------- -BackgroundColor DarkMagenta `n
        #$s = New-PSSession -ComputerName $server
        #$r=Invoke-Command -Session $s -ScriptBlock {Test-ComputerSecureChannel
        #Get Local Host Domain Info
        $dcinfo=get-addomain
        if (!(Test-ComputerSecureChannel)) {
             Write-Host "Connection to $dcinfo.dnsroot failed. Reconnect and retry." -ForegroundColor Red `n
            }
            else {
              Write-Host " Connection passed for $dcinfo.dnsroot" -ForegroundColor Green `n
                }
         
         Invoke-Command -ComputerName $server {Test-ComputerSecureChannel -verbose 

         Write-host LOCAL SYSTEM CONNECTED DOMAIN CONTROLLERS----------------- -BackgroundColor DarkMagenta `n

        (Get-ADForest).Domains | %{ Get-ADDomainController -Filter * -Server $_ }| Format-Table -Property Name,ComputerObjectDN,Domain,Forest,IPv4Address,OperatingSystem,OperatingSystemVersion

         Write-host -----------------SERVICES INFO----------------- -BackgroundColor DarkMagenta `n
        ## Get Services
        $services = Get-Service
 
        $count=$services.Count
 
        For($i = 1; $i -le $count; $i++)
        {
         
        Write-Progress -Activity "Getting Services Counts" `
        -PercentComplete (($i*100)/$count) `
        -Status "$(([math]::Round((($i)/$count * 100),0))) %"
     
        Start-Sleep -Milliseconds 100
        }

        Write-host Found $count Services -ForegroundColor Green `n


        Write-host -----------------SCHANNEL INFO----------------- -BackgroundColor DarkMagenta `n
        Enter-PSSession -ComputerName "$server"
        $scriptblock = {
        #Get Schannel TLS
        $schannel_client = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client"
        $schannel_server = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server"

        Get-ItemProperty -Path $schannel_client -Name "DisabledByDefault"
        Get-ItemProperty -Path $schannel_client -Name "Enabled"
        Get-ItemProperty -Path $schannel_server -Name "DisabledByDefault"
        Get-ItemProperty -Path $schannel_server -Name "Enabled"

        #.NET 3.5
        $dotnet35_64 = "HKLM:\SOFTWARE\Microsoft\.NETFramework\v2.0.50727"
        $dotnet35_32 = "HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v2.0.50727"
        Get-ItemProperty -Path $dotnet35_64 -Name "SystemDefaultTlsVersions"
        Get-ItemProperty -Path $dotnet35_32 -Name "SystemDefaultTlsVersions"

        #.NET 4.x
        $dotnet4x_64 = "HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319"
        $dotnet4x_32 = "HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v4.0.30319"
        Get-ItemProperty -Path $dotnet4x_64 -Name "SystemDefaultTlsVersions"
        Get-ItemProperty -Path $dotnet4x_32 -Name "SystemDefaultTlsVersions"
        }
        Invoke-command -ScriptBlock $scriptblock

          }

          Get-CimSession | Remove-CimSession
} # End Get-VMDetails Function