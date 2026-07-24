<#
.SYNOPSIS
Interactive, read-only post-deployment validation for VMware Cloud Foundation 5.2
on a four-node ESXi 8.0 management cluster.

.DESCRIPTION
Run this script from Windows PowerShell ISE by opening the file and pressing F5.
It prompts for the vCenter FQDN, cluster name, credentials, optional SDDC Manager
and NSX Manager endpoints, and an output directory.

The script performs non-disruptive checks for:
  * PowerShell and PowerCLI prerequisites
  * DNS, HTTPS reachability, and certificate expiration
  * vCenter connectivity and inventory
  * Expected four-host cluster membership
  * HA, DRS, cluster status, and triggered alarms
  * ESXi connection state, version/build consistency, hardware, DNS, NTP,
    services, hardware sensors, and alarms
  * VMkernel adapters, vMotion, vSAN traffic, physical NICs, vDS inventory,
    and configured MTU values
  * vSAN configuration, datastore accessibility/capacity, disks, health cmdlets,
    and storage-policy compliance when available
  * Lifecycle Manager cluster health when supported by installed PowerCLI
  * License visibility
  * Optional SDDC Manager REST inventory
  * Optional NSX Manager REST inventory
  * Manual acceptance items for disruptive or operational tests

Results are classified as PASS, WARN, FAIL, INFO, SKIP, or MANUAL and exported
to HTML, CSV, TXT summary, and transcript files.

The script does NOT create or delete VMs, perform vMotion, enter maintenance
mode, restart services, remediate images, shut down hosts, or trigger HA.

Exact VCF build compliance is not hard-coded. VCF 5.2 maintenance releases have
different supported component builds. Compare the collected vCenter, ESXi, NSX,
SDDC Manager, firmware, and driver versions with the approved VCF 5.2.x Bill of
Materials and hardware compatibility data.

.REQUIREMENTS
  * Windows PowerShell 5.1 and PowerShell ISE
  * VCF.PowerCLI or VMware.PowerCLI
  * Network access to the target management components
  * Read access to vCenter inventory, storage, networking, alarms, and licenses
  * Optional SDDC Manager and NSX API credentials

Install current PowerCLI when needed:
  Install-Module -Name VCF.PowerCLI -Scope CurrentUser

.SECURITY
Credentials are requested with Get-Credential and are not written to reports.
The optional untrusted-certificate setting is intended only for environments
that still use self-signed certificates. Trusted CA certificates are preferred.

.EXAMPLE
Open Test-VCF52Deployment.ps1 in PowerShell ISE and press F5.

.NOTES
Default mode is read-only. Review every FAIL, WARN, SKIP, and MANUAL result.
#>

[CmdletBinding()]
param()

Set-StrictMode -Version 2
$ErrorActionPreference = 'Stop'
$script:Results = New-Object System.Collections.Generic.List[object]
$script:VIServer = $null
$script:TranscriptStarted = $false

function Add-Check {
    param(
        [string]$Phase,
        [string]$Test,
        [ValidateSet('PASS','WARN','FAIL','INFO','SKIP','MANUAL')]
        [string]$Status,
        [string]$Target = '',
        [string]$Details = '',
        [string]$Recommendation = ''
    )
    $script:Results.Add([pscustomobject]@{
        Time=Get-Date; Phase=$Phase; Test=$Test; Status=$Status;
        Target=$Target; Details=$Details; Recommendation=$Recommendation
    }) | Out-Null

    $color = switch ($Status) {
        PASS {'Green'} WARN {'Yellow'} FAIL {'Red'}
        INFO {'Cyan'} SKIP {'DarkYellow'} MANUAL {'Magenta'}
    }
    Write-Host ("[{0,-6}] {1}: {2}" -f $Status,$Test,$Details) -ForegroundColor $color
}

function Invoke-Check {
    param(
        [string]$Phase,
        [string]$Test,
        [string]$Target = '',
        [scriptblock]$Action,
        [string]$Recommendation = 'Review connectivity, permissions, and the transcript.'
    )
    try { & $Action }
    catch {
        Add-Check $Phase $Test FAIL $Target $_.Exception.Message $Recommendation
    }
}

function Ask-YesNo {
    param([string]$Prompt,[bool]$Default=$false)
    $suffix = if($Default){'[Y/n]'}else{'[y/N]'}
    while($true){
        $a=Read-Host "$Prompt $suffix"
        if([string]::IsNullOrWhiteSpace($a)){return $Default}
        if($a -match '^(y|yes)$'){return $true}
        if($a -match '^(n|no)$'){return $false}
        Write-Host 'Enter Y or N.' -ForegroundColor Yellow
    }
}

function Ask-Required {
    param([string]$Prompt,[string]$Default='')
    while($true){
        $label=if($Default){"$Prompt [$Default]"}else{$Prompt}
        $v=Read-Host $label
        if([string]::IsNullOrWhiteSpace($v)){$v=$Default}
        if(-not [string]::IsNullOrWhiteSpace($v)){return $v.Trim()}
        Write-Host 'A value is required.' -ForegroundColor Yellow
    }
}

function Command-Exists {
    param([string]$Name)
    return [bool](Get-Command $Name -ErrorAction SilentlyContinue)
}

function Test-Dns {
    param([string]$Name)
    try {
        $ips=[Net.Dns]::GetHostAddresses($Name)|% IPAddressToString|Sort-Object -Unique
        [pscustomobject]@{Ok=($ips.Count -gt 0);Text=($ips -join ', ')}
    } catch {
        [pscustomobject]@{Ok=$false;Text=$_.Exception.Message}
    }
}

function Test-Port {
    param([string]$HostName,[int]$Port=443,[int]$Timeout=5000)
    $c=New-Object Net.Sockets.TcpClient
    try{
        $a=$c.BeginConnect($HostName,$Port,$null,$null)
        if(-not $a.AsyncWaitHandle.WaitOne($Timeout,$false)){throw 'Connection timed out.'}
        $c.EndConnect($a)
        [pscustomobject]@{Ok=$true;Text='Connection succeeded.'}
    }catch{
        [pscustomobject]@{Ok=$false;Text=$_.Exception.Message}
    }finally{$c.Close()}
}

function Get-CertInfo {
    param([string]$HostName,[int]$Port=443)
    $tcp=New-Object Net.Sockets.TcpClient
    $ssl=$null
    try{
        $tcp.Connect($HostName,$Port)
        $cb={param($s,$c,$ch,$e) $true}
        $ssl=New-Object Net.Security.SslStream($tcp.GetStream(),$false,$cb)
        $ssl.AuthenticateAsClient($HostName)
        $cert=New-Object Security.Cryptography.X509Certificates.X509Certificate2($ssl.RemoteCertificate)
        [pscustomobject]@{
            Subject=$cert.Subject;Issuer=$cert.Issuer;NotAfter=$cert.NotAfter;
            DaysLeft=[math]::Floor(($cert.NotAfter-(Get-Date)).TotalDays)
        }
    }finally{
        if($ssl){$ssl.Dispose()}
        $tcp.Close()
    }
}

function Basic-Auth {
    param([pscredential]$Credential)
    $s='{0}:{1}' -f $Credential.UserName,$Credential.GetNetworkCredential().Password
    'Basic '+[Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes($s))
}

function Invoke-RestCompat {
    param(
        [ValidateSet('GET','POST')][string]$Method,
        [string]$Uri,
        [hashtable]$Headers=@{},
        [object]$Body=$null,
        [switch]$SkipCert
    )
    $p=@{Method=$Method;Uri=$Uri;Headers=$Headers;ErrorAction='Stop'}
    if($null -ne $Body){
        $p.Body=$Body|ConvertTo-Json -Depth 10
        $p.ContentType='application/json'
    }
    $cmd=Get-Command Invoke-RestMethod
    if($SkipCert -and $cmd.Parameters.ContainsKey('SkipCertificateCheck')){
        $p.SkipCertificateCheck=$true
        return Invoke-RestMethod @p
    }
    if($SkipCert){
        $old=[Net.ServicePointManager]::ServerCertificateValidationCallback
        try{
            [Net.ServicePointManager]::ServerCertificateValidationCallback={$true}
            return Invoke-RestMethod @p
        }finally{
            [Net.ServicePointManager]::ServerCertificateValidationCallback=$old
        }
    }
    Invoke-RestMethod @p
}

function Property-Value {
    param($Object,[string[]]$Names)
    foreach($n in $Names){
        if($null -ne $Object -and $Object.PSObject.Properties.Name -contains $n){
            return $Object.$n
        }
    }
    $null
}

function Export-Reports {
    param([string]$Folder,[string]$Base,[hashtable]$Metadata)

    $csv=Join-Path $Folder "$Base.csv"
    $html=Join-Path $Folder "$Base.html"
    $txt=Join-Path $Folder "$Base-Summary.txt"
    $script:Results|Export-Csv $csv -NoTypeInformation -Encoding UTF8

    $counts=@{}
    $script:Results|Group-Object Status|%{$counts[$_.Name]=$_.Count}

    $metaRows=$Metadata.Keys|Sort-Object|%{
        "<tr><td><b>$([Net.WebUtility]::HtmlEncode($_))</b></td><td>$([Net.WebUtility]::HtmlEncode([string]$Metadata[$_]))</td></tr>"
    }
    $rows=$script:Results|%{
        $r=$_
        "<tr class='$($r.Status)'><td>$($r.Time.ToString('yyyy-MM-dd HH:mm:ss'))</td><td>$([Net.WebUtility]::HtmlEncode($r.Phase))</td><td>$([Net.WebUtility]::HtmlEncode($r.Test))</td><td><b>$($r.Status)</b></td><td>$([Net.WebUtility]::HtmlEncode($r.Target))</td><td>$([Net.WebUtility]::HtmlEncode($r.Details))</td><td>$([Net.WebUtility]::HtmlEncode($r.Recommendation))</td></tr>"
    }
    $summary='PASS','WARN','FAIL','INFO','SKIP','MANUAL'|%{
        $n=if($counts.ContainsKey($_)){$counts[$_]}else{0}
        "<span><b>$_</b>: $n&nbsp;&nbsp;</span>"
    }

    @"
<html><head><meta charset='utf-8'><style>
body{font-family:Segoe UI,Arial;margin:24px;color:#222}
table{border-collapse:collapse;width:100%;font-size:12px}
th{background:#183153;color:white;padding:7px;text-align:left}
td{border:1px solid #ccc;padding:6px;vertical-align:top}
.PASS{background:#dff0d8}.WARN{background:#fff3cd}.FAIL{background:#f8d7da}
.INFO{background:#d9edf7}.SKIP{background:#eee}.MANUAL{background:#eadcf8}
</style></head><body>
<h1>VCF 5.2 Post-Deployment Validation</h1>
<p>Read-only interactive PowerShell/PowerCLI report.</p>
<p>$($summary -join '')</p>
<h2>Run Information</h2><table>$($metaRows -join "`n")</table>
<h2>Results</h2><table>
<tr><th>Time</th><th>Phase</th><th>Test</th><th>Status</th><th>Target</th><th>Details</th><th>Recommendation</th></tr>
$($rows -join "`n")
</table>
<p>Review all FAIL, WARN, SKIP, and MANUAL items. Compare collected builds with the approved VCF 5.2.x BOM.</p>
</body></html>
"@|Set-Content $html -Encoding UTF8

    $lines=@('VCF 5.2 Validation Summary',"Generated: $(Get-Date)",'')
    foreach($s in 'PASS','WARN','FAIL','INFO','SKIP','MANUAL'){
        $n=if($counts.ContainsKey($s)){$counts[$s]}else{0}
        $lines+=('{0,-7}: {1}' -f $s,$n)
    }
    $lines+='';$lines+='Review all FAIL, WARN, SKIP, and MANUAL results.'
    $lines|Set-Content $txt -Encoding UTF8
    [pscustomobject]@{Html=$html;Csv=$csv;Summary=$txt}
}

Clear-Host
Write-Host 'VCF 5.2 Post-Deployment Validation' -ForegroundColor Cyan
Write-Host 'Read-only interactive validation for a four-node ESXi 8.0 cluster.' -ForegroundColor Gray

$vCenter=Ask-Required 'vCenter FQDN'
$clusterName=Ask-Required 'Management cluster name'
$hostText=Read-Host 'Expected host count [4]'
$expectedHosts=4
if($hostText){
    $tmp=0
    if([int]::TryParse($hostText,[ref]$tmp)-and$tmp-gt 0){$expectedHosts=$tmp}
    else{Write-Host 'Invalid value; using 4.' -ForegroundColor Yellow}
}
$outRoot=Read-Host 'Output folder [Documents\VCF-Validation]'
if([string]::IsNullOrWhiteSpace($outRoot)){
    $outRoot=Join-Path ([Environment]::GetFolderPath('MyDocuments')) 'VCF-Validation'
}
$doSddc=Ask-YesNo 'Run optional SDDC Manager API checks?' $true
if($doSddc){$sddc=Ask-Required 'SDDC Manager FQDN'}else{$sddc=''}
$doNsx=Ask-YesNo 'Run optional NSX Manager API checks?' $true
if($doNsx){$nsx=Ask-Required 'NSX Manager or VIP FQDN'}else{$nsx=''}
$skipCert=Ask-YesNo 'Allow untrusted endpoint certificates for this run?' $false

$stamp=Get-Date -Format yyyyMMdd-HHmmss
$folder=Join-Path $outRoot "VCF52-Validation-$stamp"
New-Item $folder -ItemType Directory -Force|Out-Null
$base="VCF52-Validation-$stamp"
$transcript=Join-Path $folder "$base-Transcript.txt"
try{Start-Transcript $transcript -Force|Out-Null;$script:TranscriptStarted=$true}catch{}

$meta=[ordered]@{
    Started=Get-Date;Operator=[Environment]::UserName;Computer=$env:COMPUTERNAME;
    PowerShell=$PSVersionTable.PSVersion;vCenter=$vCenter;Cluster=$clusterName;
    ExpectedHosts=$expectedHosts;'SDDC Manager'=$sddc;'NSX Manager'=$nsx;Mode='Read-only'
}

try{
    $phase='1 - Prerequisites'
    $isISE=[bool](Get-Variable psISE -Scope Global -ErrorAction SilentlyContinue)
    Add-Check $phase 'PowerShell ISE' $(if($isISE){'PASS'}else{'WARN'}) $env:COMPUTERNAME `
        $(if($isISE){'Running in PowerShell ISE.'}else{'Not running in PowerShell ISE.'}) `
        'Open the script in Windows PowerShell ISE and press F5.'

    $mods=Get-Module -ListAvailable|? Name -match '^(VCF|VMware)\.'|Sort Name,Version -Descending
    if($mods){
        Add-Check $phase 'PowerCLI modules' PASS '' (($mods|Select -First 15|%{"$($_.Name) $($_.Version)"}) -join '; ')
    }else{
        Add-Check $phase 'PowerCLI modules' FAIL '' 'No PowerCLI modules found.' 'Install-Module VCF.PowerCLI -Scope CurrentUser'
        throw 'PowerCLI is required.'
    }
    Import-Module VMware.VimAutomation.Core
    Add-Check $phase 'PowerCLI core import' PASS '' 'VMware.VimAutomation.Core imported.'

    if($skipCert){
        try{
            Set-PowerCLIConfiguration -InvalidCertificateAction Ignore -Scope Session -Confirm:$false|Out-Null
            Add-Check $phase 'PowerCLI certificate policy' WARN '' 'Invalid certificates are ignored for this PowerCLI session.' 'Use trusted CA certificates.'
        }catch{
            Add-Check $phase 'PowerCLI certificate policy' WARN '' $_.Exception.Message
        }
    }

    $phase='2 - Connectivity'
    $endpoints=@($vCenter)
    if($sddc){$endpoints+=$sddc};if($nsx){$endpoints+=$nsx}
    foreach($e in ($endpoints|Sort-Object -Unique)){
        $d=Test-Dns $e
        Add-Check $phase 'Forward DNS' $(if($d.Ok){'PASS'}else{'FAIL'}) $e $d.Text 'Correct DNS and resolver configuration.'
        $p=Test-Port $e
        Add-Check $phase 'HTTPS port 443' $(if($p.Ok){'PASS'}else{'FAIL'}) "$e`:443" $p.Text 'Review routing, firewall, VIP, and service state.'
        if($p.Ok){
            Invoke-Check $phase 'TLS certificate expiration' $e {
                $c=Get-CertInfo $e
                $s=if($c.DaysLeft-lt 0){'FAIL'}elseif($c.DaysLeft-lt 60){'WARN'}else{'PASS'}
                Add-Check $phase 'TLS certificate expiration' $s $e "Subject=$($c.Subject); Expires=$($c.NotAfter); DaysLeft=$($c.DaysLeft)" 'Renew or replace before expiration.'
            }
        }
    }

    $phase='3 - vCenter'
    $vcCred=Get-Credential -Message "Credential for $vCenter"
    $script:VIServer=Connect-VIServer $vCenter -Credential $vcCred
    Add-Check $phase 'vCenter connection' PASS $vCenter "Connected as $($vcCred.UserName)."
    $about=$script:VIServer.ExtensionData.Content.About
    Add-Check $phase 'vCenter build inventory' INFO $vCenter "$($about.FullName); Version=$($about.Version); Build=$($about.Build)"
    $meta['vCenter Version']=$about.Version;$meta['vCenter Build']=$about.Build

    $clusters=@(Get-Cluster -Name $clusterName -Server $script:VIServer)
    if($clusters.Count-ne 1){throw "Expected one cluster named '$clusterName'; found $($clusters.Count)."}
    $cluster=$clusters[0]
    Add-Check $phase 'Cluster lookup' PASS $clusterName 'Exactly one matching cluster found.'

    Invoke-Check $phase 'vCenter triggered alarms' $vCenter {
        $a=@($script:VIServer.ExtensionData.Content.RootFolder.TriggeredAlarmState)
        $r=@($a|? OverallStatus -eq red);$y=@($a|? OverallStatus -eq yellow)
        $s=if($r.Count){'FAIL'}elseif($y.Count){'WARN'}else{'PASS'}
        Add-Check $phase 'vCenter triggered alarms' $s $vCenter "Red=$($r.Count); Yellow=$($y.Count); Total=$($a.Count)" 'Review every triggered alarm.'
    }

    $phase='4 - Cluster'
    $hosts=@(Get-VMHost -Location $cluster|Sort Name)
    Add-Check $phase 'Expected host count' $(if($hosts.Count-eq$expectedHosts){'PASS'}else{'FAIL'}) $cluster.Name "Expected=$expectedHosts; Found=$($hosts.Count)" 'Reconcile vCenter and SDDC Manager inventory.'
    Add-Check $phase 'HA enabled' $(if($cluster.HAEnabled){'PASS'}else{'FAIL'}) $cluster.Name "HAEnabled=$($cluster.HAEnabled)" 'Enable HA according to the design.'
    Add-Check $phase 'DRS enabled' $(if($cluster.DrsEnabled){'PASS'}else{'FAIL'}) $cluster.Name "DRSEnabled=$($cluster.DrsEnabled); Level=$($cluster.DrsAutomationLevel)" 'Enable DRS according to the design.'
    $cs=[string]$cluster.ExtensionData.OverallStatus
    Add-Check $phase 'Cluster overall status' $(switch($cs){green{'PASS'}yellow{'WARN'}red{'FAIL'}default{'INFO'}}) $cluster.Name "OverallStatus=$cs"

    $phase='5 - ESXi Hosts'
    $groups=$hosts|Group Version,Build
    Add-Check $phase 'Consistent ESXi builds' $(if($groups.Count-eq 1){'PASS'}else{'FAIL'}) $cluster.Name (($groups|%{"$($_.Name) x $($_.Count)"}) -join '; ') 'Align hosts with the approved VCF desired image.'
    foreach($h in $hosts){
        Add-Check $phase 'Host connection state' $(if($h.ConnectionState-eq'Connected'){'PASS'}else{'FAIL'}) $h.Name "Connection=$($h.ConnectionState); Power=$($h.PowerState)"
        Add-Check $phase 'ESXi 8.x detected' $(if([version]$h.Version-ge[version]'8.0'){'PASS'}else{'FAIL'}) $h.Name "Version=$($h.Version); Build=$($h.Build)" 'Compare the exact build with the approved VCF 5.2.x BOM.'
        $d=Test-Dns $h.Name
        Add-Check $phase 'Host DNS' $(if($d.Ok){'PASS'}else{'FAIL'}) $h.Name $d.Text
        Invoke-Check $phase 'Host hardware inventory' $h.Name {
            if(Command-Exists Get-VMHostHardware){
                $hw=Get-VMHostHardware $h
                Add-Check $phase 'Host hardware inventory' INFO $h.Name "Manufacturer=$($hw.Manufacturer); Model=$($hw.Model); Serial=$($hw.SerialNumber); BIOS=$($hw.BiosVersion)"
            }else{Add-Check $phase 'Host hardware inventory' SKIP $h.Name 'Get-VMHostHardware unavailable.'}
        }
        Invoke-Check $phase 'NTP configuration' $h.Name {
            $ntp=@(Get-VMHostNtpServer $h)
            Add-Check $phase 'NTP configuration' $(if($ntp.Count){'PASS'}else{'FAIL'}) $h.Name $(if($ntp){$ntp -join ', '}else{'No NTP servers configured.'}) 'Configure approved redundant NTP servers.'
        }
        Invoke-Check $phase 'NTP service' $h.Name {
            $svc=Get-VMHostService $h|?{$_.Key-eq'ntpd'-or$_.Label-match'NTP'}|Select -First 1
            if($svc){Add-Check $phase 'NTP service' $(if($svc.Running){'PASS'}else{'FAIL'}) $h.Name "Running=$($svc.Running); Policy=$($svc.Policy)"}
            else{Add-Check $phase 'NTP service' SKIP $h.Name 'NTP service not returned.'}
        }
        Invoke-Check $phase 'Hardware sensors' $h.Name {
            $sensors=@($h.ExtensionData.Runtime.HealthSystemRuntime.SystemHealthInfo.NumericSensorInfo)
            $bad=@($sensors|?{$_.HealthState.Key-and$_.HealthState.Key-notin @('green','unknown')})
            Add-Check $phase 'Hardware sensors' $(if($bad.Count){'FAIL'}else{'PASS'}) $h.Name "Sensors=$($sensors.Count); NonGreen=$($bad.Count)" 'Review vCenter and server management-controller health.'
        }
        Invoke-Check $phase 'Host alarms' $h.Name {
            $a=@($h.ExtensionData.TriggeredAlarmState);$r=@($a|? OverallStatus -eq red);$y=@($a|? OverallStatus -eq yellow)
            Add-Check $phase 'Host alarms' $(if($r.Count){'FAIL'}elseif($y.Count){'WARN'}else{'PASS'}) $h.Name "Red=$($r.Count); Yellow=$($y.Count); Total=$($a.Count)"
        }
    }

    $phase='6 - Networking'
    foreach($h in $hosts){
        Invoke-Check $phase 'VMkernel inventory' $h.Name {
            $vmks=@(Get-VMHostNetworkAdapter $h -VMKernel)
            foreach($v in $vmks){
                $services=@()
                if($v.ManagementTrafficEnabled){$services+='Management'}
                if($v.VMotionEnabled){$services+='vMotion'}
                if($v.VsanTrafficEnabled){$services+='vSAN'}
                Add-Check $phase 'VMkernel adapter' INFO "$($h.Name)/$($v.Name)" "IP=$($v.IP); MTU=$($v.Mtu); Services=$($services -join ',')"
            }
            Add-Check $phase 'vMotion VMkernel' $(if(@($vmks|? VMotionEnabled).Count){'PASS'}else{'FAIL'}) $h.Name "Enabled adapters=$(@($vmks|? VMotionEnabled).Count)"
            Add-Check $phase 'vSAN VMkernel' $(if(@($vmks|? VsanTrafficEnabled).Count){'PASS'}else{'FAIL'}) $h.Name "Enabled adapters=$(@($vmks|? VsanTrafficEnabled).Count)"
        }
        Invoke-Check $phase 'Physical NIC links' $h.Name {
            $n=@(Get-VMHostNetworkAdapter $h -Physical)
            $down=@($n|?{-not$_.BitRatePerSec-or$_.BitRatePerSec-le 0})
            $detail=$n|%{'{0}:{1}Gbps' -f $_.Name,[math]::Round($_.BitRatePerSec/1GB,2)}
            Add-Check $phase 'Physical NIC links' $(if($down.Count){'WARN'}else{'PASS'}) $h.Name ($detail -join '; ') 'Confirm whether down uplinks are expected.'
        }
    }
    Invoke-Check $phase 'Distributed switches' $cluster.Name {
        if(Command-Exists Get-VDSwitch){
            $vds=@(Get-VDSwitch -VMHost $hosts|Sort Name -Unique)
            foreach($v in $vds){Add-Check $phase 'Distributed switch' INFO $v.Name "Version=$($v.Version); MTU=$($v.Mtu); Uplinks=$($v.NumUplinkPorts)"}
            if(-not$vds){Add-Check $phase 'Distributed switches' WARN $cluster.Name 'No vDS returned.'}
        }else{Add-Check $phase 'Distributed switches' SKIP $cluster.Name 'Get-VDSwitch unavailable.'}
    }
    Add-Check $phase 'End-to-end MTU test' MANUAL $cluster.Name 'Configured MTU does not prove packet delivery.' 'Use supported vmkping/NSX path tests for vMotion, vSAN, and TEP networks.'

    $phase='7 - vSAN'
    Invoke-Check $phase 'vSAN configuration' $cluster.Name {
        if(Command-Exists Get-VsanClusterConfiguration){
            $c=Get-VsanClusterConfiguration $cluster
            Add-Check $phase 'vSAN configuration' INFO $cluster.Name (($c|Out-String).Trim())
        }else{Add-Check $phase 'vSAN configuration' SKIP $cluster.Name 'Get-VsanClusterConfiguration unavailable.'}
    }
    Invoke-Check $phase 'vSAN datastore' $cluster.Name {
        $ds=@(Get-Datastore -Location $cluster|?{$_.Type-match'vsan'-or$_.Name-match'vsan'})
        if(-not$ds){Add-Check $phase 'vSAN datastore' FAIL $cluster.Name 'No vSAN datastore detected.'}
        foreach($d in $ds){
            $pct=if($d.CapacityGB){[math]::Round(($d.FreeSpaceGB/$d.CapacityGB)*100,1)}else{0}
            Add-Check $phase 'vSAN datastore' $(if($d.State-eq'Available'){'PASS'}else{'FAIL'}) $d.Name "State=$($d.State); CapacityGB=$([math]::Round($d.CapacityGB,2)); FreeGB=$([math]::Round($d.FreeSpaceGB,2)); FreePercent=$pct"
        }
    }
    Invoke-Check $phase 'vSAN disks' $cluster.Name {
        if(Command-Exists Get-VsanDisk){
            $disks=@(Get-VsanDisk -Cluster $cluster)
            Add-Check $phase 'vSAN disks' $(if($disks.Count){'INFO'}else{'WARN'}) $cluster.Name "Returned disks=$($disks.Count)" 'Review disk health in vSAN Skyline Health.'
        }else{Add-Check $phase 'vSAN disks' SKIP $cluster.Name 'Get-VsanDisk unavailable.'}
    }
    Invoke-Check $phase 'vSAN health cmdlet' $cluster.Name {
        $cmd=@('Test-VsanClusterHealth','Get-VsanClusterHealth')|?{Command-Exists $_}|Select -First 1
        if($cmd){
            $x=&$cmd -Cluster $cluster
            Add-Check $phase 'vSAN health cmdlet' INFO $cluster.Name (($x|Out-String).Trim()) 'Confirm all Skyline/vSAN checks are green.'
        }else{Add-Check $phase 'vSAN health cmdlet' SKIP $cluster.Name 'No supported vSAN health cmdlet found.' 'Review Skyline Health in vCenter.'}
    }
    Invoke-Check $phase 'Storage policy compliance' $cluster.Name {
        if(Command-Exists Get-SpbmEntityConfiguration){
            $vms=@(Get-VM -Location $cluster)
            if($vms){
                $spbm=@(Get-SpbmEntityConfiguration -VM $vms)
                $bad=@($spbm|?{[string]$_.ComplianceStatus-notmatch'^compliant$'})
                Add-Check $phase 'Storage policy compliance' $(if($bad.Count){'WARN'}else{'PASS'}) $cluster.Name "Entities=$($spbm.Count); NonCompliantOrUnknown=$($bad.Count)"
            }else{Add-Check $phase 'Storage policy compliance' INFO $cluster.Name 'No VMs found.'}
        }else{Add-Check $phase 'Storage policy compliance' SKIP $cluster.Name 'Get-SpbmEntityConfiguration unavailable.'}
    }

    $phase='8 - Lifecycle'
    Invoke-Check $phase 'Lifecycle Manager health' $cluster.Name {
        if(Command-Exists Test-LcmClusterHealth){
            $l=Test-LcmClusterHealth -Cluster $cluster
            Add-Check $phase 'Lifecycle Manager health' INFO $cluster.Name (($l|Out-String).Trim()) 'Confirm all hosts comply with the VCF-approved desired state.'
        }else{Add-Check $phase 'Lifecycle Manager health' SKIP $cluster.Name 'Test-LcmClusterHealth unavailable.'}
    }
    Add-Check $phase 'VCF 5.2.x BOM comparison' MANUAL $cluster.Name (($groups|% Name)-join'; ') 'Compare all component, driver, and firmware builds with the exact approved VCF 5.2.x BOM.'

    $phase='9 - Licensing'
    Invoke-Check $phase 'vCenter license visibility' $vCenter {
        $lm=Get-View -Id $script:VIServer.ExtensionData.Content.LicenseManager
        Add-Check $phase 'vCenter license visibility' INFO $vCenter "License entries=$(@($lm.Licenses).Count)" 'Review assignments and entitlement.'
    }

    $phase='10 - SDDC Manager'
    if($doSddc){
        $cred=Get-Credential -Message "SDDC Manager API credential for $sddc"
        Invoke-Check $phase 'SDDC authentication' $sddc {
            $token=Invoke-RestCompat POST "https://$sddc/v1/tokens" @{} @{username=$cred.UserName;password=$cred.GetNetworkCredential().Password} -SkipCert:$skipCert
            $access=Property-Value $token @('accessToken','access_token')
            if(-not$access){throw 'Token response did not contain an access token.'}
            $script:SddcHeaders=@{Authorization="Bearer $access";Accept='application/json'}
            Add-Check $phase 'SDDC authentication' PASS $sddc 'Bearer token obtained.'
        }
        if($script:SddcHeaders){
            foreach($api in @(
                @{Name='Workload domains';Path='/v1/domains'},
                @{Name='SDDC clusters';Path='/v1/clusters'},
                @{Name='Recent tasks';Path='/v1/tasks'}
            )){
                Invoke-Check $phase $api.Name $sddc {
                    $r=Invoke-RestCompat GET "https://$sddc$($api.Path)" $script:SddcHeaders $null -SkipCert:$skipCert
                    $items=Property-Value $r @('elements','items','results')
                    $count=if($null-ne$items){@($items).Count}else{1}
                    Add-Check $phase $api.Name INFO $sddc "API=$($api.Path); Returned=$count"
                }
            }
        }
    }else{Add-Check $phase 'SDDC API checks' SKIP '' 'Operator skipped SDDC Manager checks.'}
    Add-Check $phase 'SDDC services and SoS health' MANUAL $sddc 'Not fully validated through vCenter PowerCLI.' 'Review SDDC Manager health, workflows, credentials, certificates, disk usage, and SoS health output.'

    $phase='11 - NSX'
    if($doNsx){
        $cred=Get-Credential -Message "NSX API credential for $nsx"
        $headers=@{Authorization=Basic-Auth $cred;Accept='application/json'}
        foreach($api in @(
            @{Name='NSX manager cluster';Path='/api/v1/cluster/status'},
            @{Name='Transport nodes';Path='/api/v1/transport-nodes'},
            @{Name='Edge clusters';Path='/api/v1/edge-clusters'},
            @{Name='Transport zones';Path='/api/v1/transport-zones'}
        )){
            Invoke-Check $phase $api.Name $nsx {
                $r=Invoke-RestCompat GET "https://$nsx$($api.Path)" $headers $null -SkipCert:$skipCert
                $items=Property-Value $r @('results','items')
                $count=if($null-ne$items){@($items).Count}else{1}
                $status=Property-Value $r @('status','cluster_status')
                $result=if([string]$status-match'DOWN|DEGRADED|FAILED|UNAVAILABLE'){'FAIL'}else{'INFO'}
                Add-Check $phase $api.Name $result $nsx "API=$($api.Path); Status=$status; Returned=$count"
            }
        }
        Add-Check $phase 'NSX TEP connectivity' MANUAL $nsx 'Inventory does not prove every TEP data path.' 'Use NSX path tests or supported vmkping procedures.'
    }else{Add-Check $phase 'NSX API checks' SKIP '' 'Operator skipped NSX checks.'}

    $phase='12 - Manual Acceptance'
    $manual=@{
        'Test VM deployment/removal'='Deploy a small test VM using the approved network and storage policy, validate power operations, then remove it.'
        'Live vMotion'='Migrate a non-critical test VM between hosts during an approved test.'
        'Maintenance mode'='Test one host at a time using the correct vSAN data-migration option.'
        'HA failover'='Perform only under an approved change plan with rollback and application validation.'
        'Backup configuration'='Verify schedules for vCenter, SDDC Manager, NSX, and other management appliances.'
        'Restore test'='Validate restoration in an isolated or approved recovery exercise.'
        'Syslog and alerts'='Confirm log delivery and test a controlled notification.'
        'Reverse DNS'='Validate PTR records from all management appliances and hosts.'
        'Time accuracy'='Confirm actual synchronization and clock offset, not only configured servers.'
        'Security review'='Review SSO groups, local accounts, SSH, lockdown, service accounts, passwords, and certificates.'
    }
    foreach($k in $manual.Keys){
        Add-Check $phase $k MANUAL $cluster.Name 'Not executed by this read-only script.' $manual[$k]
    }
}catch{
    Add-Check 'Script' 'Unhandled error' FAIL '' $_.Exception.Message 'Review the transcript and correct the prerequisite or connection problem.'
}finally{
    if($script:VIServer){
        try{Disconnect-VIServer $script:VIServer -Confirm:$false|Out-Null;Add-Check 'Cleanup' 'Disconnect vCenter' PASS $vCenter 'Disconnected.'}catch{}
    }
    $meta.Completed=Get-Date;$meta.Results=$script:Results.Count
    try{
        $paths=Export-Reports $folder $base $meta
        Write-Host "`nReports created:" -ForegroundColor Green
        Write-Host "HTML: $($paths.Html)"
        Write-Host "CSV: $($paths.Csv)"
        Write-Host "Summary: $($paths.Summary)"
        Write-Host "Transcript: $transcript"
        if(Ask-YesNo 'Open the HTML report now?' $true){Start-Process $paths.Html}
    }catch{Write-Host "Report export failed: $($_.Exception.Message)" -ForegroundColor Red}
    if($script:TranscriptStarted){try{Stop-Transcript|Out-Null}catch{}}
}
Write-Host "`nValidation complete. Review all FAIL, WARN, SKIP, and MANUAL results." -ForegroundColor Cyan