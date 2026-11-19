<#
.SYNOPSIS
    Read-only prerequisite assessment for the ESXi rolling maintenance script.
.DESCRIPTION
    Checks local PowerShell, module availability and loadability, package tooling,
    basic network resolution and TCP connectivity. Produces CSV, JSON and text reports.
    Never installs software or changes ESXi/vCenter configuration.
.AUTHOR
    Michael Palmieri
.VERSION
    0.2.0 - 2026-11-19
.NOTES
    Created By: Michael Palmieri
.DISCLAIMER
    USE AT YOUR OWN RISK. This script is provided "AS IS" without warranty of any kind,
    either expressed or implied. The author assumes no responsibility for damage,
    loss of access, configuration changes, service interruption, or any other
    unintended consequence resulting from the use or misuse of this script.
    Review and test this script before using it in a production environment.
.EXAMPLE
    .\Test-EsxiMaintenancePrerequisites.ps1 -VCenter vcsa.example.com
#>
[CmdletBinding()]
param(
    [string]$VCenter,
    [string]$ReportDirectory = (Join-Path ([Environment]::GetFolderPath('UserProfile')) 'EsxiRollingLogs'),
    [switch]$SkipNetworkTests
)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$results = [System.Collections.Generic.List[object]]::new()
function Add-Result {
    param([string]$Category,[string]$Item,[string]$Status,[string]$Detected,[string]$Required,[string]$Action)
    $results.Add([pscustomobject]@{Category=$Category;Item=$Item;Status=$Status;Detected=$Detected;Required=$Required;EngineerAction=$Action})
}
$psVersion=$PSVersionTable.PSVersion.ToString()
if($PSVersionTable.PSVersion -ge [version]'7.2') {
    Add-Result 'Runtime' 'PowerShell' 'PASS' $psVersion 'PowerShell 7.2+ (script baseline)' 'None; verify supported PowerCLI release for this runtime.'
} else {
    Add-Result 'Runtime' 'PowerShell' 'BLOCK' $psVersion 'PowerShell 7.2+ (script baseline)' 'Install an approved PowerShell 7.2+ version, then rerun using pwsh. Do not assume latest is compatible.'
}
Add-Result 'Runtime' 'Operating system' 'INFO' ([System.Runtime.InteropServices.RuntimeInformation]::OSDescription) 'Supported by chosen PowerShell/PowerCLI versions' 'Check the Broadcom PowerCLI compatibility documentation for the selected versions.'
$moduleName='VMware.VimAutomation.Core'
$available=@(Get-Module -ListAvailable -Name $moduleName | Sort-Object Version -Descending)
if($available.Count -eq 0) {
    Add-Result 'PowerCLI' $moduleName 'BLOCK' 'Not found in PSModulePath' 'Compatible VMware/VCF PowerCLI Core module' 'Obtain an approved, version-pinned PowerCLI distribution from the authorized repository; install under change control; rerun this test.'
} else {
    $selected=$available[0]
    try {
        Import-Module -Name $selected.Path -ErrorAction Stop
        foreach($command in @('Connect-VIServer','Get-Cluster','Get-VMHost','Get-VM','Get-View','Set-VMHost','Restart-VMHost','Get-Task','Disconnect-VIServer')) {
            if(-not (Get-Command -Name $command -ErrorAction SilentlyContinue)) {
                Add-Result 'PowerCLI command' $command 'BLOCK' 'Missing after module import' 'Command available' 'Verify installed PowerCLI distribution and module compatibility; reinstall approved version if necessary.'
            }
        }
        Add-Result 'PowerCLI' $moduleName 'PASS' ([string]$selected.Version) 'Compatible Core module with required commands' 'Module loaded; still verify release compatibility with your vCenter and ESXi versions.'
    } catch {
        Add-Result 'PowerCLI' $moduleName 'BLOCK' ([string]$selected.Version) 'Module must import successfully' ('Investigate module load error: '+$_.Exception.Message)
    }
}
foreach($pkg in @('Microsoft.PowerShell.PSResourceGet','PowerShellGet')) {
    $mods=@(Get-Module -ListAvailable -Name $pkg | Sort-Object Version -Descending)
    if($mods.Count) { Add-Result 'Installer tooling' $pkg 'INFO' ([string]$mods[0].Version) 'Optional; needed only for approved installation workflow' 'No installation is performed by this script.' }
    else { Add-Result 'Installer tooling' $pkg 'INFO' 'Not installed' 'Optional; needed only for approved installation workflow' 'Install approved package tooling only if your deployment process requires it.' }
}
foreach($optional in @('VMware.VimAutomation.Storage','VMware.VimAutomation.Vds','VMware.VimAutomation.Nsxt')) {
    $mods=@(Get-Module -ListAvailable -Name $optional | Sort-Object Version -Descending)
    if($mods.Count) {Add-Result 'Extended features' $optional 'INFO' ([string]$mods[0].Version) 'Depends on enabled features in a future qualified release' 'Presence does not prove vSAN/NSX/VCF support.'}
    else {Add-Result 'Extended features' $optional 'INFO' 'Not installed' 'Not required for current non-vSAN execution candidate' 'Evaluate only if adding version-qualified vSAN/NSX checks.'}
}
if(-not [string]::IsNullOrWhiteSpace($VCenter)) {
    if($SkipNetworkTests) {
        Add-Result 'Connectivity' 'vCenter network' 'NOT_TESTED' $VCenter 'DNS and TCP 443 reachable' 'Rerun without -SkipNetworkTests to perform basic network tests.'
    } else {
        try {
            $dns=@([System.Net.Dns]::GetHostAddresses($VCenter))
            if($dns.Count -eq 0){throw 'DNS returned no addresses.'}
            Add-Result 'Connectivity' 'vCenter DNS' 'PASS' ($dns.IPAddressToString -join ', ') 'Resolves to an approved management endpoint' 'Verify addresses are expected; DNS alone does not validate endpoint identity.'
        } catch {
            Add-Result 'Connectivity' 'vCenter DNS' 'BLOCK' $VCenter 'DNS resolution' ('Verify DNS or name: '+$_.Exception.Message)
        }
        $client=[System.Net.Sockets.TcpClient]::new()
        try {
            $async=$client.BeginConnect($VCenter,443,$null,$null)
            if(-not $async.AsyncWaitHandle.WaitOne(3000)) {throw 'TCP connection timed out after 3 seconds.'}
            $client.EndConnect($async)
            Add-Result 'Connectivity' 'vCenter TCP 443' 'PASS' $VCenter 'TCP 443 reachable' 'Still validate TLS trust, authentication and API permissions separately.'
        } catch {
            Add-Result 'Connectivity' 'vCenter TCP 443' 'BLOCK' $VCenter 'TCP 443 reachable' ('Check routing, firewall, endpoint: '+$_.Exception.Message)
        } finally {$client.Dispose()}
    }
} else {
    Add-Result 'Connectivity' 'vCenter' 'NOT_TESTED' 'No -VCenter supplied' 'Named vCenter for network checks' 'Specify -VCenter to check DNS and TCP 443.'
}
Add-Result 'Compatibility' 'Release matrix' 'NOT_TESTED' 'No vCenter/ESXi build inventory' 'Approved vCenter, ESXi, PowerCLI and VCF combination' 'Confirm exact builds against current Broadcom interoperability and product documentation before executing changes.'
Add-Result 'Authorization' 'vCenter privileges' 'NOT_TESTED' 'Not authenticated' 'Privileges to read inventory, migrate VMs, enter maintenance and reboot hosts' 'Verify using a dedicated least-privilege service identity and approved test plan.'
Add-Result 'Cluster safety' 'HA/DRS/vMotion/capacity/vSAN/VCF/NSX' 'NOT_TESTED' 'No authenticated cluster preflight in this checker' 'Verified cluster-specific health and eligibility' 'Run cluster audit and approved platform-specific checks. Do not infer safety from local prerequisites.'
$stamp=Get-Date -Format 'yyyyMMdd_HHmmss'
$runId=[guid]::NewGuid().ToString('N').Substring(0,8)
try {
    New-Item -ItemType Directory -Path $ReportDirectory -Force -ErrorAction Stop | Out-Null
    $base=Join-Path $ReportDirectory "Prerequisites_${stamp}_${runId}"
    $csv="$base.csv"; $json="$base.json"; $txt="$base.txt"
    $results | Export-Csv -LiteralPath $csv -NoTypeInformation -Encoding utf8
    $results | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $json -Encoding utf8
    $lines=@("ESXi Rolling Maintenance - Prerequisite Report", "Generated: $(Get-Date -Format o)", "Target: $VCenter", '')
    foreach($r in $results){$lines+= "[$($r.Status)] $($r.Category) / $($r.Item)"; $lines+="  Detected: $($r.Detected)"; $lines+="  Required: $($r.Required)"; $lines+="  Engineer action: $($r.EngineerAction)"; $lines+=''}
    $lines | Set-Content -LiteralPath $txt -Encoding utf8
    $results | Format-Table Category,Item,Status,Detected -AutoSize | Out-Host
    Write-Host "`nDetailed report: $txt`nCSV: $csv`nJSON: $json"
} catch {
    Write-Warning "Could not write report: $($_.Exception.Message)"
    $results | Format-Table Category,Item,Status,EngineerAction -Wrap | Out-Host
    throw
}
if(@($results | Where-Object Status -eq 'BLOCK').Count -gt 0){
    Write-Warning 'BLOCKING local prerequisite failures found. Review EngineerAction in the report.'
}
# Emit a single object for orchestration; direct users see the table above.
[pscustomobject]@{HasBlockingIssues=(@($results | Where-Object Status -eq 'BLOCK').Count -gt 0);ReportPath=$txt;CsvPath=$csv;JsonPath=$json;Results=$results.ToArray()}
