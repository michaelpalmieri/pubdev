<#
.SYNOPSIS
    Audits a selected vCenter cluster and performs guarded, sequential ESXi host maintenance and reboot in a qualified non-vSAN environment.
.DESCRIPTION
    Connects to vCenter, discovers clusters, performs read-only checks by default,
    and optionally runs a one-host-at-a-time rolling reboot. Each host must enter
    maintenance mode, reboot, reconnect, exit maintenance, and pass recovery checks
    before the next host begins. vSAN execution is intentionally NOT implemented.
    VCF execution is NOT qualified. This is a lab/pilot candidate, not a guarantee
    of production readiness. All execution requires explicit opt-in.
.AUTHOR
    Michael Palmieri
.VERSION
    0.2.0 - Safety-first test candidate (2026-11-19)
.REQUIREMENTS
    PowerShell 7.2+, installed VMware/VCF PowerCLI modules, vCenter permissions,
    fully automated DRS, approved change window and verified capacity/migration plan.
.NOTES
    Created By: Michael Palmieri
.DISCLAIMER
    USE AT YOUR OWN RISK. This script is provided "AS IS" without warranty of any kind,
    either expressed or implied. The author assumes no responsibility for damage,
    loss of access, configuration changes, service interruption, or any other
    unintended consequence resulting from the use or misuse of this script.
    Review and test this script before using it in a production environment.
.EXAMPLE
    .\Invoke-ClusterRollingMaintenance.ps1 -VCenter vcsa.example.com
.EXAMPLE
    .\Invoke-ClusterRollingMaintenance.ps1 -VCenter vcsa.example.com -ClusterName Compute01
.EXAMPLE
    .\Invoke-ClusterRollingMaintenance.ps1 -VCenter vcsa.example.com -ClusterName Compute01 -Execute -ApprovedChange CHG12345 -ConfirmNonVcf -ConfirmCapacityReviewed
#>
[CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='High')]
param(
    [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$VCenter,
    [string]$ClusterName,
    [switch]$Execute,
    [switch]$PrerequisitesOnly,
    [string]$ApprovedChange,
    [switch]$ConfirmNonVcf,
    [switch]$ConfirmCapacityReviewed,
    [ValidateRange(5,240)][int]$MaintenanceTimeoutMinutes=90,
    [ValidateRange(5,120)][int]$RebootTimeoutMinutes=45,
    [ValidateRange(5,120)][int]$RecoveryTimeoutMinutes=30,
    [ValidateRange(5,120)][int]$PollSeconds=15,
    [string]$LogDirectory=(Join-Path ([Environment]::GetFolderPath('UserProfile')) 'EsxiRollingLogs')
)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$connection=$null
$logFile=$null
$script:RunId=[guid]::NewGuid().ToString('N')
function Write-Audit {
    param([string]$Level,[string]$Message)
    $line='{0} [{1}] [{2}] {3}' -f (Get-Date -Format 'o'),$Level,$script:RunId,$Message
    Write-Host $line
    if($script:logFile){ Add-Content -LiteralPath $script:logFile -Value $line -ErrorAction Stop }
}
function Get-ExactCluster {
    param($Server,[string]$Name)
    $all=@(Get-Cluster -Server $Server)
    if([string]::IsNullOrWhiteSpace($Name)){
        $all | Select-Object Name,DrsEnabled,DrsAutomationLevel,HAEnabled | Format-Table -AutoSize | Out-Host
        throw 'Read-only discovery complete. Specify -ClusterName for a targeted audit.'
    }
    $matches=@($all | Where-Object { $_.Name -ceq $Name })
    if($matches.Count -ne 1){ throw "Cluster name '$Name' matched $($matches.Count) clusters. Require exactly one." }
    return $matches[0]
}
function Get-HostInventory {
    param($Cluster,$Server)
    return @(Get-VMHost -Location $Cluster -Server $Server | Sort-Object Name)
}
function Get-HostVMs {
    param($HostObject,$Server)
    return @(Get-VM -Location $HostObject -Server $Server)
}
function Get-FreshHost {
    param([string]$HostId,$Server)
    $matches=@(Get-VMHost -Server $Server | Where-Object { $_.Id -eq $HostId })
    if($matches.Count -ne 1){throw "Host identity $HostId not uniquely found."}
    return $matches[0]
}
function Assert-ClusterSafe {
    param($Cluster,$Server,[string]$TargetId)
    $fresh=@(Get-Cluster -Server $Server | Where-Object {$_.Id -eq $Cluster.Id})
    if($fresh.Count -ne 1){throw 'Cluster identity changed or is inaccessible.'}
    $c=$fresh[0]
    if(-not $c.DrsEnabled -or [string]$c.DrsAutomationLevel -ne 'FullyAutomated'){
        throw 'Fully automated DRS is mandatory for this execution candidate.'
    }
    if(-not $c.HAEnabled){throw 'Cluster HA is disabled. Execution blocked by policy.'}
    $hosts=Get-HostInventory -Cluster $c -Server $Server
    if($hosts.Count -lt 2){throw 'At least two cluster hosts required.'}
    $bad=@($hosts | Where-Object { $_.ConnectionState -ne 'Connected' })
    if($bad.Count -gt 0){throw "Hosts not connected/available: $($bad.Name -join ', ')"}
    if($TargetId -and @($hosts | Where-Object {$_.Id -eq $TargetId}).Count -ne 1){throw 'Target host is no longer in selected cluster.'}
    return $hosts
}
function Wait-HostState {
    param([string]$HostId,$Server,[string]$Expected,[int]$TimeoutMinutes,[string]$Phase)
    $deadline=(Get-Date).AddMinutes($TimeoutMinutes)
    while((Get-Date) -lt $deadline){
        $hostNow=Get-FreshHost -HostId $HostId -Server $Server
        $vms=Get-HostVMs -HostObject $hostNow -Server $Server
        $powered=@($vms | Where-Object {$_.PowerState -eq 'PoweredOn'})
        Write-Audit INFO "$Phase host=$($hostNow.Name) state=$($hostNow.ConnectionState) registeredVMs=$($vms.Count) poweredOnVMs=$($powered.Count)"
        if([string]$hostNow.ConnectionState -eq $Expected){return $hostNow}
        Start-Sleep -Seconds $PollSeconds
    }
    throw "Timeout waiting for host $HostId to reach $Expected during $Phase. Task may still be running: MANUAL RECONCILIATION REQUIRED."
}
try {
    New-Item -ItemType Directory -Path $LogDirectory -Force | Out-Null
    $script:logFile=Join-Path $LogDirectory ("Rolling_{0}_{1}.log" -f (Get-Date -Format 'yyyyMMdd_HHmmss'),$script:RunId)
    Write-Audit INFO 'Starting. Default is read-only audit.'
    $checker=Join-Path $PSScriptRoot 'Test-EsxiMaintenancePrerequisites.ps1'
    if(-not (Test-Path -LiteralPath $checker -PathType Leaf)) {
        throw "Missing companion prerequisite checker: $checker. Place both scripts in the same directory."
    }
    $preflight = & $checker -VCenter $VCenter -ReportDirectory $LogDirectory
    Write-Audit INFO "Prerequisite report=$($preflight.ReportPath)"
    if($PrerequisitesOnly) {Write-Audit INFO 'Prerequisites-only mode complete. No vCenter login or host changes.'; return}
    if($preflight.HasBlockingIssues) {throw "Blocking prerequisites found. Review $($preflight.ReportPath)"}
    Import-Module VMware.VimAutomation.Core -ErrorAction Stop
    $connection=Connect-VIServer -Server $VCenter -ErrorAction Stop
    $cluster=Get-ExactCluster -Server $connection -Name $ClusterName
    $hosts=Get-HostInventory -Cluster $cluster -Server $connection
    Write-Audit INFO "Cluster=$($cluster.Name) hosts=$($hosts.Count) DRS=$($cluster.DrsEnabled) automation=$($cluster.DrsAutomationLevel) HA=$($cluster.HAEnabled)"
    $vsanFlag=$null
    # Prefer the vCenter cluster configuration's vSAN enabled field. Unknown => fail closed.
    $clusterView=Get-View -Id $cluster.Id -Server $connection -ErrorAction Stop
    if($null -eq $clusterView.ConfigurationEx -or $null -eq $clusterView.ConfigurationEx.VsanConfigInfo){
        Write-Audit WARN 'vSAN status could not be established; audit may continue, execution will be blocked.'
    } else {
        $vsanFlag=$clusterView.ConfigurationEx.VsanConfigInfo.Enabled
    }
    Write-Audit INFO "vSAN enabled=$vsanFlag"
    foreach($h in $hosts){
        $vms=Get-HostVMs -HostObject $h -Server $connection
        Write-Audit INFO "INVENTORY host=$($h.Name) state=$($h.ConnectionState) ESXi=$($h.Version) registeredVMs=$($vms.Count) poweredOn=$(@($vms | Where-Object {$_.PowerState -eq 'PoweredOn'}).Count)"
    }
    if(-not $Execute){Write-Audit INFO 'AUDIT ONLY. No maintenance, VM migration or reboot requested.'; return}
    if($WhatIfPreference){Write-Audit INFO 'WHATIF: no changes requested.'; return}
    if($null -eq $vsanFlag){throw 'vSAN status unknown; execution blocked.'}
    if($vsanFlag){throw 'vSAN execution deliberately disabled in v0.1.0. Audit only.'}
    if(-not $ConfirmNonVcf){throw 'VCF is not automatically classified. Require explicit -ConfirmNonVcf after independent verification.'}
    if(-not $ConfirmCapacityReviewed){throw 'Capacity/vMotion/HA admission/affinity assessment must be independently approved (-ConfirmCapacityReviewed).'}
    if([string]::IsNullOrWhiteSpace($ApprovedChange)){throw 'Require -ApprovedChange change-ticket identifier.'}
    $hosts=Assert-ClusterSafe -Cluster $cluster -Server $connection -TargetId ''
    foreach($hostItem in $hosts){
        $current=Get-FreshHost -HostId $hostItem.Id -Server $connection
        if($current.ConnectionState -ne 'Connected'){throw "Host $($current.Name) not in initial Connected state; stop."}
        $null=Assert-ClusterSafe -Cluster $cluster -Server $connection -TargetId $current.Id
        $initialVMs=Get-HostVMs -HostObject $current -Server $connection
        Write-Audit INFO "BEGIN host=$($current.Name) initialVMs=$($initialVMs.Count) change=$ApprovedChange"
        if(-not $PSCmdlet.ShouldProcess($current.Name,'Evacuate, enter maintenance, reboot, exit maintenance')){
            throw 'Operator declined host operation. Sequence stopped.'
        }
        # RunAsync allows us to poll vCenter inventory while DRS evacuates powered-on VMs.
        $task=Set-VMHost -VMHost $current -State Maintenance -RunAsync -Server $connection -ErrorAction Stop
        $deadline=(Get-Date).AddMinutes($MaintenanceTimeoutMinutes)
        do {
            Start-Sleep -Seconds $PollSeconds
            $taskNow=Get-Task -Id $task.Id -Server $connection -ErrorAction Stop
            $now=Get-FreshHost -HostId $current.Id -Server $connection
            $remaining=Get-HostVMs -HostObject $now -Server $connection
            $running=@($remaining | Where-Object {$_.PowerState -eq 'PoweredOn'})
            Write-Audit INFO "EVACUATION host=$($now.Name) task=$($taskNow.State) initial=$($initialVMs.Count) remainingRegistered=$($remaining.Count) remainingPoweredOn=$($running.Count)"
            if($taskNow.State -eq 'Error'){throw "Maintenance task failed on $($current.Name): $($taskNow.Description)"}
            if($taskNow.State -eq 'Success'){break}
            if((Get-Date) -ge $deadline){throw 'Maintenance timeout; task may remain active. STOP and reconcile manually.'}
        } while($true)
        $now=Get-FreshHost -HostId $current.Id -Server $connection
        if($now.ConnectionState -ne 'Maintenance'){throw 'Maintenance task finished but host not in maintenance state.'}
        $left=Get-HostVMs -HostObject $now -Server $connection
        if(@($left | Where-Object {$_.PowerState -eq 'PoweredOn'}).Count -gt 0){throw 'Powered-on VMs remain on maintenance host. Reboot blocked.'}
        # Powered-off registered VMs can remain; their presence is logged, not treated as migrated.
        Write-Audit INFO "REBOOT host=$($now.Name) registeredVMsRemaining=$($left.Count)"
        $beforeView=Get-View -Id $current.Id -Server $connection -ErrorAction Stop
        $beforeBoot=$beforeView.Runtime.BootTime
        if($null -eq $beforeBoot){throw 'Host boot time unavailable; reboot blocked.'}
        Restart-VMHost -VMHost $now -Confirm:$false -Server $connection -ErrorAction Stop | Out-Null
        # A maintenance state immediately after issuing reboot could be the OLD state.
        # Require a strictly newer ESXi boot timestamp, plus maintenance state.
        $rebootDeadline=(Get-Date).AddMinutes($RebootTimeoutMinutes)
        $rebootVerified=$false
        while((Get-Date) -lt $rebootDeadline){
            Start-Sleep -Seconds $PollSeconds
            try {
                $checkView=Get-View -Id $current.Id -Server $connection -ErrorAction Stop
                $newBoot=$checkView.Runtime.BootTime
                $state=[string]$checkView.Runtime.ConnectionState
                Write-Audit INFO "REBOOT_CHECK host=$($current.Name) state=$state bootTime=$newBoot previousBoot=$beforeBoot"
                if($newBoot -and ([datetime]$newBoot -gt [datetime]$beforeBoot) -and $state -eq 'maintenance'){
                    $rebootVerified=$true; break
                }
            } catch {Write-Audit WARN "Host unavailable during reboot polling: $($_.Exception.Message)"}
        }
        if(-not $rebootVerified){throw 'Reboot not verified by newer host boot timestamp and maintenance state. Stop; reconcile manually.'}
        $now=Get-FreshHost -HostId $current.Id -Server $connection
        Set-VMHost -VMHost $now -State Connected -Server $connection -ErrorAction Stop | Out-Null
        $null=Wait-HostState -HostId $current.Id -Server $connection -Expected 'Connected' -TimeoutMinutes $RecoveryTimeoutMinutes -Phase 'Exit maintenance'
        $null=Assert-ClusterSafe -Cluster $cluster -Server $connection -TargetId $current.Id
        Write-Audit INFO "COMPLETE host=$($current.Name) - boot timestamp and basic recovery gates passed; additional infrastructure checks required."
    }
    Write-Audit INFO 'All selected cluster hosts processed; review detailed logs and infrastructure health.'
} catch {
    if($script:logFile){Write-Audit ERROR $_.Exception.Message}
    else {Write-Error $_.Exception.Message}
    throw
} finally {
    if($connection){Disconnect-VIServer -Server $connection -Confirm:$false -ErrorAction SilentlyContinue | Out-Null}
}
