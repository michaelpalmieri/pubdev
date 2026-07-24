<#
.SYNOPSIS
Creates and configures the vSAN VMkernel adapter (vmk2) on multiple ESXi hosts.

.DESCRIPTION
This script automates the configuration of the VMware vSAN network on a
group of standalone ESXi hosts using VMware PowerCLI.

The script connects directly to each ESXi host and performs the following:

    • Verifies that vSwitch0 exists.
    • Creates or updates the vSAN Standard Port Group.
    • Configures VLAN ID 5.
    • Creates or updates vmk2.
    • Assigns the correct IP address.
    • Enables vSAN traffic.
    • Disconnects from the ESXi host.

The script is idempotent and may be safely re-run.

.NOTES
Author      : Michael Palmieri
Version     : 1.0
Requires    : VMware PowerCLI
Platform    : VMware ESXi
Purpose     : VMware Cloud Foundation Lab Automation

.DISCLAIMER
THIS SCRIPT IS PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND.

This script is intended for educational, demonstration, and VMware Cloud Foundation lab environments. It creates and powers on virtual machines, attaches storage, modifies VM hardware, mounts installation media, and applies advanced VMX settings.

You should review and test this script in a non-production environment before use. Confirm datastore names, port group names, ISO paths, MAC addresses, CPU, memory, and disk requirements before running.

The author assumes no responsibility for data loss, service interruption, misconfiguration, failed deployments, licensing issues, or any other damages resulting from the use of this script.

Use this script at your own risk.
#>

# Requires VMware PowerCLI

Set-PowerCLIConfiguration -InvalidCertificateAction Ignore -Confirm:$false

$vSwitch = "vSwitch0"
$PortGroupName = "vSAN"
$VlanId = 5
$SubnetMask = "255.255.255.224"

$Hosts = @(
    @{ Name="VCF01.esx.local"; vSANIP="172.16.5.6" }
    @{ Name="VCF02.esx.local"; vSANIP="172.16.5.7" }
    @{ Name="VCF03.esx.local"; vSANIP="172.16.5.8" }
    @{ Name="VCF04.esx.local"; vSANIP="172.16.5.9" }
)

Clear-Host

Write-Host ""
Write-Host "==========================================================" -ForegroundColor Yellow
Write-Host " VMware Cloud Foundation vSAN Configuration Utility" -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Yellow
Write-Host ""

Write-Host "Hosts to Configure:" -ForegroundColor White
$Hosts | ForEach-Object {
    Write-Host "  • $($_.Name)"
}

Write-Host ""
Write-Host "Configuration:" -ForegroundColor White
Write-Host "  Standard Switch : $vSwitch"
Write-Host "  Port Group      : $PortGroupName"
Write-Host "  VLAN ID         : $VlanId"
Write-Host "  VMkernel        : vmk2"
Write-Host "  Subnet Mask     : $SubnetMask"
Write-Host ""

$Continue = Read-Host "Continue? (Y/N)"

if ($Continue -notmatch '^[Yy]$') {
    Write-Host ""
    Write-Host "Operation cancelled." -ForegroundColor Yellow
    return
}

Write-Host ""

$Credential = Get-Credential -Message "Enter the ESXi root credentials"

foreach ($ESXiHost in $Hosts) {

    $VIServer = $null

    Write-Host ""
    Write-Host "==========================================================" -ForegroundColor DarkGray
    Write-Host " Configuring $($ESXiHost.Name)" -ForegroundColor Cyan
    Write-Host "==========================================================" -ForegroundColor DarkGray

    try {

        $VIServer = Connect-VIServer `
            -Server $ESXiHost.Name `
            -Credential $Credential `
            -ErrorAction Stop

        $VMHost = Get-VMHost `
            -Server $VIServer `
            -Name $ESXiHost.Name `
            -ErrorAction Stop

        $VSS = Get-VirtualSwitch `
            -Server $VIServer `
            -VMHost $VMHost `
            -Name $vSwitch `
            -ErrorAction Stop

        #
        # Create or Update vSAN Port Group
        #
        $PortGroup = Get-VirtualPortGroup `
            -Server $VIServer `
            -VMHost $VMHost `
            -Name $PortGroupName `
            -ErrorAction SilentlyContinue

        if (-not $PortGroup) {

            Write-Host "Creating Port Group '$PortGroupName'..." -ForegroundColor Yellow

            $PortGroup = New-VirtualPortGroup `
                -VirtualSwitch $VSS `
                -Name $PortGroupName `
                -VLanId $VlanId
        }
        else {

            Write-Host "Updating Port Group '$PortGroupName'..." -ForegroundColor Yellow

            Set-VirtualPortGroup `
                -VirtualPortGroup $PortGroup `
                -VLanId $VlanId `
                -Confirm:$false | Out-Null
        }

        #
        # Create or Update vmk2
        #
        $VMK = Get-VMHostNetworkAdapter `
            -Server $VIServer `
            -VMHost $VMHost `
            -VMKernel `
            -Name vmk2 `
            -ErrorAction SilentlyContinue

        if (-not $VMK) {

            Write-Host "Creating vmk2..." -ForegroundColor Yellow

            New-VMHostNetworkAdapter `
                -VMHost $VMHost `
                -VirtualSwitch $VSS `
                -PortGroup $PortGroupName `
                -IP $ESXiHost.vSANIP `
                -SubnetMask $SubnetMask `
                -VsanTrafficEnabled $true `
                -ErrorAction Stop | Out-Null
        }
        else {

            Write-Host "Updating vmk2..." -ForegroundColor Yellow

            Set-VMHostNetworkAdapter `
                -VirtualNic $VMK `
                -IP $ESXiHost.vSANIP `
                -SubnetMask $SubnetMask `
                -VsanTrafficEnabled $true `
                -Confirm:$false `
                -ErrorAction Stop | Out-Null
        }

        Write-Host ""
        Write-Host "✓ Successfully configured $($ESXiHost.Name)" -ForegroundColor Green
    }
    catch {

        Write-Host ""
        Write-Host "✗ Failed to configure $($ESXiHost.Name)" -ForegroundColor Red
        Write-Host $_.Exception.Message -ForegroundColor Red
    }
    finally {

        if ($VIServer) {
            Disconnect-VIServer `
                -Server $VIServer `
                -Confirm:$false | Out-Null
        }
    }
}

Write-Host ""
Write-Host "==========================================================" -ForegroundColor Green
Write-Host " vSAN VMkernel configuration completed." -ForegroundColor Green
Write-Host "==========================================================" -ForegroundColor Green