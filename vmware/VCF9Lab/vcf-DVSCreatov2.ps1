<#
.SYNOPSIS
Creates the VCF Virtual Distributed Switch and required Distributed Port Groups.

.DESCRIPTION
Prompts for vCenter, credentials, and datacenter name. Creates VCF-VDS with two uplinks,
creates required Distributed Port Groups, configures VLANs, and sets security policies
to Accept for Promiscuous Mode, MAC Changes, and Forged Transmits.

.DISCLAIMER
THIS SCRIPT IS PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND.

This script is intended for educational, demonstration, and VMware Cloud Foundation lab environments. It creates and powers on virtual machines, attaches storage, modifies VM hardware, mounts installation media, and applies advanced VMX settings.

You should review and test this script in a non-production environment before use. Confirm datastore names, port group names, ISO paths, MAC addresses, CPU, memory, and disk requirements before running.

The author assumes no responsibility for data loss, service interruption, misconfiguration, failed deployments, licensing issues, or any other damages resulting from the use of this script.

Use this script at your own risk.
#>

Set-PowerCLIConfiguration -InvalidCertificateAction Ignore -Confirm:$false

$vCenter = Read-Host "Enter the vCenter Server FQDN or IP"
$DatacenterName = Read-Host "Enter the Datacenter Name"
$Credential = Get-Credential -Message "Enter your vCenter credentials"

$VDSName    = "VCF-VDS"
$NumUplinks = 2
$MTU        = 1500

$DistributedPortGroups = @(
    @{ Name="DPG-ALL-VLAN"; VLANType="Trunk";  VLAN="0-4094" },
    @{ Name="DPG-vMotion";  VLANType="Access"; VLAN=2 },
    @{ Name="DPG-vSAN";     VLANType="Access"; VLAN=5 },
    @{ Name="DPG-NSX-TEP";  VLANType="Access"; VLAN=9 },
    @{ Name="DPG-VMNET6";   VLANType="Access"; VLAN=6 },
    @{ Name="DPG-VMNET7";   VLANType="Access"; VLAN=7 }
)

try {
    Write-Host "Connecting to vCenter $vCenter..." -ForegroundColor Cyan

    Connect-VIServer `
        -Server $vCenter `
        -Credential $Credential `
        -ErrorAction Stop | Out-Null

    $Datacenter = Get-Datacenter `
        -Name $DatacenterName `
        -ErrorAction Stop

    $VDS = Get-VDSwitch `
        -Name $VDSName `
        -ErrorAction SilentlyContinue

    if (-not $VDS) {
        Write-Host "Creating VDS $VDSName..." -ForegroundColor Cyan

        $VDS = New-VDSwitch `
            -Name $VDSName `
            -Location $Datacenter `
            -NumUplinkPorts $NumUplinks `
            -Mtu $MTU `
            -ErrorAction Stop
    }
    else {
        Write-Host "VDS $VDSName already exists." -ForegroundColor Yellow
    }

    foreach ($DPG in $DistributedPortGroups) {

        $PortGroup = Get-VDPortgroup `
            -VDSwitch $VDS `
            -Name $DPG.Name `
            -ErrorAction SilentlyContinue

        if (-not $PortGroup) {
            Write-Host "Creating distributed port group $($DPG.Name)..." -ForegroundColor Cyan

            $PortGroup = New-VDPortgroup `
                -VDSwitch $VDS `
                -Name $DPG.Name `
                -NumPorts 128 `
                -ErrorAction Stop
        }
        else {
            Write-Host "Distributed port group $($DPG.Name) already exists." -ForegroundColor Yellow
        }

        if ($DPG.VLANType -eq "Trunk") {
            Write-Host "Setting $($DPG.Name) VLAN trunk $($DPG.VLAN)..." -ForegroundColor Cyan

            $PortGroup | Set-VDVlanConfiguration `
                -VlanTrunkRange $DPG.VLAN `
                -Confirm:$false `
                -ErrorAction Stop
        }
        else {
            Write-Host "Setting $($DPG.Name) VLAN ID $($DPG.VLAN)..." -ForegroundColor Cyan

            $PortGroup | Set-VDVlanConfiguration `
                -VlanId $DPG.VLAN `
                -Confirm:$false `
                -ErrorAction Stop
        }

        Write-Host "Setting security policy on $($DPG.Name)..." -ForegroundColor Cyan

        $SecurityPolicy = Get-VDSecurityPolicy `
            -VDPortgroup $PortGroup `
            -ErrorAction Stop

        Set-VDSecurityPolicy `
            -VDSecurityPolicy $SecurityPolicy `
            -AllowPromiscuous $true `
            -MacChanges $true `
            -ForgedTransmits $true `
            -Confirm:$false `
            -ErrorAction Stop | Out-Null
    }

    Write-Host "VCF-VDS and Distributed Port Groups configured successfully." -ForegroundColor Green
}
catch {
    Write-Error "Script failed: $($_.Exception.Message)"
}
finally {
    Disconnect-VIServer -Server $vCenter -Confirm:$false
}