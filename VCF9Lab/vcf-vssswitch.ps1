```powershell
<#
.SYNOPSIS
Configures standard networking for a VMware Cloud Foundation lab on standalone ESXi hosts.

.DESCRIPTION
Prompts for ESXi credentials, connects to each ESXi host, configures vSwitch0,
adds vmnic0 and vmnic1 as uplinks, creates required Standard Port Groups,
sets VLAN IDs, enables permissive security policies, and creates or updates
vmk1 for vMotion traffic.

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

$Hosts = @(
    @{ Name="VCF01.esx.local"; vMotionIP="172.16.2.6"; SubnetMask="255.255.255.224" },
    @{ Name="VCF02.esx.local"; vMotionIP="172.16.2.7"; SubnetMask="255.255.255.224" },
    @{ Name="VCF03.esx.local"; vMotionIP="172.16.2.8"; SubnetMask="255.255.255.224" },
    @{ Name="VCF04.esx.local"; vMotionIP="172.16.2.9"; SubnetMask="255.255.255.224" }
)

$PortGroups = @(
    @{ Name="Management"; VLAN=3 },
    @{ Name="vMotion"; VLAN=2 },
    @{ Name="vSAN"; VLAN=5 },
    @{ Name="NSX-TEP"; VLAN=9 },
    @{ Name="VM-NET-6"; VLAN=6 },
    @{ Name="VM-NET-7"; VLAN=7 },
    @{ Name="ALL-VLAN-PG"; VLAN=4095 }
)

Write-Host ""
Write-Host "==============================================================" -ForegroundColor Yellow
Write-Host " VMware Cloud Foundation Standard Networking Configuration" -ForegroundColor Cyan
Write-Host "==============================================================" -ForegroundColor Yellow
Write-Host ""
Write-Host "The following ESXi hosts will be configured:" -ForegroundColor White
$Hosts | ForEach-Object { Write-Host "  - $($_.Name)" }
Write-Host ""
Write-Host "This script will:"
Write-Host "  - Add vmnic0 and vmnic1 to vSwitch0 if needed"
Write-Host "  - Create or update Standard Port Groups"
Write-Host "  - Configure VLAN IDs"
Write-Host "  - Enable Promiscuous Mode, MAC Changes, and Forged Transmits"
Write-Host "  - Create or update vmk1 for vMotion"
Write-Host ""

$Continue = Read-Host "Continue? (Y/N)"

if ($Continue -notmatch '^[Yy]$') {
    Write-Host "Operation cancelled." -ForegroundColor Yellow
    return
}

$Credential = Get-Credential -Message "Enter ESXi credentials, for example root"

foreach ($ESXiHost in $Hosts) {

    $VIServer = $null

    Write-Host ""
    Write-Host "====================================================" -ForegroundColor DarkGray
    Write-Host "Configuring $($ESXiHost.Name)" -ForegroundColor Cyan
    Write-Host "====================================================" -ForegroundColor DarkGray

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

        foreach ($nic in "vmnic0","vmnic1") {

            $PhysicalNic = Get-VMHostNetworkAdapter `
                -Server $VIServer `
                -VMHost $VMHost `
                -Physical `
                -Name $nic `
                -ErrorAction SilentlyContinue

            if ($PhysicalNic) {
                if ($PhysicalNic.VirtualSwitchId -ne $VSS.Id) {
                    Write-Host "Adding $nic to $vSwitch..." -ForegroundColor Yellow

                    Add-VirtualSwitchPhysicalNetworkAdapter `
                        -VirtualSwitch $VSS `
                        -VMHostPhysicalNic $PhysicalNic `
                        -Confirm:$false | Out-Null
                }
                else {
                    Write-Host "$nic is already assigned to $vSwitch." -ForegroundColor DarkGray
                }
            }
            else {
                Write-Warning "$nic was not found on $($ESXiHost.Name)."
            }
        }

        foreach ($PG in $PortGroups) {

            $PortGroup = Get-VirtualPortGroup `
                -Server $VIServer `
                -VMHost $VMHost `
                -Name $PG.Name `
                -ErrorAction SilentlyContinue

            if (-not $PortGroup) {
                Write-Host "Creating Port Group $($PG.Name) with VLAN $($PG.VLAN)..." -ForegroundColor Yellow

                $PortGroup = New-VirtualPortGroup `
                    -VirtualSwitch $VSS `
                    -Name $PG.Name `
                    -VLanId $PG.VLAN `
                    -ErrorAction Stop
            }
            else {
                Write-Host "Updating Port Group $($PG.Name) to VLAN $($PG.VLAN)..." -ForegroundColor Yellow

                Set-VirtualPortGroup `
                    -VirtualPortGroup $PortGroup `
                    -VLanId $PG.VLAN `
                    -Confirm:$false `
                    -ErrorAction Stop | Out-Null
            }

            Get-SecurityPolicy -VirtualPortGroup $PortGroup |
                Set-SecurityPolicy `
                    -AllowPromiscuous $true `
                    -MacChanges $true `
                    -ForgedTransmits $true `
                    -Confirm:$false | Out-Null
        }

        $VMK = Get-VMHostNetworkAdapter `
            -Server $VIServer `
            -VMHost $VMHost `
            -VMKernel `
            -Name vmk1 `
            -ErrorAction SilentlyContinue

        if (-not $VMK) {
            Write-Host "Creating vmk1 for vMotion..." -ForegroundColor Yellow

            New-VMHostNetworkAdapter `
                -VMHost $VMHost `
                -VirtualSwitch $VSS `
                -PortGroup "vMotion" `
                -IP $ESXiHost.vMotionIP `
                -SubnetMask $ESXiHost.SubnetMask `
                -VMotionEnabled $true `
                -ErrorAction Stop | Out-Null
        }
        else {
            Write-Host "Updating vmk1 for vMotion..." -ForegroundColor Yellow

            Set-VMHostNetworkAdapter `
                -VirtualNic $VMK `
                -IP $ESXiHost.vMotionIP `
                -SubnetMask $ESXiHost.SubnetMask `
                -VMotionEnabled $true `
                -Confirm:$false `
                -ErrorAction Stop | Out-Null
        }

        Write-Host "$($ESXiHost.Name) configured successfully." -ForegroundColor Green
    }
    catch {
        Write-Warning "Failed to configure $($ESXiHost.Name): $($_.Exception.Message)"
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
Write-Host "====================================================" -ForegroundColor Green
Write-Host "ESXi networking configuration complete." -ForegroundColor Green
Write-Host "====================================================" -ForegroundColor Green
```
