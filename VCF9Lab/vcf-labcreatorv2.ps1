```powershell
<#
.SYNOPSIS
Deploys nested ESXi virtual machines with fixed MAC addresses for automated Kickstart installation.

.DESCRIPTION
This script automates the deployment of four nested ESXi virtual machines on a standalone ESXi host using VMware PowerCLI.

The script prompts for the target ESXi host, username, and password, then connects directly to the ESXi host. It creates each nested ESXi VM with predefined compute, storage, network, ISO, and VMX configuration settings required for a VMware Cloud Foundation lab deployment.

For each nested ESXi VM, the script performs the following tasks:

    • Creates the nested ESXi virtual machine.
    • Configures 6 vCPUs and 32 GB of memory.
    • Creates a 40 GB thin-provisioned operating system disk.
    • Removes any default network adapters.
    • Adds two VMXNET3 network adapters.
    • Assigns fixed MAC addresses for Kickstart automation.
    • Connects both network adapters to the ALL-VLAN-PG port group.
    • Adds four additional 30 GB thin-provisioned disks.
    • Validates that the VM has five total disks.
    • Validates that the VM has two network adapters.
    • Mounts the ESXi Kickstart ISO.
    • Enables nested virtualization.
    • Applies required advanced VMX parameters.
    • Powers on the VM.
    • Reports success or failure for each VM.

Nested ESXi Virtual Machines Created

    vcf01
    vcf02
    vcf03
    vcf04

Fixed MAC Address Assignments

    vcf01
        NIC 1: 00:50:56:11:22:60
        NIC 2: 00:50:56:11:23:60

    vcf02
        NIC 1: 00:50:56:11:22:61
        NIC 2: 00:50:56:11:23:61

    vcf03
        NIC 1: 00:50:56:11:22:62
        NIC 2: 00:50:56:11:23:62

    vcf04
        NIC 1: 00:50:56:11:22:63
        NIC 2: 00:50:56:11:23:63

VM Configuration

    Guest OS Type   : vmkernel8Guest
    vCPU Count      : 6
    Cores/Socket    : 6
    Memory          : 32 GB
    OS Disk         : 40 GB Thin
    Additional Disk : 4 x 30 GB Thin
    Network Adapter : 2 x VMXNET3
    Port Group      : ALL-VLAN-PG
    ISO             : [LocalStorage4ESX02] /VCF/ESXi-9.0.1-Kickstart.iso

.NOTES
Author      : Michael Palmieri
Version     : 2.0
Requires    : VMware PowerCLI
Platform    : VMware ESXi
Purpose     : VMware Cloud Foundation Nested ESXi Lab Deployment

The script connects directly to a standalone ESXi host and does not require vCenter Server.

The fixed MAC addresses are intended to support automated Kickstart installation logic. Ensure the MAC addresses match the expected values in the Kickstart configuration before running the script.

.DISCLAIMER
THIS SCRIPT IS PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND.

This script is intended for educational, demonstration, and VMware Cloud Foundation lab environments. It creates and powers on virtual machines, attaches storage, modifies VM hardware, mounts installation media, and applies advanced VMX settings.

You should review and test this script in a non-production environment before use. Confirm datastore names, port group names, ISO paths, MAC addresses, CPU, memory, and disk requirements before running.

The author assumes no responsibility for data loss, service interruption, misconfiguration, failed deployments, licensing issues, or any other damages resulting from the use of this script.

Use this script at your own risk.

.EXAMPLE
PS> .\Deploy-NestedESXi.ps1

Prompts for the ESXi host and credentials, deploys the nested ESXi VMs, mounts the Kickstart ISO, configures nested virtualization, and powers on each VM.

.LINK
https://developer.vmware.com/powercli/
#>
```


$ESXiHost = Read-Host "Enter ESXi Host IP or FQDN"
$ESXiUser = Read-Host "Enter ESXi Username"

$ESXiCredential = Get-Credential `
    -UserName $ESXiUser `
    -Message "Enter password for $ESXiUser@$ESXiHost"

$Datastore = "ESX02LocalNVMeDisk1"
$PortGroup = "ALL-VLAN-PG"
$ISOPath   = "[LocalStorage4ESX02] /VCF/ESXi-9.0.1-Kickstart.iso"

$NestedHosts = @(
    @{ VMName = "vcf01"; Mac1 = "00:50:56:11:22:60"; Mac2 = "00:50:56:11:23:60" },
    @{ VMName = "vcf02"; Mac1 = "00:50:56:11:22:61"; Mac2 = "00:50:56:11:23:61" },
    @{ VMName = "vcf03"; Mac1 = "00:50:56:11:22:62"; Mac2 = "00:50:56:11:23:62" },
    @{ VMName = "vcf04"; Mac1 = "00:50:56:11:22:63"; Mac2 = "00:50:56:11:23:63" }
)

function Write-Step {
    param(
        [int]$Step,
        [int]$Total,
        [string]$VMName,
        [string]$Message
    )

    $Percent = [math]::Round(($Step / $Total) * 100)

    Write-Progress `
        -Activity "Deploying $VMName" `
        -Status $Message `
        -PercentComplete $Percent

    Write-Host "[$VMName] [$Step/$Total] $Message" -ForegroundColor Cyan
}

Set-PowerCLIConfiguration `
    -InvalidCertificateAction Ignore `
    -Confirm:$false | Out-Null

Connect-VIServer `
    -Server $ESXiHost `
    -Credential $ESXiCredential

foreach ($NestedHost in $NestedHosts) {

    $VMName = $NestedHost.VMName
    $TotalSteps = 11

    try {
        Write-Host ""
        Write-Host "=========================================" -ForegroundColor Yellow
        Write-Host "Deploying $VMName" -ForegroundColor Green
        Write-Host "=========================================" -ForegroundColor Yellow

        Write-Step 1 $TotalSteps $VMName "Creating VM with 40 GB OS disk"

        $vm = New-VM `
            -Name $VMName `
            -VMHost $ESXiHost `
            -Datastore $Datastore `
            -DiskGB 40 `
            -MemoryGB 32 `
            -NumCpu 6 `
            -CoresPerSocket 6 `
            -GuestId vmkernel8Guest `
            -DiskStorageFormat Thin `
            -ErrorAction Stop

        Start-Sleep -Seconds 3
        $vm = Get-VM -Name $VMName -ErrorAction Stop

        Write-Step 2 $TotalSteps $VMName "Removing default network adapters"

        Get-NetworkAdapter -VM $vm |
            Remove-NetworkAdapter `
                -Confirm:$false `
                -ErrorAction SilentlyContinue

        Start-Sleep -Seconds 2
        $vm = Get-VM -Name $VMName -ErrorAction Stop

        Write-Step 3 $TotalSteps $VMName "Adding Network Adapter 1 with MAC $($NestedHost.Mac1)"

        New-NetworkAdapter `
            -VM $vm `
            -NetworkName $PortGroup `
            -Type Vmxnet3 `
            -MacAddress $NestedHost.Mac1 `
            -StartConnected:$true `
            -ErrorAction Stop `
            -Confirm:$false | Out-Null

        Write-Step 4 $TotalSteps $VMName "Adding Network Adapter 2 with MAC $($NestedHost.Mac2)"

        New-NetworkAdapter `
            -VM $vm `
            -NetworkName $PortGroup `
            -Type Vmxnet3 `
            -MacAddress $NestedHost.Mac2 `
            -StartConnected:$true `
            -ErrorAction Stop `
            -Confirm:$false | Out-Null

        Write-Step 5 $TotalSteps $VMName "Adding four 30 GB disks"

        for ($diskNumber = 1; $diskNumber -le 4; $diskNumber++) {
            Write-Host "[$VMName] Adding 30 GB disk $diskNumber of 4" -ForegroundColor Gray

            $vm = Get-VM -Name $VMName -ErrorAction Stop

            New-HardDisk `
                -VM $vm `
                -CapacityGB 30 `
                -Datastore $Datastore `
                -StorageFormat Thin `
                -Persistence Persistent `
                -ErrorAction Stop `
                -Confirm:$false | Out-Null

            Start-Sleep -Seconds 1
        }

        Write-Step 6 $TotalSteps $VMName "Validating disks"

        $vm = Get-VM -Name $VMName -ErrorAction Stop
        $diskCount = (Get-HardDisk -VM $vm).Count

        if ($diskCount -ne 5) {
            throw "Expected 5 disks total. Found $diskCount."
        }

        Write-Step 7 $TotalSteps $VMName "Validating network adapters"

        $nics = Get-NetworkAdapter -VM $vm
        $nicCount = $nics.Count

        if ($nicCount -ne 2) {
            throw "Expected 2 network adapters. Found $nicCount."
        }

        $nics | ForEach-Object {
            Write-Host "[$VMName] $($_.Name) -> $($_.NetworkName) / MAC $($_.MacAddress)" -ForegroundColor Gray
        }

        if (($nics | Where-Object { $_.NetworkName -ne $PortGroup }).Count -gt 0) {
            throw "One or more NICs are not attached to $PortGroup."
        }

        Write-Step 8 $TotalSteps $VMName "Creating CD/DVD drive if missing and mounting Kickstart ESXi ISO"

        $vm = Get-VM -Name $VMName -ErrorAction Stop
        $cd = Get-CDDrive -VM $vm -ErrorAction SilentlyContinue

        if ($null -eq $cd) {
            New-CDDrive `
                -VM $vm `
                -IsoPath $ISOPath `
                -StartConnected:$true `
                -Confirm:$false `
                -ErrorAction Stop | Out-Null
        }
        else {
            Set-CDDrive `
                -CD $cd `
                -IsoPath $ISOPath `
                -StartConnected:$true `
                -Confirm:$false `
                -ErrorAction Stop | Out-Null
        }

        Write-Step 9 $TotalSteps $VMName "Configuring nested virtualization and VMX parameters"

        $vm = Get-VM -Name $VMName -ErrorAction Stop
        $vmView = Get-View $vm.Id

        $spec = New-Object VMware.Vim.VirtualMachineConfigSpec
        $spec.NestedHVEnabled = $true

        $spec.ExtraConfig = @(
            (New-Object VMware.Vim.OptionValue -Property @{
                Key   = "monitor_control.enable_fullcpuid"
                Value = "TRUE"
            }),
            (New-Object VMware.Vim.OptionValue -Property @{
                Key   = "featMask.vm.cpuid.pdpe1gb"
                Value = "Val:1"
            })
        )

        $vmView.ReconfigVM_Task($spec) | Out-Null

        Start-Sleep -Seconds 5

        Write-Step 10 $TotalSteps $VMName "Powering on VM"

        $vm = Get-VM -Name $VMName -ErrorAction Stop

        if ($vm.PowerState -ne "PoweredOn") {
            Start-VM `
                -VM $vm `
                -Confirm:$false `
                -ErrorAction Stop | Out-Null
        }

        Start-Sleep -Seconds 3

        $vm = Get-VM -Name $VMName -ErrorAction Stop

        if ($vm.PowerState -ne "PoweredOn") {
            throw "VM did not power on. Current state: $($vm.PowerState)"
        }

        Write-Step 11 $TotalSteps $VMName "Deployment complete"

        Write-Progress -Activity "Deploying $VMName" -Completed

        Write-Host ""
        Write-Host "SUCCESS: $VMName created and powered on." -ForegroundColor Green
        Write-Host "Kickstart ISO mounted: $ISOPath" -ForegroundColor Yellow
        Write-Host "Expected MAC for Kickstart: $($NestedHost.Mac1)" -ForegroundColor Yellow
    }
    catch {
        Write-Progress -Activity "Deploying $VMName" -Completed

        Write-Host ""
        Write-Host "FAILED: $VMName" -ForegroundColor Red
        Write-Host $_.Exception.Message -ForegroundColor Red

        continue
    }
}

Disconnect-VIServer `
    -Server $ESXiHost `
    -Confirm:$false

Write-Host ""
Write-Host "Deployment script finished." -ForegroundColor Green