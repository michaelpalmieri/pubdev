<#
.SYNOPSIS
    Deploys Nested ESXi VMs with fixed MAC addresses for Kickstart.
    
    Disclaimer:
        This software is provided AS-IS with no warranty expressed or implied.
        Use at your own risk.
#>

$ESXiHost = Read-Host "Enter ESXi Host IP or FQDN"
$ESXiUser = Read-Host "Enter ESXi Username"

$ESXiCredential = Get-Credential `
    -UserName $ESXiUser `
    -Message "Enter password for $ESXiUser@$ESXiHost"

$Datastore = "ESX02LocalNVMeDisk1"
$PortGroup = "ALL-VLAN-PG"
$ISOPath   = "[LocalStorage4ESX02]  /VCF/ESXi-9.0.1-Kickstart.iso"

$NestedHosts = @(
    @{ VMName = "Nested-ESX01"; Mac1 = "00:50:56:11:22:60"; Mac2 = "00:50:56:11:23:60" },
    @{ VMName = "Nested-ESX02"; Mac1 = "00:50:56:11:22:61"; Mac2 = "00:50:56:11:23:61" },
    @{ VMName = "Nested-ESX03"; Mac1 = "00:50:56:11:22:62"; Mac2 = "00:50:56:11:23:62" },
    @{ VMName = "Nested-ESX04"; Mac1 = "00:50:56:11:22:63"; Mac2 = "00:50:56:11:23:63" }
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