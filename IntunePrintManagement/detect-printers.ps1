<#
.SYNOPSIS
Detects whether the required direct-IP printers are installed and configured
correctly on an Intune-managed Windows device.

.DESCRIPTION
This detection script checks two network printers that are installed directly
by IP address without using a Windows print server.

The script verifies the following for each configured printer:

- The required printer driver is installed.
- The Standard TCP/IP printer port exists.
- The printer port points to the expected IP address.
- The printer queue exists.
- The printer queue uses the expected driver.
- The printer queue uses the expected TCP/IP port.

This script is intended to be used as the Detection Script in a Microsoft Intune
Remediations package.

If any required printer component is missing or configured incorrectly, the
script exits with code 1. Intune then runs the associated remediation script.

If all configured printers are installed correctly, the script exits with code 0.

This script does not install printer drivers, printer ports, or printer queues.
It only detects their current state.

.INTUNE SETTINGS
Run this script using the logged-on credentials: No
Enforce script signature check: No
Run script in 64-bit PowerShell: Yes

Assign the remediation package to a device group.

.NOTES
Created By: Michael Palmieri
Version: 2.2
Last Updated: July 16, 2026

This script is intended for Microsoft Entra joined and Intune-managed Windows
devices.

The printer driver names must exactly match the names returned by:

    Get-PrinterDriver | Select-Object Name

The printer IP addresses should be static addresses or DHCP reservations.

.DISCLAIMER
THIS SCRIPT IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO WARRANTIES OF MERCHANTABILITY, FITNESS
FOR A PARTICULAR PURPOSE, AND NON-INFRINGEMENT.

USE THIS SCRIPT AT YOUR OWN RISK.

Always test this script on a pilot group before deploying it broadly.
#>

#Requires -Version 5.1

$ErrorActionPreference = "Stop"

# -----------------------------------------------------------------------------
# Printer configuration
# Replace these values with the actual printer information.
# -----------------------------------------------------------------------------

$ExpectedPrinters = @(
    @{
        Name       = "Xerox 7830"
        IPAddress  = "192.168.1.202"
        PortName   = "IP_192.168.1.202"
        DriverName = "Xerox Global Print Drive PCL 6"
    },
    @{
        Name       = "Xerox 7835"
        IPAddress  = "192.168.1.28"
        PortName   = "IP_192.168.1.28"
        DriverName = "Xerox Global Print Drive PCL 6"
    }
)

# -----------------------------------------------------------------------------
# Detection
# -----------------------------------------------------------------------------

$Problems = [System.Collections.Generic.List[string]]::new()

try {
    Import-Module PrintManagement -ErrorAction Stop
}
catch {
    Write-Output "Unable to load the PrintManagement module: $($_.Exception.Message)"
    exit 1
}

foreach ($Expected in $ExpectedPrinters) {
    $PrinterName = $Expected.Name
    $IPAddress   = $Expected.IPAddress
    $PortName    = $Expected.PortName
    $DriverName  = $Expected.DriverName

    # Verify the printer driver.
    $Driver = Get-PrinterDriver `
        -Name $DriverName `
        -ErrorAction SilentlyContinue

    if (-not $Driver) {
        $Problems.Add(
            "Missing printer driver '$DriverName' required by '$PrinterName'."
        )

        continue
    }

    # Verify the TCP/IP printer port.
    $Port = Get-PrinterPort `
        -Name $PortName `
        -ErrorAction SilentlyContinue

    if (-not $Port) {
        $Problems.Add(
            "Missing printer port '$PortName' for '$PrinterName'."
        )
    }
    elseif (
        $Port.PrinterHostAddress -and
        $Port.PrinterHostAddress -ne $IPAddress
    ) {
        $Problems.Add(
            "Printer port '$PortName' points to '$($Port.PrinterHostAddress)' instead of '$IPAddress'."
        )
    }

    # Verify the printer queue.
    $Printer = Get-Printer `
        -Name $PrinterName `
        -ErrorAction SilentlyContinue

    if (-not $Printer) {
        $Problems.Add(
            "Missing printer queue '$PrinterName'."
        )

        continue
    }

    if ($Printer.PortName -ne $PortName) {
        $Problems.Add(
            "Printer '$PrinterName' uses port '$($Printer.PortName)' instead of '$PortName'."
        )
    }

    if ($Printer.DriverName -ne $DriverName) {
        $Problems.Add(
            "Printer '$PrinterName' uses driver '$($Printer.DriverName)' instead of '$DriverName'."
        )
    }
}

# -----------------------------------------------------------------------------
# Detection result
# -----------------------------------------------------------------------------

if ($Problems.Count -gt 0) {
    Write-Output "Printer remediation is required."
    Write-Output ($Problems -join " ")

    exit 1
}

Write-Output "All configured printers are installed and configured correctly."

exit 0