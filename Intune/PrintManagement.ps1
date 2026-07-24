<#
====================================================================================
Print Server Printer Mapping Script - Microsoft Intune
Version: 1.0

Created By: Michael Palmieri
Last Updated: June 26, 2026

DESCRIPTION
-----------
Maps shared printers from a Windows Print Server using UNC paths for devices
managed by Microsoft Intune.

Example:
\\PRINT01\HP-Lobby

USAGE
-----
1. Replace the printer paths in the $Printers array with your organization's
   shared printer paths.
2. Verify the print server is reachable from client devices.
3. Ensure the required printer drivers are available on client devices or that
   your Point and Print policy allows installation.
4. Upload this script to Microsoft Intune:
      Devices
      -> Scripts and Remediations
      -> Platform Scripts
      -> Add
5. Recommended Intune Settings:
      • Run this script using the logged on credentials: Yes
      • Enforce script signature check: No
      • Run script in 64-bit PowerShell: Yes
6. Assign the script to the appropriate Microsoft Entra ID device or user group.
7. Monitor deployment status within the Intune Admin Center.

DISCLAIMER
----------
THIS SCRIPT IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE, AND NON-INFRINGEMENT.

USE THIS SCRIPT AT YOUR OWN RISK.

Always test this script in a non-production or pilot environment before
deploying it broadly. The author assumes no responsibility for any direct,
indirect, incidental, or consequential damages, including but not limited to
printer deployment failures, driver issues, network interruptions,
misconfiguration, service disruption, or data loss resulting from the use of
this script.

By using this script, you acknowledge that you are solely responsible for
verifying its suitability for your environment.

CHANGE LOG
----------
Version 1.0
- Initial release
- Supports mapping multiple shared printers from a Windows Print Server
- Optional default printer assignment
- Designed for Microsoft Intune Platform Scripts
- Prevents duplicate printer mappings
====================================================================================
#>

# -----------------------------
# Printer Configuration
# -----------------------------

$Printers = @(
    "\\PRINT01\HP-Lobby",
    "\\PRINT01\Warehouse-Printer"
)

# Optional default printer
$DefaultPrinter = "\\PRINT01\HP-Lobby"

# -----------------------------
# Map Printers
# -----------------------------

foreach ($Printer in $Printers) {

    Write-Host "Processing printer: $Printer"

    $ExistingPrinter = Get-Printer -ErrorAction SilentlyContinue | Where-Object {
        $_.Name -eq $Printer -or $_.ShareName -eq ($Printer.Split('\')[-1])
    }

    if (-not $ExistingPrinter) {
        try {
            Write-Host "Mapping printer: $Printer"
            Add-Printer -ConnectionName $Printer -ErrorAction Stop
            Write-Host "Successfully mapped: $Printer"
        }
        catch {
            Write-Host "Failed to map printer: $Printer"
            Write-Host $_.Exception.Message
            exit 1
        }
    }
    else {
        Write-Host "Printer already mapped: $Printer"
    }

    Write-Host ""
}

# -----------------------------
# Set Default Printer
# -----------------------------

if ($DefaultPrinter) {
    try {
        Write-Host "Setting default printer: $DefaultPrinter"

        $PrinterObject = Get-Printer -ErrorAction SilentlyContinue | Where-Object {
            $_.Name -eq $DefaultPrinter -or $_.ShareName -eq ($DefaultPrinter.Split('\')[-1])
        }

        if ($PrinterObject) {
            (New-Object -ComObject WScript.Network).SetDefaultPrinter($DefaultPrinter)
            Write-Host "Default printer set successfully."
        }
        else {
            Write-Host "Default printer was not found after mapping."
        }
    }
    catch {
        Write-Host "Failed to set default printer."
        Write-Host $_.Exception.Message
    }
}

Write-Host "Printer mapping completed."

exit 0