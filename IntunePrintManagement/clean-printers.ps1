<#
.SYNOPSIS
Removes Windows Print Server printer connections.

.DESCRIPTION
This script removes shared printer connections that were installed from one or
more Windows Print Servers.

Examples:

    \\PRINTSERVER\Xerox 7830
    \\PRINTSERVER\Xerox 7835

The script DOES NOT remove:

• Direct TCP/IP printers
• Local printers
• USB printers
• Microsoft PDF
• XPS
• OneNote

This script is intended for Microsoft Intune Platform Scripts.

.INTUNE SETTINGS

Run this script using the logged-on credentials : Yes

Run script in 64-bit PowerShell : Yes

Enforce signature check : No

Assign to a USER group.

.NOTES

Created By: Michael Palmieri
Version: 1.0
Last Updated: July 16, 2026

#>

#Requires -Version 5.1

$ErrorActionPreference = "Continue"

# -------------------------------------------------------------------
# Configuration
# -------------------------------------------------------------------

# Add every old print server here.

$PrintServers = @(
    "PRINTSERVER"
)

# -------------------------------------------------------------------
# Logging
# -------------------------------------------------------------------

$LogFolder = "$env:LOCALAPPDATA\PrinterCleanup"

if (!(Test-Path $LogFolder))
{
    New-Item `
        -ItemType Directory `
        -Path $LogFolder `
        -Force | Out-Null
}

$LogFile = Join-Path $LogFolder "PrinterCleanup.log"

function Write-Log
{
    param([string]$Message)

    $Time = Get-Date -Format "yyyy-MM-dd HH:mm:ss"

    "$Time  $Message" |
        Out-File `
            -FilePath $LogFile `
            -Append `
            -Encoding UTF8
}

Write-Log "========================================"
Write-Log "Printer cleanup started."
Write-Log "Running as $([Security.Principal.WindowsIdentity]::GetCurrent().Name)"

# -------------------------------------------------------------------
# Remove network printers
# -------------------------------------------------------------------

$Printers = Get-Printer

foreach ($Printer in $Printers)
{
    foreach ($Server in $PrintServers)
    {
        if (
            $Printer.Type -eq "Connection" -or
            $Printer.Name -like "\\$Server\*" -or
            $Printer.ComputerName -eq "\\$Server" -or
            $Printer.ComputerName -eq $Server
        )
        {
            try
            {
                Write-Log "Removing $($Printer.Name)"

                Remove-Printer `
                    -Name $Printer.Name `
                    -Confirm:$false `
                    -ErrorAction Stop

                Write-Log "Successfully removed $($Printer.Name)"
            }
            catch
            {
                Write-Log "FAILED: $($_.Exception.Message)"
            }
        }
    }
}

Write-Log "Printer cleanup completed."

exit 0