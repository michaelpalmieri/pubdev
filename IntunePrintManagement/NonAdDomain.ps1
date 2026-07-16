<#
====================================================================================
TCP/IP Printer Deployment Script - Microsoft Intune
Version: 2.0

Created By: Michael Palmieri
Last Updated: July 16, 2026

DESCRIPTION
-----------
This script installs two network printers directly by IP address. It creates a
Standard TCP/IP printer port for each printer and then creates the printer using
an existing printer driver on the Windows device.

This script does not connect to a Windows Print Server.

USAGE
-----
1. Update the printer configuration in the $Printers section:
   - Name: Friendly name displayed in Windows.
   - IPAddress: Printer's static IP address.
   - DriverName: Exact printer driver name installed on the computer.
   - PortName: Name assigned to the TCP/IP printer port.

2. To view installed printer driver names on a test computer, run:

      Get-PrinterDriver | Select-Object Name

3. Verify that each required printer driver is installed before running this
   script. If the driver is not already installed, deploy the manufacturer
   driver through Intune before deploying this script.

4. Upload the script to Microsoft Intune:

      Devices
      -> Scripts and remediations
      -> Platform scripts
      -> Add
      -> Windows 10 and later

5. Recommended Intune settings:

      Run this script using the logged-on credentials: No
      Enforce script signature check: No
      Run script in 64-bit PowerShell: Yes

6. Assign the script to the appropriate device group.

7. Test the script on a small pilot group before assigning it broadly.

DISCLAIMER
----------
THIS SCRIPT IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO WARRANTIES OF MERCHANTABILITY, FITNESS
FOR A PARTICULAR PURPOSE, AND NON-INFRINGEMENT.

USE THIS SCRIPT AT YOUR OWN RISK.

Always test this script in a non-production or pilot environment before
deploying it broadly. The author assumes no responsibility for printer
deployment failures, driver problems, network interruptions, configuration
changes, service disruption, data loss, or other issues resulting from the use
of this script.

By using this script, you acknowledge that you are responsible for validating
its suitability, security, and operation within your environment.

CHANGE LOG
----------
Version 2.0
- Changed deployment from print-server connections to direct IP printing.
- Supports two TCP/IP printers.
- Creates printer ports when they do not exist.
- Verifies that required printer drivers are installed.
- Prevents duplicate printer and port creation.
- Adds Intune-compatible logging and exit codes.
====================================================================================
#>

#Requires -Version 5.1

$ErrorActionPreference = "Stop"

# -----------------------------------------------------------------------------
# Printer configuration
# Replace these sample values with your printer information.
# -----------------------------------------------------------------------------

$Printers = @(
    @{
        Name       = "Front Office Printer"
        IPAddress  = "192.168.1.50"
        PortName   = "IP_192.168.1.50"
        DriverName = "HP Universal Printing PCL 6"
    },
    @{
        Name       = "Warehouse Printer"
        IPAddress  = "192.168.1.51"
        PortName   = "IP_192.168.1.51"
        DriverName = "HP Universal Printing PCL 6"
    }
)

# Standard RAW printing port used by most network printers.
$PrinterPortNumber = 9100

# -----------------------------------------------------------------------------
# Logging
# -----------------------------------------------------------------------------

$LogDirectory = "C:\ProgramData\IntunePrinterDeployment"
$LogFile = Join-Path $LogDirectory "PrinterDeployment.log"

if (-not (Test-Path -Path $LogDirectory)) {
    New-Item -Path $LogDirectory -ItemType Directory -Force | Out-Null
}

function Write-Log {
    param(
        [Parameter(Mandatory)]
        [string]$Message,

        [ValidateSet("INFO", "WARNING", "ERROR")]
        [string]$Level = "INFO"
    )

    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $LogEntry = "[$Timestamp] [$Level] $Message"

    Write-Output $LogEntry
    Add-Content -Path $LogFile -Value $LogEntry
}

# -----------------------------------------------------------------------------
# Validate Print Spooler
# -----------------------------------------------------------------------------

try {
    $Spooler = Get-Service -Name "Spooler"

    if ($Spooler.Status -ne "Running") {
        Write-Log -Message "The Print Spooler service is not running. Attempting to start it." -Level "WARNING"
        Start-Service -Name "Spooler"
        Write-Log -Message "The Print Spooler service was started successfully."
    }
}
catch {
    Write-Log -Message "Unable to verify or start the Print Spooler service. $($_.Exception.Message)" -Level "ERROR"
    exit 1
}

# -----------------------------------------------------------------------------
# Install printers
# -----------------------------------------------------------------------------

$DeploymentFailed = $false

foreach ($Printer in $Printers) {
    $PrinterName = $Printer.Name
    $IPAddress   = $Printer.IPAddress
    $PortName    = $Printer.PortName
    $DriverName  = $Printer.DriverName

    Write-Log -Message "Processing printer '$PrinterName' at IP address $IPAddress."

    try {
        # Validate required values.
        if ([string]::IsNullOrWhiteSpace($PrinterName) -or
            [string]::IsNullOrWhiteSpace($IPAddress) -or
            [string]::IsNullOrWhiteSpace($PortName) -or
            [string]::IsNullOrWhiteSpace($DriverName)) {

            throw "One or more required printer configuration values are empty."
        }

        # Validate the IP address format.
        $ParsedIPAddress = $null

        if (-not [System.Net.IPAddress]::TryParse(
                $IPAddress,
                [ref]$ParsedIPAddress
            )) {
            throw "'$IPAddress' is not a valid IP address."
        }

        # Verify that the required driver is installed.
        $InstalledDriver = Get-PrinterDriver -Name $DriverName -ErrorAction SilentlyContinue

        if (-not $InstalledDriver) {
            throw "The printer driver '$DriverName' is not installed. Deploy the driver before deploying this printer."
        }

        Write-Log -Message "Printer driver '$DriverName' is installed."

        # Check whether the port already exists.
        $ExistingPort = Get-PrinterPort -Name $PortName -ErrorAction SilentlyContinue

        if (-not $ExistingPort) {
            Write-Log -Message "Creating TCP/IP port '$PortName' for $IPAddress."

            Add-PrinterPort `
                -Name $PortName `
                -PrinterHostAddress $IPAddress `
                -PortNumber $PrinterPortNumber

            Write-Log -Message "TCP/IP port '$PortName' was created successfully."
        }
        elseif ($ExistingPort.PrinterHostAddress -and
                $ExistingPort.PrinterHostAddress -ne $IPAddress) {

            throw "Port '$PortName' already exists but points to '$($ExistingPort.PrinterHostAddress)' instead of '$IPAddress'."
        }
        else {
            Write-Log -Message "TCP/IP port '$PortName' already exists."
        }

        # Check whether the printer already exists.
        $ExistingPrinter = Get-Printer -Name $PrinterName -ErrorAction SilentlyContinue

        if (-not $ExistingPrinter) {
            Write-Log -Message "Installing printer '$PrinterName'."

            Add-Printer `
                -Name $PrinterName `
                -DriverName $DriverName `
                -PortName $PortName

            Write-Log -Message "Printer '$PrinterName' was installed successfully."
        }
        else {
            # Correct the existing printer if its port or driver has changed.
            if ($ExistingPrinter.PortName -ne $PortName -or
                $ExistingPrinter.DriverName -ne $DriverName) {

                Write-Log -Message "Printer '$PrinterName' exists with different settings. Updating it." -Level "WARNING"

                Set-Printer `
                    -Name $PrinterName `
                    -DriverName $DriverName `
                    -PortName $PortName

                Write-Log -Message "Printer '$PrinterName' was updated successfully."
            }
            else {
                Write-Log -Message "Printer '$PrinterName' is already installed with the correct settings."
            }
        }
    }
    catch {
        $DeploymentFailed = $true
        Write-Log -Message "Failed to deploy printer '$PrinterName'. $($_.Exception.Message)" -Level "ERROR"
    }
}

# -----------------------------------------------------------------------------
# Deployment result
# -----------------------------------------------------------------------------

if ($DeploymentFailed) {
    Write-Log -Message "Printer deployment completed with one or more errors." -Level "ERROR"
    exit 1
}

Write-Log -Message "Both printers were deployed successfully."
exit 0