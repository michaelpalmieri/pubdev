<#
.SYNOPSIS
Installs and repairs direct-IP printers on Intune-managed Windows devices.

.DESCRIPTION
This remediation script installs two network printers directly by IP address.
It does not connect to or use a Windows print server.

For each configured printer, the script performs the following actions:

- Verifies that the Windows Print Spooler service is enabled and running.
- Loads the Windows PrintManagement PowerShell module.
- Verifies that the required printer driver is installed.
- Waits and retries if the printer driver is not immediately available.
- Creates a Standard TCP/IP printer port when the port does not exist.
- Verifies that an existing port points to the correct IP address.
- Creates the printer queue when it does not exist.
- Updates an existing printer if its driver or port is incorrect.
- Verifies the completed printer configuration.
- Writes deployment results to a log file.
- Returns an Intune-compatible exit code.

The script is intended to be used as the Remediation Script in a Microsoft
Intune Remediations package.

This script does not install the printer driver files. The required printer
driver must already be installed and registered with Windows before this script
can create the printer queue.

The printer driver may be deployed separately through Intune, included in the
Windows image, or installed using a manufacturer-provided installer.

.INTUNE SETTINGS
Run this script using the logged-on credentials: No
Enforce script signature check: No
Run script in 64-bit PowerShell: Yes

Assign the remediation package to a device group.

The script runs in the NT AUTHORITY\SYSTEM context.

.LOGGING
The script writes its log to:

    C:\ProgramData\IntunePrinterDeployment\PrinterDeployment.log

Use the following command to review recent entries:

    Get-Content `
        "C:\ProgramData\IntunePrinterDeployment\PrinterDeployment.log" `
        -Tail 100

.NOTES
Created By: Michael Palmieri
Version: 2.3
Last Updated: July 16, 2026

This script is intended for Microsoft Entra joined and Intune-managed Windows
devices.

The printer driver names must exactly match the names returned by:

    Get-PrinterDriver | Select-Object Name

The printer IP addresses should be static addresses or DHCP reservations.

The configured printers use RAW TCP/IP printing on port 9100.

.DISCLAIMER
THIS SCRIPT IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO WARRANTIES OF MERCHANTABILITY, FITNESS
FOR A PARTICULAR PURPOSE, AND NON-INFRINGEMENT.

USE THIS SCRIPT AT YOUR OWN RISK.

Always test this script in a non-production environment or with a pilot device
group before deploying it broadly.

The author assumes no responsibility for printer deployment failures, driver
problems, network interruptions, configuration changes, service disruption,
data loss, or other issues resulting from the use of this script.
#>

#Requires -Version 5.1

$ErrorActionPreference = "Stop"

# -----------------------------------------------------------------------------
# Printer configuration
# Replace these values with the actual printer information.
# -----------------------------------------------------------------------------

$Printers = @(
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

# Standard RAW printing port used by most network printers.
$PrinterPortNumber = 9100

# Retry settings for printer driver discovery.
$DriverRetryCount = 12
$DriverRetryDelaySeconds = 10

# -----------------------------------------------------------------------------
# Logging
# -----------------------------------------------------------------------------

$LogDirectory = Join-Path `
    -Path $env:ProgramData `
    -ChildPath "IntunePrinterDeployment"

$LogFile = Join-Path `
    -Path $LogDirectory `
    -ChildPath "PrinterDeployment.log"

if (-not (Test-Path -Path $LogDirectory)) {
    New-Item `
        -Path $LogDirectory `
        -ItemType Directory `
        -Force |
        Out-Null
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

    try {
        Add-Content `
            -Path $LogFile `
            -Value $LogEntry `
            -Encoding UTF8
    }
    catch {
        Write-Output "Unable to write to the deployment log: $($_.Exception.Message)"
    }
}

function Get-RequiredPrinterDriver {
    param(
        [Parameter(Mandatory)]
        [string]$Name
    )

    for (
        $Attempt = 1
        $Attempt -le $DriverRetryCount
        $Attempt++
    ) {
        $Driver = Get-PrinterDriver `
            -Name $Name `
            -ErrorAction SilentlyContinue

        if ($Driver) {
            return $Driver
        }

        Write-Log `
            -Message "Printer driver '$Name' was not found. Attempt $Attempt of $DriverRetryCount." `
            -Level "WARNING"

        Start-Sleep -Seconds $DriverRetryDelaySeconds
    }

    return $null
}

# -----------------------------------------------------------------------------
# Initial diagnostics
# -----------------------------------------------------------------------------

Write-Log -Message "Starting direct-IP printer deployment."
Write-Log -Message "Script version: 2.3"
Write-Log -Message "Running as: $([Security.Principal.WindowsIdentity]::GetCurrent().Name)"
Write-Log -Message "Computer name: $env:COMPUTERNAME"
Write-Log -Message "64-bit PowerShell process: $([Environment]::Is64BitProcess)"
Write-Log -Message "PowerShell version: $($PSVersionTable.PSVersion)"

# -----------------------------------------------------------------------------
# Load PrintManagement module
# -----------------------------------------------------------------------------

try {
    Import-Module `
        -Name PrintManagement `
        -ErrorAction Stop

    Write-Log -Message "The PrintManagement module loaded successfully."

    Write-Log -Message "Available printer drivers:"
    Get-PrinterDriver | ForEach-Object {
        Write-Log -Message $_.Name
    }
}
catch {
    Write-Log `
        -Message "Unable to load the PrintManagement module. $($_.Exception.Message)" `
        -Level "ERROR"

    exit 1
}

# -----------------------------------------------------------------------------
# Validate Print Spooler
# -----------------------------------------------------------------------------

try {
    $Spooler = Get-Service `
        -Name "Spooler" `
        -ErrorAction Stop

    if ($Spooler.StartType -eq "Disabled") {
        Write-Log `
            -Message "The Print Spooler is disabled. Changing its startup type to Automatic." `
            -Level "WARNING"

        Set-Service `
            -Name "Spooler" `
            -StartupType Automatic `
            -ErrorAction Stop
    }

    if ($Spooler.Status -ne "Running") {
        Write-Log `
            -Message "The Print Spooler is not running. Attempting to start it." `
            -Level "WARNING"

        Start-Service `
            -Name "Spooler" `
            -ErrorAction Stop
    }

    $Spooler = Get-Service `
        -Name "Spooler" `
        -ErrorAction Stop

    $Spooler.WaitForStatus(
        [System.ServiceProcess.ServiceControllerStatus]::Running,
        [TimeSpan]::FromSeconds(30)
    )

    Write-Log -Message "The Print Spooler service is running."
}
catch {
    Write-Log `
        -Message "Unable to verify or start the Print Spooler service. $($_.Exception.Message)" `
        -Level "ERROR"

    exit 1
}

# -----------------------------------------------------------------------------
# Install or repair printers
# -----------------------------------------------------------------------------

$DeploymentFailed = $false

foreach ($PrinterConfiguration in $Printers) {
    $PrinterName = $PrinterConfiguration.Name
    $IPAddress   = $PrinterConfiguration.IPAddress
    $PortName    = $PrinterConfiguration.PortName
    $DriverName  = $PrinterConfiguration.DriverName

    Write-Log `
        -Message "Processing printer '$PrinterName' at IP address '$IPAddress'."

    try {
        # Validate required settings.
        if (
            [string]::IsNullOrWhiteSpace($PrinterName) -or
            [string]::IsNullOrWhiteSpace($IPAddress) -or
            [string]::IsNullOrWhiteSpace($PortName) -or
            [string]::IsNullOrWhiteSpace($DriverName)
        ) {
            throw "One or more required printer configuration values are empty."
        }

        # Validate the IP address.
        $ParsedIPAddress = $null

        if (
            -not [System.Net.IPAddress]::TryParse(
                $IPAddress,
                [ref]$ParsedIPAddress
            )
        ) {
            throw "'$IPAddress' is not a valid IP address."
        }

        # Verify that the required printer driver exists.
        $InstalledDriver = Get-RequiredPrinterDriver `
            -Name $DriverName

        if (-not $InstalledDriver) {
            $AvailableDrivers = Get-PrinterDriver `
                -ErrorAction SilentlyContinue |
                Select-Object -ExpandProperty Name

            Write-Log `
                -Message "Installed printer drivers: $($AvailableDrivers -join ' | ')" `
                -Level "ERROR"

            throw "The printer driver '$DriverName' is not installed or the configured name does not match the registered Windows driver name."
        }

        Write-Log `
            -Message "Printer driver '$DriverName' is installed."

        # ---------------------------------------------------------------------
        # Create or validate the TCP/IP printer port
        # ---------------------------------------------------------------------

        $ExistingPort = Get-PrinterPort `
            -Name $PortName `
            -ErrorAction SilentlyContinue

        if (-not $ExistingPort) {
            Write-Log `
                -Message "Creating TCP/IP port '$PortName' for '$IPAddress'."

            Add-PrinterPort `
                -Name $PortName `
                -PrinterHostAddress $IPAddress `
                -PortNumber $PrinterPortNumber `
                -ErrorAction Stop

            $ExistingPort = Get-PrinterPort `
                -Name $PortName `
                -ErrorAction Stop

            Write-Log `
                -Message "TCP/IP port '$PortName' was created successfully."
        }
        elseif (
            $ExistingPort.PrinterHostAddress -and
            $ExistingPort.PrinterHostAddress -ne $IPAddress
        ) {
            throw "Port '$PortName' already exists but points to '$($ExistingPort.PrinterHostAddress)' instead of '$IPAddress'."
        }
        else {
            Write-Log `
                -Message "TCP/IP port '$PortName' already exists and is configured correctly."
        }

        # ---------------------------------------------------------------------
        # Create or repair the printer queue
        # ---------------------------------------------------------------------

        $ExistingPrinter = Get-Printer `
            -Name $PrinterName `
            -ErrorAction SilentlyContinue

        if (-not $ExistingPrinter) {
            Write-Log `
                -Message "Installing printer '$PrinterName'."

            Add-Printer `
                -Name $PrinterName `
                -DriverName $DriverName `
                -PortName $PortName `
                -ErrorAction Stop

            Write-Log `
                -Message "Printer '$PrinterName' was installed successfully."
        }
        elseif (
            $ExistingPrinter.PortName -ne $PortName -or
            $ExistingPrinter.DriverName -ne $DriverName
        ) {
            Write-Log `
                -Message "Printer '$PrinterName' exists with incorrect settings. Updating it." `
                -Level "WARNING"

            Set-Printer `
                -Name $PrinterName `
                -DriverName $DriverName `
                -PortName $PortName `
                -ErrorAction Stop

            Write-Log `
                -Message "Printer '$PrinterName' was updated successfully."
        }
        else {
            Write-Log `
                -Message "Printer '$PrinterName' is already installed and configured correctly."
        }

        # ---------------------------------------------------------------------
        # Verify the final printer configuration
        # ---------------------------------------------------------------------

        $VerifiedPrinter = Get-Printer `
            -Name $PrinterName `
            -ErrorAction Stop

        if ($VerifiedPrinter.PortName -ne $PortName) {
            throw "Printer verification failed. Expected port '$PortName', but found '$($VerifiedPrinter.PortName)'."
        }

        if ($VerifiedPrinter.DriverName -ne $DriverName) {
            throw "Printer verification failed. Expected driver '$DriverName', but found '$($VerifiedPrinter.DriverName)'."
        }

        Write-Log `
            -Message "Printer '$PrinterName' was verified successfully."
    }
    catch {
        $DeploymentFailed = $true

        Write-Log `
            -Message "Failed to deploy printer '$PrinterName'. $($_.Exception.Message)" `
            -Level "ERROR"

        Write-Log `
            -Message "Script line number: $($_.InvocationInfo.ScriptLineNumber)" `
            -Level "ERROR"

        Write-Log `
            -Message "Failed command: $($_.InvocationInfo.Line)" `
            -Level "ERROR"

        Write-Log `
            -Message "Full error details: $($_ | Out-String)" `
            -Level "ERROR"
    }
}

# -----------------------------------------------------------------------------
# Deployment result
# -----------------------------------------------------------------------------

if ($DeploymentFailed) {
    Write-Log `
        -Message "Direct-IP printer deployment completed with one or more errors." `
        -Level "ERROR"

    exit 1
}

Write-Log `
    -Message "All configured direct-IP printers were deployed successfully."

exit 0