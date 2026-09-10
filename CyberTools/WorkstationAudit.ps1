<#
.SYNOPSIS
    Audits local Administrators group membership across Windows domain workstations.

.DESCRIPTION
    This script queries Active Directory for enabled Windows workstations,
    checks whether each workstation is reachable, and retrieves the members
    of the local Administrators group.

    Results are exported to a CSV report that includes:
        - Computer name
        - Operating system
        - Last logon date
        - Online/offline/error status
        - Administrator account or group name
        - Object type
        - Principal source

    This can be useful for reviewing local administrator access across
    an Active Directory environment.

.AUTHOR
    Michael Palmieri

.DISCLAIMER
    USE AT YOUR OWN RISK.

    This script is provided "AS IS" without warranty of any kind, either
    expressed or implied.

    The author assumes no responsibility for any damage, data loss,
    service interruption, security issue, configuration change, or other
    unintended consequence resulting from the use or misuse of this script.

    Always review and test this script in a non-production environment
    before using it in production.

.REQUIREMENTS
    - Windows PowerShell 5.1 or later
    - ActiveDirectory PowerShell module
    - Appropriate permissions to query Active Directory
    - Appropriate administrative permissions on target workstations
    - PowerShell Remoting enabled and accessible on target workstations

.NOTES
    Author: Michael Palmieri

    IMPORTANT:
    Membership returned by this script may include Active Directory groups.
    It does not recursively expand those groups into individual users.

    USE AT YOUR OWN RISK.
#>


# ============================================================
#                     CONFIGURATION
# ============================================================

# Location where the final CSV report will be saved.
$OutputPath = "C:\Temp\Workstation-LocalAdmins.csv"


# ============================================================
#                LOAD REQUIRED POWERSHELL MODULE
# ============================================================

# Import the Active Directory PowerShell module.
# This module provides Get-ADComputer and other AD cmdlets.
try {

    Import-Module ActiveDirectory -ErrorAction Stop

}
catch {

    Write-Error "Unable to load the ActiveDirectory PowerShell module."
    Write-Error "Install RSAT Active Directory tools before running this script."

    exit 1
}


# ============================================================
#                CREATE OUTPUT DIRECTORY
# ============================================================

# Determine the directory portion of the output path.
$OutputDirectory = Split-Path $OutputPath -Parent

# Create the output directory if it does not already exist.
if (!(Test-Path $OutputDirectory)) {

    Write-Host "Creating output directory: $OutputDirectory" -ForegroundColor Yellow

    New-Item `
        -ItemType Directory `
        -Path $OutputDirectory `
        -Force | Out-Null
}


# ============================================================
#                  DISPLAY DISCLAIMER
# ============================================================

Write-Host ""
Write-Host "============================================================" -ForegroundColor Red
Write-Host "                 USE AT YOUR OWN RISK" -ForegroundColor Red
Write-Host "============================================================" -ForegroundColor Red
Write-Host ""
Write-Host "This script will remotely query domain workstations." -ForegroundColor Yellow
Write-Host "Author: Michael Palmieri" -ForegroundColor Cyan
Write-Host ""


# ============================================================
#            GET WORKSTATIONS FROM ACTIVE DIRECTORY
# ============================================================

Write-Host "Retrieving Windows workstations from Active Directory..." `
    -ForegroundColor Cyan

try {

    # Retrieve enabled Windows computers from Active Directory.
    #
    # The OperatingSystem property is requested so that servers
    # can be excluded later.
    #
    # LastLogonDate is included in the report to help identify
    # potentially stale workstation objects.

    $Computers = Get-ADComputer `
        -Filter 'Enabled -eq $true -and OperatingSystem -like "Windows*"' `
        -Properties OperatingSystem, LastLogonDate |
        Where-Object {

            # Exclude Windows Server operating systems.
            $_.OperatingSystem -notlike "*Server*"

        } |
        Sort-Object Name

}
catch {

    Write-Error "Failed to retrieve computers from Active Directory."
    Write-Error $_.Exception.Message

    exit 1
}


# Display the number of workstations found.
Write-Host "Found $($Computers.Count) Windows workstations." `
    -ForegroundColor Green

Write-Host ""


# ============================================================
#                  AUDIT EACH WORKSTATION
# ============================================================

# Process each workstation returned by Active Directory.
$Results = foreach ($Computer in $Computers) {

    # Store the computer name in a shorter variable.
    $ComputerName = $Computer.Name

    Write-Host "Checking $ComputerName..." -ForegroundColor Yellow


    # --------------------------------------------------------
    # Check whether the workstation responds to ICMP/ping.
    #
    # NOTE:
    # Some environments block ICMP even when the workstation
    # is online. If your environment blocks ping, you may want
    # to remove this check.
    # --------------------------------------------------------

    if (!(Test-Connection `
            -ComputerName $ComputerName `
            -Count 1 `
            -Quiet `
            -ErrorAction SilentlyContinue)) {

        # Record the workstation as offline/unreachable.
        [PSCustomObject]@{

            ComputerName    = $ComputerName
            OperatingSystem = $Computer.OperatingSystem
            LastLogonDate   = $Computer.LastLogonDate
            Status          = "Offline / No Ping Response"
            AdminName       = $null
            ObjectClass     = $null
            PrincipalSource = $null

        }

        # Move to the next workstation.
        continue
    }


    # --------------------------------------------------------
    # Attempt to remotely retrieve the local Administrators
    # group membership.
    # --------------------------------------------------------

    try {

        $Admins = Invoke-Command `
            -ComputerName $ComputerName `
            -ScriptBlock {

                # Get all members of the built-in local
                # Administrators group.
                Get-LocalGroupMember `
                    -Group "Administrators" |
                    Select-Object `
                        Name,
                        ObjectClass,
                        PrincipalSource

            } `
            -ErrorAction Stop


        # ----------------------------------------------------
        # Process administrator accounts/groups returned from
        # the remote workstation.
        # ----------------------------------------------------

        if ($Admins) {

            foreach ($Admin in $Admins) {

                # Generate one report row for every member of
                # the local Administrators group.
                [PSCustomObject]@{

                    ComputerName    = $ComputerName
                    OperatingSystem = $Computer.OperatingSystem
                    LastLogonDate   = $Computer.LastLogonDate
                    Status          = "Online"
                    AdminName       = $Admin.Name
                    ObjectClass     = $Admin.ObjectClass
                    PrincipalSource = $Admin.PrincipalSource

                }
            }
        }
        else {

            # This condition is unusual but provides a report
            # entry if no members are returned.
            [PSCustomObject]@{

                ComputerName    = $ComputerName
                OperatingSystem = $Computer.OperatingSystem
                LastLogonDate   = $Computer.LastLogonDate
                Status          = "Online - No Members Returned"
                AdminName       = $null
                ObjectClass     = $null
                PrincipalSource = $null

            }
        }
    }
    catch {

        # ----------------------------------------------------
        # If PowerShell Remoting fails, capture the error
        # instead of stopping the entire audit.
        # ----------------------------------------------------

        [PSCustomObject]@{

            ComputerName    = $ComputerName
            OperatingSystem = $Computer.OperatingSystem
            LastLogonDate   = $Computer.LastLogonDate
            Status          = "Error: $($_.Exception.Message)"
            AdminName       = $null
            ObjectClass     = $null
            PrincipalSource = $null

        }
    }
}


# ============================================================
#                    EXPORT THE REPORT
# ============================================================

Write-Host ""
Write-Host "Exporting audit results..." -ForegroundColor Cyan

try {

    # Export all collected results to CSV.
    $Results |
        Export-Csv `
            -Path $OutputPath `
            -NoTypeInformation `
            -Encoding UTF8

}
catch {

    Write-Error "Unable to export the report."
    Write-Error $_.Exception.Message

    exit 1
}


# ============================================================
#                   DISPLAY SUMMARY
# ============================================================

Write-Host ""
Write-Host "============================================================" `
    -ForegroundColor Green

Write-Host "                    AUDIT COMPLETE" `
    -ForegroundColor Green

Write-Host "============================================================" `
    -ForegroundColor Green

Write-Host ""
Write-Host "Report saved to:" -ForegroundColor Cyan
Write-Host $OutputPath -ForegroundColor White
Write-Host ""


# Display administrator memberships in the PowerShell console.
$Results |
    Where-Object { $_.AdminName } |
    Format-Table `
        ComputerName,
        AdminName,
        ObjectClass,
        PrincipalSource `
        -AutoSize


# ============================================================
#                        END OF SCRIPT
# ============================================================

Write-Host ""
Write-Host "Script Author: Michael Palmieri" -ForegroundColor Cyan
Write-Host "USE AT YOUR OWN RISK." -ForegroundColor Red
Write-Host ""