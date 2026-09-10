<#
.SYNOPSIS
    Removes a specified Active Directory user from the local Administrators
    group on a remote Windows workstation.

.DESCRIPTION
    This script prompts the administrator for:

        - Remote computer name
        - Active Directory username

    The script then connects to the remote computer using PowerShell Remoting,
    checks the local Administrators group for the specified user, displays the
    matching account, and prompts for confirmation before removing the user.

    After removal, the script performs a verification check to confirm that
    the account is no longer a direct member of the local Administrators group.

    IMPORTANT:
    This script removes only DIRECT membership from the local Administrators
    group.

    If the user receives administrator rights because they belong to an
    Active Directory group that is itself a member of the local Administrators
    group, removing the individual account will NOT remove those inherited
    administrator rights.

.AUTHOR
    Michael Palmieri

.DISCLAIMER
    USE AT YOUR OWN RISK.

    This script is provided "AS IS" without warranty of any kind, either
    expressed or implied.

    The author assumes no responsibility for damage, loss of access,
    configuration changes, service interruption, or any other unintended
    consequence resulting from the use or misuse of this script.

    Review and test this script before using it in a production environment.

.REQUIREMENTS
    - Windows PowerShell 5.1 or later
    - PowerShell Remoting enabled on the remote workstation
    - Administrative permissions on the remote workstation
    - Network/firewall access to WinRM

.NOTES
    Author: Michael Palmieri

    USE AT YOUR OWN RISK.
#>


# ============================================================
#                      DISPLAY HEADER
# ============================================================

Clear-Host

Write-Host ""
Write-Host "============================================================" -ForegroundColor Red
Write-Host "      REMOVE USER FROM REMOTE LOCAL ADMINISTRATORS" -ForegroundColor Yellow
Write-Host "============================================================" -ForegroundColor Red
Write-Host ""
Write-Host "USE AT YOUR OWN RISK." -ForegroundColor Red
Write-Host ""


# ============================================================
#                  PROMPT FOR COMPUTER NAME
# ============================================================

$ComputerName = Read-Host "Enter the remote computer name"

# Remove accidental leading/trailing spaces.
$ComputerName = $ComputerName.Trim()

# Make sure a computer name was entered.
if ([string]::IsNullOrWhiteSpace($ComputerName)) {

    Write-Host ""
    Write-Host "ERROR: A computer name was not entered." -ForegroundColor Red
    exit 1
}


# ============================================================
#                    TEST REMOTE COMPUTER
# ============================================================

Write-Host ""
Write-Host "Testing connection to $ComputerName..." -ForegroundColor Cyan

# Ping is used only as an initial connectivity check.
# Some environments block ICMP. If yours does, you can remove
# this section and rely on Test-WSMan instead.

if (!(Test-Connection `
        -ComputerName $ComputerName `
        -Count 1 `
        -Quiet `
        -ErrorAction SilentlyContinue)) {

    Write-Host ""
    Write-Host "WARNING: $ComputerName did not respond to ping." `
        -ForegroundColor Yellow

    Write-Host "The system may be offline or ICMP may be blocked." `
        -ForegroundColor Yellow
}


# ============================================================
#                    TEST POWERSHELL REMOTING
# ============================================================

Write-Host ""
Write-Host "Testing PowerShell Remoting..." -ForegroundColor Cyan

try {

    Test-WSMan `
        -ComputerName $ComputerName `
        -ErrorAction Stop |
        Out-Null

    Write-Host "PowerShell Remoting is available." -ForegroundColor Green
}
catch {

    Write-Host ""
    Write-Host "ERROR: Unable to establish a PowerShell Remoting connection." `
        -ForegroundColor Red

    Write-Host ""
    Write-Host "Computer: $ComputerName" -ForegroundColor White
    Write-Host "Error: $($_.Exception.Message)" -ForegroundColor Red

    Write-Host ""
    Write-Host "Verify:" -ForegroundColor Yellow
    Write-Host "  - The computer is online"
    Write-Host "  - WinRM / PowerShell Remoting is enabled"
    Write-Host "  - Windows Firewall permits WinRM"
    Write-Host "  - You have administrative rights"

    exit 1
}


# ============================================================
#                  PROMPT FOR AD USERNAME
# ============================================================

Write-Host ""

$UserName = Read-Host "Enter the user's Active Directory username (example: jsmith)"

$UserName = $UserName.Trim()

if ([string]::IsNullOrWhiteSpace($UserName)) {

    Write-Host ""
    Write-Host "ERROR: A username was not entered." -ForegroundColor Red
    exit 1
}


# ============================================================
#                 NORMALIZE USERNAME INPUT
# ============================================================

# Allow the administrator to enter:
#
#     jsmith
#     DOMAIN\jsmith
#     jsmith@domain.com
#
# For matching purposes, extract the SAM-style username.

$SamAccountName = $UserName

# If DOMAIN\username was entered, keep only username.
if ($SamAccountName -like "*\*") {

    $SamAccountName = $SamAccountName.Split("\")[-1]
}

# If username@domain.com was entered, keep only username.
if ($SamAccountName -like "*@*") {

    $SamAccountName = $SamAccountName.Split("@")[0]
}


Write-Host ""
Write-Host "Target Computer : $ComputerName" -ForegroundColor Cyan
Write-Host "Target User     : $SamAccountName" -ForegroundColor Cyan
Write-Host ""


# ============================================================
#          CHECK LOCAL ADMINISTRATORS GROUP MEMBERSHIP
# ============================================================

Write-Host "Checking local Administrators group..." -ForegroundColor Cyan

try {

    $MatchingAdmins = Invoke-Command `
        -ComputerName $ComputerName `
        -ArgumentList $SamAccountName `
        -ScriptBlock {

            param (
                $TargetUser
            )

            # Retrieve all members of the local Administrators group.
            $Admins = Get-LocalGroupMember `
                -Group "Administrators" `
                -ErrorAction Stop

            # Look specifically for USER objects whose account name
            # matches the requested username.
            #
            # Examples:
            #
            # DOMAIN\jsmith
            # COMPUTER\jsmith

            $Admins |
                Where-Object {

                    $_.ObjectClass -eq "User" -and
                    (
                        $_.Name -eq $TargetUser -or
                        $_.Name -like "*\$TargetUser"
                    )
                } |
                Select-Object Name, ObjectClass, PrincipalSource, SID

        } `
        -ErrorAction Stop

}
catch {

    Write-Host ""
    Write-Host "ERROR: Unable to query the Administrators group." `
        -ForegroundColor Red

    Write-Host $_.Exception.Message -ForegroundColor Red

    exit 1
}


# ============================================================
#                    USER NOT FOUND
# ============================================================

if (!$MatchingAdmins) {

    Write-Host ""
    Write-Host "------------------------------------------------------------" `
        -ForegroundColor Yellow

    Write-Host "No direct local Administrator membership was found for:" `
        -ForegroundColor Yellow

    Write-Host ""
    Write-Host "    $SamAccountName" -ForegroundColor White
    Write-Host ""
    Write-Host "Computer: $ComputerName" -ForegroundColor White

    Write-Host ""
    Write-Host "NOTE:" -ForegroundColor Cyan

    Write-Host "The user could still have administrator rights through an" `
        -ForegroundColor Cyan

    Write-Host "Active Directory group that is a member of Administrators." `
        -ForegroundColor Cyan

    Write-Host ""

    exit 0
}


# ============================================================
#                  DISPLAY MATCHING ACCOUNT
# ============================================================

Write-Host ""
Write-Host "Administrator membership found:" -ForegroundColor Green
Write-Host ""

$MatchingAdmins |
    Format-Table `
        Name,
        ObjectClass,
        PrincipalSource,
        SID `
        -AutoSize


# ============================================================
#                    SAFETY CHECK
# ============================================================

# If somehow more than one matching account was returned,
# stop rather than blindly removing multiple accounts.

if (@($MatchingAdmins).Count -gt 1) {

    Write-Host ""
    Write-Host "WARNING: More than one matching account was found." `
        -ForegroundColor Red

    Write-Host "No changes were made." -ForegroundColor Yellow

    exit 1
}


# Store the exact account name returned by Windows.
$ExactAccountName = $MatchingAdmins.Name


# ============================================================
#                    CONFIRM REMOVAL
# ============================================================

Write-Host ""
Write-Host "============================================================" `
    -ForegroundColor Red

Write-Host "WARNING: YOU ARE ABOUT TO CHANGE ADMINISTRATOR MEMBERSHIP" `
    -ForegroundColor Red

Write-Host "============================================================" `
    -ForegroundColor Red

Write-Host ""
Write-Host "Computer : $ComputerName" -ForegroundColor Yellow
Write-Host "Account  : $ExactAccountName" -ForegroundColor Yellow
Write-Host ""

$Confirmation = Read-Host "Type YES to remove this account from local Administrators"

# Require an explicit YES.
if ($Confirmation -ne "YES") {

    Write-Host ""
    Write-Host "Operation cancelled. No changes were made." `
        -ForegroundColor Yellow

    exit 0
}


# ============================================================
#              REMOVE USER FROM ADMINISTRATORS
# ============================================================

Write-Host ""
Write-Host "Removing $ExactAccountName from Administrators..." `
    -ForegroundColor Cyan

try {

    Invoke-Command `
        -ComputerName $ComputerName `
        -ArgumentList $ExactAccountName `
        -ScriptBlock {

            param (
                $AccountName
            )

            # Remove the exact account from the built-in
            # local Administrators group.
            Remove-LocalGroupMember `
                -Group "Administrators" `
                -Member $AccountName `
                -ErrorAction Stop

        } `
        -ErrorAction Stop

}
catch {

    Write-Host ""
    Write-Host "ERROR: The account could not be removed." `
        -ForegroundColor Red

    Write-Host $_.Exception.Message -ForegroundColor Red

    exit 1
}


# ============================================================
#                      VERIFY REMOVAL
# ============================================================

Write-Host ""
Write-Host "Verifying removal..." -ForegroundColor Cyan

try {

    $StillAdmin = Invoke-Command `
        -ComputerName $ComputerName `
        -ArgumentList $ExactAccountName `
        -ScriptBlock {

            param (
                $AccountName
            )

            Get-LocalGroupMember `
                -Group "Administrators" `
                -ErrorAction Stop |
                Where-Object {

                    $_.Name -eq $AccountName
                }

        } `
        -ErrorAction Stop

}
catch {

    Write-Host ""
    Write-Host "WARNING: Removal was attempted, but verification failed." `
        -ForegroundColor Yellow

    Write-Host $_.Exception.Message -ForegroundColor Yellow

    exit 1
}


# ============================================================
#                      FINAL RESULT
# ============================================================

if (!$StillAdmin) {

    Write-Host ""
    Write-Host "============================================================" `
        -ForegroundColor Green

    Write-Host "                    REMOVAL SUCCESSFUL" `
        -ForegroundColor Green

    Write-Host "============================================================" `
        -ForegroundColor Green

    Write-Host ""
    Write-Host "Computer : $ComputerName" -ForegroundColor White
    Write-Host "Removed  : $ExactAccountName" -ForegroundColor White

    Write-Host ""
    Write-Host "The account is no longer a DIRECT member of the" `
        -ForegroundColor Green

    Write-Host "local Administrators group." -ForegroundColor Green

}
else {

    Write-Host ""
    Write-Host "WARNING: The account still appears in Administrators." `
        -ForegroundColor Red

    Write-Host ""
    Write-Host "No further automated action was taken." `
        -ForegroundColor Yellow
}


# ============================================================
#                         END SCRIPT
# ============================================================

Write-Host ""
Write-Host "USE AT YOUR OWN RISK." -ForegroundColor Red
Write-Host ""