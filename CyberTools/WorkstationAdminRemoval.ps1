<#
.SYNOPSIS
    Removes a specified Active Directory user from the local Administrators
    group on a remote Windows workstation.

.DESCRIPTION
    This script prompts the administrator for:

        - Remote computer name
        - Active Directory username

    The script then:

        1. Tests connectivity to the remote workstation.
        2. Verifies that PowerShell Remoting is available.
        3. Checks whether the specified user is a direct member of the
           local Administrators group.
        4. Displays the matching account.
        5. Requires explicit confirmation before making any change.
        6. Removes the user from the local Administrators group.
        7. Verifies that the account was successfully removed.

    IMPORTANT:
    This script removes only DIRECT user membership from the local
    Administrators group.

    If the user has administrator privileges through an Active Directory
    group that is a member of the local Administrators group, those
    inherited privileges will not be removed.

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

# Set the PowerShell console window title.
$Host.UI.RawUI.WindowTitle = "Remote Local Administrator Management"

Write-Host ""
Write-Host "  Remote Local Administrator Management" -ForegroundColor Cyan
Write-Host "  --------------------------------------" -ForegroundColor DarkGray
Write-Host ""
Write-Host "  Remove an Active Directory user from the local" -ForegroundColor Gray
Write-Host "  Administrators group on a remote workstation." -ForegroundColor Gray
Write-Host ""

# Display a concise safety warning.
Write-Host "  WARNING" -ForegroundColor Yellow
Write-Host "  Use at your own risk. Changes affect local administrator access." `
    -ForegroundColor DarkYellow

Write-Host ""
Write-Host "  ------------------------------------------------------------" `
    -ForegroundColor DarkGray
Write-Host ""


# ============================================================
#                  PROMPT FOR COMPUTER NAME
# ============================================================

Write-Host "  Target Computer" -ForegroundColor Cyan
Write-Host "  Example: PC-12345" -ForegroundColor DarkGray

$ComputerName = Read-Host "  Computer Name"

# Remove accidental leading or trailing spaces.
$ComputerName = $ComputerName.Trim()

# Validate that a computer name was entered.
if ([string]::IsNullOrWhiteSpace($ComputerName)) {

    Write-Host ""
    Write-Host "  [ERROR] A computer name was not entered." -ForegroundColor Red
    Write-Host ""

    exit 1
}


# ============================================================
#                    TEST REMOTE COMPUTER
# ============================================================

Write-Host ""
Write-Host "  Checking connection to $ComputerName..." -ForegroundColor Gray

# Ping is used only as an initial connectivity check.
# Some organizations block ICMP, so failure here does not
# automatically stop the script.

if (!(Test-Connection `
        -ComputerName $ComputerName `
        -Count 1 `
        -Quiet `
        -ErrorAction SilentlyContinue)) {

    Write-Host "  [WARNING] No ping response from $ComputerName." `
        -ForegroundColor Yellow

    Write-Host "            The computer may be offline or ICMP may be blocked." `
        -ForegroundColor DarkYellow
}
else {

    Write-Host "  [OK] Computer responded to ping." -ForegroundColor Green
}


# ============================================================
#                    TEST POWERSHELL REMOTING
# ============================================================

Write-Host "  Checking PowerShell Remoting..." -ForegroundColor Gray

try {

    Test-WSMan `
        -ComputerName $ComputerName `
        -ErrorAction Stop |
        Out-Null

    Write-Host "  [OK] PowerShell Remoting is available." -ForegroundColor Green
}
catch {

    Write-Host ""
    Write-Host "  [ERROR] Unable to connect using PowerShell Remoting." `
        -ForegroundColor Red

    Write-Host ""
    Write-Host "  Computer : $ComputerName" -ForegroundColor White
    Write-Host "  Details  : $($_.Exception.Message)" -ForegroundColor DarkGray
    Write-Host ""

    Write-Host "  Verify the following:" -ForegroundColor Yellow
    Write-Host "    - The workstation is online"
    Write-Host "    - WinRM / PowerShell Remoting is enabled"
    Write-Host "    - Windows Firewall permits WinRM"
    Write-Host "    - Your account has administrative rights"
    Write-Host ""

    exit 1
}


# ============================================================
#                  PROMPT FOR AD USERNAME
# ============================================================

Write-Host ""
Write-Host "  Active Directory User" -ForegroundColor Cyan
Write-Host "  Examples: jsmith, DOMAIN\jsmith, jsmith@domain.com" `
    -ForegroundColor DarkGray

$UserName = Read-Host "  Username"

$UserName = $UserName.Trim()

# Validate that a username was entered.
if ([string]::IsNullOrWhiteSpace($UserName)) {

    Write-Host ""
    Write-Host "  [ERROR] A username was not entered." -ForegroundColor Red
    Write-Host ""

    exit 1
}


# ============================================================
#                 NORMALIZE USERNAME INPUT
# ============================================================

# Allow the administrator to enter any of these forms:
#
#     jsmith
#     DOMAIN\jsmith
#     jsmith@domain.com
#
# For matching purposes, extract the SAM-style username.

$SamAccountName = $UserName

# Convert DOMAIN\username to username.
if ($SamAccountName -like "*\*") {

    $SamAccountName = $SamAccountName.Split("\")[-1]
}

# Convert username@domain.com to username.
if ($SamAccountName -like "*@*") {

    $SamAccountName = $SamAccountName.Split("@")[0]
}


# ============================================================
#                    DISPLAY TARGET SUMMARY
# ============================================================

Write-Host ""
Write-Host "  Target Summary" -ForegroundColor Cyan
Write-Host "  --------------" -ForegroundColor DarkGray
Write-Host ("  Computer : {0}" -f $ComputerName) -ForegroundColor White
Write-Host ("  User     : {0}" -f $SamAccountName) -ForegroundColor White
Write-Host ""


# ============================================================
#          CHECK LOCAL ADMINISTRATORS GROUP MEMBERSHIP
# ============================================================

Write-Host "  Checking local Administrators group..." -ForegroundColor Gray

try {

    $MatchingAdmins = Invoke-Command `
        -ComputerName $ComputerName `
        -ArgumentList $SamAccountName `
        -ScriptBlock {

            param (
                $TargetUser
            )

            # Retrieve all direct members of the local
            # Administrators group.
            $Admins = Get-LocalGroupMember `
                -Group "Administrators" `
                -ErrorAction Stop

            # Search only USER objects.
            #
            # Match forms such as:
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
                Select-Object `
                    Name,
                    ObjectClass,
                    PrincipalSource,
                    SID

        } `
        -ErrorAction Stop

}
catch {

    Write-Host ""
    Write-Host "  [ERROR] Unable to query the local Administrators group." `
        -ForegroundColor Red

    Write-Host "  Details: $($_.Exception.Message)" -ForegroundColor DarkGray
    Write-Host ""

    exit 1
}


# ============================================================
#                    USER NOT FOUND
# ============================================================

if (!$MatchingAdmins) {

    Write-Host ""
    Write-Host "  [INFO] No direct administrator membership was found." `
        -ForegroundColor Yellow

    Write-Host ""
    Write-Host ("  Computer : {0}" -f $ComputerName) -ForegroundColor White
    Write-Host ("  User     : {0}" -f $SamAccountName) -ForegroundColor White
    Write-Host ""

    Write-Host "  The user may still have administrator access through an" `
        -ForegroundColor DarkYellow

    Write-Host "  Active Directory group that is a member of Administrators." `
        -ForegroundColor DarkYellow

    Write-Host ""

    exit 0
}


# ============================================================
#                  DISPLAY MATCHING ACCOUNT
# ============================================================

Write-Host ""
Write-Host "  Administrator Membership Found" -ForegroundColor Green
Write-Host "  ------------------------------" -ForegroundColor DarkGray
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

# If more than one account matches the supplied username,
# stop rather than potentially removing the wrong account.

if (@($MatchingAdmins).Count -gt 1) {

    Write-Host ""
    Write-Host "  [ERROR] More than one matching account was found." `
        -ForegroundColor Red

    Write-Host "  No changes were made." -ForegroundColor Yellow
    Write-Host ""

    exit 1
}


# Store the exact account name returned by Windows.
$ExactAccountName = $MatchingAdmins.Name


# ============================================================
#                    CONFIRM REMOVAL
# ============================================================

Write-Host ""
Write-Host "  Confirmation Required" -ForegroundColor Yellow
Write-Host "  ---------------------" -ForegroundColor DarkGray
Write-Host ""

Write-Host ("  Computer : {0}" -f $ComputerName) -ForegroundColor White
Write-Host ("  Account  : {0}" -f $ExactAccountName) -ForegroundColor White
Write-Host ""

Write-Host "  This will remove the account from the local Administrators group." `
    -ForegroundColor DarkYellow

Write-Host ""

$Confirmation = Read-Host "  Type YES to continue"

# Require the administrator to type YES exactly.
if ($Confirmation -ne "YES") {

    Write-Host ""
    Write-Host "  [CANCELLED] No changes were made." -ForegroundColor Yellow
    Write-Host ""

    exit 0
}


# ============================================================
#              REMOVE USER FROM ADMINISTRATORS
# ============================================================

Write-Host ""
Write-Host "  Removing $ExactAccountName from local Administrators..." `
    -ForegroundColor Gray

try {

    Invoke-Command `
        -ComputerName $ComputerName `
        -ArgumentList $ExactAccountName `
        -ScriptBlock {

            param (
                $AccountName
            )

            # Remove the exact account returned by
            # Get-LocalGroupMember.
            Remove-LocalGroupMember `
                -Group "Administrators" `
                -Member $AccountName `
                -ErrorAction Stop

        } `
        -ErrorAction Stop

}
catch {

    Write-Host ""
    Write-Host "  [ERROR] The account could not be removed." `
        -ForegroundColor Red

    Write-Host "  Details: $($_.Exception.Message)" -ForegroundColor DarkGray
    Write-Host ""

    exit 1
}


# ============================================================
#                      VERIFY REMOVAL
# ============================================================

Write-Host "  Verifying removal..." -ForegroundColor Gray

try {

    $StillAdmin = Invoke-Command `
        -ComputerName $ComputerName `
        -ArgumentList $ExactAccountName `
        -ScriptBlock {

            param (
                $AccountName
            )

            # Query the Administrators group again and check
            # whether the exact account is still present.
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
    Write-Host "  [WARNING] Removal was attempted, but verification failed." `
        -ForegroundColor Yellow

    Write-Host "  Details: $($_.Exception.Message)" -ForegroundColor DarkGray
    Write-Host ""

    exit 1
}


# ============================================================
#                      FINAL RESULT
# ============================================================

if (!$StillAdmin) {

    Write-Host ""
    Write-Host "  [SUCCESS] Administrator access removed." `
        -ForegroundColor Green

    Write-Host ""
    Write-Host ("  Computer : {0}" -f $ComputerName) -ForegroundColor White
    Write-Host ("  Account  : {0}" -f $ExactAccountName) -ForegroundColor White
    Write-Host ""

    Write-Host "  The account is no longer a direct member of the" `
        -ForegroundColor Green

    Write-Host "  local Administrators group." `
        -ForegroundColor Green
}
else {

    Write-Host ""
    Write-Host "  [WARNING] The account still appears in the local" `
        -ForegroundColor Yellow

    Write-Host "            Administrators group." `
        -ForegroundColor Yellow

    Write-Host ""
    Write-Host "  No additional automated changes were attempted." `
        -ForegroundColor DarkYellow
}


# ============================================================
#                         END SCRIPT
# ============================================================

Write-Host ""
Write-Host "  ------------------------------------------------------------" `
    -ForegroundColor DarkGray

Write-Host ""
Write-Host "  Script End." -ForegroundColor DarkYellow
Write-Host ""