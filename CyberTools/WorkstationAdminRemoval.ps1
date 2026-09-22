<#
.SYNOPSIS
    Removes a specified Active Directory user from the local Administrators
    group on a remote Windows workstation.

.DESCRIPTION
    This script provides an interactive administrative tool for removing
    direct Active Directory user memberships from the local Administrators
    group on remote Windows workstations.

    The administrator is prompted for:

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
        8. Prompts to process another user or exit.

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
#                    CONSOLE CONFIGURATION
# ============================================================

# Set the PowerShell console window title.
$Host.UI.RawUI.WindowTitle = "Remote Local Administrator Management"


# ============================================================
#                       HEADER FUNCTION
# ============================================================

function Show-Header {

    Clear-Host

    Write-Host ""
    Write-Host "  Remote Local Administrator Management" -ForegroundColor Cyan
    Write-Host "  --------------------------------------" -ForegroundColor DarkGray
    Write-Host ""
    Write-Host "  Remove an Active Directory user from the local" -ForegroundColor Gray
    Write-Host "  Administrators group on a remote workstation." -ForegroundColor Gray
    Write-Host ""

    Write-Host "  WARNING" -ForegroundColor Yellow
    Write-Host "  Use at your own risk. Changes affect local administrator access." `
        -ForegroundColor DarkYellow

    Write-Host ""
    Write-Host "  ------------------------------------------------------------" `
        -ForegroundColor DarkGray
    Write-Host ""
}


# ============================================================
#                       MENU FUNCTION
# ============================================================

function Show-ContinueMenu {

    Write-Host ""
    Write-Host "  ------------------------------------------------------------" `
        -ForegroundColor DarkGray

    Write-Host ""
    Write-Host "  What would you like to do?" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  [1] Remove another user" -ForegroundColor White
    Write-Host "  [2] Exit" -ForegroundColor White
    Write-Host ""

    # Continue asking until a valid selection is entered.
    do {

        $MenuSelection = Read-Host "  Selection"

        switch ($MenuSelection) {

            "1" {
                return $true
            }

            "2" {
                return $false
            }

            default {

                Write-Host ""
                Write-Host "  [WARNING] Please enter 1 or 2." `
                    -ForegroundColor Yellow
                Write-Host ""
            }
        }

    } while ($true)
}


# ============================================================
#                       MAIN PROGRAM LOOP
# ============================================================

$ContinueRunning = $true

while ($ContinueRunning) {

    # Display a clean screen for each operation.
    Show-Header


    # ========================================================
    #                  PROMPT FOR COMPUTER
    # ========================================================

    Write-Host "  Target Computer" -ForegroundColor Cyan
    Write-Host "  Example: PC-12345" -ForegroundColor DarkGray

    $ComputerName = Read-Host "  Computer Name"

    $ComputerName = $ComputerName.Trim()


    # Validate computer name.
    if ([string]::IsNullOrWhiteSpace($ComputerName)) {

        Write-Host ""
        Write-Host "  [ERROR] A computer name was not entered." `
            -ForegroundColor Red

        $ContinueRunning = Show-ContinueMenu

        continue
    }


    # ========================================================
    #                    TEST CONNECTIVITY
    # ========================================================

    Write-Host ""
    Write-Host "  Checking connection to $ComputerName..." `
        -ForegroundColor Gray


    # Ping is only an informational connectivity test.
    # Some environments block ICMP, so a failed ping does not
    # automatically prevent the WinRM connection attempt.

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

        Write-Host "  [OK] Computer responded to ping." `
            -ForegroundColor Green
    }


    # ========================================================
    #                 TEST POWERSHELL REMOTING
    # ========================================================

    Write-Host "  Checking PowerShell Remoting..." `
        -ForegroundColor Gray

    try {

        Test-WSMan `
            -ComputerName $ComputerName `
            -ErrorAction Stop |
            Out-Null

        Write-Host "  [OK] PowerShell Remoting is available." `
            -ForegroundColor Green
    }
    catch {

        Write-Host ""
        Write-Host "  [ERROR] Unable to connect using PowerShell Remoting." `
            -ForegroundColor Red

        Write-Host ""
        Write-Host "  Computer : $ComputerName" `
            -ForegroundColor White

        Write-Host "  Details  : $($_.Exception.Message)" `
            -ForegroundColor DarkGray

        Write-Host ""
        Write-Host "  Verify the following:" `
            -ForegroundColor Yellow

        Write-Host "    - The workstation is online"
        Write-Host "    - WinRM / PowerShell Remoting is enabled"
        Write-Host "    - Windows Firewall permits WinRM"
        Write-Host "    - Your account has administrative rights"

        # Return to the menu instead of terminating the script.
        $ContinueRunning = Show-ContinueMenu

        continue
    }


    # ========================================================
    #                  PROMPT FOR USERNAME
    # ========================================================

    Write-Host ""
    Write-Host "  Active Directory User" -ForegroundColor Cyan

    Write-Host "  Examples: jsmith, DOMAIN\jsmith, jsmith@domain.com" `
        -ForegroundColor DarkGray

    $UserName = Read-Host "  Username"

    $UserName = $UserName.Trim()


    # Validate username.
    if ([string]::IsNullOrWhiteSpace($UserName)) {

        Write-Host ""
        Write-Host "  [ERROR] A username was not entered." `
            -ForegroundColor Red

        $ContinueRunning = Show-ContinueMenu

        continue
    }


    # ========================================================
    #                 NORMALIZE USERNAME
    # ========================================================

    # Allow any of the following:
    #
    #     jsmith
    #     DOMAIN\jsmith
    #     jsmith@domain.com
    #
    # Extract the SAM-style username for matching.

    $SamAccountName = $UserName


    # Convert DOMAIN\username to username.
    if ($SamAccountName -like "*\*") {

        $SamAccountName = $SamAccountName.Split("\")[-1]
    }


    # Convert username@domain.com to username.
    if ($SamAccountName -like "*@*") {

        $SamAccountName = $SamAccountName.Split("@")[0]
    }


    # ========================================================
    #                    TARGET SUMMARY
    # ========================================================

    Write-Host ""
    Write-Host "  Target Summary" -ForegroundColor Cyan
    Write-Host "  --------------" -ForegroundColor DarkGray

    Write-Host ("  Computer : {0}" -f $ComputerName) `
        -ForegroundColor White

    Write-Host ("  User     : {0}" -f $SamAccountName) `
        -ForegroundColor White

    Write-Host ""


    # ========================================================
    #             CHECK ADMINISTRATORS MEMBERSHIP
    # ========================================================

    Write-Host "  Checking local Administrators group..." `
        -ForegroundColor Gray

    try {

        $MatchingAdmins = Invoke-Command `
            -ComputerName $ComputerName `
            -ArgumentList $SamAccountName `
            -ScriptBlock {

                param (
                    $TargetUser
                )

                # Retrieve direct members of the local
                # Administrators group.

                $Admins = Get-LocalGroupMember `
                    -Group "Administrators" `
                    -ErrorAction Stop


                # Search USER objects for the requested account.
                #
                # Possible returned names include:
                #
                #     DOMAIN\jsmith
                #     COMPUTER\jsmith

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

        Write-Host "  Details: $($_.Exception.Message)" `
            -ForegroundColor DarkGray

        $ContinueRunning = Show-ContinueMenu

        continue
    }


    # ========================================================
    #                     USER NOT FOUND
    # ========================================================

    if (!$MatchingAdmins) {

        Write-Host ""
        Write-Host "  [INFO] No direct administrator membership was found." `
            -ForegroundColor Yellow

        Write-Host ""
        Write-Host ("  Computer : {0}" -f $ComputerName) `
            -ForegroundColor White

        Write-Host ("  User     : {0}" -f $SamAccountName) `
            -ForegroundColor White

        Write-Host ""
        Write-Host "  The user may still have administrator access through an" `
            -ForegroundColor DarkYellow

        Write-Host "  Active Directory group that is a member of Administrators." `
            -ForegroundColor DarkYellow


        # Instead of exiting, ask whether another user should
        # be processed.
        $ContinueRunning = Show-ContinueMenu

        continue
    }


    # ========================================================
    #                 DISPLAY MATCHING ACCOUNT
    # ========================================================

    Write-Host ""
    Write-Host "  Administrator Membership Found" `
        -ForegroundColor Green

    Write-Host "  ------------------------------" `
        -ForegroundColor DarkGray

    Write-Host ""

    $MatchingAdmins |
        Format-Table `
            Name,
            ObjectClass,
            PrincipalSource,
            SID `
            -AutoSize


    # ========================================================
    #                       SAFETY CHECK
    # ========================================================

    # If multiple accounts somehow match the supplied username,
    # stop this operation instead of risking removal of the
    # wrong account.

    if (@($MatchingAdmins).Count -gt 1) {

        Write-Host ""
        Write-Host "  [ERROR] More than one matching account was found." `
            -ForegroundColor Red

        Write-Host "  No changes were made." `
            -ForegroundColor Yellow

        $ContinueRunning = Show-ContinueMenu

        continue
    }


    # Store the exact account name returned by Windows.
    $ExactAccountName = $MatchingAdmins.Name


    # ========================================================
    #                    CONFIRM REMOVAL
    # ========================================================

    Write-Host ""
    Write-Host "  Confirmation Required" `
        -ForegroundColor Yellow

    Write-Host "  ---------------------" `
        -ForegroundColor DarkGray

    Write-Host ""

    Write-Host ("  Computer : {0}" -f $ComputerName) `
        -ForegroundColor White

    Write-Host ("  Account  : {0}" -f $ExactAccountName) `
        -ForegroundColor White

    Write-Host ""

    Write-Host "  This will remove the account from the local Administrators group." `
        -ForegroundColor DarkYellow

    Write-Host ""

    $Confirmation = Read-Host "  Type YES to continue"


    # Require explicit confirmation.
    if ($Confirmation -ne "YES") {

        Write-Host ""
        Write-Host "  [CANCELLED] No changes were made." `
            -ForegroundColor Yellow

        $ContinueRunning = Show-ContinueMenu

        continue
    }


    # ========================================================
    #                 REMOVE ADMIN MEMBERSHIP
    # ========================================================

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

        Write-Host "  Details: $($_.Exception.Message)" `
            -ForegroundColor DarkGray

        $ContinueRunning = Show-ContinueMenu

        continue
    }


    # ========================================================
    #                      VERIFY REMOVAL
    # ========================================================

    Write-Host "  Verifying removal..." `
        -ForegroundColor Gray

    try {

        $StillAdmin = Invoke-Command `
            -ComputerName $ComputerName `
            -ArgumentList $ExactAccountName `
            -ScriptBlock {

                param (
                    $AccountName
                )

                # Query Administrators again to verify that
                # the exact account is no longer present.

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

        Write-Host "  Details: $($_.Exception.Message)" `
            -ForegroundColor DarkGray

        $ContinueRunning = Show-ContinueMenu

        continue
    }


    # ========================================================
    #                       FINAL RESULT
    # ========================================================

    if (!$StillAdmin) {

        Write-Host ""
        Write-Host "  [SUCCESS] Administrator access removed." `
            -ForegroundColor Green

        Write-Host ""

        Write-Host ("  Computer : {0}" -f $ComputerName) `
            -ForegroundColor White

        Write-Host ("  Account  : {0}" -f $ExactAccountName) `
            -ForegroundColor White

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


    # ========================================================
    #                  PROCESS ANOTHER USER?
    # ========================================================

    $ContinueRunning = Show-ContinueMenu
}


# ============================================================
#                         EXIT SCREEN
# ============================================================

Clear-Host

Write-Host ""
Write-Host "  Remote Local Administrator Management" `
    -ForegroundColor Cyan

Write-Host "  --------------------------------------" `
    -ForegroundColor DarkGray

Write-Host ""
Write-Host "  Session complete." -ForegroundColor Green
Write-Host ""
Write-Host "  USE AT YOUR OWN RISK." -ForegroundColor DarkYellow
Write-Host ""