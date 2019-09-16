# PowerShell 4.0 and Above
# Windows 8 and later

function Evaluate-BitlockerCompliance {
    <#
    .SYNOPSIS
        Checks Bitlocker compliance and returns true or false
    .DESCRIPTION
        Checks to see if BitLocker encryption is enabled for all applicable drives. Returns
        true or false depending on status. By default only checks Operating System drives
    .PARAMETER AllDrives
        If this switch is provided, all drives are checked to ensure encryption is enabled
    .EXAMPLE
        Evaluate-BitLockerCompliance
    #>
    param (
        [Parameter(Mandatory=$false)]
            [switch] $AllDrives
    )

    try { 
        # If the AllDrives switch is not provided only check if bitlocker is enabled on Operating System Drives
        if ($AllDrives -eq $false) {
            $driveInfo = Get-BitlockerVolume -ErrorAction Stop | Where-Object { $_.VolumeType -eq "OperatingSystem" }
        } else {
            $driveInfo = Get-BitLockerVolume -ErrorAction Stop
        }

        # If Encryption status is Off on any of the returned devices return false
        foreach ($drive in $driveInfo) {
            if ($drive.ProtectionStatus -eq 'Off') {
                return $false
            }
        }

        # return true, all applicable drives have encryption enabled
        return $true
    } catch { 

        return "Unable to determine BitLocker status, make sure you are running as admin" 
    }
}


Evaluate-BitlockerCompliance
