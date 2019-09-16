# PowerShell 4.0 and Above
# Windows 8 and later

function Remediate-BitLockerCompliance {
    <#
    .SYNOPSIS
        Enables BitLocker on applicable drives
    .DESCRIPTION
        Enabled BitLocker on applicable drives. Returns true or false to indicate success of remediation
    .PARAMETER AllDrives
        If this switch is provided, all drives are checked to ensure encryption is enabled
    .PARAMETER RecoveryKeyPath
        If path is provided, recovery key will be exported to a text file in the provided path
    .EXAMPLE
        Remediate-BitLockerCompliance
        Remediate-BitLockerCompliance -AllDrives
        Remediate-BitLockerCompliance -AllDrives -RecoveryKeyPath "C:\Bitlocker Recovery Keys"
    #>
    param (
        [Parameter(Mandatory=$false)]
            [switch] $AllDrives,
        [Parameter(Mandatory=$false)]
            [string] $RecoveryKeyPath
    )

    try {

        # If the AllDrives switch is not provided only encrypt operating system drives
        if ($AllDrives -eq $false) {
            $toEncrypt = Get-BitlockerVolume -ErrorAction Stop | Where-Object { $_.VolumeType -eq "OperatingSystem" -and $_.VolumeStatus -match 'Decrypted' }
        } else {
            $driveInfo = Get-BitLockerVolume -ErrorAction Stop | Where-Object { $_.VolumeStatus -match 'Decrypted' }
        }

        # Enable bitlocker for each applicable device
        foreach ($drive in $toEncrypt) {
            $driveLetter = $drive.MountPoint.Replace(':','')
            Enable-BitLocker -MountPoint $driveLetter -EncryptionMethod Aes128 -RecoveryPasswordProtector | Out-Null

            # if recovery key path is provided export the recovery keys to txt files in the provided path
            if (-not([string]::IsNullOrEmpty($RecoveryKeyPath))) {
                $keyProtector = $(Get-BitLockerVolume -MountPoint $driveLetter).KeyProtector | Where-Object { $_.KeyProtectorType -eq "RecoveryPassword" } 
                Set-Content -Path "$RecoveryKeyPath\BitLockerRecoveryKey_$driveLetter.txt" -Force -Value "Recovery Key ID: $($keyProtector.KeyProtectorId) `n Recovery Key: $($keyProtector.RecoveryPassword)"
            }
        }

        return $true

    } catch {
        Write-Output "Unable to remediate BitLocker Compliance, please ensure you are running as admin"
        return $false
    }
}

Remediate-BitLockerCompliance