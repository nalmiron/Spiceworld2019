function Create-DemoADObjects {
    <#
    .SYNOPSIS
        Creates JEADemo OU and accounts 
    .DESCRIPTION
        This function will create a new OU called JEADemo and two respective accounts within that OU. You must have the appropriate privledges for this to run. This 
        was developed directly on a LAB domain controller. If you want to run this on a domain joined client you will need to import the Active Directory Module

        NOTE: Not intended for a production domain environment. Use at your own risk.
    .PARAMETER RootDomainPath
        LDAP path to the root of your domain. Ex. "DC=lab,DC=automox,DC=com"
    .EXAMPLE
        Create-DemoADObjects
    #>
    param (
        [Parameter(Mandatory=$true)]
          [string] $RootDomainPath
    )
    try {
        # Create OU
        New-ADOrganizationalUnit -Name "JEADemo" -Path $RootDomainPath

        # Create Security Groups
        New-ADGroup -Name "DNS Admins" -SamAccountName DNSAdmins -GroupCategory Security -GroupScope Global -DisplayName "DNS Administrators" -Path "OU=JEADemo,$RootDomainPath" -Description "Members of this group are DNS Administrators"
        New-ADGroup -Name "Help Desk Technicians" -SamAccountName HelpDeskTechs -GroupCategory Security -GroupScope Global -DisplayName "Help Desk Technicians" -Path "OU=JEADemo,$RootDomainPath" -Description "Members of this group are Help Desk Technicians"
        New-ADGroup -Name "JEA Enabled" -SamAccountName JEAEnabled -GroupCategory Security -GroupScope Global -DisplayName "Help Enabled" -Path "OU=JEADemo,$RootDomainPath" -Description "Members of this group are enabled for JEA usage"

        # Create Users
        New-ADUser -Name u-htech -AccountPassword $(ConvertTo-SecureString -AsPlainText "superSecretP@ss" -Force) -Path "OU=JEADemo,$RootDomainPath" -Enabled $true
        New-ADUser -Name u-dadmin -AccountPassword $(ConvertTo-SecureString -AsPlainText "superSecretP@ss" -Force) -Path "OU=JEADemo,$RootDomainPath" -Enabled $true
        New-ADUser -Name u-dadmin2 -AccountPassword $(ConvertTo-SecureString -AsPlainText "superSecretP@ss" -Force) -Path "OU=JEADemo,$RootDomainPath" -Enabled $true
        New-ADUser -Name a-fadmin -AccountPassword $(ConvertTo-SecureString -AsPlainText "superSecretP@ss" -Force) -Path "OU=JEADemo,$RootDomainPath" -Enabled $true

        #region Define Group Membership
        # Add members to DNSAdmins group
        Add-ADGroupMember -Identity DNSAdmins -Members u-dadmin
        Add-ADGroupMember -Identity DNSAdmins -Members u-dadmin2
        Add-ADGroupMember -Identity DNSAdmins -Members a-fadmin

        # Add members to HelpDeskTech group
        Add-ADGroupMember -Identity HelpDeskTechs -Members u-htech
        Add-ADGroupMember -Identity HelpDeskTechs -Members a-fadmin

        # Add members to JEAEnabled group
        Add-ADGroupMember -Identity JEAEnabled -Members u-dadmin
        Add-ADGroupMember -Identity JEAEnabled -Members u-htech
        Add-ADGroupMember -Identity JEAEnabled -Members a-fadmin
        
        # Add member to Domain Admins Group
        Add-ADGroupMember -Identity "Domain Admins" -Members a-fadmin
        Add-ADGroupMember -Identity "Domain Admins" -Members s-JEAContextAccount
        #endregion Define Group Membership

        Write-Host "JEADemo OU, Accounts, and Security Groups created"
    } catch {
        $error[0]
        Write-Host "Demo has already been setup"
    }
}

function Init-Directory {
    <#
    .SYNOPSIS
        Initializes provided directory
    .DESCRIPTION
        Checks if provided directory exists. Will create it if not found.
    .PARAMETER Path
        Path of the desired directory
    .EXAMPLE
        Init-Directory -Path "C:\JEA\Rolecapabilities"
    #>
    param (
        [Parameter(Mandatory=$true)]
            [string] $Path
    )

    if (-not(Test-Path $path)) {
        New-Item $Path -ItemType Directory | Out-Null
    }
}

function Generate-JEAFiles {
    <#
    .SYNOPSIS
        Generates Role Capability and Session Configuration files for this JEA Demo
    .DESCRIPTION
        Generates Role Capability and Session Configuration files for this JEA Demo
    .PARAMETER RoleCapabilityPath
        Path where the generated role capability files should be stored
    .PARAMETER SessionConfigurationPath
        Path where the generated session configurations files should be stored
    .PARAMETER TranscriptsPath
        Path where the generated session transcripts will be stored
    .EXAMPLE
        Generate-JEAFiles -RoleCapabilityPath "C:\JEA\RoleCapabilities" -SessionConfigurationPath "C:\JEA\SessionConfigurations"
    #>
    param (
        [Parameter(Mandatory=$true)]
            [string] $RoleCapabilityPath,
        [Parameter(Mandatory=$true)]
            [string] $SessionConfigurationPath,
        [Parameter(Mandatory=$true)]
            [string] $TranscriptsPath
    )

    #region Role Capability Files
    # Create Role Capability file for DNS Role
    $dnsRoleParameters = @{
            Path = "$RoleCapabilityPath\DNSAdmin.psrc"
            Author = "Nick"
            CompanyName = "Automox"
            Description = "This role enables DNS admins to clear DNS Server cache, Restart the DNS Service, and restart the computer"
            ModulesToImport = "Microsoft.PowerShell.Core"
            VisibleCmdlets = "Clear-DnsServerCache",
                "Get-*",
                @{ Name = "Restart-Service"; Parameters = @{ Name = "Name"; ValidateSet = "DNS", "dnscache"; },
                                                          @{ Name = "Force" } },
                @{ Name = "Restart-Computer"; Parameters = @{ Name = "ComputerName"; ValidateSet = "localhost", "."; } }
            VisibleExternalCommands = 'C:\Windows\System32\whoami.exe'
        }
    New-PSRoleCapabilityFile @dnsRoleParameters

    # Create Role Capability file for HelpDesk Role
    $helpDeskRoleParameters = @{
            Path = "$RoleCapabilityPath\HelpDeskTech.psrc"
            Author = "Nick"
            CompanyName = "Automox"
            Description = "This role enables DNS admins to clear DNS Server cache, Restart the DNS Service, and restart the computer"
            ModulesToImport = "Microsoft.PowerShell.Core", "ActiveDirectory"
            VisibleCmdlets = "Get-*",
                @{ Name ="Set-ADAccountPassword"; Parameters = @{ Name = "Identity"; ValidatePattern = "u-*" }, 
                                                               @{ Name = "NewPassword"; ValidateSet = "Get-Password" },
                                                               @{ Name = "Reset" } }
            VisibleExternalCommands = "C:\Windows\System32\whoami.exe"
            AliasDefinitions = @{ Name = 'Get-Password'; Value = 'Read-Host -Prompt "Provide New Password" -AsSecureString'}
        }
    New-PSRoleCapabilityFile @helpDeskRoleParameters
    #endregion Role Capability Files

    #region Session Configuration Files
    $roles = @{
        'LAB\DNSAdmins' = @{ RoleCapabilities = 'DNSAdmin' }
        'LAB\HelpDeskTechs' = @{ RoleCapabilities = 'HelpDeskTech' }
        'LAB\Domain Admins' = @{ RoleCapabilities = 'DNSAdmin', 'HelpDeskTech' }
    }
    New-PSSessionConfigurationFile -SessionType RestrictedRemoteServer `
                                    -Path "$SessionConfigurationPath\JEADemo.pssc" `
                                    -RunAsVirtualAccount `
                                    -TranscriptDirectory "$TranscriptsPath" `
                                    -RoleDefinitions $roles `
                                    -RequiredGroups @{ Or = 'JEAEnabled', 'Domain Admins' }
    #endregion Session Configuration Files

}

function Setup-JEADemo {
<#
    .SYNOPSIS
        Sets up everything you need to work through this JEA Demo
    .DESCRIPTION
        Sets up everything needed to work through this JEA Demo including Directories, AD Objects, and JEA files
    .PARAMETER RootDomainPath
        LDAP path to the root of your domain. Ex. "DC=lab,DC=automox,DC=com"
    .PARAMETER RootFilePath
        Path where you want the JEA files stored. A "JEA" directory will be created in the provided location
    .EXAMPLE
        Setup-JEADemo -RootDomainPath "DC=lab,DC=automox,DC=com" -RootFilePath "C:\Temp"
    #>
    param (
        [Parameter(Mandatory=$true)]
          [string] $RootDomainPath,
        [Parameter(Mandatory=$true)]
          [string] $RootFilePath
    )

    $roleCapabilityPath = "$RootFilePath\JEA\RoleCapabilities"
    $sessionConfigurationPath = "$RootFilePath\JEA\SessionConfigurations"
    $transcriptPath = "$RootFilePath\JEA\Transcripts"

    # Initialize Directories
    Init-Directory -path "$RootFilePath\JEA"
    Init-Directory -path $RoleCapabilityPath
    Init-Directory -path $sessionConfigurationPath

    # Add JEA folder to PSModulePath, this allows visibility of the RoleConfigurationFiles
    $env:PSModulePath = $env:PSModulePath + ";c:\JEA"


    # Create AD Objects
    Create-DemoADObjects -RootDomainPath $rootDomainPath

    # Generate JEA Demo files
    Generate-JEAFiles -RoleCapabilityPath $roleCapabilityPath -SessionConfigurationPath $sessionConfigurationPath -TranscriptsPath $transcriptPath

}

Setup-JEADemo -RootDomainPath "DC=lab,DC=automox,DC=com" -RootFilePath "C:\"