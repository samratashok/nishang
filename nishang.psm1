
<#
Import this module to use all the scripts in Nishang, except Keylogger, in the current PowerShell session. The module must reside in the Nishang folder.

PS > Import-Module .\nishang.psm1

http://www.labofapenetrationtester.com/2014/06/nishang-0-3-4.html
https://github.com/samratashok/nishang
#>


if(!$PSScriptRoot)
{ 
    $PSScriptRoot = Split-Path $MyInvocation.MyCommand.Path -Parent
}

if ($PSVersionTable.PSVersion.Major -eq 2)
{
    #Code stolen from here https://github.com/mattifestation/PowerSploit
    Get-ChildItem -Recurse $PSScriptRoot *.ps1  | Where-Object {($_.Name -ne 'Keylogger.ps1'-or $_.Name -ne 'Invoke-Prasadhak.ps1' -or $_.Name -ne 'Get-WebCredentials.ps1')} | ForEach-Object  {Import-Module $_.FullName -DisableNameChecking}
}
else
{
    Get-ChildItem -Recurse $PSScriptRoot *.ps1  | Where-Object {($_.Name -ne 'Keylogger.ps1')} | ForEach-Object  {Import-Module $_.FullName -DisableNameChecking}
}

