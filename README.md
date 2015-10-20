#Nishang

###Nishang is a framework and collection of scripts and payloads which enables usage of PowerShell for offensive security and penetration testing. Nishang is useful during various phases of a penetration test and is most powerful for post exploitation usage.
By [nikhil_mitt](https://twitter.com/nikhil_mitt)
####Scripts
Nishang currently contains the following scripts and payloads.

#####Antak - the Webshell
[Antak](https://github.com/samratashok/nishang/tree/master/Antak-WebShell)

Execute PowerShell scripts in memory, run commands, and download and upload files using this webshell.

#####Backdoors
[HTTP-Backdoor](https://github.com/samratashok/nishang/blob/master/Backdoors/HTTP-Backdoor.ps1)

A backdoor which can receive instructions from third party websites and execute PowerShell scripts in memory.

[DNS_TXT_Pwnage](https://github.com/samratashok/nishang/blob/master/Backdoors/DNS_TXT_Pwnage.ps1)

A backdoor which can receive commands and PowerShell scripts from DNS TXT queries, execute them on a target, and be remotely controlled using the queries.

[Execute-OnTime](https://github.com/samratashok/nishang/blob/master/Backdoors/Execute-OnTime.ps1)

A backdoor which can execute PowerShell scripts at a given time on a target.

[Gupt-Backdoor](https://github.com/samratashok/nishang/blob/master/Backdoors/Gupt-Backdoor.ps1)

A backdoor which can receive commands and scripts from a WLAN SSID without connecting to it. 

[Add-ScrnSaveBackdoor](https://github.com/samratashok/nishang/blob/master/Backdoors/Add-ScrnSaveBackdoor.ps1)

A backdoor which can use Windows screen saver for remote command and script execution. 

[Invoke-ADSBackdoor](https://github.com/samratashok/nishang/blob/master/Backdoors/Invoke-ADSBackdoor.ps1)

A backdoor which can use alternate data streams and Windows Registry to achieve persistence. 

#####Client
[Out-CHM](https://github.com/samratashok/nishang/blob/master/Client/Out-CHM.ps1)

Create infected CHM files which can execute PowerShell commands and scripts.

[Out-Word](https://github.com/samratashok/nishang/blob/master/Client/Out-Word.ps1)

Create Word files and infect existing ones to run PowerShell commands and scripts.

[Out-Excel](https://github.com/samratashok/nishang/blob/master/Client/Out-Excel.ps1)

Create Excel files and infect existing ones to run PowerShell commands and scripts.

[Out-HTA](https://github.com/samratashok/nishang/blob/master/Client/Out-HTA.ps1)

Create a HTA file which can be deployed on a web server and used in phishing campaigns. 

[Out-Java](https://github.com/samratashok/nishang/blob/master/Client/Out-Java.ps1)

Create signed JAR files which can be used with applets for script and command execution.

[Out-Shortcut](https://github.com/samratashok/nishang/blob/master/Client/Out-Shortcut.ps1)

Create shortcut files capable of executing commands and scripts.

[Out-WebQuery](https://github.com/samratashok/nishang/blob/master/Client/Out-WebQuery.ps1)

Create IQY files for phishing credentials and SMB hashes.


#####Escalation
[Enable-DuplicateToken](https://github.com/samratashok/nishang/blob/master/Escalation/Enable-DuplicateToken.ps1)

When SYSTEM privileges are required.

[Remove-Update](https://github.com/samratashok/nishang/blob/master/Escalation/Remove-Update.ps1)

Introduce vulnerabilities by removing patches.

[Invoke-PsUACme](https://github.com/samratashok/nishang/blob/master/Escalation/Invoke-PsUACme.ps1)

Bypass UAC.

#####Execution
[Download-Execute-PS](https://github.com/samratashok/nishang/blob/master/Execution/Download-Execute-PS.ps1)

Download and execute a PowerShell script in memory.

[Download_Execute](https://github.com/samratashok/nishang/blob/master/Execution/Download_Execute.ps1)

Download an executable in text format, convert it to an executable, and execute.

[Execute-Command-MSSQL](https://github.com/samratashok/nishang/blob/master/Execution/Execute-Command-MSSQL.ps1)

Run PowerShell commands, native commands, or SQL commands on a MSSQL Server with sufficient privileges.

[Execute-DNSTXT-Code](https://github.com/samratashok/nishang/blob/master/Execution/Execute-DNSTXT-Code.ps1)

Execute shellcode in memory using DNS TXT queries.

#####Gather
[Check-VM](https://github.com/samratashok/nishang/blob/master/Gather/Check-VM.ps1)

Check for a virtual machine.

[Copy-VSS](https://github.com/samratashok/nishang/blob/master/Gather/Copy-VSS.ps1)

Copy the SAM file using Volume Shadow Copy Service.

[Invoke-CredentialsPhish](https://github.com/samratashok/nishang/blob/master/Gather/Credentials.ps1)

Trick a user into giving credentials in plain text.

[FireBuster](https://github.com/samratashok/nishang/blob/master/Gather/FireBuster.ps1)
[FireListener](https://github.com/samratashok/nishang/blob/master/Gather/FireListener.ps1)

A pair of scripts for egress testing

[Get-Information](https://github.com/samratashok/nishang/blob/master/Gather/Get-Information.ps1)

Get juicy information from a target.

[Get-LSASecret](https://github.com/samratashok/nishang/blob/master/Gather/Get-LSASecret.ps1)

Get LSA Secret from a target.

[Get-PassHashes](https://github.com/samratashok/nishang/blob/master/Gather/Get-PassHashes.ps1)

Get password hashes from a target.

[Get-WLAN-Keys](https://github.com/samratashok/nishang/blob/master/Gather/Get-WLAN-Keys.ps1)

Get WLAN keys in plain text from a target.

[Keylogger](https://github.com/samratashok/nishang/blob/master/Gather/Keylogger.ps1)

Log keystrokes from a target.

[Invoke-MimikatzWdigestDowngrade](https://github.com/samratashok/nishang/blob/master/Gather/Invoke-MimikatzWDigestDowngrade.ps1)

Dump user passwords in plain on Windows 8.1 and Server 2012

[Get-PassHints](https://github.com/samratashok/nishang/blob/master/Gather/Get-PassHints.ps1)

Get password hints of Windows users from a target.

#####Pivot
[Create-MultipleSessions](https://github.com/samratashok/nishang/blob/master/Pivot/Create-MultipleSessions.ps1)

Check credentials on multiple computers and create PSSessions.

[Run-EXEonRemote](https://github.com/samratashok/nishang/blob/master/Pivot/Run-EXEonRemote.ps1)
Copy and execute an executable on multiple machines.

[Invoke-NetworkRelay](https://github.com/samratashok/nishang/blob/master/Pivot/Invoke-NetworkRelay.ps1)
Create network relays between computers.

#####Prasadhak
[Prasadhak](https://github.com/samratashok/nishang/blob/master/Prasadhak/Prasadhak.ps1)

Check running hashes of running process against the VirusTotal database.

#####Scan
[Brute-Force](https://github.com/samratashok/nishang/blob/master/Scan/Brute-Force.ps1)

Brute force FTP, Active Directory, MSSQL, and Sharepoint.

[Port-Scan](https://github.com/samratashok/nishang/blob/master/Scan/Port-Scan.ps1)

A handy port scanner.

#####Powerpreter
[Powerpreter](https://github.com/samratashok/nishang/tree/master/powerpreter)

All the functionality of nishang in a single script module.

#####Shells
[Invoke-PsGcat](https://github.com/samratashok/nishang/blob/master/Shells/Invoke-PsGcat.ps1)

Send commands and scripts to specifed Gmail account to be executed by Invoke-PsGcatAgent

[Invoke-PsGcatAgent](https://github.com/samratashok/nishang/blob/master/Shells/Invoke-PsGcatAgent.ps1)

Execute commands and scripts sent by Invoke-PsGcat.

[Invoke-PowerShellTcp](https://github.com/samratashok/nishang/blob/master/Shells/Invoke-PowerShellTcp.ps1)

An interactive PowerShell reverse connect or bind shell

[Invoke-PowerShellTcpOneLine](https://github.com/samratashok/nishang/blob/master/Shells/Invoke-PowerShellTcpOneLine.ps1)

Stripped down version of Invoke-PowerShellTcp. Also contains, a skeleton version which could fit in two tweets.

[Invoke-PowerShellUdp](https://github.com/samratashok/nishang/blob/master/Shells/Invoke-PowerShellUdp.ps1)

An interactive PowerShell reverse connect or bind shell over UDP

[Invoke-PowerShellUdpOneLine](https://github.com/samratashok/nishang/blob/master/Shells/Invoke-PowerShellUdpOneLine.ps1)

Stripped down version of Invoke-PowerShellUdp.

[Invoke-PoshRatHttps](https://github.com/samratashok/nishang/blob/master/Shells/Invoke-PoshRatHttps.ps1)

Reverse interactive PowerShell over HTTPS.

[Invoke-PoshRatHttp](https://github.com/samratashok/nishang/blob/master/Shells/Invoke-PoshRatHttp.ps1)

Reverse interactive PowerShell over HTTP.

[Remove-PoshRat](https://github.com/samratashok/nishang/blob/master/Shells/Remove-PoshRat.ps1)

Clean the system after using Invoke-PoshRatHttps

[Invoke-PowerShellWmi](https://github.com/samratashok/nishang/blob/master/Shells/Invoke-PowerShellWmi.ps1)

Interactive PowerShell using WMI.

[Invoke-PowerShellIcmp](https://github.com/samratashok/nishang/blob/master/Shells/Invoke-PowerShellIcmp.ps1)

An interactive PowerShell reverse shell over ICMP.


#####Utility
[Add-Exfiltration](https://github.com/samratashok/nishang/blob/master/Utility/Add-Exfiltration.ps1)

Add data exfiltration capability to Gmail, Pastebin, a web server, and DNS to any script.

[Add-Persistence](https://github.com/samratashok/nishang/blob/master/Utility/Add-Persistence.ps1)

Add reboot persistence capability to a script.

[Remove-Persistence](https://github.com/samratashok/nishang/blob/master/Utility/Remove-Persistence.ps1)

Remote persistence added by the Add-Persistence script.

[Do-Exfiltration](https://github.com/samratashok/nishang/blob/master/Utility/Do-Exfiltration.ps1)

Pipe (|) this to any script to exfiltrate the output.

[Download](https://github.com/samratashok/nishang/blob/master/Utility/Download.ps1)

Transfer a file to the target.

[Parse_Keys](https://github.com/samratashok/nishang/blob/master/Utility/Parse_Keys.ps1)

Parse keys logged by the keylogger.

[Invoke-Encode](https://github.com/samratashok/nishang/blob/master/Utility/Invoke-Encode.ps1)

Encode and compress a script or string.

[Invoke-Decode](https://github.com/samratashok/nishang/blob/master/Utility/Invoke-Decode.ps1)

Decode and decompress a script or string from Invoke-Encode.

[Start-CaptureServer](https://github.com/samratashok/nishang/blob/master/Utility/Start-CaptureServer.ps1)

Run a web server which logs Basic authentication and SMB hashes.

[Base64ToString]
[StringToBase64]
[ExetoText]
[TexttoExe]

####Usage

Import all the scripts in the current PowerShell session (PowerShell v3 onwards).

PS > Import-Module .\nishang.psm1

Use the individual scripts with dot sourcing.

PS > . C:\nishang\Gather\Get-Information.ps1

PS > Get-Information

To get help about any script or function, use:

PS > Get-Help [scriptname] -full

Note that the help is available for the function loaded after running the script and not the script itself since version 0.3.8. In all cases, the function name is same as the script name.

For example, to see the help about Get-WLAN-Keys.ps1, use

PS> . C:\nishang\Get-WLAN-Keys.ps1

PS> Get-Help Get-WLAN-Keys -Full


####Updates

Updates about Nishang can be found at my blog http://labofapenetrationtester.com and my Twitter feed @nikhil_mitt.

####Bugs, Feedback and Feature Requests
Please raise an issue if you encounter a bug or have a feature request. You can email me at nikhil [dot] uitrgpv at gmail.com

#####Mailing List
For feedback, discussions, and feature requests, join: http://groups.google.com/group/nishang-users

#####Contributing
I am always looking for contributors to Nishang. Please submit requests or drop me an email.

#####Blog Posts

Some helpful blog posts to check out for beginners:

http://www.labofapenetrationtester.com/2014/06/nishang-0-3-4.html

http://labofapenetrationtester.com/2012/08/introducing-nishang-powereshell-for.html

http://labofapenetrationtester.com/2013/08/powerpreter-and-nishang-Part-1.html

http://www.labofapenetrationtester.com/2013/09/powerpreter-and-nishang-Part-2.html 

All posts about Nishang:

http://www.labofapenetrationtester.com/search/label/Nishang
