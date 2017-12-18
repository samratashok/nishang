function Invoke-NetworkRelay
{    
<#
.SYNOPSIS
Nishang script which can be used to run netsh port forwarding/relaying commands on remote computers. 

.DESCRIPTION
This script is a wrapper around the netsh Windows command's portproxy functionality. It could be used to create and remove 
network relays between computers. The script is useful in scenarios when you want to access a port or service running on a
target computer which is accessible only through another computer(s) between you and the target computer. Another interesting
usecase is when you want to expose a local service to the network.

.PARAMETER Relay
Specify the type of relay from "v4tov4","v6tov4","v4tov6" and "v6tov6". Default is v4tov4.
v4tov4 - Listen on v4 and connect to v4.


.PARAMETER ListenAddress
The local/listener IP address to which a remote port will be forwarded. Default is 0.0.0.0 (IPv4)

.PARAMETER ListenPort
The local/listener port to which a remote port will be forwarded. Default is 8888.

.PARAMETER ConnectAddress
The target/destination IP address whose port will be forwarded/mapped to a local port.

.PARAMETER ConnectPort
The target/destination port which will be forwarded/mapped to a local port.

.PARAMETER ComputerName
The name or IP address of the computer where the netsh command would be executed.

.PARAMETER UserName
Username for the computer specified with the ComputerName parameter.

.PARAMETER Password
Password for the computer specified with the ComputerName parameter.

.PARAMETER Delete
Use the Delete switch to delete a network relay specified by above options.

.PARAMETER Show
Use the Show switch to show all relays on a computer.

.EXAMPLE
PS > Invoke-NetworkRelay -Relay v4tov4 -ListenAddress 192.168.254.141 -Listenport 8888 -ConnectAddress 192.168.1.22  -ConnectPort 445 -ComputerName 192.168.254.141
Add a network relay which listens on IPv4 and connects to IPv4 and forwards port 445 from 192.168.1.22 to port 8888 of 192.168.254.141. 

.EXAMPLE
PS > Invoke-NetworkRelay -Relay v6tov4 -ListenAddress :: -Listenport 8888 -ConnectAddress 192.168.1.22  -ConnectPort 445 -ComputerName 192.168.254.141
Add a network relay which listens on IPv6 and connects to IPv4 and forwards port 445 from 192.168.1.22 to port 8888 of 192.168.254.141. 

.EXAMPLE
PS > Invoke-NetworkRelay -Relay v6tov6 -ListenAddress :: -Listenport 8888 -ConnectAddress fe80::19ed:c169:128c:b68d  -ConnectPort 445 -ComputerName domainpc -Username bharat\domainuser -Password Password1234
Add a network relay which listens on IPv6 and connects to IPv6 and forwards port 445 from fe80::19ed:c169:128c:b68d to port 8888 of domainpc 

.EXAMPLE
PS > Invoke-NetworkRelay -Relay v4tov4 -ListenAddress 192.168.254.141 -Listenport 8888 -ConnectAddress 192.168.1.22  -ConnectPort 445 -ComputerName 192.168.254.141 -Delete
Delete the network relay specified by the ListenAddress and Listen Port.

.EXAMPLE
PS > Invoke-NetworkRelay -ComputerName domainpc -Username bharat\domainuser -Password Password1234 -Show
Show all network relays on the domainpc computer


.LINK
http://www.labofapenetrationtester.com/2015/04/pillage-the-village-powershell-version.html
https://github.com/samratashok/nishang
#>  
    
    [CmdletBinding(DefaultParameterSetName="AddOrDelete")] Param( 

        [Parameter(Position = 0, Mandatory = $False, ParameterSetName="AddOrDelete")]
        [ValidateSet("v4tov4","v6tov4","v4tov6","v6tov6")]
        [String]
        $Relay="v4tov4",

        [Parameter(Position = 1, Mandatory = $False, ParameterSetName="AddOrDelete")]
        [String]
        $ListenAddress = "0.0.0.0",

        [Parameter(Position = 2, Mandatory= $False, ParameterSetName="AddOrDelete")]
        [String]
        $ListenPort = 8888,

        [Parameter(Position = 3, Mandatory = $True, ParameterSetName="AddOrDelete")]
        [String]
        $ConnectAddress,

        [Parameter(Position = 4, Mandatory = $True, ParameterSetName="AddOrDelete")]
        [String]
        $ConnectPort,

        [Parameter(Position = 5, Mandatory = $False, ParameterSetName="AddOrDelete")]
        [Parameter(Position = 0, Mandatory = $False, ParameterSetName="Show")]
        [String]
        $ComputerName,

        [Parameter(Position = 6, Mandatory = $False, ParameterSetName="AddOrDelete")]
        [Parameter(Position = 1, Mandatory = $False, ParameterSetName="Show")]
        $UserName,
        
        [Parameter(Position = 7, Mandatory = $False, ParameterSetName="AddOrDelete")]
        [Parameter(Position = 2, Mandatory = $False, ParameterSetName="Show")]
        $Password,

        [Parameter(Mandatory = $False, ParameterSetName="AddOrDelete")]
        [Switch]
        $Delete,

        [Parameter(Mandatory = $False, ParameterSetName="Show")]
        [Switch]
        $Show

    )


    #Check if Username and Password are provided
    if ($UserName -and $Password)
    {
        $SecurePassword = ConvertTo-SecureString $Password -AsPlainText -Force
	    $Creds = New-Object System.Management.Automation.PSCredential ($UserName, $SecurePassword)
    }
    else
    {
        $Creds = $False
    }
    
    if ($Show)
    {
        if ($Creds)
        {
            Invoke-Command -ScriptBlock {netsh interface portproxy show all} -ComputerName $ComputerName -Credential $Creds
        }
        else
        {
            Invoke-Command -ScriptBlock {netsh interface portproxy show all} -ComputerName $ComputerName 
        }
    }
    
    if (!$Delete -and !$Show)
    {
        #Prepare relay commands
        $V4tov4Relay = "netsh interface portproxy add v4tov4 listenport=$ListenPort listenaddress=$ListenAddress connectport=$ConnectPort connectaddress=$ConnectAddress protocol=tcp"
        $V6toV4Relay = "netsh interface portproxy add v6tov4 listenport=$ListenPort listenaddress=$ListenAddress connectport=$ConnectPort connectaddress=$ConnectAddress"
        $V4tov6Relay = "netsh interface portproxy add v4tov6 listenport=$ListenPort listenaddress=$ListenAddress connectport=$ConnectPort connectaddress=$ConnectAddress"
        $V6toV6Relay = "netsh interface portproxy add v6tov6 listenport=$ListenPort listenaddress=$ListenAddress connectport=$ConnectPort connectaddress=$ConnectAddress protocol=tcp"

        #Create a scriptblock depending upon the type of relay.
        switch ($Relay)
        {   
            "v4tov4" 
            {
                $sb = [ScriptBlock]::Create($V4toV4Relay)
                Write-Output "Initiating v4tov4 Relay. Listening on $ListenAddress, Port $ListenPort. Connecting to $Connectaddress, Port $Connectport"
            }
            "v6tov4" 
            {
                $sb = [ScriptBlock]::Create($V6toV4Relay)
                Write-Output "Initiating v6tov4 Relay. Listening on $ListenAddress, Port $ListenPort. Connecting to $Connectaddress, Port $Connectport"
            }
            "v4tov6" 
            {
                $sb = [ScriptBlock]::Create($V4toV6Relay)
                Write-Output "Initiating v4tov6 Relay. Listening on $ListenAddress, Port $ListenPort. Connecting to $Connectaddress, Port $Connectport"
            }
            "v6tov6" 
            {
                $sb = [ScriptBlock]::Create($V6toV6Relay)
                Write-Output "Initiating v6tov6 Relay. Listening on $ListenAddress, Port $ListenPort. Connecting to $Connectaddress, Port $Connectport"
            }
        }
    
        #Execute the netsh command on remote computer
        if ($Creds)
        {
            Invoke-Command -ScriptBlock $sb -ComputerName $ComputerName -Credential $Creds
            Invoke-Command -ScriptBlock {param ($SBRelay) netsh interface portproxy show $SBRelay } -ArgumentList $Relay -ComputerName $ComputerName -Credential $Creds
        }
        else
        {
            Invoke-Command -ScriptBlock $sb -ComputerName $ComputerName
            Invoke-Command -ScriptBlock {netsh interface portproxy show $Relay } -ComputerName $ComputerName
        }
    }
    if ($Delete)
    {
        #Relay commands for deletion
        $V4tov4Relay = "netsh interface portproxy delete v4tov4 listenport=$ListenPort listenaddress=$ListenAddress protocol=tcp"
        $V6toV4Relay = "netsh interface portproxy delete v6tov4 listenport=$ListenPort listenaddress=$ListenAddress"
        $V4tov6Relay = "netsh interface portproxy delete v4tov6 listenport=$ListenPort listenaddress=$ListenAddress"
        $V6toV6Relay = "netsh interface portproxy delete v6tov6 listenport=$ListenPort listenaddress=$ListenAddress protocol=tcp"

        #Create a scriptblock for deleting the relay, depending upon its type.
        switch ($Relay)
        {   
            "v4tov4" 
            {
                $sbdelete = [ScriptBlock]::Create($V4toV4Relay)
                Write-Output "Deleting v4tov4 Relay which was listening on $ListenAddress, Port $ListenPort and connecting to $Connectaddress, Port $Connectport"
            }
            "v6tov4" 
            {
                $sbdelete = [ScriptBlock]::Create($V6toV4Relay)
                Write-Output "Deleting v6tov4 Relay which was listening on $ListenAddress, Port $ListenPort and connecting to $Connectaddress, Port $Connectport"
            }
            "v4tov6" 
            {
                $sbdelete = [ScriptBlock]::Create($V4toV6Relay)
                Write-Output "Deleting v4tov6 Relay which was listening on $ListenAddress, Port $ListenPort and connecting to $Connectaddress, Port $Connectport"
            }
            "v6tov6" 
            {
                $sbdelete = [ScriptBlock]::Create($V6toV6Relay)
                Write-Output "Deleting v6tov6 Relay which was listening on $ListenAddress, Port $ListenPort and connecting to $Connectaddress, Port $Connectport"
            }
        }
    
        #Execute the netsh command on remote computer
        if ($Creds)
        {
            Invoke-Command -ScriptBlock $sbdelete -ComputerName $ComputerName -Credential $Creds
            Invoke-Command -ScriptBlock {param ($SBRelay) netsh interface portproxy show $SBRelay } -ArgumentList $Relay -ComputerName $ComputerName -Credential $Creds
        }
        else
        {
            Invoke-Command -ScriptBlock $sbdelete -ComputerName $ComputerName
            Invoke-Command -ScriptBlock {netsh interface portproxy show $Relay } -ComputerName $ComputerName
        }
    }
}

