function Remove-PoshRat
{
<#
.SYNOPSIS
Nishang script which removes firewall rules installed by PoshRat.

.DESCRIPTION
Use this script to remove firewall rules installed by PoshRat.
Firewall rules with the name of 
"Windows Update HTTPS" are removed by this script. 

The script must be run from an elevated shell.

.PARAMETER IPAddress
The IP address which was specified for listener. 

.EXAMPLE
PS > Remove-PoshRat -IPAddress 192.168.254.1

Above removes the certificates and firewall rules added by Invoke-PoshRatHttps

.EXAMPLE
PS > Remove-PoshRat

.LINK
http://www.labofapenetrationtester.com/2015/05/week-of-powershell-shells-day-3.html
https://github.com/subTee/PoshRat
https://github.com/samratashok/nishang
#>     
    [CmdletBinding()] Param(

        [Parameter(Position = 0, Mandatory = $true)]
        [String]
        $IPAddress
    )

    #Delete the Firewall rules
    netsh advfirewall firewall delete rule name="WindowsUpdate HTTPS"
    netsh advfirewall firewall delete rule name="WindowsUpdate HTTP"
}

