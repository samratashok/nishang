function Remove-PoshRat
{
<#
.SYNOPSIS
Nishang script which removes certificates and firewall rules installed by PoshRat.

.DESCRIPTION
Use this script to remove certificates and firewall rules installed by PoshRat.
Root Certificate with the name of "Windows Update Agent" and firewall rules with the name of 
"Windows Update HTTPS" and "Windows Update HTTP" are removed by this script. 

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

    function Remove-CACertificate ([String] $CertName)
    {
        $CACertificate = (Get-ChildItem Cert:\LocalMachine\My | Where-Object {$_.Subject -match $CertName })
        $StoreScope = "LocalMachine"
        $StoreName = "My"
        $store = New-Object System.Security.Cryptography.X509Certificates.X509Store $StoreName, $StoreScope
        $store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
        $store.Remove($CACertificate)
        $store.Close()
    }
    #Remove the certificate
    Remove-CACertificate "Windows Update Agent"
    Remove-CaCertificate $IPAddress
    #Delete the Firewall rules
    netsh advfirewall firewall delete rule name="WindowsUpdate HTTPS"
    netsh advfirewall firewall delete rule name="WindowsUpdate HTTP"
}