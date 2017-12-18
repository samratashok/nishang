function ConvertTo-ROT13
{
<#
.SYNOPSIS
Nishang script which can encode a string to ROT13 or decode a ROT13 string.

.DESCRIPTION
Nishang script which can encode a string to ROT13 or decode a ROT13 string.

.PARAMETER rot13string
The string which needs to be encoded or decode.

.EXAMPLE
PS > ConvertTo-ROT13 -rot13string supersecret
Use above command to encode a string.

.EXAMPLE
PS > ConvertTo-ROT13 -rot13string fhcrefrperg
Use above command to decode a string.

.LINK
http://learningpcs.blogspot.com/2012/06/powershell-v2-function-convertfrom.html
http://www.labofapenetrationtester.com/2016/11/exfiltration-of-user-credentials-using-wlan-ssid.html
https://github.com/samratashok/nishang
#>
    [CmdletBinding()] param(
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

