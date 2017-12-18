function Invoke-Encode
{
<#
.SYNOPSIS
Script for Nishang to encode and compress plain data.

.DESCRIPTION
The script asks for a path to a plain file or string, encodes it and writes to a file "encoded.txt" in the current working directory.

If the switch -OutCommand is used. An encoded command which could be executed on a non-powershell console is also generated.
The encoded command is useful in case of non-interactive shells like webshell or when special characters in scripts may
create problems, for example, a meterpreter session.

.PARAMETER DataToEncode
The path of the file to be decoded. Use with -IsString to enter a string.

.PARAMETER OutputFilePath
The path of the output file. Default is "encoded.txt" in the current working directory.

.PARAMETER OutputCommandFilePath
The path of the output file where encoded command would be written. Default is "encodedcommand.txt" in the current working directory.

.PARAMETER IsString
Use this to specify the data/command to be encodedif you are passing a string in place of a filepath.

.PARAMETER OutCommand
Generate an encoded command which could be used with -EncodedCommand parameter of PowerShell.

.PARAMETER PostScriptCommand
Generate a PowerShell command which is much smaller than encoded scripts. Useful in scenrios where
longer commands or scripts could not be used. 

.EXAMPLE

PS > Invoke-Encode -DataToEncode C:\scripts\data.txt

Use above command to generate encoded data which could be Decoded using the Invoke-Decode script.


PS > Invoke-Encode -DataToEncode C:\scripts\evil.ps1 -OutCommand

Use above command to generate encoded data and encoded command which could be used on a non-powershell console.
Use powershell -EncodedCommand <generated code here>


.EXAMPLE

PS > Invoke-Encode "A Secret message" -IsString

Use above to encode a string.


.EXAMPLE

PS > Invoke-Encode Get-Process -IsString -OutCommand

Use above to encode a command.


.LINK
http://www.darkoperator.com/blog/2013/3/21/powershell-basics-execution-policy-and-code-signing-part-2.html
https://github.com/samratashok/nishang

#>
    [CmdletBinding()] Param(
        [Parameter(Position = 0, Mandatory = $True)]
        [String]
        $DataToEncode,

        [Parameter(Position = 1, Mandatory = $False)]
        [String]
        $OutputFilePath = ".\encoded.txt", 

        [Parameter(Position = 2, Mandatory = $False)]
        [String]
        $OutputCommandFilePath = ".\encodedcommand.txt",

        [Switch]
        $OutCommand,

        [Switch]
        $IsString,

        [Switch]
        $PostScriptCommand

    )
    if($IsString -eq $true)
    {
    
       $Enc = $DataToEncode
       
    }
    else
    {
        $Enc = Get-Content $DataToEncode -Encoding Ascii
    }


    #Compression logic from http://www.darkoperator.com/blog/2013/3/21/powershell-basics-execution-policy-and-code-signing-part-2.html
    $ms = New-Object IO.MemoryStream
    $action = [IO.Compression.CompressionMode]::Compress
    $cs = New-Object IO.Compression.DeflateStream ($ms,$action)
    $sw = New-Object IO.StreamWriter ($cs, [Text.Encoding]::ASCII)
    $Enc | ForEach-Object {$sw.WriteLine($_)}
    $sw.Close()
    
    # Base64 encode stream
    $Compressed = [Convert]::ToBase64String($ms.ToArray())
    Out-File -InputObject $Compressed -FilePath $OutputFilePath
    Write-Output "Encoded data written to $OutputFilePath"

    if (($OutCommand -eq $True) -or ($PostScriptCommand -eq $True))
    {
        #http://www.darkoperator.com/blog/2013/3/21/powershell-basics-execution-policy-and-code-signing-part-2.html
        $command = "Invoke-Expression `$(New-Object IO.StreamReader (" +

        "`$(New-Object IO.Compression.DeflateStream (" +

        "`$(New-Object IO.MemoryStream (,"+

        "`$([Convert]::FromBase64String('$Compressed')))), " +

        "[IO.Compression.CompressionMode]::Decompress)),"+

        " [Text.Encoding]::ASCII)).ReadToEnd();"
        
        #Generate Base64 encoded command to use with the powershell -encodedcommand paramter"
        $UnicodeEncoder = New-Object System.Text.UnicodeEncoding
        $EncScript = [Convert]::ToBase64String($UnicodeEncoder.GetBytes($command))
        #Check for max. length supported by Windows. If the base64 encoded command is longer use the other one.
        if (($EncScript.Length -gt 8190) -or ($PostScriptCommand -eq $True))
        {
            Out-File -InputObject $command -FilePath $OutputCommandFilePath
            Write-Output "Encoded command written to $OutputCommandFilePath"
        }
        else
        {
            Out-File -InputObject $EncScript -FilePath $OutputCommandFilePath
            Write-Output "Encoded command written to $OutputCommandFilePath"
        }
    }
}

