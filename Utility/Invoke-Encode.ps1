<#
.SYNOPSIS
Script for Nishang to encode and compress plain data.

.DESCRIPTION
The script asks for a path to a plain file, encodes it and writes to a file "encoded.txt" in the current working directory.
If the switch OutCommand is used. A command which could be used with "powershell.exe -encodedcommand" is also generated.

.PARAMETER DataToEncode
The path of the file to be decoded. Use with -IsString to enter a string.

.PARAMETER OutputFilePath
The path of the output file. Default is "encoded.txt" in the current working directory.

.PARAMETER OutputCommandFilePath
The path of the output file where encoded command would be written. Default is "encodedcommand.txt" in the current working directory.

.PARAMETER IsString
Use this to specify if you are passing a string ins place of a filepath.

.EXAMPLE

PS > Invoke-Encode -DataToEncode C:\files\encoded.txt -OutCommand

Use above command to generate encoded data and encoded command which could be used with "powershell.exe -encodedcommand"


.EXAMPLE

PS > Invoke-Encode -DataToEncode C:\files\encoded.txt

.EXAMPLE

PS > Invoke-Encode Get-Process -IsString

Use above to decode a string.

.LINK
http://blog.karstein-consulting.com/2010/10/19/how-to-embedd-compressed-scripts-in-other-powershell-scripts/
http://www.darkoperator.com/blog/2013/3/21/powershell-basics-execution-policy-and-code-signing-part-2.html
https://github.com/samratashok/nishang

#>



function Invoke-Encode
{
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
        $IsString
    )
    if($IsString -eq $true)
    {
    
       $Enc = $DataToEncode
       
    }
    else
    {
        $Enc = Get-Content $DataToEncode -Encoding UTF8 
    }

    $data = [string]::Join("`n", $Enc)
    $ms = New-Object System.IO.MemoryStream
    $cs = New-Object System.IO.Compression.GZipStream($ms, [System.IO.Compression.CompressionMode]::Compress)
    $sw = New-Object System.IO.StreamWriter($cs)
    $sw.Write($data)
    $sw.Close();
    $Compressed = [Convert]::ToBase64String($ms.ToArray())
    Write-Verbose $Compressed
    Out-File -InputObject $Compressed -FilePath $OutputFilePath
    Write-Output "Encoded data written to $OutputFilePath"

    if ($OutCommand -eq $True)
    {
        #http://www.darkoperator.com/blog/2013/3/21/powershell-basics-execution-policy-and-code-signing-part-2.html
        $command = "Invoke-Expression `$(New-Object IO.StreamReader (" +

        "`$(New-Object IO.Compression.GZipStream (" +

        "`$(New-Object IO.MemoryStream (,"+

        "`$([Convert]::FromBase64String('$Compressed')))), " +

        "[IO.Compression.CompressionMode]::Decompress)),"+

        " [Text.Encoding]::ASCII)).ReadToEnd();"
        Write-Verbose $command
        Out-File -InputObject $command -FilePath $OutputCommandFilePath
        Write-Output "Encoded command written to $OutputCommandFilePath"
    }
}