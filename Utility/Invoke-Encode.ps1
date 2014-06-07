<#
.SYNOPSIS
Script for Nishang to encode and compress plain data.

.DESCRIPTION
The script asks for a path to a plain file, encodes it and writes to a file "encoded.txt" in the current working directory.
Both the encoding and decoding is based on the code by ikarstein.

.PARAMETER DataToEncode
The path of the file to be decoded. Use with -IsString to enter a string.


.PARAMETER OutputFilePath
The path of the output file. Default is "encoded.txt" in the current working directory.

.PARAMETER IsString
Use this to specify if you are passing a string ins place of a filepath.

.EXAMPLE

PS > Invoke-Encode -DataToEncode C:\files\encoded.txt

.EXAMPLE

PS > Invoke-Encode Get-Process -IsString

Use above to decode a string.

.LINK
http://blog.karstein-consulting.com/2010/10/19/how-to-embedd-compressed-scripts-in-other-powershell-scripts/
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
    $Compressed
    Out-File -InputObject $Compressed -FilePath .\encoded.txt
    Write-Host "Decode data written to $OutputFilePath"
}