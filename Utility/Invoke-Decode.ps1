
function Invoke-Decode
{
<#
.SYNOPSIS
Script for Nishang to decode the data encoded by Invoke-Encode, DNS TXT and POST exfiltration methods.

.DESCRIPTION
The script asks for an encoded string as an option, decodes it and writes to a file "decoded.txt" in the current working directory.
Both the encoding and decoding is based on the code by ikarstein.

.PARAMETER EncodedData
The path of the file to be decoded. Use with -IsString to enter a string.


.PARAMETER OutputFilePath
The path of the output file. Default is "decoded.txt" in the current working directory.

.PARAMETER IsString
Use this to specify if you are passing a string ins place of a filepath.

.EXAMPLE

PS > Invoke-Decode -EncodedData C:\files\encoded.txt

.EXAMPLE

PS > Invoke-Decode c08t0Q0oyk9OLS7m5QIA -IsString

Use above to decode a string.

.LINK
http://www.darkoperator.com/blog/2013/3/21/powershell-basics-execution-policy-and-code-signing-part-2.html
https://github.com/samratashok/nishang

#>
    [CmdletBinding()] Param(
        [Parameter(Position = 0, Mandatory = $True)]
        [String]
        $EncodedData,

        [Parameter(Position = 1, Mandatory = $False)]
        [String]
        $OutputFilePath = ".\decoded.txt", 

        [Switch]
        $IsString
    )
    
    if($IsString -eq $true)
    {
    
       $data = $EncodedData
       
    }
    else
    {
        $data = Get-Content $EncodedData -Encoding UTF8 
    }
    $dec = [System.Convert]::FromBase64String($data)
    $ms = New-Object System.IO.MemoryStream
    $ms.Write($dec, 0, $dec.Length)
    $ms.Seek(0,0) | Out-Null
    $cs = New-Object System.IO.Compression.DeflateStream ($ms, [System.IO.Compression.CompressionMode]::Decompress)
    $sr = New-Object System.IO.StreamReader($cs)
    $output = $sr.readtoend()
    Out-File -InputObject $output -FilePath $OutputFilePath
    Write-Host "Decode data written to $OutputFilePath"
}

