function Out-DnsTxt
{
<#
.SYNOPSIS
Script for Nishang to generate DNS TXT records which could be used with other scripts. 

.DESCRIPTION
Use this script to generate DNS TXT records to be used with DNS_TXT_Pwnage and Execute-DNSTXT-Code.
The script asks for a path to a plain file or string, compresses and encodes it and writes to a file "encodedtxt.txt" in the current working directory.
Each line in the generated file is a DNS TXT record to be saved in separate subbdomain.
The length of DNS TXT records is assumed to be 255 characters by the script.

.PARAMETER DataToEncode
The path of the file to be decoded. Use with -IsString to enter a string.

.PARAMETER OutputFilePath
The path of the output file. Default is "encodedtxt.txt" in the current working directory.

.PARAMETER $LengthOfTXT
The length of the TXT records. Default is 255.

.PARAMETER IsString
Use this to specify the command to be encoded if you are passing a string in place of a filepath.

.EXAMPLE
PS > OUT-DNSTXT -DataToEncode C:\nishang\Gather\Get-Information.ps1
Use above command to generate encoded DNS TXT records. Each record must be put in a separate subdomain.

.EXAMPLE
PS > OUT-DNSTXT "Get-Service" -IsString
Use above to generate TXT records for a command.


.EXAMPLE
PS > OUT-DNSTXT -DataToEncode C:\shellcode\shellcode.txt
Use above command to generate encoded DNS TXT records for a shellcode. Each record must be put in a separate subdomain.

.LINK
http://www.labofapenetrationtester.com/2015/01/fun-with-dns-txt-records-and-powershell.html
https://github.com/samratashok/nishang

#>
    [CmdletBinding()] Param(
        [Parameter(Position = 0, Mandatory = $True)]
        [String]
        $DataToEncode,

        [Parameter(Position = 1, Mandatory = $False)]
        [String]
        $OutputFilePath = "$pwd\encodedtxt.txt", 

        [Parameter(Mandatory = $False)]
        [String]
        $LengthOfTXT = 255, 

        [Switch]
        $IsString
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
    $index = [math]::floor($Compressed.Length/$LengthOfTXT)
    $i = 0
    Out-File -InputObject $null -FilePath $OutputFilePath
    #Split encoded input in strings of 255 characters if its length is more than 255.
    if ($Compressed.Length -gt $LengthOfTXT)
    {
        while ($i -lt $index )
        {
            $TXTRecord = $Compressed.Substring($i*$LengthOfTXT,$LengthOfTXT)
            $i +=1
            Out-File -InputObject $TXTRecord -FilePath $OutputFilePath -Append
            Out-File -InputObject "`n`n`n" -FilePath $OutputFilePath -Append
        }
        $remainingindex = $Compressed.Length%$LengthOfTXT
        if ($remainingindex -ne 0)
        {
            $TXTRecord = $Compressed.Substring($index*$LengthOfTXT, $remainingindex)
            $TotalRecords = $index + 1
        }
        #Write to file
        Out-File -InputObject $TXTRecord -FilePath $OutputFilePath -Append
        Write-Output "You need to create $TotalRecords TXT records."
        Write-Output "All TXT Records written to $OutputFilePath"
    }
    #If the input has small length, it could be used in a single subdomain.
    else
    {
        Write-Output "TXT Record could fit in single subdomain."
        Write-Output $Compressed
        Out-File -InputObject $Compressed -FilePath $OutputFilePath -Append
        Write-Output "TXT Records written to $OutputFilePath"
    }


}

