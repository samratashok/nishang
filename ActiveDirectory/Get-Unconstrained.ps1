function Get-Unconstrained {
<# 
.SYNOPSIS 
Nishang script which searches computers in current domain which have Unconstrained Delegation Enabled.
 
.DESCRIPTION 
The script searches in the current domain for computers which have Unconstrained Delegation enabled.

The script needs to be run from an elevated shell. It requires ActiveDirectory module available with RSAT-AD-PowerShell
Windows feature. The feature and module are auto-enabled by the script on a Windows Server 2012 machine.

The commands used in this post are taken from this post https://adsecurity.org/?p=1667

.PARAMETER Details
Returns more detailed description of the computer with Unconstrained delegation.

.EXAMPLE 
PS > Get-Unconstrained 
Use above command to search for computers which have unconstrained delegation enabled. Shows name of the computers.


.EXAMPLE 
PS > Get-Unconstrained -Details
Use above command to search for computers which have unconstrained delegation enabled. Shows detailed output.
 
.LINK 
http://www.labofapenetrationtester.com/2016/02/getting-domain-admin-with-kerberos-unconstrained-delegation.html
https://adsecurity.org/?p=1667
https://github.com/samratashok/nishang
#>

    [CmdletBinding()] Param (
        [Parameter(Position = 0, Mandatory=$False)]
        [Switch]
        $Detailed
    )


    # Check if User is Elevated
    $currentPrincipal = New-Object Security.Principal.WindowsPrincipal( [Security.Principal.WindowsIdentity]::GetCurrent())
    if($currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) -ne $true) 
    {
        Write-Warning "Run the Command as an Administrator"
        break
    }

    #Check for Server 2012
    $OSVersion = (Get-WmiObject -Class win32_OperatingSystem).BuildNumber
    if($OSVersion -notmatch 96)
    {
        Write-Warning "This script needs ActiveDirectory module which is available in Server 2012 with RSAT-AD-PowerShell. For other Window versions, you need to install the module manually."
    }
    else
    {
        Write-Verbose "Running on Server 2012"
    }

    #Check if the Windows feature is already installed
    if((Get-WindowsFeature -Name RSAT-AD-PowerShell).InstallState -ne "Installed")
    {
        Write-Warning "Required module not found. Installing it."
        Add-WindowsFeature -Name RSAT-AD-Powershell -Verbose
    }
    else
    {
        Write-Verbose "Required module found. Continuing.."
    }
    
    #Import the required module
    Write-Verbose "Importing the ActiveDirectory Module"
    Import-Module ActiveDirectory

    #Search for Unconstrained delegation
    Write-Output "Searching for domain computers with Unconstrained Delegation"
    $computer = Get-ADComputer -Filter {(TrustedForDelegation -eq $True) -and (PrimaryGroupID -eq 515)}
    if ($Detailed)
    {
        Get-ADComputer $computer.Name -Properties *
    }
    else
    {
        $computer.DnsHostName
    }
}