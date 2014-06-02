
#Get-ChildItem (Join-Path $PSScriptRoot *.ps1) #| % { . $_.FullName}

Get-ChildItem -Recurse (Join-Path $PSScriptRoot *.ps1) | ForEach-Object { if ($_.Name -ne "Keylogger.ps1") {. $_.FullName}}

