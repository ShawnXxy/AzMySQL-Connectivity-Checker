# [System.Reflection.Assembly]::LoadWithPartialName("MySql.Data")

# Parameter region when Invoke-Command -ScriptBlock is used
$parameters = $args[0]
if ($null -ne $parameters) {
    $Server = $parameters['Server']
    $Database = $parameters['Database']
    $User = $parameters['User']
    $Password = $parameters['Password']
    $EncryptionProtocol = $parameters['EncryptionProtocol']
    if ($null -ne $parameters['RepositoryBranch']) {
        $RepositoryBranch = $parameters['RepositoryBranch']
    }
}

$Server = $Server.Trim()
$Server = $Server.Replace('tcp:', '')
$Server = $Server.Replace(',3306', '')
# $Server = $Server.Replace(',3342', '')
$Server = $Server.Replace(';', '')

if ($null -eq $User -or '' -eq $User) {
    $User = 'AzMySQLConnCheckerUser'
}

if ($null -eq $Password -or '' -eq $Password) {
    $Password = 'AzMySQLConnCheckerPassword'
}

if ($null -eq $Database -or '' -eq $Database) {
    $Database = 'information_schema'
}

if ($null -eq $Local) {
    $Local = $false
}

if ($null -eq $RepositoryBranch) {
    $RepositoryBranch = 'master'
}

# PowerShell Container Image Support Start

if (!$(Get-Command 'Test-NetConnection' -errorAction SilentlyContinue)) {
    function Test-NetConnection {
        param(
            [Parameter(Position = 0, Mandatory = $true)] $HostName,
            [Parameter(Mandatory = $true)] $Port
        );
        process {
            $client = [TcpClient]::new()
            
            try {
                $client.Connect($HostName, $Port)
                $result = @{TcpTestSucceeded = $true; InterfaceAlias = 'Unsupported' }
            }
            catch {
                $result = @{TcpTestSucceeded = $false; InterfaceAlias = 'Unsupported' }
            }

            $client.Dispose()

            return $result
        }
    }
}

if (!$(Get-Command 'Resolve-DnsName' -errorAction SilentlyContinue)) {
    function Resolve-DnsName {
        param(
            [Parameter(Position = 0)] $Name,
            [Parameter()] $Server,
            [switch] $CacheOnly,
            [switch] $DnsOnly,
            [switch] $NoHostsFile
        );
        process {
            # ToDo: Add support
            Write-Host "WARNING: Current environment doesn't support multiple DNS sources."
            return @{ IPAddress = [Dns]::GetHostAddresses($Name).IPAddressToString };
        }
    }
}

if (!$(Get-Command 'Get-NetAdapter' -errorAction SilentlyContinue)) {
    function Get-NetAdapter {
        param(
            [Parameter(Position = 0, Mandatory = $true)] $HostName,
            [Parameter(Mandatory = $true)] $Port
        );
        process {
            Write-Host 'Unsupported'
        }
    }
}

if (!$(Get-Command 'netsh' -errorAction SilentlyContinue) -and $CollectNetworkTrace) {
    Write-Host "WARNING: Current environment doesn't support network trace capture. This option is now disabled!"
    $CollectNetworkTrace = $false
}

# PowerShell Container Image Support End

function IsMySQLFlexPublic([String] $resolvedAddress) {
    
    $hasPrivateLink = HasPrivateLink $Server
    $gateway = $MySQLSterlingGateways| Where-Object { $_.Gateways -eq $resolvedAddress }

    # return [bool]((!$gateway) -and (!$hasPrivateLink))
    if (!$gateway -and (!$hasPrivateLink)) {
        return $true
    }
    else {
        return $false
    }
}

function IsMySQLVNet([String] $resolvedAddress) {
    
    $hasPrivateLink = HasPrivateLink $Server
    $gateway = $MySQLSterlingGateways| Where-Object { $_.Gateways -eq $resolvedAddress }

    # return [bool]((!$gateway) -and ($hasPrivateLink))
    if (!$gateway -and $hasPrivateLink) {
        return $true
    }
    else {
        return $false
    }
}

function SendAnonymousUsageData {
    try {
        #Despite computername and username will be used to calculate a hash string, this will keep you anonymous but allow us to identify multiple runs from the same user
        $StringBuilderHash = [System.Text.StringBuilder]::new()
        
        $text = $env:computername + $env:username
        if ([string]::IsNullOrEmpty($text)) {
            $text = $Host.InstanceId
        }
        
        [System.Security.Cryptography.HashAlgorithm]::Create("MD5").ComputeHash([System.Text.Encoding]::UTF8.GetBytes($text)) | ForEach-Object {
            [Void]$StringBuilderHash.Append($_.ToString("x2"))
        }

        $body = New-Object PSObject `
        | Add-Member -PassThru NoteProperty name 'Microsoft.ApplicationInsights.Event' `
        | Add-Member -PassThru NoteProperty time $([System.dateTime]::UtcNow.ToString('o')) `
        | Add-Member -PassThru NoteProperty iKey "c65afb3b-f428-49d2-a3de-cf2ecc803cc3" `
        | Add-Member -PassThru NoteProperty tags (New-Object PSObject | Add-Member -PassThru NoteProperty 'ai.user.id' $StringBuilderHash.ToString()) `
        | Add-Member -PassThru NoteProperty data (New-Object PSObject `
            | Add-Member -PassThru NoteProperty baseType 'EventData' `
            | Add-Member -PassThru NoteProperty baseData (New-Object PSObject `
                | Add-Member -PassThru NoteProperty ver 2 `
                | Add-Member -PassThru NoteProperty name '1.4'));

        $body = $body | ConvertTo-JSON -depth 5;
        Invoke-WebRequest -Uri 'https://dc.services.visualstudio.com/v2/track' -Method 'POST' -UseBasicParsing -body $body > $null
    }
    catch {
        Write-Output 'Error sending anonymous usage data:'
        Write-Output $_.Exception.Message
    }
}

function PrintLocalNetworkConfiguration() {
    if (![System.Net.NetworkInformation.NetworkInterface]::GetIsNetworkAvailable()) {
        Write-Output "There's no network connection available!"
        throw
    }

    $computerProperties = [System.Net.NetworkInformation.IPGlobalProperties]::GetIPGlobalProperties()
    $networkInterfaces = [System.Net.NetworkInformation.NetworkInterface]::GetAllNetworkInterfaces()

    Write-Output $('Interface information for ' + $computerProperties.HostName + '.' + $networkInterfaces.DomainName)

    foreach ($networkInterface in $networkInterfaces) {
        if ($networkInterface.NetworkInterfaceType -eq 'Loopback') {
            continue
        }

        $properties = $networkInterface.GetIPProperties()

        Write-Output $(' Interface name: ' + $networkInterface.Name)
        Write-Output $(' Interface description: ' + $networkInterface.Description)
        Write-Output $(' Interface type: ' + $networkInterface.NetworkInterfaceType)
        Write-Output $(' Operational status: ' + $networkInterface.OperationalStatus)

        Write-Output ' Unicast address list:'
        Write-Output $('  ' + [String]::Join([Environment]::NewLine + '  ', [System.Linq.Enumerable]::Select($properties.UnicastAddresses, [Func[System.Net.NetworkInformation.UnicastIPAddressInformation, IPAddress]] { $args[0].Address })))

        Write-Output ' DNS server address list:'
        Write-Output $('  ' + [String]::Join([Environment]::NewLine + '  ', $properties.DnsAddresses))

        Write-Output ''
    }
}

function PrintDNSResults($dnsResult, [string] $dnsSource) {
    if ($dnsResult) {
        Write-Output $(' Found DNS record in' + $dnsSource + '(IP Address:' + $dnsResult.IPAddress + ')')
    }
    else {
        Write-Output $(' Could not find DNS record in' + $dnsSource)
    }
}

function ValidateDNS([String] $Server) {
    Try {
        Write-Output $('Validating DNS record for' + $Server)

        $DNSfromHosts = Resolve-DnsName -Name $Server -CacheOnly -ErrorAction SilentlyContinue
        PrintDNSResults $DNSfromHosts 'hosts file'

        $DNSfromCache = Resolve-DnsName -Name $Server -NoHostsFile -CacheOnly -ErrorAction SilentlyContinue
        PrintDNSResults $DNSfromCache 'cache'

        $DNSfromCustomerServer = Resolve-DnsName -Name $Server -DnsOnly -ErrorAction SilentlyContinue
        PrintDNSResults $DNSfromCustomerServer 'DNS server'

        $DNSfromAzureDNS = Resolve-DnsName -Name $Server -DnsOnly -Server 208.67.222.222 -ErrorAction SilentlyContinue
        PrintDNSResults $DNSfromAzureDNS 'Open DNS'
    }
    Catch {
        Write-Output "Error at ValidateDNS"
        Write-Output $_.Exception.Message
    }
}

if ([string]::IsNullOrEmpty($env:TEMP)) {
    $env:TEMP = '/tmp';
}

try {
    Write-Output '******************************************'
    Write-Output '      Azure MySQL Connectivity Checker      '
    Write-Output '******************************************'
    Write-Output "WARNING: Reduced version of Azure MySQL Connectivity Checker is running due to current environment's nature/limitations."
    Write-Output 'WARNING: This version does not create any output files, please copy the output directly from the console.'
    
    if (!$Server -or $Server.Length -eq 0) {
        Write-Output 'The $Server parameter is empty'
        Write-Output 'Please see more details about how to use this tool at https://github.com/ShawnXxy/AzMySQL-Connectivity-Checker'
        Write-Output ''
        throw
    }
    
    if (!$Server.EndsWith('.mysql.database.azure.com') `
            -and !$Server.EndsWith('.privatelink.mysql.database.azure.com') `
            -and !$Server.EndsWith('.mysql.database.chinacloudapi.cn') `
            -and !$Server.EndsWith('.privatelink.mysql.database.chinacloudapi.com')) {
        $Server = $Server + '.mysql.database.azure.com'
    }

    if ($SendAnonymousUsageData) {
        SendAnonymousUsageData
    }

    PrintLocalNetworkConfiguration
    ValidateDNS $Server
    
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 -bor [Net.SecurityProtocolType]::Tls11 -bor [Net.SecurityProtocolType]::Tls
    $path = $env:TEMP + "/TDSClient.dll"
    
    if (Test-Path $path) {
        Remove-Item $path
    }
    
    Invoke-WebRequest -Uri $('https://github.com/ShawnXxy/AzMySQL-Connectivity-Checker/raw/' + $RepositoryBranch + '/netstandard2.0/TDSClient.dll') -OutFile $path -UseBasicParsing
    
    $path = $env:TEMP + "/TDSClient.dll"
    $assembly = [System.IO.File]::ReadAllBytes($path)
    [System.Reflection.Assembly]::Load($assembly) | Out-Null
    
    [TDSClient.TDS.Utilities.LoggingUtilities]::SetVerboseLog([Console]::Out)
    try {
        switch ($EncryptionProtocol) {
            'Tls 1.0' {
                $encryption = [System.Security.Authentication.SslProtocols]::Tls
                break
            }
            'Tls 1.1' {
                $encryption = [System.Security.Authentication.SslProtocols]::Tls11
                break
            }
            'Tls 1.2' {
                $encryption = [System.Security.Authentication.SslProtocols]::Tls12
                break
            }
            # Not supported
            #'Tls 1.3' {
            #    $encryption = [System.Security.Authentication.SslProtocols]::Tls13
            #    break
            #}
            default {
                # Allow the operating system to choose the best protocol to use
                $encryption = [System.Security.Authentication.SslProtocols]::Tls12 -bor [System.Security.Authentication.SslProtocols]::Tls11 -bor [System.Security.Authentication.SslProtocols]::Default
            }
        }
    
        $Port = 3306
    
        $tdsClient = [TDSClient.TDS.Client.TDSSQLTestClient]::new($Server, $Port, $User, $Password, $Database, $encryption)
        $tdsClient.Connect()
        $tdsClient.Disconnect()
    }
    catch {
        [TDSClient.TDS.Utilities.LoggingUtilities]::WriteLog('Failure: ' + $_.Exception.InnerException.Message)
    }
    finally {
        [TDSClient.TDS.Utilities.LoggingUtilities]::ClearVerboseLog()
    }
} catch {
    Write-Output $_.Exception.Message
}