﻿#Run locally parameters
try {
    [System.Reflection.Assembly]::LoadWithPartialName("MySql.Data")
}
catch {
    Write-Host MySQL Connector has not been installed on this Machine. Will use local one instead.
}


$LocalPath = [System.IO.Path]::GetDirectoryName($MyInvocation.MyCommand.Definition)
$Path = Join-Path $LocalPath 'AzureMySQLConnectivityChecker.ps1'

# Script parameters
$parameters = @{
    Server   = '.mysql.database.azure.com'
    Database = ''  # Set the name of the database you wish to test, 'information_schema' will be used by default if nothing is set
    User     = ''  # Set the login username you wish to use, 'AzMySQLConnCheckerUser' will be used by default if nothing is set
    Password = ''  # Set the login password you wish to use, 'AzMySQLConnCheckerPassword' will be used by default if nothing is set

    ## Optional parameters (default values will be used if ommited)
    SendAnonymousUsageData             = $true  # Set as $true (default) or $false； Send Anonymous Usage Data.
    CollectNetworkTrace                = $true  # Set as $true (default) or $false
    ConnectionAttempts                 = 3 # Number of connection attempts while running advanced connectivity tests
    DelayBetweenConnections            = 1 # Number of seconds to wait between connection attempts while running advanced connectivity tests
    #EncryptionProtocol = '' # Supported values: 'Tls 1.0', 'Tls 1.1', 'Tls 1.2'; Without this parameter operating system will choose the best protocol to use

    ## Run locally parameters
    Local                              = $true # Do Not Change
    LocalPath                          = $LocalPath # Do Not Change
}

Write-Host 'Please wait...'
Write-Host '(The tests are being run inside a PowerShell job and output will be updated only once the job completes all the tests)'
$ProgressPreference = "SilentlyContinue";
$job = Start-Job -ArgumentList $parameters -FilePath $Path
Wait-Job $job | Out-Null
Receive-Job -Job $job