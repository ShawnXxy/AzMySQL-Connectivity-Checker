# Azure MySQL Connectivity Checker

Inspired by https://github.com/Azure/SQL-Connectivity-Checker.

This PowerShell script will test the database connection as well as check the network connectivity to the Azure Database for MySQL instance. If the connection breaks, it will give generic instructions on how to fix it.
- Supports Single, Flexible (please provide FQDN).
- Supports Public Cloud (*.msyql.database.azure.com), Azure China (*.mysql.database.chinacloudapi.cn)  

**In order to run it you need to:**
1. Open Windows PowerShell ISE (in Administrator mode if possible)
In order for a network trace to be collected along with the tests ('CollectNetworkTrace' parameter) on the Windows Machine, PowerShell must be run as an administrator.

2. Open a New Script window

3. Paste the following in the script window:

    ```powershell
    
    $parameters = @{
        # Supports Single, Flexible (please provide FQDN, priavete endpoint and Vnet Ingested Flexible is supported)
        # Supports Public Cloud (*.msyql.database.azure.com), Azure China (*.mysql.database.chinacloudapi.cn)
        Server = '.mysql.database.azure.com' # or any other supported FQDN
        Database = ''  # Set the name of the database you wish to test, 'information_schema' will be used by default if nothing is set
        User = ''  # Set the login username you wish to use, 'AzMySQLConnCheckerUser' will be used by default if nothing is set
        Password = ''  # Set the login password you wish to use, 'AzMySQLConnCheckerPassword' will be used by default if nothing is set

        ## Optional parameters (default values will be used if omitted)
        SendAnonymousUsageData = $true  # Set as $true (default) or $false
        RunAdvancedConnectivityPolicyTests = $true  # Set as $true (default) or $false, this will load the library from Microsoft's GitHub repository needed for running advanced connectivity tests
        ConnectionAttempts = 1 # Number of connection attempts while running advanced connectivity tests
        DelayBetweenConnections = 1 # Number of seconds to wait between connection attempts while running advanced connectivity tests
        CollectNetworkTrace = $true  # Set as $true (default) or $false
        #EncryptionProtocol = '' # Supported values: 'Tls 1.0', 'Tls 1.1', 'Tls 1.2'; Without this parameter operating system will choose the best protocol to use
    }

    $ProgressPreference = "SilentlyContinue";
    $scriptFile = '/AzureMySQLConnectivityChecker.ps1'
    $scriptUrlBase = 'https://raw.githubusercontent.com/marlonj-ms/AzMySQL-Connectivity-Checker/master'
    cls
    Write-Host 'Trying to download the script file from GitHub (https://github.com/marlonj-ms/AzMySQL-Connectivity-Checker), please wait...'
    try {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 -bor [Net.SecurityProtocolType]::Tls11 -bor [Net.SecurityProtocolType]::Tls
        [System.Reflection.Assembly]::LoadWithPartialName("MySql.Data")
        Invoke-Command -ScriptBlock ([Scriptblock]::Create((Invoke-WebRequest ($scriptUrlBase + $scriptFile) -UseBasicParsing -TimeoutSec 60).Content)) -ArgumentList $parameters
        }
    catch {
        Write-Host 'ERROR: The script file could not be downloaded or the script execution failed:' -ForegroundColor Red
        $_.Exception
        Write-Host 'Confirm this machine can access https://github.com/marlonj-ms/MySQL-Connectivity-Checker/' -ForegroundColor Yellow
        Write-Host 'or use a machine with Internet access to see how to run this from machines without Internet. See how at https://github.com/marlonj-ms/MySQL-Connectivity-Checker/' -ForegroundColor Yellow
        Write-Host 'or raise your issue at https://github.com/marlonj-ms/AzMySQL-Connectivity-Checker/issues if the script execution fails..' -ForegroundColor Yellow
    }
    #end
    ```
4. Set the parameters on the script. You must set the server name and database name. User and password are optional, but best practices.

5. Run it.  
   Results are displayed in the output window. If the user has permissions to create folders, a folder with the resulting log file will be created, along with a ZIP file (`AllFiles.zip`). When running on Windows, the folder opens automatically after the script completes.

6. Examine the output for any issues detected, and recommended steps to resolve the issue.

## Run from Linux

With the current release, PowerShell uses .NET 5.0 as its runtime. PowerShell runs on Windows, macOS, and Linux platforms.  

In order to run this script on Linux you need to 
1. Installing PowerShell on Linux (if you haven't before).
   See how to get the packages at https://docs.microsoft.com/powershell/scripting/install/installing-powershell-core-on-linux

2. In Linux commandline, run ***pwsh*** from a Linux terminal to start a powershell terminal. 

3. Set the parameters on the following script then copy paste it to the powershell terminal started in above step#2. You must set the server name and database name. User and password are optional, but best practices.
    ```powershell
    $parameters = @{
        # Supports Single, Flexible (please provide FQDN, priavete endpoint and Vnet Ingested Flexible is supported)
        # Supports Public Cloud (*.msyql.database.azure.com), Azure China (*.mysql.database.chinacloudapi.cn)
        Server = '.mysql.database.azure.com' # or any other supported FQDN
        Database = ''  # Set the name of the database you wish to test, 'information_schema' will be used by default if nothing is set
        User = ''  # Set the login username you wish to use, 'AzMySQLConnCheckerUser' will be used by default if nothing is set
        Password = ''  # Set the login password you wish to use, 'AzMySQLConnCheckerPassword' will be used by default if nothing is set

        ## Optional parameters (default values will be used if omitted)
        SendAnonymousUsageData = $true  # Set as $true (default) or $false
        RunAdvancedConnectivityPolicyTests = $true  # Set as $true (default) or $false, this will load the library from Microsoft's GitHub repository needed for running advanced connectivity tests
        ConnectionAttempts = 1 # Number of connection attempts while running advanced connectivity tests
        DelayBetweenConnections = 1 # Number of seconds to wait between connection attempts while running advanced connectivity tests
        CollectNetworkTrace = $true  # Set as $true (default) or $false
        #EncryptionProtocol = '' # Supported values: 'Tls 1.0', 'Tls 1.1', 'Tls 1.2'; Without this parameter operating system will choose the best protocol to use
    }

    $ProgressPreference = "SilentlyContinue";
    $scriptFile = '/AzureMySQLConnectivityChecker.ps1'
    $scriptUrlBase = 'https://raw.githubusercontent.com/marlonj-ms/AzMySQL-Connectivity-Checker/master'
    cls
    Write-Host 'Trying to download the script file from GitHub (https://github.com/marlonj-ms/AzMySQL-Connectivity-Checker), please wait...'
    try {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 -bor [Net.SecurityProtocolType]::Tls11 -bor [Net.SecurityProtocolType]::Tls
        Invoke-Command -ScriptBlock ([Scriptblock]::Create((Invoke-WebRequest ($scriptUrlBase + $scriptFile) -UseBasicParsing -TimeoutSec 60).Content)) -ArgumentList $parameters
        }
    catch {
        Write-Host 'ERROR: The script file could not be downloaded:' -ForegroundColor Red
        $_.Exception
        Write-Host 'Confirm this machine can access https://github.com/marlonj-ms/MySQL-Connectivity-Checker/' -ForegroundColor Yellow
        Write-Host 'or use a machine with Internet access to see how to run this from machines without Internet. See how at https://github.com/marlonj-ms/MySQL-Connectivity-Checker/' -ForegroundColor Yellow
        Write-Host 'or raise your issue at https://github.com/marlonj-ms/AzMySQL-Connectivity-Checker/issues if the script execution fails..' -ForegroundColor Yellow
    }
    #end
    ```
4. Examine the output for any issues detected, and recommended steps to resolve the issue.

> Note: if you experienced errors loading *mysql.data.dll* in Linux, please try to load in manually as below:
> 1. Installing Mono on Linux (if you haven't before).    
   See how to get the packages at https://www.mono-project.com/download/stable/#download-lin-ubuntu
> 2. Download MySQL .Net connector and save on Linux from https://dev.mysql.com/downloads/connector/net/
    ![image](/rsc/mysql-net-connector.png)
    Making sure the folder is unzipped.
> 3. After the package is installed, run ***pwsh*** from a Linux terminal. In the openned PowerShell console, register mysqlclient library by running the following command:
>   ````powershell
>       sudo gacutil -i "{path_to_folder_from_step#3}/v4.xx/MySql.Data.dll"  # replace {path_to_folder_from_step#3} with the path to the folder where the package is saved on your Linux machine
>   ````
> 4. Before running the test script above, load the mysqlclient first by running the following command:
>   ````powershell
>       [system.reflection.Assembly]::LoadFrom("{path_to_folder_from_step#3}/v4.xx/MySql.Data.dll") # replace {path_to_folder_from_step#3} with the path to the folder where the package is saved on your Linux machine
>   ````

## How to run this from machines whithout Internet access

**In order to run it from machines without Internet access you need to:**

1. From a machine with Internet access
    - Navigate to https://github.com/marlonj-ms/AzMySQL-Connectivity-Checker
    - Click on the green button named 'Clone or download'
    - Select 'Download ZIP'

1. Copy the downloaded zip file to the machine you need to run tests from.

1. Extract all the files into a folder.

1. Open Windows PowerShell ISE in Administrator mode.  
For the better results, our recommendation is to use the advanced connectivity tests which demand to start PowerShell in Administrator mode. You can still run the basic tests, in case you decide not to run this way. Please note that script parameters 'RunAdvancedConnectivityPolicyTests' and 'CollectNetworkTrace' will only work if the admin privileges are granted.

1. From PowerShell ISE, open the file named 'RunLocally.ps1' you can find in the previous folder.

1. Set the parameters on the script, you need to set server name. Database name, user and password are optional but desirable.

1. Save the changes.

1. Click Run Script (play button). You cannot run this partially or copy paste to the command line.

1. The results can be seen in the output window.
If the user has the permissions to create folders, a folder with the resulting log file will be created.
When running on Windows, the folder will be opened automatically after the script completes.
A zip file with all the log files (AllFiles.zip) will be created.



# Contributing

This project welcomes contributions and suggestions.  Most contributions require you to agree to a
Contributor License Agreement (CLA) declaring that you have the right to, and actually do, grant us
the rights to use your contribution. For details, visit https://cla.opensource.microsoft.com.

When you submit a pull request, a CLA bot will automatically determine whether you need to provide
a CLA and decorate the PR appropriately (e.g., status check, comment). Simply follow the instructions
provided by the bot. You will only need to do this once across all repos using our CLA.

This project has adopted the [Microsoft Open Source Code of Conduct](https://opensource.microsoft.com/codeofconduct/).
For more information see the [Code of Conduct FAQ](https://opensource.microsoft.com/codeofconduct/faq/) or
contact [opencode@microsoft.com](mailto:opencode@microsoft.com) with any additional questions or comments.
