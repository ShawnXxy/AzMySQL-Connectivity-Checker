## Copyright (c) Microsoft Corporation.
#Licensed under the MIT license.

#Azure SQL Connectivity Checker

#THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
#FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
#WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

using namespace System
using namespace System.Net
using namespace System.net.Sockets
using namespace System.Collections.Generic
using namespace System.Diagnostics
using namespace Microsoft.Azure.PowerShell.Cmdlets.MySql
using namespace MySql.Data.MySqlClient

# [System.Reflection.Assembly]::LoadWithPartialName("MySql.Data")

# Parameter region for when script is run directly
# Supports Single, Flexible (please provide FQDN, priavete endpoint and Vnet Ingested Flexible is supported)
# Supports Public Cloud (*.msyql.database.azure.com), Azure China (*.mysql.database.chinacloudapi.cn)
$Server = '.mysql.database.azure.com' # or any other supported FQDN
$Database = ''  # Set the name of the database you wish to test, 'information_schema' will be used by default if nothing is set
$User = ''  # Set the login username you wish to use, 'AzMySQLConnCheckerUser' will be used by default if nothing is set
$Password = ''  # Set the login password you wish to use, 'AzMySQLConnCheckerPassword' will be used by default if nothing is set
# In case you want to hide the password (like during a remote session), uncomment the 2 lines below (by removing leading #) and password will be asked during execution
# $Credentials = Get-Credential -Message "Credentials to test connections to the database (optional)" -User $User
# $Password = $Credentials.GetNetworkCredential().password

# Optional parameters (default values will be used if omitted)
$SendAnonymousUsageData = $true  # Set as $true (default) or $false
$RunAdvancedConnectivityPolicyTests = $true  # Set as $true (default) or $false#Set as $true (default) or $false, this will download library needed for running advanced connectivity policy tests
$ConnectionAttempts = 1
$DelayBetweenConnections = 1
$CollectNetworkTrace = $true  # Set as $true (default) or $false
#EncryptionProtocol = ''  # Supported values: 'Tls 1.0', 'Tls 1.1', 'Tls 1.2'; Without this parameter operating system will choose the best protocol to use

# Parameter region when Invoke-Command -ScriptBlock is used
$parameters = $args[0]
if ($null -ne $parameters) {
    $Server = $parameters['Server']
    $Database = $parameters['Database']
    $User = $parameters['User']
    $Password = $parameters['Password']
    if ($null -ne $parameters['SendAnonymousUsageData']) {
        $SendAnonymousUsageData = $parameters['SendAnonymousUsageData']
    }
    if ($null -ne $parameters['RunAdvancedConnectivityPolicyTests']) {
        $RunAdvancedConnectivityPolicyTests = $parameters['RunAdvancedConnectivityPolicyTests']
    }
    if ($null -ne $parameters['CollectNetworkTrace']) {
        $CollectNetworkTrace = $parameters['CollectNetworkTrace']
    }
    $EncryptionProtocol = $parameters['EncryptionProtocol']
    if ($null -ne $parameters['Local']) {
        $Local = $parameters['Local']
    }
    if ($null -ne $parameters['LocalPath']) {
        $LocalPath = $parameters['LocalPath']
    }
    if ($null -ne $parameters['RepositoryBranch']) {
        $RepositoryBranch = $parameters['RepositoryBranch']
    }
    if ($null -ne $parameters['ConnectionAttempts']) {
        $ConnectionAttempts = $parameters['ConnectionAttempts']
    }
    if ($null -ne $parameters['DelayBetweenConnections']) {
        $DelayBetweenConnections = $parameters['DelayBetweenConnections']
    }
}

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

$CustomerRunningInElevatedMode = $false
if ($PSVersionTable.Platform -eq 'Unix') {
    if ((id -u) -eq 0) {
        $CustomerRunningInElevatedMode = $true
    }
}
else {
    $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    if ($currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        $CustomerRunningInElevatedMode = $true
    }
}

$MySQLSterlingGateways = @(
    New-Object PSObject -Property @{Region = "Australia Central"; Gateways = ("20.36.105.0"); TRs = ('tr136'); Cluster = 'australiacentral1-a.worker.database.windows.net'; }
    New-Object PSObject -Property @{Region = "Australia Central2"; Gateways = ("20.36.113.0"); TRs = ('tr50', 'tr51'); Cluster = 'australiacentral2-a.worker.database.windows.net'; }
    New-Object PSObject -Property @{Region = "Australia East"; Gateways = ("13.75.149.87", "40.79.161.1"); TRs = ('tr15', 'tr596', 'tr1240', 'tr1999', 'tr2726', 'tr3782', 'tr3899', 'tr4588'); Cluster = 'australiaeast1-a.worker.database.windows.net'; }
    New-Object PSObject -Property @{Region = "Australia South East"; Gateways = ("13.73.109.251", "13.77.48.10", "13.77.49.32"); TRs = ('tr15', 'tr1116'); Cluster = 'australiasoutheast1-a.worker.database.windows.net'; }
    New-Object PSObject -Property @{Region = "Brazil South"; Gateways = ("191.233.201.8", "191.233.200.16", "104.41.11.5"); TRs = ('tr12', 'tr199', 'tr425', 'tr503', 'tr633'); Cluster = 'brazilsouth1-a.worker.database.windows.net'; }
    New-Object PSObject -Property @{Region = "Brazil South East"; Gateways = ("191.233.48.2"); TRs = ('tr17'); Cluster = 'brazilsoutheast1-a.worker.database.windows.net'; }
    New-Object PSObject -Property @{Region = "Canada Central"; Gateways = ("40.85.224.249", "52.228.35.221"); TRs = ('tr658', 'tr925', 'tr1570', 'tr1727', 'tr2239', 'tr2764'); Cluster = 'canadacentral1-a.worker.database.windows.net'; }
    New-Object PSObject -Property @{Region = "Canada East"; Gateways = ("40.86.226.166", "52.242.30.154"); TRs = ('tr10', 'tr329'); Cluster = 'canadaeast1-a.worker.database.windows.net'; }
    New-Object PSObject -Property @{Region = "Central US"; Gateways = ("23.99.160.139", "52.182.136.37", "52.182.136.38", "13.67.215.62"); TRs = ('tr39', 'tr281', 'tr383', 'tr506', 'tr4444', 'tr4445', 'tr4613', 'tr5880', 'tr6180', 'tr6729', 'tr6963', 'tr7275', 'tr7328', 'tr7640'); Cluster = 'centralus1-a.worker.database.windows.net'; }
    New-Object PSObject -Property @{Region = "China East"; Gateways = ("139.219.130.35"); TRs = ('tr6', 'tr8'); Cluster = 'chinaeast1-a.worker.database.chinacloudapi.cn'; }
    New-Object PSObject -Property @{Region = "China East 2"; Gateways = ("40.73.82.1", "52.130.120.89"); TRs = ('tr2', 'tr138', 'tr169', 'tr195', 'tr215', 'tr384', 'tr764', 'tr848', 'tr986', 'tr1042'); Cluster = 'chinaeast2-a.worker.database.chinacloudapi.cn'; }
    New-Object PSObject -Property @{Region = "China North"; Gateways = ("139.219.15.17"); TRs = ('tr6', 'tr8', 'tr9'); Cluster = 'chinanorth1-a.worker.database.chinacloudapi.cn'; }
    New-Object PSObject -Property @{Region = "China North 2"; Gateways = ("40.73.50.0"); TRs = ('tr2', 'tr37', 'tr120', 'tr166', 'tr239', 'tr268'); Cluster = 'chinanorth2-a.worker.database.chinacloudapi.cn'; }
    New-Object PSObject -Property @{Region = "East Asia"; Gateways = ("13.75.33.20", "52.175.33.150", "13.75.33.20", "13.75.33.21"); TRs = ('tr24', 'tr93', 'tr503', 'tr737', 'tr898', 'tr1174', 'tr1183'); Cluster = 'eastasia1-a.worker.database.windows.net'; }
    New-Object PSObject -Property @{Region = "East US"; Gateways = ("40.71.8.203", "40.71.83.113", "40.121.158.30", '191.238.6.43'); TRs = ('tr236', 'tr280', 'tr281', 'tr2600', 'tr2653', 'tr2904', 'tr3748', 'tr5266', 'tr6003', 'tr6437', 'tr7336', 'tr7785', 'tr8640', 'tr9433', 'tr9727', 'tr10457', 'tr11364', 'tr11365', 'tr12171', 'tr12479', 'tr13539', 'tr13845', 'tr14556', 'tr15139', 'tr15831', 'tr16694', 'tr17000', 'tr17709', 'tr17812', 'tr18971', 'tr20209', 'tr20723', 'tr21339', 'tr21913', 'tr21968', 'tr22044', 'tr23074', 'tr23112', 'tr23229', 'tr24602'); Cluster = 'eastus1-a.worker.database.windows.net'; }
    New-Object PSObject -Property @{Region = "East US 2"; Gateways = ("40.70.144.38", "52.167.105.38", "52.177.185.181"); TRs = ('tr61', 'tr63', 'tr333', 'tr2523', 'tr3206', 'tr3905', 'tr4112', 'tr4206', 'tr4487', 'tr5048', 'tr6043', 'tr6075', 'tr6801', 'tr6802', 'tr7232', 'tr7406', 'tr7465', 'tr8150', 'tr8602', 'tr9151', 'tr9302', 'tr9666', 'tr9982', 'tr11096', 'tr11323', 'tr12012', 'tr12461', 'tr12781', 'tr12867', 'tr13226', 'tr13318', 'tr13423', 'tr13859'); Cluster = 'eastus2-a.worker.database.windows.net'; }
    New-Object PSObject -Property @{Region = "France Central"; Gateways = ("40.79.137.0", "40.79.129.1"); TRs = ('tr6', 'tr203', 'tr278', 'tr388', 'tr485', 'tr598', 'tr827', 'tr840'); Cluster = 'francecentral1-a.worker.database.windows.net'; }
    New-Object PSObject -Property @{Region = "France South"; Gateways = ("40.79.177.0"); TRs = ('tr25'); Cluster = 'francesouth1-a.worker.database.windows.net'; }
    New-Object PSObject -Property @{Region = "Germany Central"; Gateways = ("51.4.144.100"); TRs = ('tr5'); Cluster = 'germanycentral1-a.worker.database.cloudapi.de'; }
    New-Object PSObject -Property @{Region = "Germany North"; Gateways = ("51.116.56.0"); TRs = ('tr21'); Cluster = 'germanynorth1-a.worker.database.windows.net'; }
    New-Object PSObject -Property @{Region = "Germany West Central"; Gateways = ("51.116.152.0"); TRs = ('tr21', 'tr163', 'tr234', 'tr593', 'tr655', 'tr951'); Cluster = 'germanywestcentral1-a.worker.database.windows.net'; }
    New-Object PSObject -Property @{Region = "India Central"; Gateways = ("104.211.96.159"); TRs = ('tr16', 'tr107', 'tr169', 'tr580', 'tr789', 'tr916', 'tr917', 'tr992'); Cluster = 'indiacentral1-a.worker.database.windows.net'; }
    New-Object PSObject -Property @{Region = "India South"; Gateways = ("104.211.224.146"); TRs = ('tr9', 'tr512'); Cluster = 'indiasouth1-a.worker.database.windows.net'; }
    New-Object PSObject -Property @{Region = "India West"; Gateways = ("104.211.160.80"); TRs = ('tr8', 'tr100'); Cluster = 'indiawest1-a.worker.database.windows.net'; }
    New-Object PSObject -Property @{Region = "Japan East"; Gateways = ("40.79.192.23", "40.79.184.8", "13.78.61.196"); TRs = ('tr23', 'tr212', 'tr373', 'tr398', 'tr525', 'tr861', 'tr1272', 'tr1595', 'tr1689', 'tr1815', 'tr1816', 'tr2077', 'tr2140', 'tr2184', 'tr2258', 'tr2437', 'tr3083'); Cluster = 'japaneast1-a.worker.database.windows.net'; }
    New-Object PSObject -Property @{Region = "Japan West"; Gateways = ("191.238.68.11", "40.74.96.6", "40.74.96.7", "104.214.148.156"); TRs = ('tr12', 'tr322'); Cluster = 'japanwest1-a.worker.database.windows.net'; }
    New-Object PSObject -Property @{Region = "Korea Central"; Gateways = ("52.231.17.13", "52.231.32.42"); TRs = ('tr10', 'tr555', 'tr611'); Cluster = 'koreacentral1-a.worker.database.windows.net'; }
    New-Object PSObject -Property @{Region = "Korea South"; Gateways = ("52.231.145.3", "52.231.151.97", "52.231.200.86"); TRs = ('tr4'); Cluster = 'koreasouth1-a.worker.database.windows.net'; }
    New-Object PSObject -Property @{Region = "North Central US"; Gateways = ("52.162.104.35", "52.162.104.36", "23.96.178.199"); TRs = ('tr237', 'tr1003', 'tr1663'); Cluster = 'northcentralus1-a.worker.database.windows.net'; }
    New-Object PSObject -Property @{Region = "North Europe"; Gateways = ("52.138.224.6", "52.138.224.7", "40.113.93.91", "191.235.193.75"); TRs = ('tr203', 'tr252', 'tr1097', 'tr2118', 'tr2392', 'tr2725', 'tr3909', 'tr3910', 'tr4316', 'tr4598', 'tr5584', 'tr6467', 'tr7391', 'tr7976', 'tr8352'); Cluster = 'northeurope1-a.worker.database.windows.net'; }
    New-Object PSObject -Property @{Region = "Norway East"; Gateways = ("51.120.98.32", "51.120.96.0", "51.120.96.33", "51.120.104.32", "51.120.208.32"); TRs = ('tr14', 'tr95', 'tr198'); Cluster = 'norwayeast1-a.worker.database.windows.net'; } #*
    New-Object PSObject -Property @{Region = "Norway West"; Gateways = ("51.120.208.32", "51.120.216.0"); TRs = ('tr14'); Cluster = 'norwaywest1-a.worker.database.windows.net'; } #*
    New-Object PSObject -Property @{Region = "South Africa North"; Gateways = ("102.133.152.0"); TRs = ('tr4', 'tr360', 'tr361', 'tr561', 'tr667'); Cluster = 'southafricanorth1-a.worker.database.windows.net'; } #*
    New-Object PSObject -Property @{Region = "South Africa West"; Gateways = ("102.133.24.0"); TRs = ('tr3'); Cluster = 'southafricawest1-a.worker.database.windows.net'; }
    New-Object PSObject -Property @{Region = "South Central US"; Gateways = ("104.214.16.39", "20.45.120.0", "13.66.62.124", "23.98.162.75"); TRs = ('tr50', 'tr477', 'tr1623', 'tr2199', 'tr3919', 'tr5844'); Cluster = 'southcentralus1-a.worker.database.windows.net'; }
    New-Object PSObject -Property @{Region = "South East Asia"; Gateways = ("40.78.233.2", "23.98.80.12", "104.43.15.0"); TRs = ('tr31', 'tr361', 'tr1283', 'tr1422', 'tr1766', 'tr2382', 'tr2835', 'tr3083', 'tr3194', 'tr4087', 'tr4596', 'tr5071', 'tr5219'); Cluster = 'southeastasia1-a.worker.database.windows.net'; }    
    New-Object PSObject -Property @{Region = "Sweden Central"; Gateways = ("51.12.96.32"); TRs = ('tr3'); Cluster = 'swedencentral1-a.worker.database.windows.net'; } #*
    New-Object PSObject -Property @{Region = "Sweden South"; Gateways = ("51.12.200.32"); TRs = ('tr5'); Cluster = 'swedensouth1-a.worker.database.windows.net'; } #*
    New-Object PSObject -Property @{Region = "Switzerland North"; Gateways = ("51.107.56.0"); TRs = ('tr51', 'tr195', 'tr477'); Cluster = 'switzerlandnorth1-a.worker.database.windows.net'; }
    New-Object PSObject -Property @{Region = "Switzerland West"; Gateways = ("51.107.152.0", "51.107.153.0"); TRs = ('tr51'); Cluster = 'switzerlandwest1-a.worker.database.windows.net'; }
    New-Object PSObject -Property @{Region = "UAE Central"; Gateways = ("20.37.72.64"); TRs = ('tr41', 'tr42'); Cluster = 'uaecentral1-a.worker.database.windows.net'; }
    New-Object PSObject -Property @{Region = "UAE North"; Gateways = ("65.52.248.0"); TRs = ('tr9', 'tr99', 'tr104', 'tr295', 'tr513'); Cluster = 'uaenorth1-a.worker.database.windows.net'; }
    New-Object PSObject -Property @{Region = "UK South"; Gateways = ("51.140.144.32", "51.105.64.0"); TRs = ('tr7', 'tr372', 'tr1550', 'tr2348', 'tr2738', 'tr3902', 'tr4660', 'tr4968'); Cluster = 'uksouth1-a.worker.database.windows.net'; }
    New-Object PSObject -Property @{Region = "UK West"; Gateways = ("51.141.8.11"); TRs = ('tr10', 'tr610'); Cluster = 'ukwest1-a.worker.database.windows.net'; }
    New-Object PSObject -Property @{Region = "West Central US"; Gateways = ("13.78.145.25", "52.161.100.158"); TRs = ('tr280'); Cluster = 'westcentralus1-a.worker.database.windows.net'; }
    New-Object PSObject -Property @{Region = "West Europe"; Gateways = ("13.69.105.208", "104.40.169.187", "40.68.37.158", "191.237.232.75"); TRs = ('tr208', 'tr295', 'tr311', 'tr413', 'tr515', 'tr607', 'tr2260', 'tr3183', 'tr3790', 'tr4764', 'tr5022', 'tr5622', 'tr6449', 'tr7761', 'tr8028', 'tr8909', 'tr9618', 'tr10349', 'tr10350', 'tr11225', 'tr11283', 'tr11864', 'tr12173', 'tr12307', 'tr12736', 'tr12737', 'tr13027', 'tr13349', 'tr13922', 'tr14018', 'tr14834', 'tr14857', 'tr15416', 'tr16002', 'tr16700', 'tr16980', 'tr17447', 'tr17881', 'tr18067', 'tr18336', 'tr18803', 'tr18804', 'tr18870', 'tr19404', 'tr19049', 'tr20096', 'tr21019', 'tr21830'); Cluster = 'westeurope1-a.worker.database.windows.net'; }   
    New-Object PSObject -Property @{Region = "West US"; Gateways = ("13.86.216.212", "13.86.217.212", "104.42.238.205", "23.99.34.75"); TRs = ('tr208', 'tr226', 'tr910', 'tr1833', 'tr3036', 'tr3530', 'tr4407', 'tr4596', 'tr5428'); Cluster = 'westus1-a.worker.database.windows.net'; }
    New-Object PSObject -Property @{Region = "West US 2"; Gateways = ("13.66.136.195", "13.66.136.192", "13.66.226.202"); TRs = ('tr25', 'tr174', 'tr1588', 'tr2007', 'tr2076', 'tr3941', 'tr4531', 'tr5019', 'tr5407', 'tr6011', 'tr6368', 'tr7087', 'tr7403', 'tr7608', 'tr7698', 'tr7778', 'tr8210', 'tr8626', 'tr8700', 'tr8740'); Cluster = 'westus2-a.worker.database.windows.net'; }
    New-Object PSObject -Property @{Region = "West US 3"; Gateways = ("20.150.184.2"); TRs = ('tr1235'); Cluster = 'westus3-a.worker.database.windows.net'; }
    New-Object PSObject -Property @{Region = "US DoD East"; Gateways = ("52.181.160.27"); TRs = ('tr6'); Cluster = 'usdodeast1-a.worker.database.usgovcloudapi.net'; }
    New-Object PSObject -Property @{Region = "US DoD Central"; Gateways = ("52.182.88.34"); TRs = ('tr8', 'tr16'); Cluster = 'usdodcentral1-a.worker.database.usgovcloudapi.net'; }
    New-Object PSObject -Property @{Region = "US Gov Iowa"; Gateways = ("13.72.189.52"); TRs = ('tr1'); Cluster = 'usgovcentral1-a.worker.database.usgovcloudapi.net'; }
    New-Object PSObject -Property @{Region = "US Gov Texas"; Gateways = ("52.238.116.32"); TRs = ('tr3'); Cluster = 'usgovsouthcentral1-a.worker.database.usgovcloudapi.net'; }
    New-Object PSObject -Property @{Region = "US Gov Arizona"; Gateways = ("52.244.48.33"); TRs = ('tr6'); Cluster = 'usgovsouthwest1-a.worker.database.usgovcloudapi.net'; }
    New-Object PSObject -Property @{Region = "US Gov Virginia"; Gateways = ("13.72.48.140"); TRs = ('tr8', 'tr260'); Cluster = 'usgoveast1-a.worker.database.usgovcloudapi.net'; }
)

$TRPorts = 16000..16005 # this real range would be from 16000 to 16499. For testing purpose, only list 5.
$summaryLog = New-Object -TypeName "System.Text.StringBuilder"
$summaryRecommendedAction = New-Object -TypeName "System.Text.StringBuilder"
$AnonymousRunId = ([guid]::NewGuid()).Guid

# Error Messages
$DNSResolutionFailed = 'Please make sure the server name FQDN is correct and that your machine can resolve it.
Failure to resolve domain name for your logical server is almost always the result of specifying an invalid/misspelled server name,
or a client-side networking issue that you will need to pursue with your local network administrator.'

$DNSResolutionGotMultipleAddresses = 'While testing DNS resolution from multiples sources (hosts file/cache/your DNS server/external DNS service) we got multiple addresses.
To connect to Azure MySQL Single Server, you need to allow network traffic to and from all Gateways for the region.
The Gateway used is not static, configuring a single specific address (like in hosts file) may lead to total lack of connectivity or intermittent connectivity issues (now or in the future).
Having DNS resolution switching between a couple of Gateway addresses is expected.
If you are using Private Link, a mismatch between your DNS server and OpenDNS is expected.
Please review the DNS results.'

# $DNSResolutionFailedAzureMySQLFlexPublic = ' Please make sure the server name FQDN is correct and that your machine can resolve it.
#  If public endpoint is enabled, failure to resolve domain name for your logical server is almost always the result of specifying an invalid/misspelled server name,
#  or a client-side networking issue that you will need to pursue with your local network administrator.'

$MySQL_InvalidGatewayIPAddress = 'In case you are not using Private Endpoint, please make sure the server name FQDN is correct and that your machine can resolve it to a valid gateway IP address (DNS configuration).
In case you are not using Private Link, failure to resolve domain name for your logical server is almost always the result of specifying an invalid/misspelled server name,
or a client-side networking issue that you will need to pursue with your local network administrator.
See the valid gateway addresses at https://docs.microsoft.com/en-us/azure/mysql/concepts-connectivity-architecture#azure-database-for-mysql-gateway-ip-addresses.'

$MySQL_GatewayTestFailed = 'Failure to reach the Gateway is usually a client-side networking issue (like DNS issue or a port being blocked) that you will need to pursue with your local network administrator.
See more about connectivity architecture at https://docs.microsoft.com/en-us/azure/mysql/concepts-connectivity-architecture. '

$MySQL_Redirect = "Azure MySQL Single Server supports Redirect and Proxy for the server's connection policy setting:

    Proxy: This is the default connection mode and applies in most scenarios.In this mode, all connections are proxied via the Azure MySQL Database gateways. 
    For connections to use this mode, clients need to allow outbound communication from the client to Azure MySQL gateway IP addresses on port 3306. 
    See more about connectivity architecture at https://docs.microsoft.com/en-us/azure/mysql/concepts-connectivity-architecture.

    Redirect (applies for PHP only at current state): Clients establish connections directly to the node hosting the database, leading to reduced latency and improved throughput.
    The node address and port number can be queried by [SHOW GLOBAL VARIALBES LIKE '%redir%'].
    For connections to use this mode, clients need to:
    - Allow outbound communication from the client to all Azure MySQL IP addresses in the region on ports in the range of 16000-16499.
    - Allow outbound communication from the client to Azure MySQL gateway IP addresses on port 3306.

    If you are using Proxy, the Redirect Policy related tests would not be a problem.
    If you are using Redirect, failure to reach ports in the range of 11000-11999 is usually a client-side networking issue (like DNS issue or a port being blocked) that you will need to pursue with your local network administrator.
    Please check more about redirection connection policies at https://docs.microsoft.com/en-us/azure/mysql/howto-redirection. 
   "

$AzureMySQLFlex_VNetTestFailed = "You can connect to Azure MySQL Flexible Server via private address if you are connecting from one of the following:
    - machine inside the same virtual network
    - machine in a peered virtual network
    - machine that is network connected by VPN or Azure ExpressRoute

Failure to reach the VNet Integrated Flexible Server is usually a client-side networking issue (like DNS issue or a port being blocked) that you will need to pursue with your local network administrator.
We strongly recommend you request assistance from your network administrator, some validations you may do together are:
    - The host name is valid and port used for the connection is 3306, format is tcp:<servername>.mysql.database.azure.com,3306
    - The Network Security Groups (NSG) on the managed instance subnet allows access on port 3306.
    - If you are unable to connect from an Azure hosted client (like an Azure virtual machine), check if you have a Network Security Group set on the client subnet that might be blocking *outbound* access on port 3306.
    - Any networking device used (like firewalls, NVAs) do not block the traffic mentioned above.
    - If you are using peering via VPN gateway, ensure the two virtual networks are properly peered, see more at https://docs.microsoft.com/en-us/azure/virtual-network/virtual-network-peering-overview
Learn more about how to connect your application to Azure MySQL VNet Integrated Flexible Server at https://docs.microsoft.com/en-us/azure/mysql/flexible-server/concepts-networking-vnet

"

$AzureMySQLFlex_PublicEndPoint_ConnectionTestFailed = "If the server is in a ready state shown in Portal, this usually indicates a client-side networking issue (like DNS issue or a port being blocked) that you will need to pursue with your local network administrator or firewall configuration issue that you can check from Networking blade in Portal.

We strongly recommend you performing some validations you may do as below :
    - You have Public Endpoint enabled, see https://docs.microsoft.com/en-us/azure/mysql/flexible-server/concepts-networking-public
    - Network traffic to this endpoint and port is allowed from the source and any networking appliances you may have (firewalls, etc.). Ref: https://docs.microsoft.com/en-us/azure/mysql/flexible-server/how-to-manage-firewall-portal
See more about connectivity using Public Endpoint at https://docs.microsoft.com/en-us/azure/mysql/flexible-server/concepts-networking-public
"

$AAD_login_windows_net = 'If you are using AAD Password or AAD Integrated Authentication please make sure you fix the connectivity from this machine to login.windows.net:443
This usually indicates a client-side networking issue (like DNS issue or a port being blocked) that you will need to pursue with your local network administrator.'

$AAD_login_microsoftonline_com = 'If you are using AAD Universal with MFA authentication please make sure you fix the connectivity from this machine to login.microsoftonline.com:443
This usually indicates a client-side networking issue (like DNS issue or a port being blocked) that you will need to pursue with your local network administrator.'

$AAD_secure_aadcdn_microsoftonline_p_com = 'If you are using AAD Universal with MFA authentication please make sure you fix the connectivity from this machine to secure.aadcdn.microsoftonline-p.com:443
This usually indicates a client-side networking issue (like DNS issue or a port being blocked) that you will need to pursue with your local network administrator.'

$ServerNameNotSpecified = 'The parameter $Server was not specified, please set the parameters on the script, you need to set server name. Database name, user and password are optional but desirable.
You can see more details about how to use this tool at https://github.com/ShawnXxy/AzMySQL-Connectivity-Checker'

$CannotDownloadAdvancedScript = 'Advanced connectivity policy tests script could not be downloaded!
Confirm this machine can access https://github.com/ShawnXxy/AzMySQL-Connectivity-Checker/
or use a machine with Internet access to see how to run this from machines without Internet. See how at https://github.com/ShawnXxy/AzMySQL-Connectivity-Checker/'

$DNSResolutionDNSfromHostsFile = "We detected a configuration via hosts file, note that Azure MySQL doesn't have a static IP address.
Logins for Azure MySQL can land on any of the Gateways in a region.
For this reason, we strongly discourage relying on immutability of the IP address as it could cause unnecessary downtime."

# $DNSResolutionDNSfromHostsFileMI = "We detected a configuration via hosts file, note that Managed instance doesn't have a static IP address.
# The managed instance service doesn't claim static IP address support and reserves the right to change it without notice as a part of regular maintenance cycles.
# For this reason, we strongly discourage relying on immutability of the IP address as it could cause unnecessary downtime."

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
            try {
                Write-Host "Trying to resolve DNS for" $Name
                return @{ IPAddress = [System.Net.DNS]::GetHostAddresses($Name).IPAddressToString };
            }
            catch {
                TrackWarningAnonymously ('Error at Resolve-DnsName override: ' + $_.Exception.Message)
            }
        }
    }
}

if (!$(Get-Command 'Get-NetRoute' -errorAction SilentlyContinue)) {
    function Get-NetRoute {
        param(
            [Parameter(Position = 0, Mandatory = $true)] $InterfaceAlias
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

function PrintDNSResults($dnsResult, [string] $dnsSource, $errorVariable, $Server) {
    Try {
        $dnsResultIpAddress = $null
        if ($errorVariable -and $errorVariable[0].Exception.Message -notmatch 'DNS record does not exist' -and $errorVariable[0].Exception.Message -notmatch 'DNS name does not exist') {
            $msg = 'Error getting DNS record in ' + $dnsSource + ' (' + $errorVariable[0].Exception.Message.Replace(" : " + $Server, "") + ')'
            Write-Host $msg
            [void]$summaryLog.AppendLine($msg)
            TrackWarningAnonymously $msg
        }
        else {
            if ($dnsResult -and $dnsResult.IPAddress -and !([string]::IsNullOrEmpty($dnsResult.IPAddress))) {
                $dnsResultIpAddress = $dnsResult.IPAddress
                $msg = 'Found DNS record in ' + $dnsSource + ' (IP Address:' + $dnsResult.IPAddress + ')'
                Write-Host $msg
                [void]$summaryLog.AppendLine($msg)
            }
            else {
                Write-Host 'Could not find DNS record in' $dnsSource
            }
        }
        return $dnsResultIpAddress
    }
    Catch {
        $msg = "Error at PrintDNSResults for " + $dnsSource + '(' + $_.Exception.Message + ')'
        Write-Host $msg -Foreground Red
        Write-Host $_.Exception.Message -ForegroundColor Red
        TrackWarningAnonymously $msg
    }
}

function ValidateDNS([String] $Server) {
    Try {
        Write-Host 'Validating DNS record for' $Server -ForegroundColor Green
        $DNSlist = New-Object Collections.Generic.List[string]

        if ($PSVersionTable.PSVersion.Major -le 5 -or $IsWindows) {
            Try {
                $DNSfromHostsError = $null
                $DNSfromHosts = Resolve-DnsName -Name $Server -CacheOnly -ErrorAction SilentlyContinue -ErrorVariable DNSfromHostsError
                $DNSfromHostsAddress = PrintDNSResults $DNSfromHosts 'hosts file' $DNSfromHostsError $Server
                if ($DNSfromHostsAddress -and -1 -eq $DNSlist.IndexOf($DNSfromHostsAddress)) {
                    $DNSlist.Add($DNSfromHostsAddress);
                }
            }
            Catch {
                Write-Host "Error at ValidateDNS from hosts file" -Foreground Red
                Write-Host $_.Exception.Message -ForegroundColor Red
                TrackWarningAnonymously 'Error at ValidateDNS from hosts file'
            }

            Try {
                $DNSfromCacheError = $null
                $DNSfromCache = Resolve-DnsName -Name $Server -NoHostsFile -CacheOnly -ErrorAction SilentlyContinue -ErrorVariable DNSfromCacheError
                $DNSfromCacheAddress = PrintDNSResults $DNSfromCache 'cache' $DNSfromCacheError $Server
                if ($DNSfromCacheAddress -and -1 -eq $DNSlist.IndexOf($DNSfromCacheAddress)) {
                    $DNSlist.Add($DNSfromCacheAddress);
                }
            }
            Catch {
                Write-Host "Error at ValidateDNS from cache" -Foreground Red
                Write-Host $_.Exception.Message -ForegroundColor Red
                TrackWarningAnonymously 'Error at ValidateDNS from cache'
            }

            Try {
                $DNSfromCustomerServerError = $null
                $DNSfromCustomerServer = Resolve-DnsName -Name $Server -DnsOnly -ErrorAction SilentlyContinue -ErrorVariable DNSfromCustomerServerError
                $DNSfromCustomerServerAddress = PrintDNSResults $DNSfromCustomerServer 'DNS server' $DNSfromCustomerServerError $Server
                if ($DNSfromCustomerServerAddress -and -1 -eq $DNSlist.IndexOf($DNSfromCustomerServerAddress)) {
                    $DNSlist.Add($DNSfromCustomerServerAddress);
                }
            }
            Catch {
                Write-Host "Error at ValidateDNS from DNS server" -Foreground Red
                Write-Host $_.Exception.Message -ForegroundColor Red
                TrackWarningAnonymously 'Error at ValidateDNS from DNS server'
            }

            Try {
                $DNSfromOpenDNSError = $null
                $DNSfromOpenDNS = Resolve-DnsName -Name $Server -DnsOnly -Server 208.67.222.222 -ErrorAction SilentlyContinue -ErrorVariable DNSfromOpenDNSError
                $DNSfromOpenDNSAddress = PrintDNSResults $DNSfromOpenDNS 'Open DNS' $DNSfromOpenDNSError $Server
                if ($DNSfromOpenDNSAddress -and -1 -eq $DNSlist.IndexOf($DNSfromOpenDNSAddress)) {
                    $DNSlist.Add($DNSfromOpenDNSAddress);
                }
            }
            Catch {
                Write-Host "Error at ValidateDNS from Open DNS" -Foreground Red
                Write-Host $_.Exception.Message -ForegroundColor Red
                TrackWarningAnonymously 'Error at ValidateDNS from Open DNS'
            }

            if ($DNSfromHostsAddress) {
               
                $msg = $DNSResolutionDNSfromHostsFile
          
                Write-Host
                Write-Host $msg -ForegroundColor Red
                [void]$summaryLog.AppendLine()
                [void]$summaryRecommendedAction.AppendLine()
                [void]$summaryLog.AppendLine($msg)
                [void]$summaryRecommendedAction.AppendLine($msg)
                [void]$summaryRecommendedAction.AppendLine()
            }

            if (!$DNSfromCustomerServerAddress) {
                Write-Host
                $msg = ('DNS resolution using DNS Server could not be verified, please verify if FQDN is valid and address is getting resolved properly.');
                Write-Host $msg -ForegroundColor Red
                [void]$summaryLog.AppendLine()
                [void]$summaryRecommendedAction.AppendLine()
                [void]$summaryLog.AppendLine($msg)
                [void]$summaryRecommendedAction.AppendLine($msg)
                [void]$summaryRecommendedAction.AppendLine()
                TrackWarningAnonymously 'EmptyDNSfromCustomerServer'
            }

            if (!$DNSfromOpenDNSAddress) {
                Write-Host
                $msg = ('DNS resolution using an external provider (OpenDNS) could not be verified, please verify if FQDN is valid and address is getting resolved properly.');
                Write-Host $msg -ForegroundColor Red
                [void]$summaryLog.AppendLine()
                [void]$summaryRecommendedAction.AppendLine()
                [void]$summaryLog.AppendLine($msg)
                [void]$summaryRecommendedAction.AppendLine($msg)
                [void]$summaryRecommendedAction.AppendLine()
                TrackWarningAnonymously 'EmptyDNSfromOpenDNS'
            }

            $hasPrivateLink = HasPrivateLink $Server

            if (($DNSlist.Count -gt 1) -and ($hasPrivateLink -eq $false)) {
                Write-Host
                $msg = ('WARNING: Distinct DNS records were found! (' + [string]::Join(", ", $DNSlist) + ')');
                Write-Host $msg -ForegroundColor Red
                [void]$summaryLog.AppendLine()
                [void]$summaryRecommendedAction.AppendLine()
                [void]$summaryLog.AppendLine($msg)
                [void]$summaryRecommendedAction.AppendLine($msg)
                TrackWarningAnonymously $msg

                $msg = $DNSResolutionGotMultipleAddresses
                Write-Host $msg -Foreground Red
                [void]$summaryRecommendedAction.AppendLine($msg)
            }
        }
        else {
            Write-Host 'DNS resolution:' ([System.Net.DNS]::GetHostAddresses($Server).IPAddressToString)
        }
    }
    Catch {
        Write-Host "Error at ValidateDNS" -Foreground Red
        Write-Host $_.Exception.Message -ForegroundColor Red
    }
}

# MySQL Flexible Server will not be resolved to a GW or private link 
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

# If a Azure MySQL cannot be resolved into a GW address but has privatelink FQDN, it could be 
#   -- a Single Server configured with privatelink and making connections from a client in the same vnet
#   -- a Flexible Server configured with VNet Intergrated and making connections from a client in the same vnet
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

function HasPrivateLink([String] $Server) {
    [bool]((((Resolve-DnsName $Server) | Where-Object { $_.Name -Match ".privatelink." } | Measure-Object).Count) -gt 0)
}

function SanitizeString([String] $param) {
    return ($param.Replace('\', '_').Replace('/', '_').Replace("[", "").Replace("]", "").Replace('.', '_').Replace(':', '_').Replace(',', '_'))
}

function FilterTranscript() {
    Try {
        if ($canWriteFiles) {
            $lineNumber = (Select-String -Path $file -Pattern '..TranscriptStart..').LineNumber
            if ($lineNumber) {
                (Get-Content $file | Select-Object -Skip $lineNumber) | Set-Content $file
            }
        }
    }
    Catch {
        Write-Host $_.Exception.Message -ForegroundColor Red
    }
}

# For MySQL connection protocol, it is expected that a true will be returned with exception thrown because no database is required when establishing a connections.
# In other words, connections can be successfully made without a database name. And if specifying a database, the exception could be thrown against database but connections can still be built
function TestConnectionToDatabase($Server, $gatewayPort, $Database, $User, $Password) {
    # [System.Reflection.Assembly]::LoadWithPartialName("MySql.Data")
    Write-Host
    # [void]$summaryLog.AppendLine()
    Write-Host ([string]::Format("Testing connection to database - {0} (please wait):", $Database)) -ForegroundColor White

    Try {
        
        $MySQLConnection = [MySql.Data.MySqlClient.MySqlConnection]@{ConnectionString='server='+$Server+';port='+$gatewayPort+';uid='+$User+';pwd='+$Password+';database='+$Database}
        $MySQLConnection.Open()
    
        Write-Host ([string]::Format("The connection attempt succeeded", $Database))
        [void]$summaryLog.AppendLine([string]::Format("The connection attempt to {0} database succeeded", $Database))
        [void]$summaryRecommendedAction.AppendLine([string]::Format("The connection attempt to {0} database succeeded", $Database))
        return $true

    } catch [MySql.Data.MySqlClient.MySqlException] {
        $erno = $_.Exception.Number
        $erMsg = $_.Exception.Message
        
        if ($erno -eq '1042') {
            
            Write-Host ($erno) -ForegroundColor Red
            Write-Host ($erMsg) -ForegroundColor Yellow
    
            $msg = 'Connection to database ' + $Database + ' failed due to that the server is not in a ready state.'
    
            [void]$summaryLog.AppendLine($msg)
            [void]$summaryRecommendedAction.AppendLine()
            [void]$summaryRecommendedAction.AppendLine($msg)
            [void]$summaryRecommendedAction.AppendLine('The FQDN can be resolved successfully, however, the MySQL server cannot be reached. ')
            [void]$summaryRecommendedAction.AppendLine('We suggest you:')
            [void]$summaryRecommendedAction.AppendLine('    - Please Verify if the server is put in a STOP mode in Portal!')
            [void]$summaryRecommendedAction.AppendLine('    - Please Verify if the server is in a ready state in Portal!')
            [void]$summaryRecommendedAction.AppendLine('    - Please Verify if the server is in a high CPU or Memory usage!')
            [void]$summaryRecommendedAction.AppendLine('    - The server may be in an automatic failover process and is not ready to accept connections. If the process took long, please dont hesitate to submit a support ticket!')
    
            TrackWarningAnonymously ('TestConnectionToDatabase|unavailble: ' + $erMsg)
            return $false
            
        } 
        elseif ($erMsg -Match 'using password: NO' ) {
            if ($erno -ne '0') {
                Write-Host ($erno) -ForegroundColor Red
            }
            Write-Host ($erMsg) -ForegroundColor Yellow
    
            $msg = 'Connection to database ' + $Database + ' failed due to that the password is missing.'
    
            [void]$summaryLog.AppendLine($msg)
            [void]$summaryRecommendedAction.AppendLine()
            [void]$summaryRecommendedAction.AppendLine($msg)
            [void]$summaryRecommendedAction.AppendLine('It seems that the password is not used. Please ensure the password is correctly input for a sucessful authentitication.')
    
            TrackWarningAnonymously ('TestConnectionToDatabase|Password: ' + $erMsg)
            return $false
        }
        elseif($erMsg -Match 'Access denied for user') {
            if ($erno -ne '0') {
                Write-Host ($erno) -ForegroundColor Red
            }
            Write-Host ($erMsg) -ForegroundColor Yellow
    
            $msg = 'Connection to database ' + $Database + ' failed due to that the username/password is wrong.'
    
            [void]$summaryLog.AppendLine($msg)
            [void]$summaryRecommendedAction.AppendLine()
            [void]$summaryRecommendedAction.AppendLine($msg)
            [void]$summaryRecommendedAction.AppendLine('It seems that the user/password is not correct. Please verify if the correct username/password is placed for a sucessful authentitication.')
    
            TrackWarningAnonymously ('TestConnectionToDatabase|1045: ' + $erMsg)
            return $false
        }
        elseif($erMsg -Match 'Invalid Username') {
            if ($erno -ne '0') {
                Write-Host ($erno) -ForegroundColor Red
            }
            Write-Host ($erMsg) -ForegroundColor Yellow
    
            $msg = 'Connection to database ' + $Database + ' failed.' + $erMsg
    
            [void]$summaryLog.AppendLine($msg)
            [void]$summaryRecommendedAction.AppendLine()
            [void]$summaryRecommendedAction.AppendLine($msg)
            [void]$summaryRecommendedAction.AppendLine('It seems that you are connecting to a Single Server and the format of username used for a Single Server is wrong. Please verify if the correct username is placed for a sucessful authentitication. Ref: https://docs.microsoft.com/en-us/azure/mysql/single-server/how-to-connection-string')
    
            TrackWarningAnonymously ('TestConnectionToDatabase|username: ' + $erMsg)
            return $false
        }
        elseif($erMsg -Match 'Unknown database') {
            if ($erno -ne '0') {
                Write-Host ($erno) -ForegroundColor Red
            }
            Write-Host ($erMsg) -ForegroundColor Yellow
    
            $msg = 'Connection to database ' + $Database + ' failed due to that the database does not exist.'
    
            [void]$summaryLog.AppendLine($msg)
            [void]$summaryRecommendedAction.AppendLine()
            [void]$summaryRecommendedAction.AppendLine($msg)
            [void]$summaryRecommendedAction.AppendLine('It seems that either the database name is not correct or the database does not exist. Please verify if the database exists.')
    
            TrackWarningAnonymously ('TestConnectionToDatabase|1044: ' + $erMsg)
            return $false
        }
        elseif($erMsg -Match 'too many connections') {
            if ($erno -ne '0') {
                Write-Host ($erno) -ForegroundColor Red
            }
            Write-Host ($erMsg) -ForegroundColor Yellow
    
            $msg = 'Connection to database ' + $Database + ' failed due to reaching max_connection limit.'
    
            [void]$summaryLog.AppendLine($msg)
            [void]$summaryRecommendedAction.AppendLine()
            [void]$summaryRecommendedAction.AppendLine($msg)
            [void]$summaryRecommendedAction.AppendLine('It seems that the server hit "too many connections error".')
            [void]$summaryRecommendedAction.AppendLine('We suggest you:')
            [void]$summaryRecommendedAction.AppendLine('    - Please Verify if the number of the active connections reached the max allowed limit in Portal!')
            [void]$summaryRecommendedAction.AppendLine('    - Please consider increase the value of parameter max_connection in Portal!')
            [void]$summaryRecommendedAction.AppendLine('    - Please consider scale up the tier to next level to gain more max allowed connections!')
    
            TrackWarningAnonymously ('TestConnectionToDatabase|1040: ' + $erMsg)
            return $false
        }
        else {
    
            if ($erno -ne '0') {
                Write-Host ($erno) -ForegroundColor Red
            }
            Write-Host ($erMsg) -ForegroundColor Yellow
            TrackWarningAnonymously ('TestConnectionToDatabase|Error: ' + $erMsg)
            return $false
        }
        return $false
    } catch {
        Write-Host $_.Exception.Message -ForegroundColor Yellow
        TrackWarningAnonymously 'TestConnectionToDatabase|Exception'
        return $false
    }
}

function PrintLocalNetworkConfiguration() {
    if (![System.Net.NetworkInformation.NetworkInterface]::GetIsNetworkAvailable()) {
        Write-Host "There's no network connection available!" -ForegroundColor Red
        throw
    }

    $computerProperties = [System.Net.NetworkInformation.IPGlobalProperties]::GetIPGlobalProperties()
    $networkInterfaces = [System.Net.NetworkInformation.NetworkInterface]::GetAllNetworkInterfaces()

    Write-Host 'Interface information for '$computerProperties.HostName'.'$networkInterfaces.DomainName -ForegroundColor Green

    foreach ($networkInterface in $networkInterfaces) {
        if ($networkInterface.NetworkInterfaceType -eq 'Loopback') {
            continue
        }

        $properties = $networkInterface.GetIPProperties()

        Write-Host ' Interface name: ' $networkInterface.Name
        Write-Host ' Interface description: ' $networkInterface.Description
        Write-Host ' Interface type: ' $networkInterface.NetworkInterfaceType
        Write-Host ' Operational status: ' $networkInterface.OperationalStatus

        Write-Host ' Unicast address list:'
        Write-Host $('  ' + [String]::Join([Environment]::NewLine + '  ', [System.Linq.Enumerable]::Select($properties.UnicastAddresses, [Func[System.Net.NetworkInformation.UnicastIPAddressInformation, IPAddress]] { $args[0].Address })))

        Write-Host ' DNS server address list:'
        Write-Host $('  ' + [String]::Join([Environment]::NewLine + '  ', $properties.DnsAddresses))

        Write-Host
    }
}

function RunMySQLFlexPublicConnectivityTests($resolvedAddress) {
    Try {
        $msg = 'Detected as MySQL FLexible Server using Public Endpoint'
        Write-Host $msg -ForegroundColor Yellow
        [void]$summaryLog.AppendLine($msg)

        Write-Host 'Public Endpoint connectivity test:' -ForegroundColor Green
        $testResult = Test-NetConnection $resolvedAddress -Port 3306 -WarningAction SilentlyContinue

        if ($testResult.TcpTestSucceeded) {
            Write-Host ' -> TCP test succeed' -ForegroundColor Green
            PrintAverageConnectionTime $resolvedAddress 3306
            $msg = 'TCP Connectivity to ' + $resolvedAddress + ':3306 succeed'
            [void]$summaryLog.AppendLine($msg)
            TrackWarningAnonymously 'MySQL|FlexPublic|TestSucceeded'
            RunConnectionToDatabaseTestsAndAdvancedTests $Server '3306' $Database $User $Password
        }
        else {
            Write-Host ' -> TCP test FAILED' -ForegroundColor Red
            $msg = ' Connectivity to ' + $resolvedAddress + ':3306 FAILED'
            Write-Host $msg -Foreground Red
            [void]$summaryLog.AppendLine($msg)

            $msg = ' Please make sure you fix the connectivity from this machine to ' + $resolvedAddress + ':3306 (MySQL Flexible public endpoint)'
            Write-Host $msg -Foreground Red
            [void]$summaryRecommendedAction.AppendLine($msg)

            $msg = $AzureMySQLFlex_PublicEndPoint_ConnectionTestFailed
            Write-Host $msg -Foreground Red
            [void]$summaryRecommendedAction.AppendLine($msg)

            TrackWarningAnonymously 'MySQL|FlexPublic|TestFailed'
            return $false
        }
    }
    Catch {
        Write-Host "Error at RunMySQLFlexPublicConnectivityTests" -Foreground Red
        Write-Host $_.Exception.Message -ForegroundColor Red
        TrackWarningAnonymously 'RunMySQLFlexPublicConnectivityTests|Exception'
    }
}

function RunMySQLVNetConnectivityTests($resolvedAddress) {
    Try {
        Write-Host 'Detected as Azure MySQL Server using private connections' -ForegroundColor Yellow
        # $hasPrivateLink = HasPrivateLink $Server
        # if ($hasPrivateLink) {
        #     Write-Host ' This connection seems to be using Private Link' -ForegroundColor Yellow
        #     TrackWarningAnonymously 'MySQL|FlexPrivate'
        # }
        Write-Host
        Write-Host 'Connectivity tests (please wait):' -ForegroundColor Green
        $testResult = Test-NetConnection $resolvedAddress -Port 3306 -WarningAction SilentlyContinue

        if ($testResult.TcpTestSucceeded) {
            Write-Host ' -> TCP test succeed' -ForegroundColor Green
            PrintAverageConnectionTime $resolvedAddress 3306
            TrackWarningAnonymously 'MySQL|Private|TestSucceeded'
            RunConnectionToDatabaseTestsAndAdvancedTests $Server '3306' $Database $User $Password
            return $true
        }
        else {
            Write-Host ' -> TCP test FAILED' -ForegroundColor Red
            Write-Host
            Write-Host ' Trying to get IP routes for interface:' $testResult.InterfaceAlias
            Get-NetRoute -InterfaceAlias $testResult.InterfaceAlias -ErrorAction SilentlyContinue -ErrorVariable ProcessError
            If ($ProcessError) {
                Write-Host '  Could not to get IP routes for this interface'
            }
            Write-Host

            $msg = ' Connectivity to ' + $resolvedAddress + ':3306 FAILED'
            Write-Host $msg -Foreground Red
            [void]$summaryLog.AppendLine()
            [void]$summaryLog.AppendLine($msg)
            [void]$summaryRecommendedAction.AppendLine()
            [void]$summaryRecommendedAction.AppendLine($msg)

            $msg = ' Please fix the connectivity from this machine to ' + $resolvedAddress + ':3306'
            Write-Host $msg -Foreground Red
            [void]$summaryRecommendedAction.AppendLine($msg)

            $msg = $AzureMySQLFlex_VNetTestFailed
            Write-Host $msg -Foreground Red
            [void]$summaryRecommendedAction.AppendLine($msg)

            TrackWarningAnonymously 'MySQL|Private|TestFailed'
            return $false
        }
    }
    Catch {
        Write-Host "Error at RunMySQLVNetConnectivityTests" -Foreground Red
        Write-Host $_.Exception.Message -ForegroundColor Red
        TrackWarningAnonymously 'RunMySQLVNetConnectivityTests|Exception'
        return $false
    }
}

function PrintAverageConnectionTime($addressList, $port) {
    Write-Host ' Printing average connection times for 5 connection attempts:'
    $stopwatch = [StopWatch]::new()

    foreach ($ipAddress in $addressList) {
        [double]$sum = 0
        [int]$numFailed = 0
        [int]$numSuccessful = 0

        for ($i = 0; $i -lt 5; $i++) {
            $client = [TcpClient]::new()
            try {
                $stopwatch.Restart()
                $client.Connect($ipAddress, $port)
                $stopwatch.Stop()

                $sum += $stopwatch.ElapsedMilliseconds

                $numSuccessful++
            }
            catch {
                $numFailed++
            }
            $client.Dispose()
        }

        $avg = 0
        if ($numSuccessful -ne 0) {
            $avg = $sum / $numSuccessful
        }

        $ilb = ''
        if ((IsMySQLFlexPublic $resolvedAddress) -and ($ipAddress -eq $resolvedAddress)) {
            $ilb = ' [ilb]'
        }

        Write-Host '   IP Address:'$ipAddress'  Port:'$port
        Write-Host '   Successful connections:'$numSuccessful
        Write-Host '   Failed connections:'$numFailed
        Write-Host '   Average response time:'$avg' ms '$ilb
    }
}

function RunMySQLConnectivityTests($resolvedAddress) {

    $hasPrivateLink = HasPrivateLink $Server
    $gateway = $MySQLSterlingGateways| Where-Object { $_.Gateways -eq $resolvedAddress }

    if (!$gateway) {
        if ($hasPrivateLink) {
            Write-Host ' This connection seems to be using Private Connection, skipping Gateway connectivity tests' -ForegroundColor Yellow
            TrackWarningAnonymously 'MySQL|PrivateLink'
        }
        # elseif (!$hasPrivateLink -and $resolvedAddress ) {
        #     Write-Host 'Detected as MySQL Flexible Server and public connection is used, skipping Gateway connectivity tests' -ForegroundColor Yellow
        #     TrackWarningAnonymously 'MySQL|MeruPublic'
        # }
        else {
            $msg = ' WARNING: ' + $resolvedAddress + ' is not a valid address'
            Write-Host $msg -Foreground Red
            [void]$summaryLog.AppendLine()
            [void]$summaryLog.AppendLine($msg)
            [void]$summaryRecommendedAction.AppendLine()
            [void]$summaryRecommendedAction.AppendLine($msg)

            $msg = $MySQL_InvalidGatewayIPAddress
            Write-Host $msg -Foreground Red
            [void]$summaryRecommendedAction.AppendLine($msg)

            TrackWarningAnonymously 'MySQL|InvalidGatewayIPAddressWarning'
            return $false
        }

        RunConnectionToDatabaseTestsAndAdvancedTests $Server '3306' $Database $User $Password
    }
    else {
        Write-Host 'Detected as MySQL Single Server' -ForegroundColor Yellow
        TrackWarningAnonymously 'MySQL Single'
        Write-Host ' The server' $Server 'is running on ' -ForegroundColor White -NoNewline
        Write-Host $gateway.Region -ForegroundColor Yellow

        Write-Host
        [void]$summaryLog.AppendLine()
        Write-Host 'Gateway connectivity tests (please wait):' -ForegroundColor Green
        $hasGatewayTestSuccess = $false
        foreach ($gatewayAddress in $gateway.Gateways) {
            Write-Host
            Write-Host ' Testing (gateway) connectivity to' $gatewayAddress':3306' -ForegroundColor White -NoNewline
            $testResult = Test-NetConnection $gatewayAddress -Port 3306 -WarningAction SilentlyContinue

            if ($testResult.TcpTestSucceeded) {
                $hasGatewayTestSuccess = $true
                Write-Host ' -> TCP test succeed' -ForegroundColor Green
                TrackWarningAnonymously ('MySQL|GatewayTestSucceeded|' + $gatewayAddress)
                PrintAverageConnectionTime $gatewayAddress 3306
                $msg = 'Gateway connectivity to ' + $gatewayAddress + ':3306 succeed'
                [void]$summaryLog.AppendLine($msg)
            }
            else {
                Write-Host ' -> TCP test FAILED' -ForegroundColor Red
                Write-Host
                Write-Host ' IP routes for interface:' $testResult.InterfaceAlias
                Get-NetRoute -InterfaceAlias $testResult.InterfaceAlias -ErrorAction SilentlyContinue -ErrorVariable ProcessError
                If ($ProcessError) {
                    Write-Host '  Could not to get IP routes for this interface'
                }
                Write-Host
                if ($PSVersionTable.PSVersion.Major -le 5 -or $IsWindows) {
                    tracert -h 10 $Server
                }

                $msg = 'Gateway connectivity to ' + $gatewayAddress + ':3306 FAILED'
                Write-Host $msg -Foreground Red
                [void]$summaryLog.AppendLine($msg)
                [void]$summaryRecommendedAction.AppendLine()
                [void]$summaryRecommendedAction.AppendLine($msg)

                $msg = ' Please make sure you fix the connectivity from this machine to ' + $gatewayAddress + ':3306 to avoid issues!'
                Write-Host $msg -Foreground Red
                [void]$summaryRecommendedAction.AppendLine($msg)

                $msg = $MySQL_GatewayTestFailed
                Write-Host $msg -Foreground Red
                [void]$summaryRecommendedAction.AppendLine($msg)

                TrackWarningAnonymously ('MySQL|GatewayTestFailed|' + $gatewayAddress)
            }
        }

        if ($gateway.TRs -and $gateway.Cluster -and $gateway.Cluster.Length -gt 0 ) {
            Write-Host
            Write-Host 'Redirect Policy related tests:' -ForegroundColor Green
            $redirectSucceeded = 0
            $redirectTests = 0
            foreach ($tr in $gateway.TRs | Where-Object { $_ -ne '' }) {
                $addr = [string]::Format("{0}.{1}", $tr, $gateway.Cluster)
                $trDNS = Resolve-DnsName -Name $addr -ErrorAction SilentlyContinue
                if ($null -eq $trDNS -or $null -eq $trDNS.IPAddress) {
                    Write-Host (' ' + $addr + ' DNS name could not be resolved, skipping tests on ' + $tr) -ForegroundColor Yellow
                    TrackWarningAnonymously ('TR|DNS|' + $addr)
                    continue
                }

                foreach ($port in $TRPorts) {
                    Write-Host 'Tested (redirect) connectivity to' $addr':'$port -ForegroundColor White -NoNewline
                    $tcpClient = New-Object System.Net.Sockets.TcpClient
                    $portOpen = $tcpClient.ConnectAsync($addr, $port).Wait(6000)
                    if ($portOpen) {
                        $redirectTests += 1
                        $redirectSucceeded += 1
                        Write-Host ' -> TCP test succeeded' -ForegroundColor Green
                    }
                    else {
                        $redirectTests += 1
                        Write-Host ' -> TCP test FAILED' -ForegroundColor Red
                    }
                }
            }

            if ($redirectTests -gt 0) {
                $redirectTestsResultMessage = [System.Text.StringBuilder]::new()
                [void]$redirectTestsResultMessage.AppendLine()
                $redirectTestsResultMessage.ToString()

                [void]$redirectTestsResultMessage.AppendLine('Tested (redirect) connectivity ' + $redirectTests + ' times and ' + $redirectSucceeded + ' of them succeeded')
                [void]$redirectTestsResultMessage.AppendLine('Please note this was just some tests to check connectivity using the 16000-16499 port range, not your database')

                [void]$redirectTestsResultMessage.Append('Some tests may even fail and not be a problem since ports tested here are static and Azure MySQL is a dynamic environment.')

                $msg = $redirectTestsResultMessage.ToString()
                Write-Host $msg -Foreground Yellow
                [void]$summaryLog.AppendLine($msg)

                TrackWarningAnonymously ('MySQL|Redirect|' + $gateway.Region + '|' + $redirectSucceeded + '/' + $redirectTests)

                if ($redirectSucceeded / $redirectTests -ge 0.5 ) {
                    $msg = 'Based on the result it is likely the Redirect Policy will work from this machine'
                    Write-Host $msg -Foreground Green
                    [void]$summaryLog.AppendLine($msg)
                    [void]$summaryLog.AppendLine()
                }
                else {

                    if ($redirectSucceeded / $redirectTests -eq 0.0 ) {
                        $msg = 'Based on the result the Redirect Policy will NOT work from this machine'
                        Write-Host $msg -Foreground Red
                        [void]$summaryLog.AppendLine($msg)
                        [void]$summaryLog.AppendLine()
                        TrackWarningAnonymously 'MySQL|Redirect|AllTestsFailed'
                    }
                    else {
                        $msg = 'Based on the result the Redirect Policy MAY NOT work from this machine, this can be expected for connections from outside Azure'
                        Write-Host $msg -Foreground Red
                        [void]$summaryLog.AppendLine($msg)
                        [void]$summaryLog.AppendLine()
                        TrackWarningAnonymously ('MySQL|Redirect|MoreThanHalfFailed|' + $redirectSucceeded + '/' + $redirectTests)
                    }

                    [void]$summaryRecommendedAction.AppendLine($msg)
                    $msg = $MySQL_Redirect
                    Write-Host $msg -Foreground Red
                    [void]$summaryRecommendedAction.AppendLine($msg)
                }
            }
        }

        if ($hasGatewayTestSuccess -eq $true) {
            RunConnectionToDatabaseTestsAndAdvancedTests $Server '3306' $Database $User $Password
        }
    }
}

function RunConnectivityPolicyTests($port) {
    try {
        Write-Host
        Write-Host 'Advanced connectivity policy tests (please wait):' -ForegroundColor Green

        if ($(Get-ExecutionPolicy) -eq 'Restricted') {
            $msg = ' Advanced connectivity policy tests cannot be run because of current execution policy (Restricted)!
 Please use Set-ExecutionPolicy to allow scripts to run on this system!'
            Write-Host $msg -Foreground Yellow
            [void]$summaryLog.AppendLine()
            [void]$summaryLog.AppendLine($msg)
            [void]$summaryRecommendedAction.AppendLine()
            [void]$summaryRecommendedAction.AppendLine($msg)

            TrackWarningAnonymously 'Advanced|RestrictedExecutionPolicy'
            return
        }

        $jobParameters = @{
            Server                  = $Server
            Database                = $Database
            Port                    = $port
            User                    = $User
            Password                = $Password
            EncryptionProtocol      = $EncryptionProtocol
            RepositoryBranch        = $RepositoryBranch
            Local                   = $Local
            LocalPath               = $LocalPath
            SendAnonymousUsageData  = $SendAnonymousUsageData
            AnonymousRunId          = $AnonymousRunId
            logsFolderName          = $logsFolderName
            outFolderName           = $outFolderName
            ConnectionAttempts      = $ConnectionAttempts
            DelayBetweenConnections = $DelayBetweenConnections
        }

        if ($Local) {
            Copy-Item -Path $($LocalPath + './AdvancedConnectivityPolicyTests.ps1') -Destination ".\AdvancedConnectivityPolicyTests.ps1"
        }
        else {
            try {
                [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 -bor [Net.SecurityProtocolType]::Tls11 -bor [Net.SecurityProtocolType]::Tls
                Invoke-WebRequest -Uri $('https://raw.githubusercontent.com/ShawnXxy/AzMySQL-Connectivity-Checker/' + $RepositoryBranch + '/AdvancedConnectivityPolicyTests.ps1') -OutFile ".\AdvancedConnectivityPolicyTests.ps1" -UseBasicParsing
            }
            catch {
                $msg = $CannotDownloadAdvancedScript
                Write-Host $msg -Foreground Yellow
                [void]$summaryLog.AppendLine()
                [void]$summaryLog.AppendLine($msg)
                [void]$summaryRecommendedAction.AppendLine()
                [void]$summaryRecommendedAction.AppendLine($msg)
                TrackWarningAnonymously 'Advanced|CannotDownloadScript'
                return
            }
        }

        TrackWarningAnonymously 'Advanced|Invoked'
        $job = Start-Job -ArgumentList $jobParameters -FilePath ".\AdvancedConnectivityPolicyTests.ps1"
        Wait-Job $job | Out-Null
        Receive-Job -Job $job

        Set-Location -Path $env:TEMP
        Set-Location $logsFolderName
        Set-Location $outFolderName
        $logPath = Join-Path ((Get-Location).Path) 'AdvancedTests_LastRunLog.txt'
        $result = $([System.IO.File]::ReadAllText($logPath))
        $routingMatch = [Regex]::Match($result, "Routing to: (.*)\.")

        if ($routingMatch.Success) {
            $routingArray = $routingMatch.Groups[1].Value -split ':'
            $routingServer = $routingArray[0]
            $routingPort = $routingArray[1]
            $networkingErrorMatch = [Regex]::Match($result, "Networking error 10060 while trying to connect to (.*)\.")
            $networkingErrorArray = $networkingErrorMatch.Groups[1].Value -split ':'
            $networkingErrorServer = $networkingErrorArray[0]
            $networkingErrorPort = $networkingErrorArray[1]

            if ($networkingErrorMatch.Success -and ($routingServer -ieq $networkingErrorServer) -and ($routingPort -ieq $networkingErrorPort)) {
                [void]$summaryLog.AppendLine()
                [void]$summaryRecommendedAction.AppendLine()
                $msg = "ROOT CAUSE:"
                [void]$summaryLog.AppendLine($msg)
                [void]$summaryRecommendedAction.AppendLine($msg)
                $msg = "The issue is caused by lack of direct network connectivity to the node hosting the database under REDIRECT connection type."
                [void]$summaryLog.AppendLine($msg)
                [void]$summaryRecommendedAction.AppendLine($msg)
                $msg = [string]::Format("This machine cannot connect to {0} on port {1}", $networkingErrorServer, $networkingErrorPort);
                [void]$summaryLog.AppendLine($msg)
                [void]$summaryRecommendedAction.AppendLine($msg)
                [void]$summaryRecommendedAction.AppendLine('This indicates a client-side networking issue (usually a port being blocked) that you will need to pursue with your local network administrator.')
                # if (IsMySQLFlexPublic $resolvedAddress ) {
                #     [void]$summaryRecommendedAction.AppendLine('Make sure firewalls and Network Security Groups (NSG) are open to allow access on ports 11000-11999')
                #     [void]$summaryRecommendedAction.AppendLine('Check more about connection types at https://docs.microsoft.com/en-us/azure/azure-sql/managed-instance/connection-types-overview')
                #     TrackWarningAnonymously ('Advanced|MySQL|RCA|Port' + $networkingErrorPort)
                # }
                # else {
                #     [void]$summaryRecommendedAction.AppendLine('Make sure you allow outbound communication from the client to all Azure MySQL IP addresses in the region on ports in the range of 16000-16499.')
                #     [void]$summaryRecommendedAction.AppendLine('Check more about connection policies at https://docs.microsoft.com/en-us/azure/azure-sql/database/connectivity-architecture#connection-policy')
                #     TrackWarningAnonymously ('Advanced|MySQL|RCA|Port' + $networkingErrorPort)
                # }
            }
        }
        Remove-Item ".\AdvancedConnectivityPolicyTests.ps1" -Force
    }
    catch {
        $msg = ' ERROR running Advanced Connectivity Tests: ' + $_.Exception.Message
        Write-Host $msg -Foreground Red
        [void]$summaryLog.AppendLine()
        [void]$summaryLog.AppendLine($msg)
        TrackWarningAnonymously 'ERROR running Advanced Connectivity Test'
    }
}

function LookupDatabaseMySQL($Server, $dbPort, $Database, $User, $Password) {
    # [System.Reflection.Assembly]::LoadWithPartialName("MySql.Data")
    Write-Host
    [void]$summaryLog.AppendLine()
    # Write-Host ([string]::Format("Testing connecting to database - {0} (please wait).", $Database)) -ForegroundColor Green
    Try {
        Write-Host 'Checking if' $Database 'exists:' -ForegroundColor White
        $MySQLConnection = [MySql.Data.MySqlClient.MySqlConnection]@{ConnectionString='server='+$Server+';port='+$gatewayPort+';uid='+$User+';pwd='+$Password+';database='+$Database}
        $MySQLConnection.Open()

        $MySQLCommand = New-Object MySql.Data.MySqlClient.MySqlCommand
        $MySQLCommand.Connection = $MySQLConnection

        $MySQLCommand.CommandText = "USE " + $Database + ";"
        $MySQLResult = $MySQLCommand.ExecuteReader()
        while ($MySQLResult.Read()) { 
            $MySQLResult.GetString(0) 
        }

        return $MySQLResult.C -ne 0
        
    }
    Catch {
        Write-Host $_.Exception.Message -ForegroundColor Yellow
        TrackWarningAnonymously 'LookupDatabaseMySQL|Exception'
        return $false
    }
}


function RunConnectionToDatabaseTestsAndAdvancedTests($Server, $dbPort, $Database, $User, $Password) {
    try {
        $customDatabaseNameWasSet = $Database -and $Database.Length -gt 0 -and $Database -ne 'information_schema'

        #Test information_schema database
        $canConnectToDefault = TestConnectionToDatabase $Server $dbPort 'information_schema' $User $Password

        if ($customDatabaseNameWasSet) {
            if ($canConnectToDefault -Match 'True') {
                $msg = 'Default database information_schema can be sucessfully reached. The connectiviy to this MySQL should be good.'
                Write-Host $msg -Foreground Green
                Write-Host "Can connect to default database inforamtion_schema? " + $canConnectToDefault -Foreground Yellow
                [void]$summaryRecommendedAction.AppendLine($msg)

                $databaseFound = LookupDatabaseMySQL $Server $dbPort $Database $User $Password

                if ($databaseFound -eq $true) {
                    $msg = $Database + ' was found in MySQL'
                    Write-Host $msg -Foreground Green
                    [void]$summaryLog.AppendLine($msg)

                    #Test database from parameter
                    if ($customDatabaseNameWasSet) {
                        TestConnectionToDatabase $Server $dbPort $Database $User $Password | Out-Null
                    }
                }
                else {
                    $msg = 'ERROR: ' + $Database + ' was not found in MySQL!'
                    Write-Host $msg -Foreground Red
                    [void]$summaryLog.AppendLine()
                    [void]$summaryLog.AppendLine($msg)
                    [void]$summaryRecommendedAction.AppendLine()
                    [void]$summaryRecommendedAction.AppendLine($msg)

                    $msg = 'Please confirm the database name is correct and/or look at the operation logs to see if the database has been dropped by another user.'
                    Write-Host $msg -Foreground Red
                    [void]$summaryRecommendedAction.AppendLine($msg)
                    TrackWarningAnonymously 'DatabaseNotFoundInMySQL'
                }
            }
            else {
                #Test database from parameter anyway
                $msg = 'Default database information_schema cannot be reached. There could be a connectivity issue or lacking of permission to the database. Please refer to other checks below.'
                Write-Host $msg -Foreground Red
                [void]$summaryRecommendedAction.AppendLine($msg)
                [void]$summaryRecommendedAction.AppendLine()

                $msg = 'Start to check connecitivity to custom database: ' + $Database 
                Write-Host $msg -Foreground Yellow

                if ($customDatabaseNameWasSet) {
                    TestConnectionToDatabase $Server $dbPort $Database $User $Password | Out-Null
                }
            }
        }

        #Advanced Connectivity Tests
        if ($RunAdvancedConnectivityPolicyTests) {
            RunConnectivityPolicyTests $dbPort
        }
    }
    catch {
        $msg = ' ERROR at RunConnectionToDatabaseTestsAndAdvancedTests: ' + $_.Exception.Message
        Write-Host $msg -Foreground Red
        [void]$summaryLog.AppendLine()
        [void]$summaryLog.AppendLine($msg)
        TrackWarningAnonymously 'ERROR at RunConnectionToDatabaseTestsAndAdvancedTests'
    }
}

function TrackWarningAnonymously ([String] $warningCode) {
    Try {
        if ($SendAnonymousUsageData) {
            $body = New-Object PSObject `
            | Add-Member -PassThru NoteProperty name 'Microsoft.ApplicationInsights.Event' `
            | Add-Member -PassThru NoteProperty time $([System.dateTime]::UtcNow.ToString('o')) `
            | Add-Member -PassThru NoteProperty iKey "c65afb3b-f428-49d2-a3de-cf2ecc803cc3" `
            | Add-Member -PassThru NoteProperty tags (New-Object PSObject | Add-Member -PassThru NoteProperty 'ai.user.id' $AnonymousRunId) `
            | Add-Member -PassThru NoteProperty data (New-Object PSObject `
                | Add-Member -PassThru NoteProperty baseType 'EventData' `
                | Add-Member -PassThru NoteProperty baseData (New-Object PSObject `
                    | Add-Member -PassThru NoteProperty ver 2 `
                    | Add-Member -PassThru NoteProperty name $warningCode));
            $body = $body | ConvertTo-JSON -depth 5;
            Invoke-WebRequest -Uri 'https://dc.services.visualstudio.com/v2/track' -ErrorAction SilentlyContinue -Method 'POST' -UseBasicParsing -body $body > $null
        }
    }
    Catch {
        Write-Host 'TrackWarningAnonymously exception:'
        Write-Host $_.Exception.Message -ForegroundColor Red
    }
}

$ProgressPreference = "SilentlyContinue";

if ([string]::IsNullOrEmpty($env:TEMP)) {
    $env:TEMP = '/tmp';
}

try {
    Clear-Host
    $canWriteFiles = $true
    try {
        $logsFolderName = 'AzureMySQLConnectivityCheckerResults'
        Set-Location -Path $env:TEMP
        If (!(Test-Path $logsFolderName)) {
            New-Item $logsFolderName -ItemType directory | Out-Null
            Write-Host 'The folder' $logsFolderName 'was created'
        }
        else {
            Write-Host 'The folder' $logsFolderName 'already exists'
        }
        Set-Location $logsFolderName
        $outFolderName = [System.DateTime]::Now.ToString('yyyyMMddTHHmmss')
        New-Item $outFolderName -ItemType directory | Out-Null
        Set-Location $outFolderName

        $file = '.\Log_' + (SanitizeString ($Server.Replace('.mysql.database.azure.com', ''))) + '_' + (SanitizeString $Database) + '_' + [System.DateTime]::Now.ToString('yyyyMMddTHHmmss') + '.txt'
        Start-Transcript -Path $file
        Write-Host '..TranscriptStart..'
    }
    catch {
        $canWriteFiles = $false
        Write-Host Warning: Cannot write log file -ForegroundColor Yellow
    }

    TrackWarningAnonymously 'v1.0'
    TrackWarningAnonymously ('PowerShell ' + $PSVersionTable.PSVersion + '|' + $PSVersionTable.Platform + '|' + $PSVersionTable.OS )

    try {
        Write-Host '******************************************' -ForegroundColor Green
        Write-Host '  Azure MySQL Connectivity Checker v1.0  ' -ForegroundColor Green
        Write-Host '******************************************' -ForegroundColor Green
        Write-Host
        Write-Host 'Parameters' -ForegroundColor Yellow
        Write-Host ' Server:' $Server -ForegroundColor Yellow

        if ($null -ne $Database) {
            Write-Host ' Database:' $Database -ForegroundColor Yellow
        }
        if ($null -ne $RunAdvancedConnectivityPolicyTests) {
            Write-Host ' RunAdvancedConnectivityPolicyTests:' $RunAdvancedConnectivityPolicyTests -ForegroundColor Yellow
            TrackWarningAnonymously ('RunAdvancedConnectivityPolicyTests:' + $RunAdvancedConnectivityPolicyTests)
        }
        if ($null -ne $CollectNetworkTrace) {
            Write-Host ' CollectNetworkTrace:' $CollectNetworkTrace -ForegroundColor Yellow
            TrackWarningAnonymously ('CollectNetworkTrace:' + $CollectNetworkTrace)
        }
        if ($null -ne $EncryptionProtocol) {
            Write-Host ' EncryptionProtocol:' $EncryptionProtocol -ForegroundColor Yellow
            TrackWarningAnonymously ('EncryptionProtocol:' + $EncryptionProtocol)
        }
        if ($null -ne $ConnectionAttempts) {
            Write-Host ' ConnectionAttempts:' $ConnectionAttempts -ForegroundColor Yellow
            TrackWarningAnonymously ('ConnectionAttempts:' + $ConnectionAttempts)
        }
        if ($null -ne $DelayBetweenConnections) {
            Write-Host ' DelayBetweenConnections:' $DelayBetweenConnections -ForegroundColor Yellow
            TrackWarningAnonymously ('DelayBetweenConnections:' + $DelayBetweenConnections)
        }
        Write-Host

        $Server = $Server.Trim()

        $Server = $Server.Replace('tcp:', '')
        $Server = $Server.Replace(',3306', '')
        # $Server = $Server.Replace(',3342', '')
        $Server = $Server.Replace(';', '')

        if (!$Server -or $Server.Length -eq 0 -or $Server -eq '.mysql.database.azure.com') {
            $msg = $ServerNameNotSpecified
            Write-Host $msg -Foreground Red
            [void]$summaryLog.AppendLine($msg)
            [void]$summaryRecommendedAction.AppendLine($msg)
            TrackWarningAnonymously 'ServerNameNotSpecified'
            Write-Error '' -ErrorAction Stop
        }

        if (!$Server.EndsWith('.mysql.database.azure.com') `
                -and !$Server.EndsWith('.mysql.database.chinacloudapi.cn') `
                -and !$Server.EndsWith('.mysql.database.chinacloudapi.com') `
                -and !$Server.EndsWith('.privatelink.mysql.database.azure.com')) {
            $Server = $Server + '.mysql.database.azure.com'
        }

        #Print local network configuration
        PrintLocalNetworkConfiguration

        if ($canWriteFiles -and $CollectNetworkTrace) {
            if (!$CustomerRunningInElevatedMode) {
                Write-Host 'Powershell must be run as an administrator in order to collect network trace!' -ForegroundColor Yellow
                $netWorkTraceStarted = $false
            }
            else {
                $traceFileName = (Get-Location).Path + '\NetworkTrace_' + [System.DateTime]::Now.ToString('yyyyMMddTHHmmss') + '.etl'
                $startNetworkTrace = "netsh trace start persistent=yes capture=yes tracefile=$traceFileName"
                Invoke-Expression $startNetworkTrace
                $netWorkTraceStarted = $true
            }
        }

        ValidateDNS $Server

        try {
            $dnsResult = [System.Net.DNS]::GetHostEntry($Server)
        }
        catch {
            $msg = ' ERROR: Name resolution (DNS) of ' + $Server + ' failed'
            Write-Host $msg -Foreground Red
            [void]$summaryLog.AppendLine($msg)

            if (IsMySQLFlexPublic $resolvedAddress) {
                $msg = $DNSResolutionFailedAzureMySQLFlexPublic
                Write-Host $msg -Foreground Red
                [void]$summaryRecommendedAction.AppendLine($msg)
                TrackWarningAnonymously 'DNSResolutionFailedAzureMySQLFlexPublic'
            }
            else {
                $msg = $DNSResolutionFailed
                Write-Host $msg -Foreground Red
                [void]$summaryRecommendedAction.AppendLine($msg)
                TrackWarningAnonymously 'DNSResolutionFailed'
            }
            Write-Error '' -ErrorAction Stop
        }
        $resolvedAddress = $dnsResult.AddressList[0].IPAddressToString
        $dbPort = 3306

        #Run connectivity tests
        Write-Host
        if (IsMySQLFlexPublic $resolvedAddress) {
            RunMySQLFlexPublicConnectivityTests $resolvedAddress
        }
        elseif (IsMySQLVNet $resolvedAddress) {
            RunMySQLVNetConnectivityTests $resolvedAddress
        }
        else {
            RunMySQLConnectivityTests $resolvedAddress
        }

        Write-Host
        [void]$summaryLog.AppendLine()
        Write-Host 'Test endpoints for AAD Password and Integrated Authentication:' -ForegroundColor Green
        Write-Host 'Tested connectivity to login.windows.net:443' -ForegroundColor White -NoNewline
        $tcpClient = New-Object System.Net.Sockets.TcpClient
        $portOpen = $tcpClient.ConnectAsync("login.windows.net", 443).Wait(10000)
        if ($portOpen) {
            Write-Host ' -> TCP test succeeded' -ForegroundColor Green
            $msg = 'Connectivity to login.windows.net:443 succeed (used for AAD Password and Integrated Authentication)'
            [void]$summaryLog.AppendLine($msg)
        }
        else {
            Write-Host ' -> TCP test FAILED' -ForegroundColor Red
            $msg = 'Connectivity to login.windows.net:443 FAILED (used for AAD Password and AAD Integrated Authentication)'
            Write-Host $msg -Foreground Red
            [void]$summaryLog.AppendLine($msg)

            $msg = $AAD_login_windows_net
            Write-Host $msg -Foreground Red
            [void]$summaryRecommendedAction.AppendLine()
            [void]$summaryRecommendedAction.AppendLine($msg)
            TrackWarningAnonymously 'AAD|login.windows.net'
        }

        Write-Host
        Write-Host 'Test endpoints for Universal with MFA authentication:' -ForegroundColor Green
        Write-Host ' Tested connectivity to login.microsoftonline.com:443' -ForegroundColor White -NoNewline
        $tcpClient = New-Object System.Net.Sockets.TcpClient
        $portOpen = $tcpClient.ConnectAsync("login.microsoftonline.com", 443).Wait(10000)
        if ($portOpen) {
            Write-Host ' -> TCP test succeeded' -ForegroundColor Green
            $msg = 'Connectivity to login.microsoftonline.com:443 succeed (used for AAD Universal with MFA authentication)'
            [void]$summaryLog.AppendLine($msg)
        }
        else {
            Write-Host ' -> TCP test FAILED' -ForegroundColor Red
            $msg = 'Connectivity to login.microsoftonline.com:443 FAILED (used for AAD Universal with MFA authentication)'
            Write-Host $msg -Foreground Red
            [void]$summaryLog.AppendLine($msg)

            $msg = $AAD_login_microsoftonline_com
            Write-Host $msg -Foreground Red
            [void]$summaryRecommendedAction.AppendLine()
            [void]$summaryRecommendedAction.AppendLine($msg)
            TrackWarningAnonymously 'AAD|login.microsoftonline.com'
        }

        Write-Host ' Tested connectivity to secure.aadcdn.microsoftonline-p.com:443' -ForegroundColor White -NoNewline
        $tcpClient = New-Object System.Net.Sockets.TcpClient
        $portOpen = $tcpClient.ConnectAsync("secure.aadcdn.microsoftonline-p.com", 443).Wait(10000)
        if ($portOpen) {
            Write-Host ' -> TCP test succeeded' -ForegroundColor Green
            $msg = 'Connectivity to secure.aadcdn.microsoftonline-p.com:443 succeed (used for AAD Universal with MFA authentication)'
            [void]$summaryLog.AppendLine($msg)
        }
        else {
            Write-Host ' -> TCP test FAILED' -ForegroundColor Red
            $msg = 'Connectivity to secure.aadcdn.microsoftonline-p.com:443 FAILED (used for AAD Universal with MFA authentication)'
            Write-Host $msg -Foreground Red
            [void]$summaryLog.AppendLine($msg)

            $msg = $AAD_secure_aadcdn_microsoftonline_p_com
            Write-Host $msg -Foreground Red
            [void]$summaryRecommendedAction.AppendLine()
            [void]$summaryRecommendedAction.AppendLine($msg)
            TrackWarningAnonymously 'AAD|secure.aadcdn.microsoftonline-p.com'
        }

        Write-Host
        Write-Host 'All tests are now done!' -ForegroundColor Green
    }
    catch {
        Write-Host $_.Exception.Message -ForegroundColor Red
        Write-Host 'Exception thrown while testing, stopping execution...' -ForegroundColor Yellow
    }
    finally {
        if ($netWorkTraceStarted) {
            Write-Host 'Stopping network trace.... please wait, this may take a few minutes' -ForegroundColor Yellow
            $stopNetworkTrace = "netsh trace stop"
            Invoke-Expression $stopNetworkTrace
            $netWorkTraceStarted = $false
        }

        Write-Host
        Write-Host '######################################################' -ForegroundColor Green
        Write-Host 'SUMMARY:' -ForegroundColor Yellow
        Write-Host '######################################################' -ForegroundColor Green
        Write-Host $summaryLog.ToString() -ForegroundColor Yellow
        Write-Host
        Write-Host '######################################################' -ForegroundColor Green
        Write-Host 'RECOMMENDED ACTION(S):' -ForegroundColor Yellow
        Write-Host '######################################################' -ForegroundColor Green
        if ($summaryRecommendedAction.Length -eq 0) {
            Write-Host 'We could not detect any issue while using SqlClient driver, we suggest you:' -ForegroundColor Green
            Write-Host ' - Verify if you are using an updated version of the client driver or tool.' -ForegroundColor Yellow
            Write-Host ' - Verify if you can connect using a different client driver or tool.' -ForegroundColor Yellow

            if (IsMySQLFlexPublic $resolvedAddress ) {
                Write-Host ' See required versions of drivers and tools at https://docs.microsoft.com/en-us/azure/mysql/concepts-compatibility' -ForegroundColor Yellow
            }

            Write-Host ' - Verify your connection string and credentials.' -ForegroundColor Yellow
            Write-Host ' See more at https://docs.microsoft.com/en-us/azure/mysql/single-server/how-to-connection-string' -ForegroundColor Yellow
            Write-Host
            Write-Host 'If you have any feedback/issue/request let us know at https://github.com/ShawnXxy/AzMySQL-Connectivity-Checker/issues' -ForegroundColor Green

            TrackWarningAnonymously 'NoRecommendedActions2'
        }
        else {
            Write-Host $summaryRecommendedAction.ToString() -ForegroundColor Yellow
        }
        Write-Host
        Write-Host

        if ($canWriteFiles) {
            try {
                Stop-Transcript | Out-Null
            }
            catch [System.InvalidOperationException] { }

            FilterTranscript
        }
    }
}
finally {
    if ($canWriteFiles) {
        Write-Host Log file can be found at (Get-Location).Path
        if ($PSVersionTable.PSVersion.Major -ge 5) {
            $destAllFiles = (Get-Location).Path + '/AllFiles.zip'
            Compress-Archive -Path ((Get-Location).Path + '/*.txt'), ((Get-Location).Path + '/*.cab'), ((Get-Location).Path + '/*.etl') -DestinationPath $destAllFiles -Force
            Write-Host 'A zip file with all the files can be found at' $destAllFiles -ForegroundColor Green
        }

        if ($PSVersionTable.Platform -eq 'Unix') {
            Get-ChildItem
        }
        else {
            Invoke-Item (Get-Location).Path
        }
    }
}