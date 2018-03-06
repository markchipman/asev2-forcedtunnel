#-------------------------------------------------------------------------
# Copyright (c) Microsoft.  All rights reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#--------------------------------------------------------------------------

# Variables - update to match your deployment

$subscriptionId = "00000000-0000-0000-0000-000000000000"
$aseName = "ase"
$aseResourceGroup = "ase-rg"
$logStorageAccount = "logsa"
$logResourceGroupName = "logsa-rg"
$logRule = "UserRule_azure-storage-outbound"

# Convert from Unix EPOC time to .NET DateTime format

Function ConvertFrom-UnixTime ($timestamp)
{
        $origin = New-Object -Type DateTime -ArgumentList 1970, 1, 1, 0, 0, 0, 0
        return $origin.AddSeconds($timestamp)
}

# Retrieve ASE outbound management endpoints

Function Get-ASEOutboundEndpoints ([string]$adTenant, [string]$subscriptionId, [string]$resourceGroup, [string]$aseName)
{

    $clientId = "1950a258-227b-4e31-a9cf-717495945fc2" # Well-known client ID for Azure PowerShell
    $redirectUri = "urn:ietf:wg:oauth:2.0:oob" # Redirect URI for Azure PowerShell
    $resourceAppIdURI = "https://management.core.windows.net/" # Resource URI for REST API
    $authority = "https://login.windows.net/$adTenant" # Azure AD Tenant Authority
    $apiVersion = "2016-09-01"
    $contentType = "application/json;charset=utf-8"
            
    $adal = "${env:ProgramFiles(x86)}\Microsoft SDKs\Azure\PowerShell\ServiceManagement\Azure\Services\Microsoft.IdentityModel.Clients.ActiveDirectory.dll"
    $adalforms = "${env:ProgramFiles(x86)}\Microsoft SDKs\Azure\PowerShell\ServiceManagement\Azure\Services\Microsoft.IdentityModel.Clients.ActiveDirectory.WindowsForms.dll"

    Add-Type -Path $adal
    Add-Type -Path $adalforms

    $authContext = New-Object "Microsoft.IdentityModel.Clients.ActiveDirectory.AuthenticationContext" -ArgumentList $authority
    $authResult = $authContext.AcquireToken($resourceAppIdURI, $clientId, $redirectUri, "Auto")
    $authHeader = $authResult.CreateAuthorizationHeader()
    $requestHeader = @{"Authorization" = $authHeader}

    $resourceType = "Microsoft.Web/hostingEnvironments"
    $apiOperation = "outboundnetworkdependenciesendpoints"
    $uriSuffix = "/subscriptions/${subscriptionId}/resourceGroups/${resourceGroup}/providers/${resourceType}/${aseName}/${apiOperation}?api-version=${apiVersion}"
    $managementUri = "https://management.azure.com"
    $uri = $managementUri + $uriSuffix

    $responseData = Invoke-RestMethod `
        -Uri $uri `
        -Method Get `
        -Headers $requestHeader `
        -ContentType $contentType

    return $responseData

}

# Pull NSG Flow logs

Function Get-NSGFlowLogEntries ([string]$storageAccount, [string]$resourceGroup, [string]$logRule)
{

    $logStorageContainer = "insights-logs-networksecuritygroupflowevent"
    $logStorageKey = (Get-AzureRmStorageAccountKey -Name $logStorageAccount -ResourceGroupName $logResourceGroupName)[0].Value
    $logStorageContext = New-AzureStorageContext -StorageAccountName $logStorageAccount -StorageAccountKey $logStorageKey

    $continuationToken = $null
    $blobList = @()

    Set-Location -path $env:TEMP

    Do 
    {
        $blobs = (Get-AzureStorageContainer -Name $logStorageContainer -Context $logStorageContext | Get-AzureStorageBlob)
        $continuationToken = $blobs[-1].ContinuationToken
        $blobList += $blobs.Name
    } 
    Until ( $continuationToken -eq $null )

    $logRecords = @()
    
    Foreach ($blobName in $blobList) 
    {
        $blobContent = Get-AzureStorageBlobContent -Container $logStorageContainer -Blob $blobName -Context $logStorageContext -Force
        $blobJson = Get-Content -Path $blobContent.Name | ConvertFrom-Json
        $logRecords += $blobJson.records.properties.flows | Where-Object rule -eq $logRule
    }

    return $logRecords
}

# BEGIN MAIN SCRIPT

# Authenticate to Azure - can automate with Azure AD Service Principal credentials

Login-AzureRmAccount

# Set Azure AD Tenant for selected Azure Subscription

$adTenant = 
    (Get-AzureRmSubscription `
        -SubscriptionId $subscriptionId).TenantId

# Select Azure subscription

Set-AzureRmContext -Subscription $subscriptionId -Tenant $adTenant

# Get ASE storage endpoints used for management

$aseEndpoints = Get-ASEOutboundEndpoints -adTenant $adTenant -subscriptionId $subscriptionId -resourceGroup $aseResourceGroup -aseName $aseName
$storageEndpoints = ($aseEndpoints.value | Where-Object Description -eq "Azure Storage").endpoints

# Process NSG Flow Logs 

$logRecords = Get-NSGFlowLogEntries -storageAccount $logStorageAccount -resourceGroup $logResourceGroupName -logRule $logRule

# Display NSG flow log records not matching ASE outbound storage endpoints for management

$csvHeader = "timestamp","source_ip","dest_ip","source_port","dest_port", "flag1", "flag2", "flag3"

$logRecords.flows.flowTuples | 
    convertfrom-csv -Header $csvHeader | 
    where-object dest_ip -NotIn $storageEndpoints | 
    Select-Object `
        @{n='timestamp';e={ConvertFrom-UnixTime($_.timestamp)}},
        source_ip,
        dest_ip,
        source_port,
        dest_port |
    Sort-Object -Property timestamp |
    Format-Table

# Display unique list of destination storage endpoints not matching ASE outbound storage endpoints for management

$csvHeader = "timestamp","source_ip","dest_ip","source_port","dest_port", "flag1", "flag2", "flag3"

$logRecords.flows.flowTuples | 
    convertfrom-csv -Header $csvHeader | 
    where-object dest_ip -NotIn $storageEndpoints | 
    Select-Object `
        dest_ip |
    Sort-Object -Property dest_ip -Unique
