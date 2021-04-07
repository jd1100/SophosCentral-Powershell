### function ###
function Toggle-TamperProtection {

    param (
        
        ## hostname ##
        [Parameter(Mandatory=$false,ValueFromPipeline=$true)]
        [string]
        $computerName
        ,
        [Parameter(Mandatory=$false)]
        [string]
        $csv
        ,
        [Parameter(Mandatory=$false)]
        [string]
        $all
        ,
        [Parameter(Mandatory=$false)]
        [switch]
        $enable
        ,
        [Parameter(Mandatory=$false)]
        [switch]
        $disable
    
    )

    $sophosApiResponse = Authenticate-SophosApi

    if ($disable) {
        $promptUserMessage = "disabling"
        $json = @{"enabled" = "false"} | ConvertTo-Json
    }
    elseIf ($enable) {
        $promptUserMessage = "enabling"
        $json = @{"enabled" = "true"} | ConvertTo-Json
    }
    else {
        Write-Host "[ERROR] please supply -enable or -disable flags when toggling tamper protection"
        return
    }

    if($all) {
        $promptUser = Read-Host "$($promptUserMessage) + tamper protection from all devices. Press 'y' to continue."
        if($promptUser -eq 'y') {
            $endpoints = Get-SophosEndpoints -sophosApiResponse $sophosApiResponse

            foreach ($endpoint in $endpoints) {
                $endpointId = $endpoint.id
                    
                # build the uri for removing tamper protection from the specified $ComputerName (requires the $endpointId) 
                $uri = ($sophosApiResponse['dataRegionApiUri'] + "/endpoint/v1/endpoints/" + $endpointId + "/tamper-protection")
    
                # api request to remove tamper protection 
                $tamperProtectionToggleResponse = Invoke-RestMethod -Method Post -Headers @{Authorization="Bearer $($sophosApiResponse['token_resp'].access_token)"; "X-Tenant-ID"=$sophosApiResponse['whoami_resp'].id} -ContentType "application/json" -Body $json -Uri $uri


            }

        }
        else {
            Write-Host "exiting..."
            return
        }
    }
    if($csv) {
        $endpointsCsv = Import-SophosEndpointHostList -csv $csv


        foreach ($endpoint in $endpointsCsv) {
            Write-Host $endpoint.hosts

            $endpointId = Get-SophosEndpointId -computerName $endpoint.hosts -sophosApiResponse $sophosApiResponse
                    
            # build the uri for removing tamper protection from the specified $ComputerName (requires the $endpointId) 
            $uri = ($sophosApiResponse['dataRegionApiUri'] + "/endpoint/v1/endpoints/" + $endpointId + "/tamper-protection")
            
            try {
                # api request to remove tamper protection 
                $tamperProtectionToggleResponse = Invoke-RestMethod -Method Post -Headers @{Authorization="Bearer $($sophosApiResponse['token_resp'].access_token)"; "X-Tenant-ID"=$sophosApiResponse['whoami_resp'].id} -ContentType "application/json" -Body $json -Uri $uri

            } 
            catch {
                Write-Warning "Failed to toggle tamper protection for device: $($endpoint.hosts) with id: $($endpointId)"
                Write-Warning $Error[0]  
            }

        }
    }
    elseIf ($computerName) {
        

        # get the associated endpointId for the specified $ComputerName
        
        $endpointId = Get-SophosEndpointId $computerName

        if ($endpointId -eq $null) {
            return
        }
    
        # build the uri for removing tamper protection from the specified $ComputerName (requires the $endpointId) 
        $uri = ($sophosApiResponse['dataRegionApiUri'] + "/endpoint/v1/endpoints/" + $endpointId + "/tamper-protection")
        
        # api request to remove tamper protection
        try { 
            $tamperProtectionToggleResponse = Invoke-RestMethod -Method Post -Headers @{Authorization="Bearer $($sophosApiResponse['token_resp'].access_token)"; "X-Tenant-ID"=$sophosApiResponse['whoami_resp'].id} -Uri $uri -ContentType "application/json" -Body $json
        }
        catch {
            Write-Warning "Failed to toggle tamper protection for device: $($computerName) with id: $($endpointId)"
            Write-Warning $Error[0]

        }
        

        Write-Host "$($promptUserMessage) tamper protection on device: $($ComputerName)"
    }
    else {
        Write-Host "no endpoints specified"
        return
    }
}

### function ###
function Get-SophosEndpoints {

    param (
        
        [Parameter(Mandatory=$false)]
        $sophosApiResponse
        ,
        [Parameter(Mandatory=$false)]
        [switch]
        $export
    
    )
    
    if (!($sophosApiResponse)) {
        $sophosApiResponse = Authenticate-SophosApi
    }
    
    #Write-Host "token response is: $($sophosApiResponse["token_resp"].access_token)"
    #Write-Host "whoami response: $($sophosApiResponse["whoami_resp"].id)"
    #Write-Host "data region uri: $($sophosApiResponse["dataRegionApiUri"])"

    $endpoint_key = $sophosApiResponse["endpoints_resp"].pages.nextKey
    
    $sophosEndpoints = @()
    $sophosEndpoints_noDupes = @()


    Write-Host "grabbing updated list of endpoints from sophos api..."
    Do {
    
        #Write-Host $endpoint_key
    
        $endpoints_resp = Invoke-RestMethod -Method Get -Headers @{Authorization="Bearer $($sophosApiResponse["token_resp"].access_token)"; "X-Tenant-ID"=$sophosApiResponse["whoami_resp"].id} ($($sophosApiResponse["dataRegionApiUri"])+"/endpoint/v1/endpoints?pageSize=500&pageTotal=true&pageFromKey=$($endpoint_key)")
            
        # enumerate results and append to csv
        $sophosEndpoints += @($endpoints_resp.items | 
            Select-Object -Property id,type,hostname,health,os,
            @{name="ipv4Addresses"; expression={$_.ipv4Addresses | select -First 1}},
            @{name="ipv6Addresses"; expression={$_.ipv6Addresses | Select -First 1}},
            @{name="macAddresses"; expression={$_.macAddresses | Select -First 1}},
            associatedPerson,tamperProtectionEnabled,
            @{name="endpointProtection"; expression={$_.assignedProducts[0] | Where-Object -Property code -eq -Value "endpointProtection"}},
            @{name="interceptX"; expression={$_.assignedProducts[1] | Where-Object -Property code -eq -Value "interceptX"}},
            @{name="coreAgent"; expression={$_.assignedProducts[2] | Where-Object -Property code -eq -Value "coreAgent"}},
            lastSeenAt)
        #Write-Host $endpoints_resp.items
            
        Start-Sleep -Seconds 2

        $endpoint_key = $endpoints_resp.pages.nextKey
    } 
    While ($endpoints_resp.pages.fromKey -ne "")
    
    ##----##

    ## remove duplicate devices ##
    Write-Host "removing duplicates...."

    
    # sort the endpoints using the "lastSeenAt" property descending and then group endpoints with the same hostname
    $endpoints_grouped_duplicates_sorted = $sophosEndpoints | Sort-Object {$_."lastSeenAt" -as [datetime]} -Descending | Group-Object "hostname"

    ForEach ($endpoint_group in $endpoints_grouped_duplicates_sorted) {

        # expand group of duplicate endpoint objects
        $duplicates = Select-Object -InputObject $endpoint_group -ExpandProperty "Group" 
    
        # select the unique endpoint from the duplicates
        $unique_endpoint = $duplicates | select -First 1

        $sophosEndpoints_noDupes += $unique_endpoint

    }

    if ($export) {
        $sophosEndpoints_noDupes = $sophosEndpoints_noDupes | Export-Csv -Path .\endpoints.csv -NoTypeInformation -Encoding UTF8
    } else {
        $sophosEndpoints_noDupes = $sophosEndpoints_noDupes | sort "hostname"
    }

    return $sophosEndpoints_noDupes
}

### function ###
function Get-SophosEndpointId {

    param (
    
        [Parameter(Mandatory=$true,Position=0)]
        [String] 
        $computerName
        ,
        [Parameter(Mandatory=$false)]
        $sophosApiResponse

    )
    
    $endpoints = Get-SophosEndpoints $sophosApiResponse

    # loop through all devices on sophos to find matching id for current device
    ForEach ($endpoint in $endpoints) {
        #Write-Host $endpoint
        
        if($computerName -eq $endpoint.hostname) {
            return $endpoint.id
        }

    }
    Write-Host "Device: $computerName not found. Please check spelling."
    return
}


function Authenticate-SophosApi {

    $apiCredentials = Get-SophosApiCredentials

    $client_id = $apiCredentials.client_id
    $client_secret = $apiCredentials.client_secret
    $sophosApiResponse = @{}

    Write-Host "Authenticating with Sophos API...."

    # authenticate with sophos (returns time/scope limited java web token)
    $token_resp = Invoke-RestMethod -Method Post -ContentType "application/x-www-form-urlencoded" -Body "grant_type=client_credentials&client_id=$client_id&client_secret=$client_secret&scope=token" -Uri https://id.sophos.com/api/v2/oauth2/token

    # Get Tenant ID (only 1 for UNF)
    $whoami_resp = Invoke-RestMethod -Method Get -Headers @{Authorization="Bearer $($token_resp.access_token)"} https://api.central.sophos.com/whoami/v1

    $dataRegionApiUri = $whoami_resp.apiHosts.dataRegion

    # Get all endpoints within the tenant
    $endpoints_resp = Invoke-RestMethod -Method Get -Headers @{Authorization="Bearer $($token_resp.access_token)"; "X-Tenant-ID"=$whoami_resp.id} ($($whoami_resp.apiHosts.dataRegion)+"/endpoint/v1/endpoints")

    $sophosApiResponse["token_resp"] = $token_resp
    $sophosApiResponse["whoami_resp"] = $whoami_resp
    $sophosApiResponse["endpoints_resp"] = $endpoints_resp
    $sophosApiResponse["dataRegionApiUri"] = $dataRegionApiUri

    return $sophosApiResponse
}



# authenticate with sophos api and store api session info in $sophosApiResponse hashTable
#$sophosApiResponse = Authenticate-SophosApi

# update list of all sophos endpoints (requires sophosApiResponse as argument)
# updated list of endpoints will be placed in .\endpoints.csv

function Import-SophosEndpointHostList {
    Param([string]$csv)

    if ($csv) {
        $isValidPath = (Test-Path $csv -PathType Leaf)
        if ($isValidPath -eq $false) {
            Write-Host "unable to load specified csv file. Please check to make sure it exists."
            return
        }

        try {

            $hostListCsv = Import-Csv -Path $csv -Encoding UTF8 

        }
        catch {
            Write-Error "Error Importing Csv"

        }

        if ($hostListCsv[0].psobject.properties.name -cne "hosts") {
            Write-Error "csv file must use the field header 'hosts'"
            return
        }
        return $hostListCsv
    }
    else {
        Write-Error "No csv file provided"
        return
    }
}


function Import-SophosEndpointHost {
    Param([string]$computerName)
    if ($computerName) {
        
        return $computerName

    }

    else {
        Write-Error "no host provided" 
        return
    }
}

function Get-SophosApiCredentials {
    try {
        $apiCreds = Read-Host "Enter path to sophos api credentials file (\path\to\filename.json)"
        $apiCreds = Get-Content $apiCreds | ConvertFrom-Json
        return $apiCreds
    } catch {
        Write-Error "[ERROR] file not found"
    }
    
}


#Remove-Item .\endpoints.csv
#Get-SophosEndpoints $sophosApiResponse

#$updatedEndpointsList = Import-Csv -Path .\endpoints.csv -Encoding UTF8

function Check-TamperProtectionStatus {}

#Write-Host "Checking Tamper Protection Status"
ForEach ($hostname in $hostListCsv) {
    
    ForEach ($endpoint in $updatedEndpointsList) {
        
        $tamperProtectionEnabled = [bool]::Parse($endpoint.tamperProtectionEnabled)

        #Write-Host $endpoint.hostname
        #Write-Host $hostname.hosts
    
        if($endpoint.hostname -eq $hostname.hosts -And $tamperProtectionEnabled -eq $false) {
            
            Write-Host "Tamper Protection is DISABLED for $($hostname.hosts)"

        }
        elseif ($endpoint.hostname -eq $hostname.hosts -And $tamperProtectionEnabled -eq $true) {
        
            Write-Host "Tamper Protection is ENABLED for $($hostname.hosts)"
        }
    
    }

}