# SophosCentral-Powershell
SophosCentral-Powershell is a custom powershell module with cmdlets for interacting with the [Sophos Central api](https://developer.sophos.com/intro). This project was created out of necessity for performing batch operations against the sophos central console. Contributions are welcome and encouraged :)
## Installation
``git.exe clone https://github.com/jd1100/SophosCentral-Powershell.git; Import-Module .\SophosCentral-Powershell\SophosCentral-Powershell.ps1``
## Notes
> This module assumes that there is only a single tenant in the sophos environment. There is currently no support for multiple tenants.
## cmdlets
### Toggle-TamperProtection
allows the user to enable/disable tamper protection for a single endpoint, a list of endpoints, or all endpoints in a tenant
#### usage
- ``-computerName [hostname]`` -> specify a single host for which to toggle tamper protection 
- ``-csv [/path/to/file.csv]`` -> import a list of endpoints for which to toggle tamper protection
  - > Note: the csv must be formatted with a single field named "hosts" with all the endpoint hostnames listed beneath
- ``-all`` -> toggles tamper protection for all endpoints in the sophos central console
- ``-enable`` -> enable tamper protection
- ``-disable`` -> disable tamper protection
### Get-SophosEndpoints
Enumerates all endpoints from the sophos central console. Additionally this cmdlet attempts to remove any duplicate endpoints.
#### usage
- ``-sophosApiResponse`` -> specifies a hashtable object that contains all the information needed for making api requests
  - > Note: even if not supplied, the cmdlet will attempt to authenticate on its own
- ``-export`` -> exports the endpoints to a csv file called "endpoints.csv"
### Get-SophosEndpointId
#### usage
- ``-computerName`` -> specify a single host to find the associated sophos central id
- ``-sophosApiResponse`` -> specifies a hash table object that contains all the information needed for making api requests
  - > Note: even if not supplied, the cmdlet will attempt to authenticate on its own
### Authenticate-SophosApi
performs the initial authentication with the sophos central api using oAuth2. Returns a hashtable with metadata about the respective sophos central environment
## To-Do
- enable support for multiple tenants
- Implement function/cmdlet for checking tamper protection status of a single host or a list of hosts
- Make the removal of duplicate endpoints an optional flag for the Get-SophosEndpoints cmdlet i.e. create a cmdlet for removing duplicates from the collection of endpoints grabbed using the sophos central api

