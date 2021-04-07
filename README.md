# SophosCentral-Powershell
SophosCentral-Powershell is a powershell module with cmdlets for interacting with the [Sophos Central api](https://developer.sophos.com/intro)
---
## cmdlets
### Toggle-TamperProtection
allows the user to enable/disable tamper protection for a single endpoint or a list of endpoints
#### flags (in any order)
- ``-computerName``
- ``-csv /path/to/file.csv`` -> import a list of endpoints to toggle tamper protection for
> Note: the csv must be formatted with a single field named "hosts" with all the endpoint hostnames listed beneath
- ``all`` -> toggles tamper protection for all endpoints in the sophos central console
- ``-enable``
- ``-disable`` disable tamper
#### usage
---
### Get-SophosEndpoints
### Get-SophosEndpointId
### Authenticate-SophosApi

