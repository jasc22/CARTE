<#
.SYNOPSIS
    This script retrieves all Multi-Tenant App Registrations from Entra.

.DESCRIPTION
    This script retrieves all Multi-Tenant App Registrations from Entra and lists the ones with a non-empty RedirectURI. 
    Web services that use these applications for authentication might be vulnerable to the Consent & Compromise vulnerability
    presented at BlackHat USA 2025. 
    Before running this script, make sure to connect to Microsoft Graph by running Connect-MgGraph.

.EXAMPLE
    PS C:\> .\ListMultiTenantApplications.ps1

.NOTES
    Author: Vaisha Bernard | Eye Security
    Date: July 9th, 2025
    Version: 1.0
    Script Purpose: Retrieves all Multi-Tenant App Registrations from Entra
    Dependencies: Microsoft.Graph

.LINK
    https://consentandcompromise.com

#>

# Begin Script
try {
    $Context = (Get-MgContext -WarningAction SilentlyContinue -ErrorAction STOP)
    if ($Context -eq $null) { throw }
} catch {
    Write-Host -ForegroundColor Yellow "You must install the Microsoft.Graph module and call Connect-MgGraph before running this script"
    exit
}

$apps = Get-MgApplication -Filter "SignInAudience eq 'AzureADMultipleOrgs' or SignInAudience eq 'AzureADandPersonalMicrosoftAccount'" `
             | Select-Object DisplayName, AppId, @{N="RedirectUris";E={$_.Web.RedirectUris}} `
             | Where-Object {$_.RedirectUris}

if ($apps) {
    Write-Host -ForegroundColor Yellow "Potentially vulnerable App Registrations found:"
    $global:FormatEnumerationLimit = -1
    $apps | Format-Table -AutoSize -Wrap 
    Write-Host -ForegroundColor Yellow "For all of these applications, check that they need to be registered as multi-tenant applications in Entra."
    Write-Host -ForegroundColor Yellow "And check if the application logic explicitly checks the 'iss' or the 'tid' claim in the access token for allowed tenant ID's."
} else {
    Write-Host -ForegroundColor Green "No potentially vulnerable App Registrations found!"
}