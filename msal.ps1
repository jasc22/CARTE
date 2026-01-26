# Parameters
$clientId = "YOUR_CLIENT_ID"
$tenantId = "organizations"  # or specific tenant GUID
$scopes   = @("User.Read", "offline_access")  # offline_access required for refresh token

# Interactive login
$token = Get-MsalToken `
    -ClientId $clientId `
    -TenantId $tenantId `
    -Scopes $scopes `
    -Interactive

# Inspect tokens
$token.AccessToken
$token.RefreshToken
