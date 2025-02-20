# Enumerate Intune Scripts
Write-Host "Intune scripts currently deployed in the tenant:"
(Invoke-MgGraphRequest -Method GET -Uri https://graph.microsoft.com/beta/deviceManagement/deviceManagementScripts).value

# Prompt for required values
Write-Host "Enter the file path of the PowerShell script (e.g., C:\Users\test.ps1):"
$filePath = Read-Host

Write-Host "Enter the display name for the script (e.g., Test):"
$displayName = Read-Host

Write-Host "Enter a description for the script (optional):"
$description = Read-Host

Write-Host "Enter the run as account (e.g., user/system):"
$runAsAccount = Read-Host

Write-Host "Enforce signature check? (true/false):"
$enforceSignatureCheck = Read-Host

Write-Host "Enter the file name for the script (e.g., test.ps1):"
$fileName = Read-Host

Write-Host "Enter role scope tag IDs (comma separated if multiple, e.g. 0,1,2,3,...):"
$roleScopeTagId = Read-Host

Write-Host "Run as 32-bit? (true/false):"
$runAs32Bit = Read-Host


# Read the PowerShell script file and encode it to Base64
try {
    $fileContent = Get-Content -Path $filePath -Raw
} catch {
    Write-Host "Error: Unable to read file at $filePath" -ForegroundColor Red
    exit 1
}

$scriptContent = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($fileContent))

# Prepare the body to create the script
$body = @{
    "@odata.type"           = "#microsoft.graph.deviceManagementScript"
    "displayName"           = $displayName
    "description"           = $description
    "scriptContent"         = $scriptContent
    "runAsAccount"          = $runAsAccount
    "enforceSignatureCheck" = $enforceSignatureCheck
    "fileName"              = $fileName
    "roleScopeTagIds"       = @($roleScopeTagId)
    "runAs32Bit"            = $runAs32Bit
} | ConvertTo-Json -Depth 10

#Print JSON body
Write-Host "JSON body that will be sent to Intune Platform Scripts: "
Write-Host $body

# Script Id
Write-Host "Enter Script Id:"
$scriptIdGuid = Read-Host
$scriptId = $scriptIdGuid

# Prompt user to press Enter to continue with updating the file
Write-Host "Press Enter to update $fileName"
Read-Host -Prompt "Press Enter when ready"
$response = Invoke-MgGraphRequest -Method PATCH -Uri "https://graph.microsoft.com/beta/deviceManagement/deviceManagementScripts" -Body $body

# Output the response to verify the new script creation
Write-Host "Response from Microsoft Graph API: "
$response
