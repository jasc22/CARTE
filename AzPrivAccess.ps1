<#
.SYNOPSIS
    Audits high-privileged role assignments across all Azure subscriptions in a tenant.

.DESCRIPTION
    This script enumerates all subscriptions accessible to the current user and identifies
    users, groups, and service principals with high-privileged roles (Owner, Contributor,
    User Access Administrator, etc.). Results are exported to a CSV file.

.PARAMETER OutputPath
    Path for the output CSV file. Defaults to current directory with timestamp.

.PARAMETER IncludeInherited
    Include role assignments inherited from higher scopes (management groups).

.PARAMETER CustomRoles
    Also check for custom roles with high-privilege actions.

.EXAMPLE
    .\Get-AzurePrivilegedAccess.ps1
    
.EXAMPLE
    .\Get-AzurePrivilegedAccess.ps1 -OutputPath "C:\Reports\PrivilegedAccess.csv" -IncludeInherited

.NOTES
    Requires: Az.Accounts, Az.Resources modules
    Author: Azure Security Audit Script
    Version: 1.0
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$OutputPath = ".\AzurePrivilegedAccess_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv",

    [Parameter(Mandatory = $false)]
    [switch]$IncludeInherited,

    [Parameter(Mandatory = $false)]
    [switch]$CustomRoles
)

#region Configuration

# Define high-privileged built-in roles to check
$PrivilegedRoles = @(
    @{ Name = "Owner"; Id = "8e3af657-a8ff-443c-a75c-2fe8c4bcb635"; RiskLevel = "Critical" }
    @{ Name = "Contributor"; Id = "b24988ac-6180-42a0-ab88-20f7382dd24c"; RiskLevel = "High" }
    @{ Name = "User Access Administrator"; Id = "18d7d88d-d35e-4fb5-a5c3-7773c20a72d9"; RiskLevel = "Critical" }
    @{ Name = "Security Admin"; Id = "fb1c8493-542b-48eb-b624-b4c8fea62acd"; RiskLevel = "High" }
    @{ Name = "Global Administrator"; Id = "62e90394-69f5-4237-9190-012177145e10"; RiskLevel = "Critical" }
    @{ Name = "Privileged Role Administrator"; Id = "e8611ab8-c189-46e8-94e1-60213ab1f814"; RiskLevel = "Critical" }
    @{ Name = "Application Administrator"; Id = "9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3"; RiskLevel = "High" }
    @{ Name = "Cloud Application Administrator"; Id = "158c047a-c907-4556-b7ef-446551a6b5f7"; RiskLevel = "High" }
    @{ Name = "Key Vault Administrator"; Id = "00482a5a-887f-4fb3-b363-3b7fe8e74483"; RiskLevel = "High" }
    @{ Name = "Virtual Machine Contributor"; Id = "9980e02c-c2be-4d73-94e8-173b1dc7cf3c"; RiskLevel = "Medium" }
)

# High-privilege actions to check in custom roles
$HighPrivilegeActions = @(
    "*/write",
    "*/delete",
    "*/action",
    "Microsoft.Authorization/*",
    "Microsoft.Authorization/roleAssignments/*",
    "Microsoft.Authorization/roleDefinitions/*"
)

#endregion

#region Functions

function Test-AzureConnection {
    try {
        $context = Get-AzContext
        if (-not $context) {
            Write-Host "Not connected to Azure. Initiating login..." -ForegroundColor Yellow
            Connect-AzAccount
        }
        else {
            Write-Host "Connected to Azure as: $($context.Account.Id)" -ForegroundColor Green
            Write-Host "Tenant: $($context.Tenant.Id)" -ForegroundColor Green
        }
        return $true
    }
    catch {
        Write-Error "Failed to connect to Azure: $_"
        return $false
    }
}

function Get-PrincipalDetails {
    param(
        [string]$PrincipalId,
        [string]$PrincipalType
    )
    
    $details = @{
        DisplayName = "Unknown"
        UserPrincipalName = "N/A"
        PrincipalType = $PrincipalType
        ObjectId = $PrincipalId
    }
    
    try {
        switch ($PrincipalType) {
            "User" {
                $user = Get-AzADUser -ObjectId $PrincipalId -ErrorAction SilentlyContinue
                if ($user) {
                    $details.DisplayName = $user.DisplayName
                    $details.UserPrincipalName = $user.UserPrincipalName
                }
            }
            "Group" {
                $group = Get-AzADGroup -ObjectId $PrincipalId -ErrorAction SilentlyContinue
                if ($group) {
                    $details.DisplayName = $group.DisplayName
                }
            }
            "ServicePrincipal" {
                $sp = Get-AzADServicePrincipal -ObjectId $PrincipalId -ErrorAction SilentlyContinue
                if ($sp) {
                    $details.DisplayName = $sp.DisplayName
                    $details.UserPrincipalName = $sp.AppId
                }
            }
        }
    }
    catch {
        Write-Verbose "Could not resolve principal $PrincipalId : $_"
    }
    
    return $details
}

function Test-CustomRoleIsPrivileged {
    param(
        [object]$RoleDefinition
    )
    
    foreach ($action in $RoleDefinition.Permissions.Actions) {
        foreach ($privilegedAction in $HighPrivilegeActions) {
            if ($action -like $privilegedAction) {
                return $true
            }
        }
    }
    return $false
}

function Get-SubscriptionPrivilegedAssignments {
    param(
        [object]$Subscription,
        [array]$RolesToCheck,
        [switch]$IncludeInherited,
        [switch]$CheckCustomRoles
    )
    
    $assignments = @()
    
    Write-Host "  Processing subscription: $($Subscription.Name)" -ForegroundColor Cyan
    
    try {
        # Set context to this subscription
        Set-AzContext -SubscriptionId $Subscription.Id -ErrorAction Stop | Out-Null
        
        # Get all role assignments
        $allAssignments = Get-AzRoleAssignment -ErrorAction Stop
        
        foreach ($assignment in $allAssignments) {
            $isPrivileged = $false
            $riskLevel = "Low"
            $roleInfo = $null
            
            # Check if it's a known privileged role
            $roleInfo = $RolesToCheck | Where-Object { $_.Name -eq $assignment.RoleDefinitionName }
            
            if ($roleInfo) {
                $isPrivileged = $true
                $riskLevel = $roleInfo.RiskLevel
            }
            # Check custom roles if enabled
            elseif ($CheckCustomRoles -and $assignment.RoleDefinitionId -notmatch "^/providers/Microsoft.Authorization/roleDefinitions/") {
                try {
                    $customRole = Get-AzRoleDefinition -Id $assignment.RoleDefinitionId -ErrorAction SilentlyContinue
                    if ($customRole -and (Test-CustomRoleIsPrivileged -RoleDefinition $customRole)) {
                        $isPrivileged = $true
                        $riskLevel = "High (Custom)"
                    }
                }
                catch {
                    Write-Verbose "Could not check custom role: $_"
                }
            }
            
            if (-not $isPrivileged) { continue }
            
            # Skip inherited if not requested
            if (-not $IncludeInherited -and $assignment.Scope -notlike "/subscriptions/$($Subscription.Id)*") {
                continue
            }
            
            # Get principal details
            $principal = Get-PrincipalDetails -PrincipalId $assignment.ObjectId -PrincipalType $assignment.ObjectType
            
            # Determine scope level
            $scopeLevel = switch -Regex ($assignment.Scope) {
                "^/providers/Microsoft.Management/managementGroups" { "Management Group" }
                "^/subscriptions/[^/]+$" { "Subscription" }
                "^/subscriptions/[^/]+/resourceGroups/[^/]+$" { "Resource Group" }
                default { "Resource" }
            }
            
            $assignments += [PSCustomObject]@{
                SubscriptionName    = $Subscription.Name
                SubscriptionId      = $Subscription.Id
                PrincipalName       = $principal.DisplayName
                PrincipalUPN        = $principal.UserPrincipalName
                PrincipalType       = $assignment.ObjectType
                PrincipalObjectId   = $assignment.ObjectId
                RoleName            = $assignment.RoleDefinitionName
                RoleId              = $assignment.RoleDefinitionId
                RiskLevel           = $riskLevel
                Scope               = $assignment.Scope
                ScopeLevel          = $scopeLevel
                IsInherited         = ($assignment.Scope -notlike "/subscriptions/$($Subscription.Id)*")
                AssignmentId        = $assignment.RoleAssignmentId
                CreatedOn           = $assignment.CreatedOn
                UpdatedOn           = $assignment.UpdatedOn
            }
        }
    }
    catch {
        Write-Warning "  Error processing subscription $($Subscription.Name): $_"
    }
    
    return $assignments
}

#endregion

#region Main Script

Write-Host "`n========================================" -ForegroundColor Magenta
Write-Host "  Azure Privileged Access Audit Tool" -ForegroundColor Magenta
Write-Host "========================================`n" -ForegroundColor Magenta

# Check required modules
$requiredModules = @("Az.Accounts", "Az.Resources")
foreach ($module in $requiredModules) {
    if (-not (Get-Module -ListAvailable -Name $module)) {
        Write-Error "Required module '$module' is not installed. Install it with: Install-Module $module -Scope CurrentUser"
        exit 1
    }
}

# Connect to Azure
if (-not (Test-AzureConnection)) {
    exit 1
}

# Get all accessible subscriptions
Write-Host "`nRetrieving all accessible subscriptions..." -ForegroundColor Yellow
$subscriptions = Get-AzSubscription -ErrorAction Stop
Write-Host "Found $($subscriptions.Count) subscriptions`n" -ForegroundColor Green

# Collect all privileged assignments
$allPrivilegedAssignments = @()
$processedCount = 0

foreach ($subscription in $subscriptions) {
    $processedCount++
    Write-Host "[$processedCount/$($subscriptions.Count)] " -NoNewline -ForegroundColor White
    
    $assignments = Get-SubscriptionPrivilegedAssignments `
        -Subscription $subscription `
        -RolesToCheck $PrivilegedRoles `
        -IncludeInherited:$IncludeInherited `
        -CheckCustomRoles:$CustomRoles
    
    $allPrivilegedAssignments += $assignments
    Write-Host "    Found $($assignments.Count) privileged assignments" -ForegroundColor Gray
}

# Export results
Write-Host "`n----------------------------------------" -ForegroundColor Magenta
Write-Host "Exporting results to CSV..." -ForegroundColor Yellow

$allPrivilegedAssignments | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8

Write-Host "Results exported to: $OutputPath" -ForegroundColor Green

# Display summary
Write-Host "`n========================================" -ForegroundColor Magenta
Write-Host "           AUDIT SUMMARY" -ForegroundColor Magenta
Write-Host "========================================" -ForegroundColor Magenta

Write-Host "`nTotal subscriptions scanned: $($subscriptions.Count)"
Write-Host "Total privileged assignments found: $($allPrivilegedAssignments.Count)"

# Summary by risk level
Write-Host "`nBy Risk Level:" -ForegroundColor Yellow
$allPrivilegedAssignments | Group-Object RiskLevel | Sort-Object Name | ForEach-Object {
    $color = switch ($_.Name) {
        "Critical" { "Red" }
        "High" { "DarkYellow" }
        "High (Custom)" { "DarkYellow" }
        "Medium" { "Yellow" }
        default { "White" }
    }
    Write-Host "  $($_.Name): $($_.Count)" -ForegroundColor $color
}

# Summary by principal type
Write-Host "`nBy Principal Type:" -ForegroundColor Yellow
$allPrivilegedAssignments | Group-Object PrincipalType | ForEach-Object {
    Write-Host "  $($_.Name): $($_.Count)"
}

# Summary by role
Write-Host "`nBy Role:" -ForegroundColor Yellow
$allPrivilegedAssignments | Group-Object RoleName | Sort-Object Count -Descending | Select-Object -First 10 | ForEach-Object {
    Write-Host "  $($_.Name): $($_.Count)"
}

# Highlight critical findings
$criticalAssignments = $allPrivilegedAssignments | Where-Object { $_.RiskLevel -eq "Critical" }
if ($criticalAssignments.Count -gt 0) {
    Write-Host "`n⚠️  CRITICAL FINDINGS:" -ForegroundColor Red
    Write-Host "Found $($criticalAssignments.Count) critical-risk assignments that should be reviewed:" -ForegroundColor Red
    
    $criticalAssignments | Group-Object PrincipalName | Sort-Object Count -Descending | Select-Object -First 5 | ForEach-Object {
        Write-Host "  - $($_.Name): $($_.Count) critical assignments" -ForegroundColor Red
    }
}

Write-Host "`n========================================`n" -ForegroundColor Magenta

#endregion
