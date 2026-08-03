[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'

$repoRoot = Split-Path -Parent $PSScriptRoot
$testOutputPath = Join-Path $repoRoot 'tests\out\management-plane'
$subscriptionId = '00000000-0000-0000-0000-000000000001'
$tenantId = '11111111-1111-1111-1111-111111111111'
$readerRoleId = 'acdd72a7-3385-48ef-bd42-f606fba81ae7'
$secretsUserRoleId = '4633458b-17de-408a-b874-0445c86b69e6'
$keyVaultContributorRoleId = 'f25e0fa2-a7c8-4377-a976-54943a77a395'
$unknownRoleId = '77777777-7777-7777-7777-777777777777'
$subscriptionScope = "/subscriptions/$subscriptionId"
$resourceGroupScope = "$subscriptionScope/resourceGroups/rg-dev"
$vaultScope = "$resourceGroupScope/providers/Microsoft.KeyVault/vaults/kv-dev"
$secretScope = "$vaultScope/secrets/api-key"
$managementGroupScope = '/providers/Microsoft.Management/managementGroups/platform'

$global:KeyVaultRbacAuthorizationTestContext = [pscustomobject]@{
    Account      = [pscustomobject]@{ Id = 'smoke-test@example.invalid' }
    Subscription = [pscustomobject]@{
        Id   = $subscriptionId
        Name = 'keys'
    }
    Tenant       = [pscustomobject]@{ Id = $tenantId }
}

$global:KeyVaultRbacAuthorizationTestAssignments = @(
    [pscustomobject]@{
        RoleAssignmentId   = "$managementGroupScope/providers/Microsoft.Authorization/roleAssignments/00000000-0000-0000-0000-000000000101"
        Scope              = $managementGroupScope
        ObjectId           = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'
        ObjectType         = 'Group'
        DisplayName        = 'Platform Readers'
        RoleDefinitionId   = $readerRoleId
        RoleDefinitionName = 'Reader'
    },
    [pscustomobject]@{
        RoleAssignmentId   = "$subscriptionScope/providers/Microsoft.Authorization/roleAssignments/00000000-0000-0000-0000-000000000102"
        Scope              = $subscriptionScope
        ObjectId           = 'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb'
        ObjectType         = 'Group'
        DisplayName        = 'All Keys Readers'
        RoleDefinitionId   = $readerRoleId
        RoleDefinitionName = 'Reader'
    },
    [pscustomobject]@{
        RoleAssignmentId   = "$resourceGroupScope/providers/Microsoft.Authorization/roleAssignments/00000000-0000-0000-0000-000000000103"
        Scope              = $resourceGroupScope
        ObjectId           = 'cccccccc-cccc-cccc-cccc-cccccccccccc'
        ObjectType         = 'Group'
        DisplayName        = 'Dev Resource Readers'
        RoleDefinitionId   = $readerRoleId
        RoleDefinitionName = 'Reader'
    },
    [pscustomobject]@{
        RoleAssignmentId   = "$vaultScope/providers/Microsoft.Authorization/roleAssignments/00000000-0000-0000-0000-000000000104"
        Scope              = $vaultScope
        ObjectId           = 'dddddddd-dddd-dddd-dddd-dddddddddddd'
        ObjectType         = 'ServicePrincipal'
        DisplayName        = 'Vault Management Automation'
        RoleDefinitionId   = $keyVaultContributorRoleId
        RoleDefinitionName = 'Key Vault Contributor'
    },
    [pscustomobject]@{
        RoleAssignmentId   = "$secretScope/providers/Microsoft.Authorization/roleAssignments/00000000-0000-0000-0000-000000000105"
        Scope              = $secretScope
        ObjectId           = 'eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee'
        ObjectType         = 'User'
        DisplayName        = 'Secret Exception User'
        SignInName         = 'exception@example.invalid'
        RoleDefinitionId   = $secretsUserRoleId
        RoleDefinitionName = 'Key Vault Secrets User'
    },
    [pscustomobject]@{
        RoleAssignmentId   = "$vaultScope/providers/Microsoft.Authorization/roleAssignments/00000000-0000-0000-0000-000000000109"
        Scope              = $vaultScope
        ObjectId           = '12121212-1212-1212-1212-121212121212'
        ObjectType         = 'Group'
        DisplayName        = 'Unresolved Custom Role Group'
        RoleDefinitionId   = $unknownRoleId
        RoleDefinitionName = 'Unresolved Custom Management Role'
    }
)

$global:KeyVaultRbacAuthorizationTestRoleDefinitions = @(
    [pscustomobject]@{
        Id               = $readerRoleId
        Name             = 'Reader'
        IsCustom         = $false
        Description      = 'Read control-plane resources.'
        AssignableScopes = @('/')
        Permissions      = @(
            [pscustomobject]@{
                Actions        = @('*/read')
                NotActions     = @()
                DataActions    = @()
                NotDataActions = @()
            }
        )
    },
    [pscustomobject]@{
        Id               = $secretsUserRoleId
        Name             = 'Key Vault Secrets User'
        IsCustom         = $false
        Description      = 'Read secret contents.'
        AssignableScopes = @('/')
        Permissions      = @(
            [pscustomobject]@{
                Actions        = @('Microsoft.Resources/subscriptions/resourceGroups/read')
                NotActions     = @()
                DataActions    = @(
                    'Microsoft.KeyVault/vaults/secrets/getSecret/action',
                    'Microsoft.KeyVault/vaults/secrets/readMetadata/action'
                )
                NotDataActions = @()
            }
        )
    },
    [pscustomobject]@{
        Id               = $keyVaultContributorRoleId
        Name             = 'Key Vault Contributor'
        IsCustom         = $false
        Description      = 'Manage vault resources without accessing vault data.'
        AssignableScopes = @('/')
        Permissions      = @(
            [pscustomobject]@{
                Actions        = @('Microsoft.KeyVault/vaults/*')
                NotActions     = @()
                DataActions    = @()
                NotDataActions = @()
            }
        )
    }
)

$global:KeyVaultRbacAuthorizationTestDenyAssignment = [pscustomobject]@{
    DenyAssignmentId         = "$resourceGroupScope/providers/Microsoft.Authorization/denyAssignments/00000000-0000-0000-0000-000000000106"
    Scope                    = $resourceGroupScope
    Description              = 'Protect managed resources.'
    Principals               = @([pscustomobject]@{ Id = 'ffffffff-ffff-ffff-ffff-ffffffffffff' })
    ExcludePrincipals        = @()
    DoNotApplyToChildScopes  = $false
    IsSystemProtected        = $true
    Permissions              = @(
        [pscustomobject]@{
            Actions        = @('Microsoft.KeyVault/vaults/delete')
            NotActions     = @()
            DataActions    = @()
            NotDataActions = @()
        }
    )
}

function Get-AzContext {
    return $global:KeyVaultRbacAuthorizationTestContext
}

$global:KeyVaultRbacSubscriptionQueries = New-Object System.Collections.Generic.List[object]
function Get-AzSubscription {
    param(
        [string] $SubscriptionId,
        [string] $SubscriptionName,
        [string] $TenantId,
        [object] $ErrorAction
    )

    $global:KeyVaultRbacSubscriptionQueries.Add([pscustomobject]@{
        SubscriptionId   = $SubscriptionId
        SubscriptionName = $SubscriptionName
        TenantId         = $TenantId
    })

    $resolvedSubscriptionId = if ($SubscriptionId) {
        $SubscriptionId
    }
    else {
        $global:KeyVaultRbacAuthorizationTestContext.Subscription.Id
    }
    $resolvedTenantId = if ($TenantId) { $TenantId } else { $script:tenantId }

    return [pscustomobject]@{
        Id       = $resolvedSubscriptionId
        Name     = 'keys'
        TenantId = $resolvedTenantId
        State    = 'Enabled'
    }
}

$global:KeyVaultRbacContextSwitches = New-Object System.Collections.Generic.List[object]
function Set-AzContext {
    param(
        [string] $Subscription,
        [string] $SubscriptionId,
        [string] $Tenant,
        [object] $Context,
        [object] $ErrorAction
    )

    if ($Subscription) {
        $global:KeyVaultRbacContextSwitches.Add([pscustomobject]@{
            Subscription = $Subscription
            Tenant       = $Tenant
        })
    }

    return $global:KeyVaultRbacAuthorizationTestContext
}

function Get-AzRoleAssignment {
    param(
        [string] $Scope,
        [object] $ErrorAction
    )

    if ($Scope) {
        return @(
            $global:KeyVaultRbacAuthorizationTestAssignments |
                Where-Object { $_.Scope -in @($managementGroupScope, $subscriptionScope) }
        )
    }

    return @(
        $global:KeyVaultRbacAuthorizationTestAssignments |
            Where-Object { $_.Scope -ne $managementGroupScope }
    )
}

function Get-AzRoleDefinition {
    param(
        [string] $Scope,
        [object] $ErrorAction
    )

    return $global:KeyVaultRbacAuthorizationTestRoleDefinitions
}

function Get-AzRoleEligibilityScheduleInstance {
    param(
        [string] $Scope,
        [object] $ErrorAction
    )

    if ($global:KeyVaultRbacStandalonePimFailure) {
        throw 'Simulated PIM inventory failure.'
    }

    return [pscustomobject]@{
        Id               = "$subscriptionScope/providers/Microsoft.Authorization/roleEligibilityScheduleInstances/00000000-0000-0000-0000-000000000107"
        Scope            = $subscriptionScope
        PrincipalId      = '99999999-9999-9999-9999-999999999999'
        PrincipalType    = 'User'
        PrincipalDisplayName = 'Eligible Reader'
        PrincipalEmail   = 'eligible-reader@example.invalid'
        RoleDefinitionId = "$subscriptionScope/providers/Microsoft.Authorization/roleDefinitions/$readerRoleId"
        RoleDefinitionDisplayName = 'Reader'
        AssignmentType   = 'Assigned'
        MemberType       = 'Direct'
        Status           = 'Provisioned'
        StartDateTime    = '2026-01-01T00:00:00Z'
        EndDateTime      = ''
    }
}

function Get-AzRoleAssignmentScheduleInstance {
    param(
        [string] $Scope,
        [object] $ErrorAction
    )

    return @(
        [pscustomobject]@{
            Id               = "$resourceGroupScope/providers/Microsoft.Authorization/roleAssignmentScheduleInstances/00000000-0000-0000-0000-000000000108"
            Scope            = $resourceGroupScope
            PrincipalId      = '88888888-8888-8888-8888-888888888888'
            PrincipalType    = 'User'
            PrincipalDisplayName = 'Activated Reader'
            PrincipalEmail   = 'activated-reader@example.invalid'
            RoleDefinitionId = "$subscriptionScope/providers/Microsoft.Authorization/roleDefinitions/$readerRoleId"
            RoleDefinitionDisplayName = 'Reader'
            AssignmentType   = 'Activated'
            MemberType       = 'Direct'
            Status           = 'Provisioned'
            StartDateTime    = '2026-01-01T00:00:00Z'
            EndDateTime      = '2026-01-01T08:00:00Z'
        },
        [pscustomobject]@{
            Id               = "$vaultScope/providers/Microsoft.Authorization/roleAssignmentScheduleInstances/00000000-0000-0000-0000-000000000110"
            Scope            = $vaultScope
            PrincipalId      = '89898989-8989-8989-8989-898989898989'
            PrincipalType    = 'ServicePrincipal'
            PrincipalDisplayName = 'Activated Application'
            RoleDefinitionId = "$subscriptionScope/providers/Microsoft.Authorization/roleDefinitions/$secretsUserRoleId"
            RoleDefinitionDisplayName = 'Key Vault Secrets User'
            AssignmentType   = 'Activated'
            MemberType       = 'Direct'
            Status           = 'Provisioned'
            StartDateTime    = '2026-01-01T00:00:00Z'
            EndDateTime      = '2026-01-01T08:00:00Z'
        }
    )
}

function Get-AzDenyAssignment {
    param(
        [string] $Scope,
        [object] $ErrorAction
    )

    return $global:KeyVaultRbacAuthorizationTestDenyAssignment
}

& (Join-Path $repoRoot 'scripts\Export-SubscriptionManagementPlaneAccess.ps1') `
    -SubscriptionId $subscriptionId `
    -OutputPath $testOutputPath

$reviewPath = Join-Path $testOutputPath '16-management-plane-access-review.csv'
$reviewRows = @(Import-Csv -LiteralPath $reviewPath)
if ($reviewRows.Count -ne 8) {
    throw "Expected eight management-plane review rows, got $($reviewRows.Count)."
}
$excludedRows = @(
    Import-Csv -LiteralPath (Join-Path $testOutputPath '22-non-management-rbac-exclusions.csv')
)
if ($excludedRows.Count -ne 2) {
    throw "Expected two non-management exclusions, got $($excludedRows.Count)."
}

$managementGroupRow = $reviewRows |
    Where-Object { $_.Scope -eq $managementGroupScope } |
    Select-Object -First 1
if ($managementGroupRow.ScopeLevel -ne 'ManagementGroup') {
    throw "Management-group scope was classified as '$($managementGroupRow.ScopeLevel)'."
}
if ($managementGroupRow.IsInheritedIntoSubscription -ne 'True') {
    throw 'Management-group assignment was not marked as inherited into the subscription.'
}

$subscriptionRow = $reviewRows |
    Where-Object {
        $_.RecordType -eq 'AzureRbacRoleAssignment' -and
        $_.Scope -eq $subscriptionScope
    } |
    Select-Object -First 1
if ($subscriptionRow.ScopeRelation -ne 'DirectAtSubscription') {
    throw "Subscription scope relation was '$($subscriptionRow.ScopeRelation)'."
}

$resourceGroupRow = $reviewRows |
    Where-Object {
        $_.RecordType -eq 'AzureRbacRoleAssignment' -and
        $_.Scope -eq $resourceGroupScope
    } |
    Select-Object -First 1
if ($resourceGroupRow.ReviewReason -notlike 'Candidate for target-subscription scope*') {
    throw 'Resource-group assignment did not receive the environment-subscription review prompt.'
}

$vaultRow = $reviewRows |
    Where-Object {
        $_.RecordType -eq 'AzureRbacRoleAssignment' -and
        $_.Scope -eq $vaultScope
    } |
    Select-Object -First 1
if ($vaultRow.ScopeLevel -ne 'KeyVault') {
    throw "Vault scope was classified as '$($vaultRow.ScopeLevel)'."
}
if ($vaultRow.SameTenantMoveImpact -ne 'DirectAssignmentDoesNotMove') {
    throw "Vault move impact was '$($vaultRow.SameTenantMoveImpact)'."
}
if ($vaultRow.CanModifyLegacyAccessPolicies -ne 'True') {
    throw 'Key Vault Contributor was not flagged as able to modify legacy access policies.'
}
if ($vaultRow.ManagementReviewDisposition -ne 'ReviewLegacyPolicyEscalationRisk') {
    throw 'Legacy access-policy escalation risk did not change the review disposition.'
}
$unknownRoleRow = $reviewRows |
    Where-Object { $_.RoleDefinitionId -eq $unknownRoleId } |
    Select-Object -First 1
if ($unknownRoleRow.AuthorizationPlane -ne 'UnknownRoleDefinition') {
    throw 'Unresolved role definition was not retained for management review.'
}

$secretRow = $excludedRows |
    Where-Object { $_.Scope -eq $secretScope } |
    Select-Object -First 1
if ($secretRow.ScopeLevel -ne 'KeyVaultObject') {
    throw "Secret scope was classified as '$($secretRow.ScopeLevel)'."
}
if ($secretRow.KeyVaultObjectType -ne 'secrets' -or $secretRow.KeyVaultObjectName -ne 'api-key') {
    throw 'Secret object scope details were not parsed correctly.'
}
if ($secretRow.AuthorizationPlane -ne 'MixedManagementAndDataPlane') {
    throw "Secret role plane was '$($secretRow.AuthorizationPlane)'."
}
if ($secretRow.ManagementReviewDisposition -ne 'ExcludedContainsDataActions') {
    throw 'Data-plane-bearing role was not excluded from management review.'
}

$pimEligibleRow = $reviewRows |
    Where-Object { $_.RecordType -eq 'AzurePimEligibility' } |
    Select-Object -First 1
if ($pimEligibleRow.AssignmentState -ne 'Eligible') {
    throw 'PIM eligibility was not included in the authorization review.'
}
if ($pimEligibleRow.RoleDefinitionName -ne 'Reader') {
    throw "PIM eligible role name was '$($pimEligibleRow.RoleDefinitionName)' instead of 'Reader'."
}
$pimActiveReviewRow = $reviewRows |
    Where-Object {
        $_.RecordType -eq 'AzurePimAssignment' -and
        $_.RoleDefinitionId -eq $readerRoleId
    } |
    Select-Object -First 1
if (-not $pimActiveReviewRow) {
    throw 'Management-plane PIM active schedule was not included in the authorization review.'
}
if ($pimActiveReviewRow.RoleDefinitionName -ne 'Reader') {
    throw "PIM active role name was '$($pimActiveReviewRow.RoleDefinitionName)' instead of 'Reader'."
}
if ($pimActiveReviewRow.PrincipalDisplayName -ne 'Activated Reader') {
    throw 'PIM active principal display name was not populated from the schedule instance.'
}
if ($pimActiveReviewRow.PrincipalSignInName -ne 'activated-reader@example.invalid') {
    throw 'PIM active principal email was not populated from the schedule instance.'
}
if ($pimActiveReviewRow.AuthorizationPlane -ne 'ManagementPlaneOnly') {
    throw "PIM active role plane was '$($pimActiveReviewRow.AuthorizationPlane)'."
}
$blankReviewPimRoles = @(
    $reviewRows |
        Where-Object {
            $_.RecordType -like 'AzurePim*' -and
            [string]::IsNullOrWhiteSpace($_.RoleDefinitionName)
        }
)
if ($blankReviewPimRoles.Count -gt 0) {
    throw "Extended review contains $($blankReviewPimRoles.Count) PIM rows with blank role names."
}
$pimActiveExcludedRow = $excludedRows |
    Where-Object { $_.RecordType -eq 'AzurePimAssignment' } |
    Select-Object -First 1
if (-not $pimActiveExcludedRow) {
    throw 'Data-plane-bearing PIM assignment was not written to the exclusions report.'
}

$denyRow = $reviewRows |
    Where-Object { $_.RecordType -eq 'AzureDenyAssignment' } |
    Select-Object -First 1
if ($denyRow.DenyActions -ne 'Microsoft.KeyVault/vaults/delete') {
    throw "Deny actions were '$($denyRow.DenyActions)'."
}

$roleDefinitionRows = @(
    Import-Csv -LiteralPath (Join-Path $testOutputPath '17-role-definition-classification.csv')
)
if ($roleDefinitionRows.Count -ne 3) {
    throw "Expected three used role definitions, got $($roleDefinitionRows.Count)."
}
$secretsRole = $roleDefinitionRows |
    Where-Object { $_.RoleDefinitionId -eq $secretsUserRoleId } |
    Select-Object -First 1
if ($secretsRole.DataActions -notlike '*getSecret/action*') {
    throw 'Role-definition data actions were not exported.'
}
if ($secretsRole.AuthorizationPlane -ne 'MixedManagementAndDataPlane') {
    throw "Secrets role plane was '$($secretsRole.AuthorizationPlane)'."
}

$coverageRows = @(
    Import-Csv -LiteralPath (Join-Path $testOutputPath '20-management-inventory-coverage.csv')
)
if (@($coverageRows | Where-Object { $_.Status -eq 'Failed' }).Count -gt 0) {
    throw 'Authorization inventory coverage reported an unexpected failure.'
}
if (
    -not (
        $coverageRows |
            Where-Object {
                $_.Component -eq 'ManagementPlaneClassification' -and
                $_.Status -eq 'ReviewRequired'
            }
    )
) {
    throw 'Unknown role definition did not set management classification to ReviewRequired.'
}

$standaloneOutputPath = Join-Path $testOutputPath 'keys-management-plane-permissions.csv'
if (Test-Path -LiteralPath $standaloneOutputPath) {
    Remove-Item -LiteralPath $standaloneOutputPath -Force
}
$standaloneExporterPath = Join-Path $repoRoot 'scripts\Export-KeysManagementPlanePermissions.ps1'
$global:KeyVaultRbacSubscriptionQueries.Clear()
$global:KeyVaultRbacContextSwitches.Clear()

& $standaloneExporterPath `
    -Subscription 'keys' `
    -OutputPath $standaloneOutputPath

if ($global:KeyVaultRbacSubscriptionQueries.Count -ne 1) {
    throw "Expected one tenant-scoped subscription query, got $($global:KeyVaultRbacSubscriptionQueries.Count)."
}
$standaloneSubscriptionQuery = $global:KeyVaultRbacSubscriptionQueries[0]
if ($standaloneSubscriptionQuery.SubscriptionName -ne 'keys' -or $standaloneSubscriptionQuery.TenantId -ne $tenantId) {
    throw 'Standalone export did not resolve the subscription name only within the active tenant.'
}
if ($global:KeyVaultRbacContextSwitches.Count -ne 1) {
    throw "Expected one scalar subscription context switch, got $($global:KeyVaultRbacContextSwitches.Count)."
}
$standaloneContextSwitch = $global:KeyVaultRbacContextSwitches[0]
if ($standaloneContextSwitch.Subscription -ne $subscriptionId -or $standaloneContextSwitch.Tenant -ne $tenantId) {
    throw 'Standalone export did not switch context with scalar subscription and tenant IDs.'
}

if (-not (Test-Path -LiteralPath $standaloneOutputPath)) {
    throw 'Standalone management-plane CSV was not created.'
}
$standaloneRows = @(Import-Csv -LiteralPath $standaloneOutputPath)
if ($standaloneRows.Count -ne 8) {
    throw "Expected eight standalone management-plane rows, got $($standaloneRows.Count)."
}
if ($standaloneRows.SubscriptionName -contains '') {
    throw 'Standalone export did not resolve the keys subscription name.'
}
if (@($standaloneRows | Where-Object { $_.RoleDefinitionName -eq 'Key Vault Secrets User' }).Count -gt 0) {
    throw 'Standalone management-plane CSV included a role containing DataActions.'
}
$standaloneManagementGroupRow = $standaloneRows |
    Where-Object { $_.ScopeLevel -eq 'ManagementGroup' } |
    Select-Object -First 1
if ($standaloneManagementGroupRow.IsInheritedIntoSubscription -ne 'True') {
    throw 'Standalone CSV did not include inherited management-group access.'
}
$standaloneVaultContributorRow = $standaloneRows |
    Where-Object { $_.RoleDefinitionName -eq 'Key Vault Contributor' } |
    Select-Object -First 1
if ($standaloneVaultContributorRow.CanModifyLegacyAccessPolicies -ne 'True') {
    throw 'Standalone CSV did not flag the legacy access-policy escalation risk.'
}
$standaloneUnknownRoleRow = $standaloneRows |
    Where-Object { $_.RoleDefinitionId -eq $unknownRoleId } |
    Select-Object -First 1
if ($standaloneUnknownRoleRow.IncludeInManagementPlan -ne 'ReviewRequired') {
    throw 'Standalone CSV silently omitted or approved an unresolved role definition.'
}
if (-not ($standaloneRows | Where-Object { $_.RecordType -eq 'PimEligibleRoleAssignment' })) {
    throw 'Standalone CSV did not include PIM eligibility.'
}
$standalonePimActiveRow = $standaloneRows |
    Where-Object {
        $_.RecordType -eq 'PimActiveRoleAssignment' -and
        $_.RoleDefinitionId -eq $readerRoleId
    } |
    Select-Object -First 1
if (-not $standalonePimActiveRow) {
    throw 'Standalone CSV did not include the management-plane PIM active schedule.'
}
if ($standalonePimActiveRow.RoleDefinitionName -ne 'Reader') {
    throw "Standalone PIM active role name was '$($standalonePimActiveRow.RoleDefinitionName)'."
}
if ($standalonePimActiveRow.PrincipalDisplayName -ne 'Activated Reader') {
    throw 'Standalone PIM active principal display name was blank or incorrect.'
}
if ($standalonePimActiveRow.PrincipalSignInName -ne 'activated-reader@example.invalid') {
    throw 'Standalone PIM active principal sign-in name was blank or incorrect.'
}
if ($standalonePimActiveRow.AuthorizationPlane -ne 'ManagementPlaneOnly') {
    throw "Standalone PIM active authorization plane was '$($standalonePimActiveRow.AuthorizationPlane)'."
}
$blankStandalonePimRoles = @(
    $standaloneRows |
        Where-Object {
            $_.RecordType -like 'Pim*' -and
            [string]::IsNullOrWhiteSpace($_.RoleDefinitionName)
        }
)
if ($blankStandalonePimRoles.Count -gt 0) {
    throw "Standalone CSV contains $($blankStandalonePimRoles.Count) PIM rows with blank role names."
}
if (-not ($standaloneRows | Where-Object { $_.RecordType -eq 'DenyAssignment' })) {
    throw 'Standalone CSV did not include management-plane deny assignments.'
}

$failureOutputPath = Join-Path $testOutputPath 'keys-management-plane-incomplete.csv'
if (Test-Path -LiteralPath $failureOutputPath) {
    Remove-Item -LiteralPath $failureOutputPath -Force
}
$global:KeyVaultRbacStandalonePimFailure = $true
$failedClosed = $false
try {
    & (Join-Path $repoRoot 'scripts\Export-KeysManagementPlanePermissions.ps1') `
        -Subscription 'keys' `
        -OutputPath $failureOutputPath
}
catch {
    $failedClosed = $true
}
finally {
    $global:KeyVaultRbacStandalonePimFailure = $false
}
if (-not $failedClosed) {
    throw 'Standalone export did not fail when PIM inventory failed.'
}
if (Test-Path -LiteralPath $failureOutputPath) {
    throw 'Standalone export left a partial CSV after PIM inventory failed.'
}

Write-Host "Management-plane inventory tests passed. Output: $testOutputPath"
