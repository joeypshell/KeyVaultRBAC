[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'

$repoRoot = Split-Path -Parent $PSScriptRoot
$testOut = Join-Path $repoRoot 'tests\out'
if (Test-Path -LiteralPath $testOut) {
    Remove-Item -LiteralPath $testOut -Recurse -Force
}

& (Join-Path $repoRoot 'scripts\Resolve-KeyVaultRbacMapping.ps1') `
    -PolicyInventoryPath (Join-Path $repoRoot 'tests\fixtures\02-access-policy-inventory.csv') `
    -OutputPath $testOut

$mappingPath = Join-Path $testOut '06-role-mapping-proposed.csv'
if (-not (Test-Path -LiteralPath $mappingPath)) {
    throw "Expected mapping output not found: $mappingPath"
}

$rows = Import-Csv -LiteralPath $mappingPath

function Assert-Row {
    param(
        [string] $PrincipalObjectId,
        [string] $ExpectedStatus,
        [string] $ExpectedRole
    )

    $row = $rows | Where-Object { $_.PrincipalId -eq $PrincipalObjectId } | Select-Object -First 1
    if (-not $row) {
        throw "Missing row for principal $PrincipalObjectId"
    }

    if ($row.MappingStatus -ne $ExpectedStatus) {
        throw "Principal $PrincipalObjectId status mismatch. Expected $ExpectedStatus, got $($row.MappingStatus)"
    }

    if ($row.SuggestedRole1 -ne $ExpectedRole) {
        throw "Principal $PrincipalObjectId role mismatch. Expected $ExpectedRole, got $($row.SuggestedRole1)"
    }
}

Assert-Row -PrincipalObjectId 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa' -ExpectedStatus 'ExactBuiltIn' -ExpectedRole 'Key Vault Secrets User'
Assert-Row -PrincipalObjectId 'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb' -ExpectedStatus 'CustomRoleCandidate' -ExpectedRole 'Custom: KV Secret Set Only'
Assert-Row -PrincipalObjectId 'cccccccc-cccc-cccc-cccc-cccccccccccc' -ExpectedStatus 'ExactBuiltIn' -ExpectedRole 'Key Vault Crypto Service Encryption User'

$staticCommandPath = Join-Path $testOut '10-role-assignment-commands.ps1'
$activeStaticCommands = @(Get-Content -LiteralPath $staticCommandPath | Where-Object { $_ -match '^New-AzRoleAssignment\b' })
if ($activeStaticCommands.Count -gt 0) {
    throw 'Static role-assignment commands must be commented unless explicitly requested.'
}

$approvedMappingPath = Join-Path $testOut '06-role-mapping-approved.csv'
foreach ($row in $rows) {
    if ($row.MappingStatus -eq 'ExactBuiltIn') {
        $row.ApprovedBy = 'smoke-test'
    }
}
$rows | Export-Csv -LiteralPath $approvedMappingPath -NoTypeInformation

$stagingPlanPath = Join-Path $testOut '11-rbac-assignment-plan.csv'
& (Join-Path $repoRoot 'scripts\New-KeyVaultRbacStagingPlan.ps1') `
    -MappingPath $approvedMappingPath `
    -MovePlanPath (Join-Path $repoRoot 'tests\fixtures\key-vault-subscription-move-plan.csv') `
    -OutputPath $stagingPlanPath

$stagingRows = @(Import-Csv -LiteralPath $stagingPlanPath)
if ($stagingRows.Count -ne 2) {
    throw "Expected two exact built-in staging rows, got $($stagingRows.Count)."
}

$movedRow = $stagingRows |
    Where-Object { $_.VaultName -eq 'kv-app-dev' } |
    Select-Object -First 1
if (-not $movedRow) {
    throw 'Move-aware staging row for kv-app-dev was not generated.'
}
if ($movedRow.TargetSubscriptionId -ne '00000000-0000-0000-0000-000000000002') {
    throw "Move-aware target subscription mismatch: $($movedRow.TargetSubscriptionId)"
}
if ($movedRow.TargetResourceGroup -ne 'rg-dev-keys') {
    throw "Move-aware target resource group mismatch: $($movedRow.TargetResourceGroup)"
}
if ($movedRow.ExpectedTargetVaultId -ne '/subscriptions/00000000-0000-0000-0000-000000000002/resourceGroups/rg-dev-keys/providers/Microsoft.KeyVault/vaults/kv-app-dev') {
    throw "Move-aware vault ID mismatch: $($movedRow.ExpectedTargetVaultId)"
}
if ($movedRow.StageStatus -ne 'ReadyToStage') {
    throw "Expected ReadyToStage, got $($movedRow.StageStatus)."
}

$unmovedRow = $stagingRows |
    Where-Object { $_.VaultName -eq 'kv-sql-dev' } |
    Select-Object -First 1
if (-not $unmovedRow) {
    throw 'Unmoved staging row for kv-sql-dev was not generated.'
}
if ($unmovedRow.TargetSubscriptionId -ne '00000000-0000-0000-0000-000000000001') {
    throw "Unmoved target subscription changed unexpectedly: $($unmovedRow.TargetSubscriptionId)"
}

& (Join-Path $repoRoot 'scripts\Set-KeyVaultRbacAssignments.ps1') `
    -PlanPath $stagingPlanPath `
    -ValidatePlanOnly

$invalidPlanPath = Join-Path $testOut '11-rbac-assignment-plan-invalid-scope.csv'
$invalidRows = @(Import-Csv -LiteralPath $stagingPlanPath)
$invalidRows[0].ExpectedTargetVaultId = $invalidRows[0].ExpectedTargetVaultId + '-wrong'
$invalidRows | Export-Csv -LiteralPath $invalidPlanPath -NoTypeInformation
$invalidPlanRejected = $false
try {
    & (Join-Path $repoRoot 'scripts\Set-KeyVaultRbacAssignments.ps1') `
        -PlanPath $invalidPlanPath `
        -ValidatePlanOnly
}
catch {
    $invalidPlanRejected = $true
}
if (-not $invalidPlanRejected) {
    throw 'Offline plan validation did not reject a mismatched vault resource ID.'
}

$unmappedTenantPlanPath = Join-Path $testOut '11-rbac-assignment-plan-unmapped-tenant.csv'
& (Join-Path $repoRoot 'scripts\New-KeyVaultRbacStagingPlan.ps1') `
    -MappingPath $approvedMappingPath `
    -MovePlanPath (Join-Path $repoRoot 'tests\fixtures\key-vault-cross-tenant-plan.csv') `
    -OutputPath $unmappedTenantPlanPath

$unmappedTenantRow = Import-Csv -LiteralPath $unmappedTenantPlanPath |
    Where-Object { $_.VaultName -eq 'kv-sql-dev' } |
    Select-Object -First 1
if ($unmappedTenantRow.StageStatus -ne 'NeedsPrincipalMapping') {
    throw "Expected NeedsPrincipalMapping for an unmapped target tenant, got $($unmappedTenantRow.StageStatus)."
}

$mappedTenantPlanPath = Join-Path $testOut '11-rbac-assignment-plan-mapped-tenant.csv'
& (Join-Path $repoRoot 'scripts\New-KeyVaultRbacStagingPlan.ps1') `
    -MappingPath $approvedMappingPath `
    -MovePlanPath (Join-Path $repoRoot 'tests\fixtures\key-vault-cross-tenant-plan.csv') `
    -PrincipalMapPath (Join-Path $repoRoot 'tests\fixtures\principal-map.csv') `
    -OutputPath $mappedTenantPlanPath

$mappedTenantRow = Import-Csv -LiteralPath $mappedTenantPlanPath |
    Where-Object { $_.VaultName -eq 'kv-sql-dev' } |
    Select-Object -First 1
if ($mappedTenantRow.TargetPrincipalId -ne 'dddddddd-dddd-dddd-dddd-dddddddddddd') {
    throw "Target-tenant principal mapping mismatch: $($mappedTenantRow.TargetPrincipalId)"
}
if ($mappedTenantRow.StageStatus -ne 'ReadyToStage') {
    throw "Expected mapped target-tenant row to be ReadyToStage, got $($mappedTenantRow.StageStatus)."
}
if ($mappedTenantRow.MoveTiming -ne 'ReapplyAfterTenantTransfer') {
    throw "Expected ReapplyAfterTenantTransfer, got $($mappedTenantRow.MoveTiming)."
}

Write-Host "Smoke tests passed. Output: $testOut"
