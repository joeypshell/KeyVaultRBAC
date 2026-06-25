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

Write-Host "Smoke tests passed. Output: $testOut"
