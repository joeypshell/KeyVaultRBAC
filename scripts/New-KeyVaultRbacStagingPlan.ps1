[CmdletBinding()]
param(
    [string] $MappingPath = (Join-Path (Get-Location) 'out\06-role-mapping-proposed.csv'),
    [string] $OutputPath = (Join-Path (Get-Location) 'out\11-rbac-assignment-plan.csv'),
    [string] $MovePlanPath,
    [string] $PrincipalMapPath,
    [string[]] $EligibleMappingStatus = @('ExactBuiltIn', 'AcceptableOvergrant'),
    [switch] $AllowUnapproved
)

$ErrorActionPreference = 'Stop'

function Get-RowValue {
    param(
        [object] $Row,
        [string] $Name,
        [string] $FallbackName = ''
    )

    $property = $Row.PSObject.Properties[$Name]
    if ($property -and -not [string]::IsNullOrWhiteSpace([string]$property.Value)) {
        return ([string]$property.Value).Trim()
    }

    if ($FallbackName) {
        $fallback = $Row.PSObject.Properties[$FallbackName]
        if ($fallback -and -not [string]::IsNullOrWhiteSpace([string]$fallback.Value)) {
            return ([string]$fallback.Value).Trim()
        }
    }

    return ''
}

function New-SourceVaultKey {
    param(
        [string] $SubscriptionId,
        [string] $ResourceGroup,
        [string] $VaultName
    )

    return "$SubscriptionId|$ResourceGroup|$VaultName".ToLowerInvariant()
}

function New-PrincipalMapKey {
    param(
        [string] $SourceTenantId,
        [string] $SourcePrincipalId,
        [string] $TargetTenantId
    )

    return "$SourceTenantId|$SourcePrincipalId|$TargetTenantId".ToLowerInvariant()
}

function New-VaultResourceId {
    param(
        [string] $SubscriptionId,
        [string] $ResourceGroup,
        [string] $VaultName
    )

    return "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroup/providers/Microsoft.KeyVault/vaults/$VaultName"
}

function Export-CsvWithHeader {
    param(
        [object[]] $Rows,
        [string] $Path,
        [string[]] $Headers
    )

    $parent = Split-Path -Parent $Path
    if ($parent) {
        New-Item -ItemType Directory -Path $parent -Force | Out-Null
    }

    if ($Rows.Count -gt 0) {
        $Rows | Export-Csv -LiteralPath $Path -NoTypeInformation
        return
    }

    $headerLine = (($Headers | ForEach-Object { '"' + $_.Replace('"', '""') + '"' }) -join ',')
    Set-Content -LiteralPath $Path -Value $headerLine -Encoding UTF8
}

if (-not (Test-Path -LiteralPath $MappingPath)) {
    throw "Mapping file not found: $MappingPath"
}

$moveBySourceVault = @{}
if ($MovePlanPath) {
    if (-not (Test-Path -LiteralPath $MovePlanPath)) {
        throw "Move plan file not found: $MovePlanPath"
    }

    foreach ($move in (Import-Csv -LiteralPath $MovePlanPath)) {
        $sourceSubscriptionId = Get-RowValue -Row $move -Name 'SourceSubscriptionId'
        $sourceResourceGroup = Get-RowValue -Row $move -Name 'SourceResourceGroup'
        $vaultName = Get-RowValue -Row $move -Name 'VaultName'
        $destinationSubscriptionId = Get-RowValue -Row $move -Name 'DestinationSubscriptionId'
        $destinationResourceGroup = Get-RowValue -Row $move -Name 'DestinationResourceGroup'

        if (-not $sourceSubscriptionId -or -not $sourceResourceGroup -or -not $vaultName -or
            -not $destinationSubscriptionId -or -not $destinationResourceGroup) {
            throw "Every move-plan row requires SourceSubscriptionId, SourceResourceGroup, VaultName, DestinationSubscriptionId, and DestinationResourceGroup."
        }

        $sourceKey = New-SourceVaultKey `
            -SubscriptionId $sourceSubscriptionId `
            -ResourceGroup $sourceResourceGroup `
            -VaultName $vaultName

        if ($moveBySourceVault.ContainsKey($sourceKey)) {
            throw "Duplicate move-plan entry for $sourceSubscriptionId/$sourceResourceGroup/$vaultName."
        }

        $moveBySourceVault[$sourceKey] = $move
    }
}

$principalByTenantPair = @{}
if ($PrincipalMapPath) {
    if (-not (Test-Path -LiteralPath $PrincipalMapPath)) {
        throw "Principal map file not found: $PrincipalMapPath"
    }

    foreach ($principalMap in (Import-Csv -LiteralPath $PrincipalMapPath)) {
        $sourceTenantId = Get-RowValue -Row $principalMap -Name 'SourceTenantId'
        $sourcePrincipalId = Get-RowValue -Row $principalMap -Name 'SourcePrincipalId'
        $targetTenantId = Get-RowValue -Row $principalMap -Name 'TargetTenantId'
        $targetPrincipalId = Get-RowValue -Row $principalMap -Name 'TargetPrincipalId'

        if (-not $sourcePrincipalId -or -not $targetTenantId -or -not $targetPrincipalId) {
            throw "Every principal-map row requires SourcePrincipalId, TargetTenantId, and TargetPrincipalId."
        }

        $principalKey = New-PrincipalMapKey `
            -SourceTenantId $sourceTenantId `
            -SourcePrincipalId $sourcePrincipalId `
            -TargetTenantId $targetTenantId

        if ($principalByTenantPair.ContainsKey($principalKey)) {
            throw "Duplicate principal-map entry for source principal $sourcePrincipalId and target tenant $targetTenantId."
        }

        $principalByTenantPair[$principalKey] = $targetPrincipalId
    }
}

$planRows = New-Object System.Collections.Generic.List[object]
$planByAssignmentKey = @{}

foreach ($mapping in (Import-Csv -LiteralPath $MappingPath)) {
    $mappingStatus = Get-RowValue -Row $mapping -Name 'MappingStatus'
    if ($EligibleMappingStatus -notcontains $mappingStatus) {
        continue
    }

    $sourceTenantId = Get-RowValue -Row $mapping -Name 'TenantId'
    $sourceSubscriptionId = Get-RowValue -Row $mapping -Name 'SubscriptionId'
    $sourceResourceGroup = Get-RowValue -Row $mapping -Name 'ResourceGroup'
    $vaultName = Get-RowValue -Row $mapping -Name 'VaultName'
    $sourcePrincipalId = Get-RowValue -Row $mapping -Name 'PrincipalId' -FallbackName 'PrincipalObjectId'

    if (-not $sourceSubscriptionId -or -not $sourceResourceGroup -or -not $vaultName) {
        throw "Mapping rows must include SubscriptionId, ResourceGroup, and VaultName."
    }

    $sourceVaultId = Get-RowValue -Row $mapping -Name 'VaultId'
    if (-not $sourceVaultId) {
        $sourceVaultId = New-VaultResourceId `
            -SubscriptionId $sourceSubscriptionId `
            -ResourceGroup $sourceResourceGroup `
            -VaultName $vaultName
    }

    $targetTenantId = $sourceTenantId
    $targetSubscriptionId = $sourceSubscriptionId
    $targetResourceGroup = $sourceResourceGroup
    $environment = Get-RowValue -Row $mapping -Name 'Wave'
    $moveTiming = 'NoSameTenantMovePlanned'

    $sourceKey = New-SourceVaultKey `
        -SubscriptionId $sourceSubscriptionId `
        -ResourceGroup $sourceResourceGroup `
        -VaultName $vaultName

    if ($moveBySourceVault.ContainsKey($sourceKey)) {
        $move = $moveBySourceVault[$sourceKey]
        $targetTenantIdFromMove = Get-RowValue -Row $move -Name 'DestinationTenantId'
        if ($targetTenantIdFromMove) {
            $targetTenantId = $targetTenantIdFromMove
        }

        $targetSubscriptionId = Get-RowValue -Row $move -Name 'DestinationSubscriptionId'
        $targetResourceGroup = Get-RowValue -Row $move -Name 'DestinationResourceGroup'
        $moveEnvironment = Get-RowValue -Row $move -Name 'Environment'
        if ($moveEnvironment) {
            $environment = $moveEnvironment
        }

        $moveTiming = if ($targetTenantId -and $sourceTenantId -and $targetTenantId -ine $sourceTenantId) {
            'ReapplyAfterTenantTransfer'
        }
        elseif ($targetSubscriptionId -ine $sourceSubscriptionId -or $targetResourceGroup -ine $sourceResourceGroup) {
            'StageAfterResourceMove'
        }
        else {
            'NoResourceIdChange'
        }
    }

    $targetPrincipalId = $sourcePrincipalId
    $principalMappingStatus = 'SameTenantObjectId'
    if ($targetTenantId -and -not $sourceTenantId) {
        $targetPrincipalId = ''
        $principalMappingStatus = 'SourceTenantUnknown'
    }
    elseif ($targetTenantId -and $sourceTenantId -and $targetTenantId -ine $sourceTenantId) {
        $principalKey = New-PrincipalMapKey `
            -SourceTenantId $sourceTenantId `
            -SourcePrincipalId $sourcePrincipalId `
            -TargetTenantId $targetTenantId

        if ($principalByTenantPair.ContainsKey($principalKey)) {
            $targetPrincipalId = $principalByTenantPair[$principalKey]
            $principalMappingStatus = 'MappedAcrossTenants'
        }
        else {
            $targetPrincipalId = ''
            $principalMappingStatus = 'NeedsTargetTenantMapping'
        }
    }

    $targetVaultId = New-VaultResourceId `
        -SubscriptionId $targetSubscriptionId `
        -ResourceGroup $targetResourceGroup `
        -VaultName $vaultName

    foreach ($roleNumber in 1..3) {
        $roleName = Get-RowValue -Row $mapping -Name "SuggestedRole$roleNumber"
        $roleDefinitionId = Get-RowValue -Row $mapping -Name "SuggestedRole${roleNumber}Id"
        if (-not $roleName -and -not $roleDefinitionId) {
            continue
        }

        $approvedBy = Get-RowValue -Row $mapping -Name 'ApprovedBy'
        $stageStatus = 'ReadyToStage'
        $stageReason = ''

        if (-not $sourcePrincipalId) {
            $stageStatus = 'NeedsPrincipalReview'
            $stageReason = 'Source principal ID is missing.'
        }
        elseif (-not $targetPrincipalId) {
            $stageStatus = 'NeedsPrincipalMapping'
            $stageReason = 'Target-tenant principal object ID is required.'
        }
        elseif (-not $roleDefinitionId) {
            $stageStatus = 'NeedsRoleDefinition'
            $stageReason = 'Suggested role has no approved role definition ID.'
        }
        elseif (-not $approvedBy -and -not $AllowUnapproved) {
            $stageStatus = 'NeedsApproval'
            $stageReason = 'ApprovedBy is blank.'
        }

        $assignmentKey = "$targetVaultId|$targetPrincipalId|$roleDefinitionId".ToLowerInvariant()
        if ($planByAssignmentKey.ContainsKey($assignmentKey)) {
            $existing = $planByAssignmentKey[$assignmentKey]
            $existing.SourceMappingCount = [int]$existing.SourceMappingCount + 1
            continue
        }

        $planRow = [pscustomobject]@{
            PlanVersion                  = '1'
            Environment                  = $environment
            SourceTenantId               = $sourceTenantId
            TargetTenantId               = $targetTenantId
            SourceSubscriptionId         = $sourceSubscriptionId
            SourceResourceGroup          = $sourceResourceGroup
            SourceVaultId                = $sourceVaultId
            TargetSubscriptionId         = $targetSubscriptionId
            TargetResourceGroup          = $targetResourceGroup
            VaultName                    = $vaultName
            ExpectedTargetVaultId        = $targetVaultId
            MoveTiming                   = $moveTiming
            SourcePrincipalId            = $sourcePrincipalId
            TargetPrincipalId            = $targetPrincipalId
            PrincipalMappingStatus       = $principalMappingStatus
            PrincipalType                = Get-RowValue -Row $mapping -Name 'PrincipalType'
            PrincipalDisplayName         = Get-RowValue -Row $mapping -Name 'PrincipalDisplayName'
            PrincipalAppId               = Get-RowValue -Row $mapping -Name 'PrincipalAppId'
            RoleDefinitionName           = $roleName
            RoleDefinitionId             = $roleDefinitionId
            MappingStatus                = $mappingStatus
            PermissionSignature          = Get-RowValue -Row $mapping -Name 'PermissionSignature'
            EnableRbacAuthorizationAtMap = Get-RowValue -Row $mapping -Name 'EnableRbacAuthorization'
            ApprovedBy                   = $approvedBy
            StageStatus                  = $stageStatus
            StageReason                  = $stageReason
            SourceMappingCount           = 1
            AssignmentKey                = $assignmentKey
        }

        $planRows.Add($planRow)
        $planByAssignmentKey[$assignmentKey] = $planRow
    }
}

$headers = @(
    'PlanVersion',
    'Environment',
    'SourceTenantId',
    'TargetTenantId',
    'SourceSubscriptionId',
    'SourceResourceGroup',
    'SourceVaultId',
    'TargetSubscriptionId',
    'TargetResourceGroup',
    'VaultName',
    'ExpectedTargetVaultId',
    'MoveTiming',
    'SourcePrincipalId',
    'TargetPrincipalId',
    'PrincipalMappingStatus',
    'PrincipalType',
    'PrincipalDisplayName',
    'PrincipalAppId',
    'RoleDefinitionName',
    'RoleDefinitionId',
    'MappingStatus',
    'PermissionSignature',
    'EnableRbacAuthorizationAtMap',
    'ApprovedBy',
    'StageStatus',
    'StageReason',
    'SourceMappingCount',
    'AssignmentKey'
)

$rowsToExport = @($planRows.ToArray() | Sort-Object -Property TargetSubscriptionId, TargetResourceGroup, VaultName, PrincipalDisplayName, RoleDefinitionName)
Export-CsvWithHeader -Rows $rowsToExport -Path $OutputPath -Headers $headers

$readyCount = @($rowsToExport | Where-Object { $_.StageStatus -eq 'ReadyToStage' }).Count
Write-Host "RBAC staging plan complete. Ready: $readyCount; Total: $($rowsToExport.Count); Output: $OutputPath"
