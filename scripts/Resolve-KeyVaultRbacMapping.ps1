[CmdletBinding()]
param(
    [string] $PolicyInventoryPath = (Join-Path (Get-Location) 'out\02-access-policy-inventory.csv'),
    [string] $OutputPath = (Join-Path (Get-Location) 'out'),
    [string] $PermissionMapPath,
    [string] $BuiltInRoleMapPath,
    [string] $CustomRoleCandidatesPath,
    [string] $PrincipalResolutionPath,
    [string] $ExistingRbacPath,
    [string] $DefaultWave = 'NeedsReview',
    [string[]] $CommandStatuses = @('ExactBuiltIn', 'AcceptableOvergrant')
)

$ErrorActionPreference = 'Stop'

$scriptRoot = if ($PSScriptRoot) {
    $PSScriptRoot
}
else {
    Split-Path -Parent $MyInvocation.MyCommand.Path
}

$repoRoot = Split-Path -Parent $scriptRoot

if (-not $PermissionMapPath) {
    $PermissionMapPath = Join-Path $repoRoot 'config\access-policy-permission-map.json'
}

if (-not $BuiltInRoleMapPath) {
    $BuiltInRoleMapPath = Join-Path $repoRoot 'config\built-in-role-map.json'
}

if (-not $CustomRoleCandidatesPath) {
    $CustomRoleCandidatesPath = Join-Path $repoRoot 'config\custom-role-candidates.json'
}

function Read-JsonFile {
    param([string] $Path)

    if (-not (Test-Path -LiteralPath $Path)) {
        throw "Required JSON file not found: $Path"
    }

    return (Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json)
}

function Split-PermissionList {
    param([string] $Value)

    if ([string]::IsNullOrWhiteSpace($Value)) {
        return @()
    }

    return @(
        $Value -split '[;,]' |
            ForEach-Object { $_.Trim().ToLowerInvariant() } |
            Where-Object { $_ -and $_ -ne 'none' } |
            Sort-Object -Unique
    )
}

function Same-Set {
    param(
        [string[]] $Left,
        [string[]] $Right
    )

    $diff = @(Compare-Object @($Left | Sort-Object) @($Right | Sort-Object))
    return ($diff.Count -eq 0)
}

function ConvertTo-StringArray {
    param([object] $Value)

    if ($null -eq $Value) {
        return @()
    }

    if ($Value -is [array]) {
        return @($Value | ForEach-Object { [string]$_ })
    }

    return @([string]$Value)
}

function Test-RuleCondition {
    param(
        [object] $Condition,
        [string[]] $Actual,
        [string[]] $FullSet
    )

    if ($Condition -is [string]) {
        switch ($Condition) {
            'empty' { return ($Actual.Count -eq 0) }
            'any' { return ($Actual.Count -gt 0) }
            'full' { return (Same-Set -Left $Actual -Right $FullSet) }
            default {
                return (Same-Set -Left $Actual -Right @($Condition.ToLowerInvariant()))
            }
        }
    }

    $expected = @(ConvertTo-StringArray $Condition | ForEach-Object { $_.ToLowerInvariant() })
    return (Same-Set -Left $Actual -Right $expected)
}

function Test-MappingRule {
    param(
        [object] $Rule,
        [hashtable] $PermissionSets,
        [object] $FullSets
    )

    foreach ($category in @('keys', 'secrets', 'certificates', 'storage')) {
        $conditionProperty = $Rule.when.PSObject.Properties[$category]
        if (-not $conditionProperty) {
            continue
        }

        $fullSet = @(ConvertTo-StringArray $FullSets.$category | ForEach-Object { $_.ToLowerInvariant() })
        if (-not (Test-RuleCondition -Condition $conditionProperty.Value -Actual $PermissionSets[$category] -FullSet $fullSet)) {
            return $false
        }
    }

    return $true
}

function Get-FallbackRule {
    param(
        [object[]] $FallbackRules,
        [hashtable] $PermissionSets
    )

    $hasKeys = $PermissionSets['keys'].Count -gt 0
    $hasSecrets = $PermissionSets['secrets'].Count -gt 0
    $hasCertificates = $PermissionSets['certificates'].Count -gt 0
    $hasStorage = $PermissionSets['storage'].Count -gt 0

    $conditionName = if ($hasStorage) {
        'hasStorage'
    }
    elseif ($hasKeys -and -not $hasSecrets -and -not $hasCertificates) {
        'hasKeysOnly'
    }
    elseif ($hasSecrets -and -not $hasKeys -and -not $hasCertificates) {
        'hasSecretsOnly'
    }
    elseif ($hasCertificates -and -not $hasKeys -and -not $hasSecrets) {
        'hasCertificatesOnly'
    }
    else {
        'default'
    }

    $rule = $FallbackRules | Where-Object { $_.condition -eq $conditionName } | Select-Object -First 1
    if (-not $rule) {
        $rule = $FallbackRules | Where-Object { $_.condition -eq 'default' } | Select-Object -First 1
    }

    return $rule
}

function New-PermissionSignature {
    param(
        [hashtable] $PermissionSets
    )

    $parts = foreach ($category in @('keys', 'secrets', 'certificates', 'storage')) {
        $values = @($PermissionSets[$category] | Sort-Object)
        $text = if ($values.Count) { $values -join ',' } else { 'none' }
        "$category=$text"
    }

    return ($parts -join '|')
}

function Get-PrincipalValue {
    param(
        [object] $Row,
        [string] $Primary,
        [string] $Fallback = ''
    )

    $property = $Row.PSObject.Properties[$Primary]
    if ($property -and -not [string]::IsNullOrWhiteSpace([string]$property.Value)) {
        return [string]$property.Value
    }

    if ($Fallback) {
        $fallbackProperty = $Row.PSObject.Properties[$Fallback]
        if ($fallbackProperty) {
            return [string]$fallbackProperty.Value
        }
    }

    return ''
}

function Get-CustomRoleDataActions {
    param(
        [hashtable] $PermissionSets,
        [object] $CustomConfig
    )

    $actions = New-Object System.Collections.Generic.List[string]
    foreach ($category in @('keys', 'secrets', 'certificates')) {
        foreach ($permission in $PermissionSets[$category]) {
            $categoryMap = $CustomConfig.permissionToDataAction.PSObject.Properties[$category]
            if (-not $categoryMap) {
                continue
            }

            $permissionMap = $categoryMap.Value.PSObject.Properties[$permission]
            if (-not $permissionMap) {
                continue
            }

            foreach ($action in (ConvertTo-StringArray $permissionMap.Value)) {
                if (-not $actions.Contains($action)) {
                    $actions.Add($action)
                }
            }
        }
    }

    return (($actions | Sort-Object -Unique) -join ';')
}

function Escape-QuotedString {
    param([string] $Value)

    if ($null -eq $Value) {
        return ''
    }

    return $Value.Replace("'", "''")
}

function Export-CsvWithHeader {
    param(
        $Rows,
        $Path,
        $Headers
    )

    $rowArray = New-Object System.Collections.ArrayList
    if ($null -ne $Rows) {
        $isEnumerable = $false
        if ($Rows -is [array]) {
            $isEnumerable = $true
        }
        elseif ($Rows.GetType().GetInterfaces() | Where-Object { $_.FullName -eq 'System.Collections.IEnumerable' }) {
            $isEnumerable = $true
        }

        if ($isEnumerable -and -not ($Rows -is [string]) -and -not ($Rows -is [pscustomobject])) {
            foreach ($row in $Rows) {
                [void]$rowArray.Add($row)
            }
        }
        else {
            [void]$rowArray.Add($Rows)
        }
    }

    if ($rowArray -and $rowArray.Count -gt 0) {
        $rowArray | Export-Csv -LiteralPath $Path -NoTypeInformation
        return
    }

    $headerLine = (($Headers | ForEach-Object { '"' + $_.Replace('"', '""') + '"' }) -join ',')
    Set-Content -LiteralPath $Path -Value $headerLine -Encoding UTF8
}

if (-not (Test-Path -LiteralPath $PolicyInventoryPath)) {
    throw "Policy inventory not found: $PolicyInventoryPath"
}

New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null

$permissionMap = Read-JsonFile -Path $PermissionMapPath
$builtInRoleMap = Read-JsonFile -Path $BuiltInRoleMapPath
$customConfig = Read-JsonFile -Path $CustomRoleCandidatesPath
$policies = @(Import-Csv -LiteralPath $PolicyInventoryPath)

$principalById = @{}
if ($PrincipalResolutionPath -and (Test-Path -LiteralPath $PrincipalResolutionPath)) {
    foreach ($principal in (Import-Csv -LiteralPath $PrincipalResolutionPath)) {
        if ($principal.PrincipalId -and -not $principalById.ContainsKey($principal.PrincipalId)) {
            $principalById[$principal.PrincipalId] = $principal
        }
    }
}

$existingRbacLookup = @{}
if ($ExistingRbacPath -and (Test-Path -LiteralPath $ExistingRbacPath)) {
    foreach ($assignment in (Import-Csv -LiteralPath $ExistingRbacPath)) {
        if (-not $assignment.PrincipalId -or -not $assignment.VaultId -or -not $assignment.RoleDefinitionName) {
            continue
        }

        $lookupKey = "$($assignment.VaultId.ToLowerInvariant())|$($assignment.PrincipalId.ToLowerInvariant())|$($assignment.RoleDefinitionName.ToLowerInvariant())"
        $existingRbacLookup[$lookupKey] = $true
    }
}

$roleByName = @{}
foreach ($role in $builtInRoleMap.roles) {
    $roleByName[$role.name] = $role
}

$mappingRows = New-Object System.Collections.Generic.List[object]
$customRows = New-Object System.Collections.Generic.List[object]
$unusedRows = New-Object System.Collections.Generic.List[object]

foreach ($policy in $policies) {
    $principalId = Get-PrincipalValue -Row $policy -Primary 'PrincipalObjectId' -Fallback 'PrincipalId'
    $permissionSets = @{
        keys         = @(Split-PermissionList (Get-PrincipalValue -Row $policy -Primary 'KeyPermissions'))
        secrets      = @(Split-PermissionList (Get-PrincipalValue -Row $policy -Primary 'SecretPermissions'))
        certificates = @(Split-PermissionList (Get-PrincipalValue -Row $policy -Primary 'CertificatePermissions'))
        storage      = @(Split-PermissionList (Get-PrincipalValue -Row $policy -Primary 'StoragePermissions'))
    }

    $matchedRule = $null
    foreach ($rule in $permissionMap.rules) {
        if (Test-MappingRule -Rule $rule -PermissionSets $permissionSets -FullSets $permissionMap.fullSets) {
            $matchedRule = $rule
            break
        }
    }

    if (-not $matchedRule) {
        $matchedRule = Get-FallbackRule -FallbackRules $permissionMap.fallbackRules -PermissionSets $permissionSets
    }

    $roles = @(ConvertTo-StringArray $matchedRule.suggestedRoles)
    $signature = New-PermissionSignature -PermissionSets $permissionSets
    $customDataActions = if ($matchedRule.status -eq 'CustomRoleCandidate') {
        Get-CustomRoleDataActions -PermissionSets $permissionSets -CustomConfig $customConfig
    }
    else {
        ''
    }

    $principalResolution = if ($principalById.ContainsKey($principalId)) { $principalById[$principalId] } else { $null }
    $principalType = Get-PrincipalValue -Row $policy -Primary 'PrincipalType'
    $principalDisplayName = Get-PrincipalValue -Row $policy -Primary 'PrincipalDisplayName'
    $principalAppId = Get-PrincipalValue -Row $policy -Primary 'PrincipalAppId' -Fallback 'ApplicationId'

    if ($principalResolution) {
        if (-not $principalType) { $principalType = $principalResolution.PrincipalType }
        if (-not $principalDisplayName) { $principalDisplayName = $principalResolution.PrincipalDisplayName }
        if (-not $principalAppId) { $principalAppId = $principalResolution.PrincipalAppId }
    }

    $status = [string]$matchedRule.status
    $lastSeenOperation = Get-PrincipalValue -Row $policy -Primary 'LastSeenOperation'
    $lastSeenTime = Get-PrincipalValue -Row $policy -Primary 'LastSeenTime'

    if ([string]::IsNullOrWhiteSpace($principalId) -or ($principalResolution -and $principalResolution.ResolutionStatus -eq 'Unresolved')) {
        $status = 'NeedsOwnerReview'
    }

    if ([string]::IsNullOrWhiteSpace($lastSeenOperation) -and [string]::IsNullOrWhiteSpace($lastSeenTime)) {
        $likelyUnused = $false
    }
    else {
        $likelyUnused = ([string]::IsNullOrWhiteSpace($lastSeenTime) -or $lastSeenTime -eq 'Never')
    }

    if ($likelyUnused) {
        $status = 'LikelyUnused'
    }

    $role1 = if ($roles.Count -gt 0) { $roles[0] } else { '' }
    $role2 = if ($roles.Count -gt 1) { $roles[1] } else { '' }
    $role3 = if ($roles.Count -gt 2) { $roles[2] } else { '' }

    $alreadyAssigned = $false
    if ($role1 -and $roleByName.ContainsKey($role1)) {
        $lookupKey = "$($policy.VaultId.ToLowerInvariant())|$($principalId.ToLowerInvariant())|$($role1.ToLowerInvariant())"
        $alreadyAssigned = $existingRbacLookup.ContainsKey($lookupKey)
    }

    $mappingRow = [pscustomobject]@{
        SubscriptionId          = $policy.SubscriptionId
        ResourceGroup           = $policy.ResourceGroup
        VaultName               = $policy.VaultName
        VaultId                 = $policy.VaultId
        EnableRbacAuthorization = $policy.EnableRbacAuthorization
        PrincipalId             = $principalId
        PrincipalType           = $principalType
        PrincipalDisplayName    = $principalDisplayName
        PrincipalAppId          = $principalAppId
        KeyPermissions          = ($permissionSets.keys -join ';')
        SecretPermissions       = ($permissionSets.secrets -join ';')
        CertificatePermissions  = ($permissionSets.certificates -join ';')
        StoragePermissions      = ($permissionSets.storage -join ';')
        PermissionSignature     = $signature
        SuggestedRole1          = $role1
        SuggestedRole2          = $role2
        SuggestedRole3          = $role3
        SuggestedRole1Id        = if ($roleByName.ContainsKey($role1)) { $roleByName[$role1].id } else { '' }
        MappingStatus           = $status
        RuleId                  = $matchedRule.id
        OvergrantSummary        = $matchedRule.overgrantSummary
        CustomRoleDataActions   = $customDataActions
        LastSeenOperation       = $lastSeenOperation
        LastSeenTime            = $lastSeenTime
        AppOwner                = Get-PrincipalValue -Row $policy -Primary 'AppOwner'
        Wave                    = $DefaultWave
        ApprovedBy              = ''
        AlreadyAssigned         = $alreadyAssigned
        Notes                   = $matchedRule.notes
    }

    $mappingRows.Add($mappingRow)

    if ($status -eq 'CustomRoleCandidate') {
        $customRows.Add($mappingRow)
    }

    if ($status -eq 'LikelyUnused') {
        $unusedRows.Add($mappingRow)
    }
}

$signatureSummary = $mappingRows |
    Group-Object -Property PermissionSignature |
    ForEach-Object {
        $groupRows = @($_.Group)
        [pscustomobject]@{
            PermissionSignature = $_.Name
            PrincipalCount      = @($groupRows | Select-Object -ExpandProperty PrincipalId -Unique).Count
            VaultCount          = @($groupRows | Select-Object -ExpandProperty VaultId -Unique).Count
            SuggestedRole1      = ($groupRows | Select-Object -First 1).SuggestedRole1
            MappingStatus       = ($groupRows | Select-Object -First 1).MappingStatus
            RuleId              = ($groupRows | Select-Object -First 1).RuleId
            CustomRoleDataActions = ($groupRows | Select-Object -First 1).CustomRoleDataActions
        }
    } |
    Sort-Object -Property MappingStatus, PrincipalCount -Descending

$waveRows = $mappingRows |
    Group-Object -Property Wave, MappingStatus |
    ForEach-Object {
        $groupRows = @($_.Group)
        [pscustomobject]@{
            Wave          = ($groupRows | Select-Object -First 1).Wave
            MappingStatus = ($groupRows | Select-Object -First 1).MappingStatus
            VaultCount    = @($groupRows | Select-Object -ExpandProperty VaultId -Unique).Count
            PrincipalCount = @($groupRows | Select-Object -ExpandProperty PrincipalId -Unique).Count
            AssignmentCount = $groupRows.Count
        }
    } |
    Sort-Object -Property Wave, MappingStatus

$mappingHeaders = @(
    'SubscriptionId',
    'ResourceGroup',
    'VaultName',
    'VaultId',
    'EnableRbacAuthorization',
    'PrincipalId',
    'PrincipalType',
    'PrincipalDisplayName',
    'PrincipalAppId',
    'KeyPermissions',
    'SecretPermissions',
    'CertificatePermissions',
    'StoragePermissions',
    'PermissionSignature',
    'SuggestedRole1',
    'SuggestedRole2',
    'SuggestedRole3',
    'SuggestedRole1Id',
    'MappingStatus',
    'RuleId',
    'OvergrantSummary',
    'CustomRoleDataActions',
    'LastSeenOperation',
    'LastSeenTime',
    'AppOwner',
    'Wave',
    'ApprovedBy',
    'AlreadyAssigned',
    'Notes'
)

Export-CsvWithHeader -Rows $signatureSummary -Path (Join-Path $OutputPath '05-permission-signature-summary.csv') -Headers @(
    'PermissionSignature',
    'PrincipalCount',
    'VaultCount',
    'SuggestedRole1',
    'MappingStatus',
    'RuleId',
    'CustomRoleDataActions'
)
Export-CsvWithHeader -Rows ($mappingRows.ToArray()) -Path (Join-Path $OutputPath '06-role-mapping-proposed.csv') -Headers $mappingHeaders
Export-CsvWithHeader -Rows ($customRows.ToArray()) -Path (Join-Path $OutputPath '07-custom-role-candidates.csv') -Headers $mappingHeaders
Export-CsvWithHeader -Rows ($unusedRows.ToArray()) -Path (Join-Path $OutputPath '08-likely-unused-access.csv') -Headers $mappingHeaders
Export-CsvWithHeader -Rows $waveRows -Path (Join-Path $OutputPath '09-migration-wave-plan.csv') -Headers @(
    'Wave',
    'MappingStatus',
    'VaultCount',
    'PrincipalCount',
    'AssignmentCount'
)

$commandPath = Join-Path $OutputPath '10-role-assignment-commands.ps1'
$commandLines = New-Object System.Collections.Generic.List[string]
$commandLines.Add('# Generated by Resolve-KeyVaultRbacMapping.ps1')
$commandLines.Add('# Review 06-role-mapping-proposed.csv before running any command.')
$commandLines.Add('# This script only creates role assignments. It does not enable RBAC on a vault.')
$commandLines.Add('')

foreach ($row in $mappingRows) {
    $canEmitCommand = ($CommandStatuses -contains $row.MappingStatus) -and $row.SuggestedRole1Id -and (-not $row.AlreadyAssigned)
    $principal = Escape-QuotedString $row.PrincipalId
    $role = Escape-QuotedString $row.SuggestedRole1
    $scope = Escape-QuotedString $row.VaultId

    if ($canEmitCommand) {
        $commandLines.Add("New-AzRoleAssignment -ObjectId '$principal' -RoleDefinitionName '$role' -Scope '$scope'")
    }
    else {
        $reason = "status=$($row.MappingStatus); role=$($row.SuggestedRole1); alreadyAssigned=$($row.AlreadyAssigned)"
        $commandLines.Add("# REVIEW $reason")
        $commandLines.Add("# New-AzRoleAssignment -ObjectId '$principal' -RoleDefinitionName '$role' -Scope '$scope'")
    }
}

Set-Content -LiteralPath $commandPath -Value $commandLines -Encoding UTF8

Write-Host "Mapping complete. Output path: $OutputPath"
