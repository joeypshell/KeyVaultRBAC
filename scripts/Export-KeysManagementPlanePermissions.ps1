<#
.SYNOPSIS
Exports management-plane Azure RBAC affecting the keys subscription to one CSV.

.DESCRIPTION
Collects active role assignments, inherited parent assignments, PIM eligible and
active assignments, management-plane deny assignments, role definitions, scope
details, and principal details. Role assignments whose definitions contain
DataActions are excluded so the CSV remains management-plane focused.

This script is read-only. It does not query or change Key Vault access policies,
create role assignments, or change enableRbacAuthorization.
#>
[CmdletBinding()]
param(
    [ValidateNotNullOrEmpty()]
    [string[]] $Subscription = @('keys'),

    [ValidateNotNullOrEmpty()]
    [string] $TenantId,

    [ValidateNotNullOrEmpty()]
    [string] $OutputPath = (Join-Path (Get-Location) 'keys-management-plane-permissions.csv'),

    [switch] $SkipPim,

    [switch] $SkipDenyAssignments
)

$ErrorActionPreference = 'Stop'

function Assert-CommandAvailable {
    param([string] $Name)

    if (-not (Get-Command -Name $Name -ErrorAction SilentlyContinue)) {
        throw "Required command '$Name' was not found. Install Az.Accounts and Az.Resources, then retry."
    }
}

function Get-FirstValue {
    param(
        [object] $InputObject,
        [string[]] $Path
    )

    foreach ($candidate in $Path) {
        $current = $InputObject
        $found = $true

        foreach ($segment in $candidate.Split('.')) {
            if ($null -eq $current) {
                $found = $false
                break
            }

            $property = $current.PSObject.Properties[$segment]
            if (-not $property) {
                $found = $false
                break
            }

            $current = $property.Value
        }

        if ($found -and $null -ne $current) {
            return $current
        }
    }

    return $null
}

function ConvertTo-SingleRequiredString {
    param(
        [object] $Value,
        [Parameter(Mandatory)]
        [string] $Name
    )

    $values = @(
        @($Value) |
            ForEach-Object { [string]$_ } |
            Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
    )

    if ($values.Count -ne 1) {
        throw "$Name must contain exactly one value; received $($values.Count)."
    }

    return $values[0]
}

function ConvertTo-FlatList {
    param([object] $Value)

    return @(
        @($Value) |
            Where-Object { $null -ne $_ -and -not [string]::IsNullOrWhiteSpace([string]$_) } |
            ForEach-Object { [string]$_ } |
            Sort-Object -Unique
    ) -join ';'
}

function Get-RoleDefinitionGuid {
    param([object] $Value)

    $text = [string]$Value
    if ([string]::IsNullOrWhiteSpace($text)) {
        return ''
    }

    $candidate = ($text.TrimEnd('/') -split '/')[-1]
    $guid = [guid]::Empty
    if ([guid]::TryParse($candidate, [ref]$guid)) {
        return $guid.Guid
    }

    return $candidate
}

function Get-RolePermissionList {
    param(
        [object] $RoleDefinition,
        [string] $PermissionName
    )

    $values = New-Object System.Collections.Generic.List[string]
    foreach ($value in @(Get-FirstValue -InputObject $RoleDefinition -Path @($PermissionName))) {
        if ($null -ne $value) {
            $values.Add([string]$value)
        }
    }

    foreach ($permission in @(Get-FirstValue -InputObject $RoleDefinition -Path @('Permissions'))) {
        foreach ($value in @(Get-FirstValue -InputObject $permission -Path @($PermissionName))) {
            if ($null -ne $value) {
                $values.Add([string]$value)
            }
        }
    }

    return ConvertTo-FlatList $values.ToArray()
}

function Test-RoleIncludesAction {
    param(
        [string] $Actions,
        [string] $NotActions,
        [string] $TargetAction
    )

    $isGranted = @(
        $Actions -split ';' |
            Where-Object {
                -not [string]::IsNullOrWhiteSpace($_) -and
                $TargetAction -like $_
            }
    ).Count -gt 0
    if (-not $isGranted) {
        return $false
    }

    $isExcluded = @(
        $NotActions -split ';' |
            Where-Object {
                -not [string]::IsNullOrWhiteSpace($_) -and
                $TargetAction -like $_
            }
    ).Count -gt 0

    return -not $isExcluded
}

function Get-RoleMetadata {
    param([object] $RoleDefinition)

    if (-not $RoleDefinition) {
        return [pscustomobject]@{
            AuthorizationPlane            = 'UnknownRoleDefinition'
            ManagementActions             = ''
            ManagementNotActions          = ''
            HasDataActions                = ''
            IsCustomRole                  = ''
            CanModifyLegacyAccessPolicies = ''
            IncludeInCsv                  = $true
            IncludeInManagementPlan       = 'ReviewRequired'
            ReviewDisposition             = 'ResolveRoleDefinitionBeforeApproval'
            ReviewReason                  = 'The assignment is retained because its role definition could not be resolved.'
        }
    }

    $managementActions = Get-RolePermissionList `
        -RoleDefinition $RoleDefinition `
        -PermissionName 'Actions'
    $managementNotActions = Get-RolePermissionList `
        -RoleDefinition $RoleDefinition `
        -PermissionName 'NotActions'
    $dataActions = Get-RolePermissionList `
        -RoleDefinition $RoleDefinition `
        -PermissionName 'DataActions'
    $hasManagementActions = -not [string]::IsNullOrWhiteSpace($managementActions)
    $hasDataActions = -not [string]::IsNullOrWhiteSpace($dataActions)
    $canModifyLegacyAccessPolicies = Test-RoleIncludesAction `
        -Actions $managementActions `
        -NotActions $managementNotActions `
        -TargetAction 'Microsoft.KeyVault/vaults/write'

    if ($hasManagementActions -and -not $hasDataActions) {
        $plane = 'ManagementPlaneOnly'
        $includeInCsv = $true
        $includeInPlan = 'Yes'
        if ($canModifyLegacyAccessPolicies) {
            $disposition = 'ReviewLegacyPolicyEscalationRisk'
            $reason = 'Role can modify vault configuration and legacy access policies within its scope.'
        }
        else {
            $disposition = 'ReviewScopeAndPrincipal'
            $reason = 'Confirm the principal needs this management role at the proposed target scope.'
        }
    }
    elseif ($hasDataActions) {
        $plane = if ($hasManagementActions) {
            'MixedManagementAndDataPlane'
        }
        else {
            'DataPlaneOnly'
        }
        $includeInCsv = $false
        $includeInPlan = 'No'
        $disposition = 'ExcludedContainsDataActions'
        $reason = 'Excluded because the current phase keeps Key Vault data-plane access on legacy policies.'
    }
    else {
        $plane = 'NoGrantActions'
        $includeInCsv = $false
        $includeInPlan = 'No'
        $disposition = 'ExcludedNoManagementActions'
        $reason = 'Role definition contains no management Actions.'
    }

    return [pscustomobject]@{
        AuthorizationPlane            = $plane
        ManagementActions             = $managementActions
        ManagementNotActions          = $managementNotActions
        HasDataActions                = $hasDataActions
        IsCustomRole                  = [string](Get-FirstValue -InputObject $RoleDefinition -Path @('IsCustom'))
        CanModifyLegacyAccessPolicies = $canModifyLegacyAccessPolicies
        IncludeInCsv                  = $includeInCsv
        IncludeInManagementPlan       = $includeInPlan
        ReviewDisposition             = $disposition
        ReviewReason                  = $reason
    }
}

function Get-ScopeMetadata {
    param(
        [string] $Scope,
        [string] $SelectedSubscriptionId
    )

    $normalizedScope = if ([string]::IsNullOrWhiteSpace($Scope)) {
        "/subscriptions/$SelectedSubscriptionId"
    }
    elseif ($Scope -eq '/') {
        '/'
    }
    else {
        $Scope.TrimEnd('/')
    }

    $metadata = [ordered]@{
        Scope                       = $normalizedScope
        ScopeLevel                  = 'Unknown'
        ScopeRelation               = 'Unknown'
        IsInheritedIntoSubscription = $false
        ScopedSubscriptionId        = ''
        ManagementGroupId           = ''
        ResourceGroup               = ''
        ProviderNamespace           = ''
        ResourceType                = ''
        ResourceName                = ''
        KeyVaultName                = ''
        KeyVaultObjectType          = ''
        KeyVaultObjectName          = ''
        ScopeReviewGuidance         = 'Review the assignment scope before creating destination access.'
    }

    if ($normalizedScope -eq '/') {
        $metadata.ScopeLevel = 'Tenant'
        $metadata.ScopeRelation = 'InheritedParent'
        $metadata.IsInheritedIntoSubscription = $true
        $metadata.ScopeReviewGuidance = 'Confirm tenant-root access should apply to every target subscription.'
        return [pscustomobject]$metadata
    }

    $managementGroupMatch = [regex]::Match(
        $normalizedScope,
        '^/providers/Microsoft\.Management/managementGroups/([^/]+)$',
        [System.Text.RegularExpressions.RegexOptions]::IgnoreCase
    )
    if ($managementGroupMatch.Success) {
        $metadata.ScopeLevel = 'ManagementGroup'
        $metadata.ScopeRelation = 'InheritedParent'
        $metadata.IsInheritedIntoSubscription = $true
        $metadata.ManagementGroupId = $managementGroupMatch.Groups[1].Value
        $metadata.ScopeReviewGuidance = 'Confirm each target subscription will remain under this management group.'
        return [pscustomobject]$metadata
    }

    $subscriptionMatch = [regex]::Match(
        $normalizedScope,
        '^/subscriptions/([^/]+)$',
        [System.Text.RegularExpressions.RegexOptions]::IgnoreCase
    )
    if ($subscriptionMatch.Success) {
        $metadata.ScopeLevel = 'Subscription'
        $metadata.ScopedSubscriptionId = $subscriptionMatch.Groups[1].Value
        $metadata.ScopeRelation = if ($metadata.ScopedSubscriptionId -ieq $SelectedSubscriptionId) {
            'DirectAtSubscription'
        }
        else {
            'OutsideSelectedSubscription'
        }
        $metadata.ScopeReviewGuidance = 'Decide whether this access belongs in dev, QA, production, or every target subscription.'
        return [pscustomobject]$metadata
    }

    $resourceGroupMatch = [regex]::Match(
        $normalizedScope,
        '^/subscriptions/([^/]+)/resourceGroups/([^/]+)$',
        [System.Text.RegularExpressions.RegexOptions]::IgnoreCase
    )
    if ($resourceGroupMatch.Success) {
        $metadata.ScopeLevel = 'ResourceGroup'
        $metadata.ScopedSubscriptionId = $resourceGroupMatch.Groups[1].Value
        $metadata.ResourceGroup = $resourceGroupMatch.Groups[2].Value
        $metadata.ScopeRelation = 'WithinSubscription'
        $metadata.ScopeReviewGuidance = 'Promote to environment subscription scope only if every resource in that subscription needs this access.'
        return [pscustomobject]$metadata
    }

    $resourceMatch = [regex]::Match(
        $normalizedScope,
        '^/subscriptions/([^/]+)/resourceGroups/([^/]+)/providers/([^/]+)/(.+)$',
        [System.Text.RegularExpressions.RegexOptions]::IgnoreCase
    )
    if ($resourceMatch.Success) {
        $metadata.ScopedSubscriptionId = $resourceMatch.Groups[1].Value
        $metadata.ResourceGroup = $resourceMatch.Groups[2].Value
        $metadata.ProviderNamespace = $resourceMatch.Groups[3].Value
        $metadata.ScopeRelation = 'WithinSubscription'

        $segments = @($resourceMatch.Groups[4].Value -split '/')
        $typeSegments = New-Object System.Collections.Generic.List[string]
        $nameSegments = New-Object System.Collections.Generic.List[string]
        for ($index = 0; $index -lt $segments.Count; $index += 2) {
            $typeSegments.Add($segments[$index])
            if (($index + 1) -lt $segments.Count) {
                $nameSegments.Add($segments[$index + 1])
            }
        }

        $metadata.ResourceType = "$($metadata.ProviderNamespace)/$($typeSegments -join '/')"
        $metadata.ResourceName = $nameSegments -join '/'
        $metadata.ScopeLevel = 'Resource'
        $metadata.ScopeReviewGuidance = 'Keep this assignment narrow and recreate it after a resource move if still required.'

        if (
            $metadata.ProviderNamespace -ieq 'Microsoft.KeyVault' -and
            $typeSegments.Count -gt 0 -and
            $typeSegments[0] -ieq 'vaults'
        ) {
            $metadata.KeyVaultName = if ($nameSegments.Count -gt 0) { $nameSegments[0] } else { '' }
            if ($typeSegments.Count -eq 1) {
                $metadata.ScopeLevel = 'KeyVault'
            }
            else {
                $metadata.ScopeLevel = 'KeyVaultObject'
                $metadata.KeyVaultObjectType = $typeSegments[1]
                $metadata.KeyVaultObjectName = if ($nameSegments.Count -gt 1) { $nameSegments[1] } else { '' }
            }
        }

        return [pscustomobject]$metadata
    }

    return [pscustomobject]$metadata
}

function Get-AuthorizationObjectKey {
    param(
        [object] $InputObject,
        [string] $RecordType
    )

    $identifier = [string](Get-FirstValue -InputObject $InputObject -Path @(
        'RoleAssignmentId',
        'DenyAssignmentId',
        'Id',
        'Name'
    ))
    if (-not [string]::IsNullOrWhiteSpace($identifier)) {
        return "$RecordType|$identifier".ToLowerInvariant()
    }

    $scope = [string](Get-FirstValue -InputObject $InputObject -Path @('Scope'))
    $principalId = [string](Get-FirstValue -InputObject $InputObject -Path @('ObjectId', 'PrincipalId'))
    $roleDefinitionId = Get-RoleDefinitionGuid (Get-FirstValue -InputObject $InputObject -Path @('RoleDefinitionId'))
    return "$RecordType|$scope|$principalId|$roleDefinitionId".ToLowerInvariant()
}

function Select-UniqueAuthorizationObject {
    param(
        [object[]] $InputObject,
        [string] $RecordType
    )

    $seen = @{}
    $result = New-Object System.Collections.Generic.List[object]
    foreach ($item in @($InputObject)) {
        if ($null -eq $item) {
            continue
        }

        $key = Get-AuthorizationObjectKey -InputObject $item -RecordType $RecordType
        if ($seen.ContainsKey($key)) {
            continue
        }

        $seen[$key] = $true
        $result.Add($item)
    }

    return $result.ToArray()
}

function Export-CsvRows {
    param(
        [object[]] $Rows,
        [string[]] $Headers,
        [string] $Path
    )

    $items = @($Rows | ForEach-Object { $_ })
    if ($items.Count -gt 0) {
        $items |
            Select-Object -Property $Headers |
            Export-Csv -LiteralPath $Path -NoTypeInformation -Encoding utf8
        return
    }

    $template = [ordered]@{}
    foreach ($header in $Headers) {
        $template[$header] = ''
    }
    $headerLine = ([pscustomobject]$template | ConvertTo-Csv -NoTypeInformation)[0]
    Set-Content -LiteralPath $Path -Value $headerLine -Encoding utf8
}

Assert-CommandAvailable -Name 'Get-AzContext'
Assert-CommandAvailable -Name 'Get-AzSubscription'
Assert-CommandAvailable -Name 'Set-AzContext'
Assert-CommandAvailable -Name 'Get-AzRoleAssignment'
Assert-CommandAvailable -Name 'Get-AzRoleDefinition'

if (-not $SkipPim) {
    Assert-CommandAvailable -Name 'Get-AzRoleEligibilityScheduleInstance'
    Assert-CommandAvailable -Name 'Get-AzRoleAssignmentScheduleInstance'
}
if (-not $SkipDenyAssignments) {
    Assert-CommandAvailable -Name 'Get-AzDenyAssignment'
}

$originalContext = Get-AzContext
if (-not $originalContext) {
    throw 'No Azure context found. Run Connect-AzAccount first.'
}

$subscriptionSelector = ConvertTo-SingleRequiredString `
    -Value $Subscription `
    -Name 'Subscription'

$contextTenantId = Get-FirstValue `
    -InputObject $originalContext `
    -Path @('Tenant.Id', 'Tenant.TenantId', 'TenantId')
$lookupTenantId = if ($PSBoundParameters.ContainsKey('TenantId')) {
    $TenantId
}
else {
    ConvertTo-SingleRequiredString -Value $contextTenantId -Name 'Current Azure context tenant ID'
}

$subscriptionLookupParameters = @{
    TenantId    = $lookupTenantId
    ErrorAction = 'Stop'
}
$parsedSubscriptionId = [guid]::Empty
if ([guid]::TryParse($subscriptionSelector, [ref]$parsedSubscriptionId)) {
    $subscriptionLookupParameters.SubscriptionId = $subscriptionSelector
}
else {
    $subscriptionLookupParameters.SubscriptionName = $subscriptionSelector
}

$subscriptionMatches = @(Get-AzSubscription @subscriptionLookupParameters)
if ($subscriptionMatches.Count -eq 0) {
    throw "Subscription '$subscriptionSelector' was not found in tenant '$lookupTenantId'. Verify both values with Get-AzSubscription -TenantId '$lookupTenantId'."
}
if ($subscriptionMatches.Count -gt 1) {
    $matches = $subscriptionMatches |
        ForEach-Object { "$($_.Name) [$($_.Id)] tenant=$($_.TenantId)" }
    throw "Subscription '$subscriptionSelector' is ambiguous in tenant '$lookupTenantId': $($matches -join '; '). Pass its subscription ID instead."
}

$selectedSubscription = $subscriptionMatches[0]
$subscriptionId = ConvertTo-SingleRequiredString -Value $selectedSubscription.Id -Name 'Resolved subscription ID'
$subscriptionName = ConvertTo-SingleRequiredString -Value $selectedSubscription.Name -Name 'Resolved subscription name'
$selectedTenantId = ConvertTo-SingleRequiredString -Value $selectedSubscription.TenantId -Name 'Resolved tenant ID'
if ($selectedTenantId -ine $lookupTenantId) {
    throw "Subscription '$subscriptionName' resolved to tenant '$selectedTenantId', not requested tenant '$lookupTenantId'."
}
$subscriptionScope = "/subscriptions/$subscriptionId"
$generatedUtc = [datetime]::UtcNow.ToString('o')
$resolvedOutputPath = [System.IO.Path]::GetFullPath($OutputPath)
$outputDirectory = Split-Path -Parent $resolvedOutputPath
New-Item -ItemType Directory -Path $outputDirectory -Force | Out-Null

$temporaryOutputPath = "$resolvedOutputPath.$PID.tmp"

$headers = @(
    'GeneratedUtc',
    'RecordType',
    'AssignmentState',
    'SubscriptionName',
    'SubscriptionId',
    'TenantId',
    'PrincipalId',
    'PrincipalType',
    'PrincipalDisplayName',
    'PrincipalSignInName',
    'RoleDefinitionName',
    'RoleDefinitionId',
    'IsCustomRole',
    'AuthorizationPlane',
    'IncludeInManagementPlan',
    'ManagementReviewDisposition',
    'ManagementActions',
    'ManagementNotActions',
    'CanModifyLegacyAccessPolicies',
    'Scope',
    'ScopeLevel',
    'ScopeRelation',
    'IsInheritedIntoSubscription',
    'ScopedSubscriptionId',
    'ManagementGroupId',
    'ResourceGroup',
    'ProviderNamespace',
    'ResourceType',
    'ResourceName',
    'KeyVaultName',
    'KeyVaultObjectType',
    'KeyVaultObjectName',
    'AssignmentId',
    'ConditionVersion',
    'Condition',
    'StartDateTime',
    'EndDateTime',
    'PimAssignmentType',
    'PimMemberType',
    'PimStatus',
    'DenyActions',
    'DenyNotActions',
    'DenyDataActionsPresent',
    'DenyDoNotApplyToChildScopes',
    'DenyIsSystemProtected',
    'ScopeReviewGuidance',
    'ReviewReason',
    'ProposedEnvironment',
    'ProposedTargetSubscription',
    'ProposedScope',
    'Decision',
    'DecisionOwner',
    'ApprovedBy',
    'Notes'
)

$rows = New-Object System.Collections.Generic.List[object]
$excludedDataPlaneCount = 0
$excludedNoManagementCount = 0

function New-CsvRow {
    param(
        [hashtable] $Values,
        [object] $ScopeMetadata
    )

    $row = [ordered]@{}
    foreach ($header in $headers) {
        $row[$header] = ''
    }

    $row.GeneratedUtc = $generatedUtc
    $row.SubscriptionName = $subscriptionName
    $row.SubscriptionId = $subscriptionId
    $row.TenantId = $selectedTenantId
    $row.Scope = $ScopeMetadata.Scope
    $row.ScopeLevel = $ScopeMetadata.ScopeLevel
    $row.ScopeRelation = $ScopeMetadata.ScopeRelation
    $row.IsInheritedIntoSubscription = $ScopeMetadata.IsInheritedIntoSubscription
    $row.ScopedSubscriptionId = $ScopeMetadata.ScopedSubscriptionId
    $row.ManagementGroupId = $ScopeMetadata.ManagementGroupId
    $row.ResourceGroup = $ScopeMetadata.ResourceGroup
    $row.ProviderNamespace = $ScopeMetadata.ProviderNamespace
    $row.ResourceType = $ScopeMetadata.ResourceType
    $row.ResourceName = $ScopeMetadata.ResourceName
    $row.KeyVaultName = $ScopeMetadata.KeyVaultName
    $row.KeyVaultObjectType = $ScopeMetadata.KeyVaultObjectType
    $row.KeyVaultObjectName = $ScopeMetadata.KeyVaultObjectName
    $row.ScopeReviewGuidance = $ScopeMetadata.ScopeReviewGuidance

    foreach ($entry in $Values.GetEnumerator()) {
        if ($row.Contains($entry.Key)) {
            $row[$entry.Key] = $entry.Value
        }
    }

    return [pscustomobject]$row
}

function Add-RoleAssignmentRow {
    param(
        [object] $Assignment,
        [string] $RecordType,
        [string] $AssignmentState,
        [hashtable] $RoleDefinitionIndex
    )

    $roleDefinitionId = Get-RoleDefinitionGuid (
        Get-FirstValue -InputObject $Assignment -Path @('RoleDefinitionId')
    )
    $roleDefinition = $null
    if (
        -not [string]::IsNullOrWhiteSpace($roleDefinitionId) -and
        $RoleDefinitionIndex.ContainsKey($roleDefinitionId.ToLowerInvariant())
    ) {
        $roleDefinition = $RoleDefinitionIndex[$roleDefinitionId.ToLowerInvariant()]
    }

    $roleMetadata = Get-RoleMetadata -RoleDefinition $roleDefinition
    if (-not $roleMetadata.IncludeInCsv) {
        if ($roleMetadata.HasDataActions) {
            $script:excludedDataPlaneCount++
        }
        else {
            $script:excludedNoManagementCount++
        }
        return
    }

    $scope = [string](Get-FirstValue -InputObject $Assignment -Path @('Scope'))
    $scopeMetadata = Get-ScopeMetadata -Scope $scope -SelectedSubscriptionId $subscriptionId
    $roleName = if ($roleDefinition) {
        [string](Get-FirstValue -InputObject $roleDefinition -Path @('RoleName', 'Name'))
    }
    else {
        [string](Get-FirstValue -InputObject $Assignment -Path @(
            'RoleDefinitionName',
            'ExpandedProperties.RoleDefinition.DisplayName'
        ))
    }

    $rows.Add((New-CsvRow -ScopeMetadata $scopeMetadata -Values @{
        RecordType                   = $RecordType
        AssignmentState              = $AssignmentState
        PrincipalId                  = [string](Get-FirstValue -InputObject $Assignment -Path @('ObjectId', 'PrincipalId'))
        PrincipalType                = [string](Get-FirstValue -InputObject $Assignment -Path @('ObjectType', 'PrincipalType'))
        PrincipalDisplayName         = [string](Get-FirstValue -InputObject $Assignment -Path @(
            'DisplayName',
            'ExpandedProperties.Principal.DisplayName'
        ))
        PrincipalSignInName          = [string](Get-FirstValue -InputObject $Assignment -Path @('SignInName'))
        RoleDefinitionName           = $roleName
        RoleDefinitionId             = $roleDefinitionId
        IsCustomRole                 = $roleMetadata.IsCustomRole
        AuthorizationPlane           = $roleMetadata.AuthorizationPlane
        IncludeInManagementPlan      = $roleMetadata.IncludeInManagementPlan
        ManagementReviewDisposition  = $roleMetadata.ReviewDisposition
        ManagementActions            = $roleMetadata.ManagementActions
        ManagementNotActions         = $roleMetadata.ManagementNotActions
        CanModifyLegacyAccessPolicies = $roleMetadata.CanModifyLegacyAccessPolicies
        AssignmentId                 = [string](Get-FirstValue -InputObject $Assignment -Path @('RoleAssignmentId', 'Id', 'Name'))
        ConditionVersion             = [string](Get-FirstValue -InputObject $Assignment -Path @('ConditionVersion'))
        Condition                    = [string](Get-FirstValue -InputObject $Assignment -Path @('Condition'))
        StartDateTime                = [string](Get-FirstValue -InputObject $Assignment -Path @('StartDateTime'))
        EndDateTime                  = [string](Get-FirstValue -InputObject $Assignment -Path @('EndDateTime'))
        PimAssignmentType            = [string](Get-FirstValue -InputObject $Assignment -Path @('AssignmentType'))
        PimMemberType                = [string](Get-FirstValue -InputObject $Assignment -Path @('MemberType'))
        PimStatus                    = [string](Get-FirstValue -InputObject $Assignment -Path @('Status'))
        ReviewReason                 = $roleMetadata.ReviewReason
    }))
}

try {
    Set-AzContext -Subscription $subscriptionId -Tenant $selectedTenantId -ErrorAction Stop | Out-Null

    $assignmentsBelowSubscription = @(Get-AzRoleAssignment -ErrorAction Stop)
    $assignmentsEffectiveAtSubscription = @(
        Get-AzRoleAssignment -Scope $subscriptionScope -ErrorAction Stop
    )
    $activeAssignments = @(
        Select-UniqueAuthorizationObject `
            -InputObject @($assignmentsBelowSubscription + $assignmentsEffectiveAtSubscription) `
            -RecordType 'ActiveRoleAssignment'
    )

    $roleDefinitions = @(Get-AzRoleDefinition -Scope $subscriptionScope -ErrorAction Stop)
    $roleDefinitionIndex = @{}
    foreach ($definition in $roleDefinitions) {
        $roleId = Get-RoleDefinitionGuid (
            Get-FirstValue -InputObject $definition -Path @('Name', 'Id')
        )
        if (-not [string]::IsNullOrWhiteSpace($roleId)) {
            $roleDefinitionIndex[$roleId.ToLowerInvariant()] = $definition
        }
    }

    foreach ($assignment in $activeAssignments) {
        Add-RoleAssignmentRow `
            -Assignment $assignment `
            -RecordType 'ActiveRoleAssignment' `
            -AssignmentState 'Active' `
            -RoleDefinitionIndex $roleDefinitionIndex
    }

    if ($SkipPim) {
        Write-Warning 'PIM eligible and active assignments were skipped by request.'
    }
    else {
        $pimEligible = @(
            Get-AzRoleEligibilityScheduleInstance -Scope $subscriptionScope -ErrorAction Stop
        )
        foreach ($assignment in $pimEligible) {
            Add-RoleAssignmentRow `
                -Assignment $assignment `
                -RecordType 'PimEligibleRoleAssignment' `
                -AssignmentState 'Eligible' `
                -RoleDefinitionIndex $roleDefinitionIndex
        }

        $pimActive = @(
            Get-AzRoleAssignmentScheduleInstance -Scope $subscriptionScope -ErrorAction Stop
        )
        foreach ($assignment in $pimActive) {
            Add-RoleAssignmentRow `
                -Assignment $assignment `
                -RecordType 'PimActiveRoleAssignment' `
                -AssignmentState 'PimActiveSchedule' `
                -RoleDefinitionIndex $roleDefinitionIndex
        }
    }

    if ($SkipDenyAssignments) {
        Write-Warning 'Deny assignments were skipped by request.'
    }
    else {
        $denyBelowSubscription = @(Get-AzDenyAssignment -ErrorAction Stop)
        $denyEffectiveAtSubscription = @(
            Get-AzDenyAssignment -Scope $subscriptionScope -ErrorAction Stop
        )
        $denyAssignments = @(
            Select-UniqueAuthorizationObject `
                -InputObject @($denyBelowSubscription + $denyEffectiveAtSubscription) `
                -RecordType 'DenyAssignment'
        )

        foreach ($assignment in $denyAssignments) {
            $denyActions = New-Object System.Collections.Generic.List[string]
            $denyNotActions = New-Object System.Collections.Generic.List[string]
            $denyDataActions = New-Object System.Collections.Generic.List[string]
            foreach ($permission in @(Get-FirstValue -InputObject $assignment -Path @('Permissions'))) {
                foreach ($value in @(Get-FirstValue -InputObject $permission -Path @('Actions'))) {
                    if ($null -ne $value) { $denyActions.Add([string]$value) }
                }
                foreach ($value in @(Get-FirstValue -InputObject $permission -Path @('NotActions'))) {
                    if ($null -ne $value) { $denyNotActions.Add([string]$value) }
                }
                foreach ($value in @(Get-FirstValue -InputObject $permission -Path @('DataActions'))) {
                    if ($null -ne $value) { $denyDataActions.Add([string]$value) }
                }
            }

            $denyActionsText = ConvertTo-FlatList $denyActions.ToArray()
            if ([string]::IsNullOrWhiteSpace($denyActionsText)) {
                continue
            }

            $principalIds = @(
                @(Get-FirstValue -InputObject $assignment -Path @('Principals')) |
                    ForEach-Object {
                        Get-FirstValue -InputObject $_ -Path @('Id', 'ObjectId', 'PrincipalId')
                    }
            )
            $scope = [string](Get-FirstValue -InputObject $assignment -Path @('Scope'))
            $scopeMetadata = Get-ScopeMetadata -Scope $scope -SelectedSubscriptionId $subscriptionId
            $rows.Add((New-CsvRow -ScopeMetadata $scopeMetadata -Values @{
                RecordType                    = 'DenyAssignment'
                AssignmentState               = 'Deny'
                PrincipalId                   = ConvertTo-FlatList $principalIds
                RoleDefinitionName            = 'Deny Assignment'
                AuthorizationPlane            = 'ManagementPlaneDeny'
                IncludeInManagementPlan       = 'No - review as constraint'
                ManagementReviewDisposition   = 'ReviewManagementDeny'
                AssignmentId                  = [string](Get-FirstValue -InputObject $assignment -Path @(
                    'DenyAssignmentId',
                    'Id',
                    'Name'
                ))
                DenyActions                   = $denyActionsText
                DenyNotActions                = ConvertTo-FlatList $denyNotActions.ToArray()
                DenyDataActionsPresent        = ($denyDataActions.Count -gt 0)
                DenyDoNotApplyToChildScopes   = [string](Get-FirstValue -InputObject $assignment -Path @('DoNotApplyToChildScopes'))
                DenyIsSystemProtected         = [string](Get-FirstValue -InputObject $assignment -Path @('IsSystemProtected'))
                ReviewReason                  = 'Deny assignments can override grants and can be system managed. Review separately.'
            }))
        }
    }

    $sortedRows = @(
        $rows.ToArray() |
            Sort-Object Scope, RecordType, RoleDefinitionName, PrincipalDisplayName, PrincipalId
    )
    Export-CsvRows -Rows $sortedRows -Headers $headers -Path $temporaryOutputPath
    Move-Item -LiteralPath $temporaryOutputPath -Destination $resolvedOutputPath -Force
}
finally {
    if (Test-Path -LiteralPath $temporaryOutputPath) {
        Remove-Item -LiteralPath $temporaryOutputPath -Force
    }
    if ($originalContext) {
        try {
            Set-AzContext -Context $originalContext -ErrorAction Stop | Out-Null
        }
        catch {
            Write-Warning "Unable to restore the original Azure context: $($_.Exception.Message)"
        }
    }
}

Write-Host (
    "Management-plane export complete. Subscription: {0} [{1}]; rows: {2}; data-plane-bearing assignments excluded: {3}; roles with no management Actions excluded: {4}; CSV: {5}" -f
    $subscriptionName,
    $subscriptionId,
    $rows.Count,
    $script:excludedDataPlaneCount,
    $script:excludedNoManagementCount,
    $resolvedOutputPath
)
