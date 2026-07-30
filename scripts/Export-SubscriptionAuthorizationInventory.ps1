[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string] $SubscriptionId,

    [string] $OutputPath = (Join-Path (Get-Location) 'out'),

    [switch] $SkipPim,

    [switch] $SkipDenyAssignments,

    [switch] $SkipKeyVaultAccessPolicies,

    [switch] $SkipPrincipalResolution,

    [switch] $AllowPartial
)

$ErrorActionPreference = 'Stop'

function Assert-CommandAvailable {
    param([string] $Name)

    if (-not (Get-Command -Name $Name -ErrorAction SilentlyContinue)) {
        throw "Required command '$Name' was not found. Install the relevant Az module and retry."
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

function ConvertTo-FlatList {
    param([object] $Value)

    return @(
        @($Value) |
            Where-Object { $null -ne $_ -and -not [string]::IsNullOrWhiteSpace([string]$_) } |
            ForEach-Object { [string]$_ } |
            Sort-Object -Unique
    ) -join ';'
}

function ConvertTo-CompactJson {
    param([object] $Value)

    if ($null -eq $Value) {
        return ''
    }

    return ($Value | ConvertTo-Json -Depth 30 -Compress)
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
        Scope                    = $normalizedScope
        ScopeLevel               = 'Unknown'
        ScopeRelation            = 'Unknown'
        IsInheritedIntoSubscription = $false
        ScopedSubscriptionId     = ''
        ManagementGroupId        = ''
        ResourceGroup            = ''
        ProviderNamespace        = ''
        ResourceType             = ''
        ResourceName             = ''
        KeyVaultName             = ''
        KeyVaultObjectType       = ''
        KeyVaultObjectName       = ''
        SameTenantMoveImpact     = 'Review'
        TenantTransferImpact     = 'RecreateOrReviewInTargetTenant'
        ReviewReason             = 'Review the assignment scope and intended target environment.'
    }

    if ($normalizedScope -eq '/') {
        $metadata.ScopeLevel = 'Tenant'
        $metadata.ScopeRelation = 'InheritedIntoSubscription'
        $metadata.IsInheritedIntoSubscription = $true
        $metadata.SameTenantMoveImpact = 'DependsOnTenantRootScope'
        $metadata.ReviewReason = 'Confirm tenant-root access remains intentional for every target subscription.'
        return [pscustomobject]$metadata
    }

    $managementGroupMatch = [regex]::Match(
        $normalizedScope,
        '^/providers/Microsoft\.Management/managementGroups/([^/]+)$',
        [System.Text.RegularExpressions.RegexOptions]::IgnoreCase
    )
    if ($managementGroupMatch.Success) {
        $metadata.ScopeLevel = 'ManagementGroup'
        $metadata.ScopeRelation = 'InheritedIntoSubscription'
        $metadata.IsInheritedIntoSubscription = $true
        $metadata.ManagementGroupId = $managementGroupMatch.Groups[1].Value
        $metadata.SameTenantMoveImpact = 'AppliesOnlyIfDestinationRemainsUnderScope'
        $metadata.ReviewReason = 'Confirm each target subscription remains under this management group and still requires the broad assignment.'
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
        $metadata.SameTenantMoveImpact = 'DoesNotFollowResourceToAnotherSubscription'
        $metadata.ReviewReason = 'Decide whether this access belongs in dev, QA, production, or every target subscription.'
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
        $metadata.ScopeRelation = if ($metadata.ScopedSubscriptionId -ieq $SelectedSubscriptionId) {
            'WithinSubscription'
        }
        else {
            'OutsideSelectedSubscription'
        }
        $metadata.SameTenantMoveImpact = 'DoesNotFollowResourceOutsideThisResourceGroup'
        $metadata.ReviewReason = 'Candidate for target-subscription scope only when every resource and principal in that environment requires the role.'
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
        $metadata.ScopeRelation = if ($metadata.ScopedSubscriptionId -ieq $SelectedSubscriptionId) {
            'WithinSubscription'
        }
        else {
            'OutsideSelectedSubscription'
        }

        $resourceSegments = @($resourceMatch.Groups[4].Value -split '/')
        $typeSegments = New-Object System.Collections.Generic.List[string]
        $nameSegments = New-Object System.Collections.Generic.List[string]
        for ($index = 0; $index -lt $resourceSegments.Count; $index += 2) {
            $typeSegments.Add($resourceSegments[$index])
            if (($index + 1) -lt $resourceSegments.Count) {
                $nameSegments.Add($resourceSegments[$index + 1])
            }
        }

        $metadata.ResourceType = "$($metadata.ProviderNamespace)/$($typeSegments -join '/')"
        $metadata.ResourceName = $nameSegments -join '/'
        $metadata.ScopeLevel = 'Resource'
        $metadata.SameTenantMoveImpact = 'DirectAssignmentDoesNotMove'
        $metadata.ReviewReason = 'Confirm this direct resource assignment is still required and recreate it after a resource move.'

        if (
            $metadata.ProviderNamespace -ieq 'Microsoft.KeyVault' -and
            $typeSegments.Count -gt 0 -and
            $typeSegments[0] -ieq 'vaults'
        ) {
            $metadata.KeyVaultName = if ($nameSegments.Count -gt 0) { $nameSegments[0] } else { '' }

            if ($typeSegments.Count -eq 1) {
                $metadata.ScopeLevel = 'KeyVault'
                $metadata.ReviewReason = 'Recreate this vault-level assignment at the destination vault resource ID if it remains required.'
            }
            else {
                $metadata.ScopeLevel = 'KeyVaultObject'
                $metadata.KeyVaultObjectType = $typeSegments[1]
                $metadata.KeyVaultObjectName = if ($nameSegments.Count -gt 1) { $nameSegments[1] } else { '' }
                $metadata.ReviewReason = 'Object-scope exception: validate the exact key, secret, or certificate requirement before recreating it.'
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

$script:InventoryErrors = New-Object System.Collections.Generic.List[object]
$script:CoverageRows = New-Object System.Collections.Generic.List[object]

function Add-InventoryError {
    param(
        [string] $Component,
        [System.Management.Automation.ErrorRecord] $ErrorRecord
    )

    $script:InventoryErrors.Add([pscustomobject]@{
        Component     = $Component
        ExceptionType = $ErrorRecord.Exception.GetType().FullName
        Message       = $ErrorRecord.Exception.Message
    })
}

function Add-Coverage {
    param(
        [string] $Component,
        [string] $Status,
        [int] $RecordCount,
        [string] $Notes = ''
    )

    $script:CoverageRows.Add([pscustomobject]@{
        Component   = $Component
        Status      = $Status
        RecordCount = $RecordCount
        Notes       = $Notes
    })
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

$subscription = Get-AzSubscription -SubscriptionId $SubscriptionId -ErrorAction Stop |
    Where-Object { [string]$_.Id -ieq $SubscriptionId } |
    Select-Object -First 1
if (-not $subscription) {
    throw "Subscription '$SubscriptionId' was not found in the current Azure context."
}

$selectedTenantId = [string]$subscription.TenantId
$selectedSubscriptionId = [string]$subscription.Id
$selectedSubscriptionName = [string]$subscription.Name
$subscriptionScope = "/subscriptions/$selectedSubscriptionId"

New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
$resolvedOutputPath = (Resolve-Path -LiteralPath $OutputPath).Path

$ownedOutputNames = @(
    '16-authorization-review.csv',
    '17-role-definitions-used.csv',
    '18-principal-summary.csv',
    '19-scope-summary.csv',
    '20-inventory-coverage.csv',
    '21-inventory-errors.csv'
)
foreach ($name in $ownedOutputNames) {
    $path = Join-Path $resolvedOutputPath $name
    if (Test-Path -LiteralPath $path) {
        Remove-Item -LiteralPath $path -Force
    }
}

$activeAssignments = @()
$pimEligibleAssignments = @()
$pimActiveAssignments = @()
$denyAssignments = @()
$roleDefinitions = @()
$legacyPolicyRows = @()
$legacyPrincipalRows = @()

try {
    Set-AzContext -Subscription $selectedSubscriptionId -Tenant $selectedTenantId -ErrorAction Stop | Out-Null

    try {
        $underSubscription = @(Get-AzRoleAssignment -IncludeClassicAdministrators -ErrorAction Stop)
        $effectiveAtSubscription = @(
            Get-AzRoleAssignment `
                -Scope $subscriptionScope `
                -IncludeClassicAdministrators `
                -ErrorAction Stop
        )
        $activeAssignments = @(
            Select-UniqueAuthorizationObject `
                -InputObject @($underSubscription + $effectiveAtSubscription) `
                -RecordType 'AzureRbacRoleAssignment'
        )
        Add-Coverage -Component 'ActiveAndClassicRbac' -Status 'Complete' -RecordCount $activeAssignments.Count
    }
    catch {
        Add-InventoryError -Component 'ActiveAndClassicRbac' -ErrorRecord $_
        Add-Coverage -Component 'ActiveAndClassicRbac' -Status 'Failed' -RecordCount 0 -Notes $_.Exception.Message
    }

    if ($SkipPim) {
        Add-Coverage -Component 'PimEligibleRbac' -Status 'Skipped' -RecordCount 0
        Add-Coverage -Component 'PimActiveRbac' -Status 'Skipped' -RecordCount 0
    }
    else {
        try {
            $pimEligibleAssignments = @(
                Get-AzRoleEligibilityScheduleInstance -Scope $subscriptionScope -ErrorAction Stop
            )
            Add-Coverage -Component 'PimEligibleRbac' -Status 'Complete' -RecordCount $pimEligibleAssignments.Count
        }
        catch {
            Add-InventoryError -Component 'PimEligibleRbac' -ErrorRecord $_
            Add-Coverage -Component 'PimEligibleRbac' -Status 'Failed' -RecordCount 0 -Notes $_.Exception.Message
        }

        try {
            $pimActiveAssignments = @(
                Get-AzRoleAssignmentScheduleInstance -Scope $subscriptionScope -ErrorAction Stop
            )
            Add-Coverage -Component 'PimActiveRbac' -Status 'Complete' -RecordCount $pimActiveAssignments.Count
        }
        catch {
            Add-InventoryError -Component 'PimActiveRbac' -ErrorRecord $_
            Add-Coverage -Component 'PimActiveRbac' -Status 'Failed' -RecordCount 0 -Notes $_.Exception.Message
        }
    }

    if ($SkipDenyAssignments) {
        Add-Coverage -Component 'DenyAssignments' -Status 'Skipped' -RecordCount 0
    }
    else {
        try {
            $denyUnderSubscription = @(Get-AzDenyAssignment -ErrorAction Stop)
            $denyEffectiveAtSubscription = @(
                Get-AzDenyAssignment -Scope $subscriptionScope -ErrorAction Stop
            )
            $denyAssignments = @(
                Select-UniqueAuthorizationObject `
                    -InputObject @($denyUnderSubscription + $denyEffectiveAtSubscription) `
                    -RecordType 'AzureDenyAssignment'
            )
            Add-Coverage -Component 'DenyAssignments' -Status 'Complete' -RecordCount $denyAssignments.Count
        }
        catch {
            Add-InventoryError -Component 'DenyAssignments' -ErrorRecord $_
            Add-Coverage -Component 'DenyAssignments' -Status 'Failed' -RecordCount 0 -Notes $_.Exception.Message
        }
    }

    try {
        $roleDefinitions = @(Get-AzRoleDefinition -Scope $subscriptionScope -ErrorAction Stop)
        Add-Coverage -Component 'RoleDefinitions' -Status 'Complete' -RecordCount $roleDefinitions.Count
    }
    catch {
        Add-InventoryError -Component 'RoleDefinitions' -ErrorRecord $_
        Add-Coverage -Component 'RoleDefinitions' -Status 'Failed' -RecordCount 0 -Notes $_.Exception.Message
    }

    if ($SkipKeyVaultAccessPolicies) {
        Add-Coverage -Component 'LegacyKeyVaultAccessPolicies' -Status 'Skipped' -RecordCount 0
        Add-Coverage `
            -Component 'LegacyPrincipalResolution' `
            -Status 'Skipped' `
            -RecordCount 0 `
            -Notes 'Legacy Key Vault access-policy export was skipped.'
    }
    else {
        try {
            $legacyOutputNames = @(
                '01-vault-inventory.csv',
                '02-access-policy-inventory.csv',
                '03-existing-rbac-inventory.csv',
                '04-principal-resolution.csv'
            )
            foreach ($name in $legacyOutputNames) {
                $path = Join-Path $resolvedOutputPath $name
                if (Test-Path -LiteralPath $path) {
                    Remove-Item -LiteralPath $path -Force
                }
            }

            $legacyParameters = @{
                OutputPath     = $resolvedOutputPath
                SubscriptionId = @($selectedSubscriptionId)
            }
            if (-not $SkipPrincipalResolution) {
                $legacyParameters.ResolvePrincipals = $true
            }

            & (Join-Path $PSScriptRoot 'Export-KeyVaultLegacyAccess.ps1') @legacyParameters

            $legacyPolicyPath = Join-Path $resolvedOutputPath '02-access-policy-inventory.csv'
            if (Test-Path -LiteralPath $legacyPolicyPath) {
                $legacyPolicyRows = @(Import-Csv -LiteralPath $legacyPolicyPath)
            }
            Add-Coverage -Component 'LegacyKeyVaultAccessPolicies' -Status 'Complete' -RecordCount $legacyPolicyRows.Count

            $legacyPrincipalPath = Join-Path $resolvedOutputPath '04-principal-resolution.csv'
            if (Test-Path -LiteralPath $legacyPrincipalPath) {
                $legacyPrincipalRows = @(Import-Csv -LiteralPath $legacyPrincipalPath)
            }

            if ($SkipPrincipalResolution) {
                Add-Coverage `
                    -Component 'LegacyPrincipalResolution' `
                    -Status 'Skipped' `
                    -RecordCount $legacyPrincipalRows.Count `
                    -Notes 'Principal IDs were exported without Entra object resolution.'
            }
            else {
                $unresolvedPrincipalCount = @(
                    $legacyPrincipalRows |
                        Where-Object { $_.ResolutionStatus -ne 'Resolved' }
                ).Count
                $principalResolutionStatus = if ($unresolvedPrincipalCount -gt 0) {
                    'ReviewRequired'
                }
                else {
                    'Complete'
                }
                Add-Coverage `
                    -Component 'LegacyPrincipalResolution' `
                    -Status $principalResolutionStatus `
                    -RecordCount $legacyPrincipalRows.Count `
                    -Notes (
                        'Resolved: {0}; unresolved or deleted: {1}. Review 04-principal-resolution.csv.' -f
                        ($legacyPrincipalRows.Count - $unresolvedPrincipalCount),
                        $unresolvedPrincipalCount
                    )
            }
        }
        catch {
            Add-InventoryError -Component 'LegacyKeyVaultAccessPolicies' -ErrorRecord $_
            Add-Coverage -Component 'LegacyKeyVaultAccessPolicies' -Status 'Failed' -RecordCount 0 -Notes $_.Exception.Message
            if ($SkipPrincipalResolution) {
                Add-Coverage `
                    -Component 'LegacyPrincipalResolution' `
                    -Status 'Skipped' `
                    -RecordCount 0 `
                    -Notes 'Principal resolution was not requested.'
            }
            else {
                Add-Coverage `
                    -Component 'LegacyPrincipalResolution' `
                    -Status 'Failed' `
                    -RecordCount 0 `
                    -Notes 'Legacy access-policy export failed before principal resolution could be verified.'
            }
        }
    }

    $roleDefinitionByGuid = @{}
    foreach ($roleDefinition in $roleDefinitions) {
        $roleDefinitionGuid = Get-RoleDefinitionGuid (Get-FirstValue -InputObject $roleDefinition -Path @('Name', 'Id'))
        if (-not [string]::IsNullOrWhiteSpace($roleDefinitionGuid)) {
            $roleDefinitionByGuid[$roleDefinitionGuid.ToLowerInvariant()] = $roleDefinition
        }
    }

    $reviewHeaders = @(
        'RecordType',
        'AssignmentState',
        'SubscriptionName',
        'SubscriptionId',
        'TenantId',
        'PrincipalId',
        'PrincipalType',
        'PrincipalDisplayName',
        'PrincipalSignInName',
        'PrincipalAppId',
        'RoleDefinitionName',
        'RoleDefinitionId',
        'IsCustomRole',
        'Scope',
        'ScopeLevel',
        'ScopeRelation',
        'IsInheritedIntoSubscription',
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
        'Description',
        'CanDelegate',
        'StartDateTime',
        'EndDateTime',
        'PimAssignmentType',
        'PimMemberType',
        'PimStatus',
        'KeyPermissions',
        'SecretPermissions',
        'CertificatePermissions',
        'StoragePermissions',
        'DenyActions',
        'DenyNotActions',
        'DenyDataActions',
        'DenyNotDataActions',
        'DenyExcludePrincipals',
        'DenyDoNotApplyToChildScopes',
        'DenyIsSystemProtected',
        'SameTenantMoveImpact',
        'TenantTransferImpact',
        'ReviewReason',
        'ProposedEnvironment',
        'ProposedTargetSubscription',
        'ProposedScopeLevel',
        'ProposedRole',
        'Decision',
        'DecisionOwner',
        'ApprovedBy',
        'Notes'
    )

    function New-ReviewRow {
        param([hashtable] $Values)

        $scope = [string]$Values.Scope
        $scopeMetadata = Get-ScopeMetadata -Scope $scope -SelectedSubscriptionId $selectedSubscriptionId
        $row = [ordered]@{}
        foreach ($header in $reviewHeaders) {
            $row[$header] = ''
        }

        $row.SubscriptionName = $selectedSubscriptionName
        $row.SubscriptionId = $selectedSubscriptionId
        $row.TenantId = $selectedTenantId
        $row.Scope = $scopeMetadata.Scope
        $row.ScopeLevel = $scopeMetadata.ScopeLevel
        $row.ScopeRelation = $scopeMetadata.ScopeRelation
        $row.IsInheritedIntoSubscription = $scopeMetadata.IsInheritedIntoSubscription
        $row.ManagementGroupId = $scopeMetadata.ManagementGroupId
        $row.ResourceGroup = $scopeMetadata.ResourceGroup
        $row.ProviderNamespace = $scopeMetadata.ProviderNamespace
        $row.ResourceType = $scopeMetadata.ResourceType
        $row.ResourceName = $scopeMetadata.ResourceName
        $row.KeyVaultName = $scopeMetadata.KeyVaultName
        $row.KeyVaultObjectType = $scopeMetadata.KeyVaultObjectType
        $row.KeyVaultObjectName = $scopeMetadata.KeyVaultObjectName
        $row.SameTenantMoveImpact = $scopeMetadata.SameTenantMoveImpact
        $row.TenantTransferImpact = $scopeMetadata.TenantTransferImpact
        $row.ReviewReason = $scopeMetadata.ReviewReason

        foreach ($entry in $Values.GetEnumerator()) {
            if ($row.Contains($entry.Key)) {
                $row[$entry.Key] = $entry.Value
            }
        }

        return [pscustomobject]$row
    }

    function Get-RoleDetails {
        param(
            [object] $RoleDefinitionId,
            [string] $FallbackName
        )

        $roleGuid = Get-RoleDefinitionGuid $RoleDefinitionId
        $definition = $null
        if (
            -not [string]::IsNullOrWhiteSpace($roleGuid) -and
            $roleDefinitionByGuid.ContainsKey($roleGuid.ToLowerInvariant())
        ) {
            $definition = $roleDefinitionByGuid[$roleGuid.ToLowerInvariant()]
        }

        return [pscustomobject]@{
            Id       = $roleGuid
            Name     = if ($definition) {
                [string](Get-FirstValue -InputObject $definition -Path @('RoleName', 'Name'))
            }
            else {
                $FallbackName
            }
            IsCustom = if ($definition) {
                [string](Get-FirstValue -InputObject $definition -Path @('IsCustom'))
            }
            else {
                ''
            }
        }
    }

    $reviewRows = New-Object System.Collections.Generic.List[object]

    foreach ($assignment in $activeAssignments) {
        $scope = [string](Get-FirstValue -InputObject $assignment -Path @('Scope'))
        $roleDetails = Get-RoleDetails `
            -RoleDefinitionId (Get-FirstValue -InputObject $assignment -Path @('RoleDefinitionId')) `
            -FallbackName ([string](Get-FirstValue -InputObject $assignment -Path @('RoleDefinitionName')))

        $reviewRows.Add((New-ReviewRow -Values @{
            RecordType          = 'AzureRbacRoleAssignment'
            AssignmentState     = 'Active'
            PrincipalId         = [string](Get-FirstValue -InputObject $assignment -Path @('ObjectId', 'PrincipalId'))
            PrincipalType       = [string](Get-FirstValue -InputObject $assignment -Path @('ObjectType', 'PrincipalType'))
            PrincipalDisplayName = [string](Get-FirstValue -InputObject $assignment -Path @('DisplayName'))
            PrincipalSignInName = [string](Get-FirstValue -InputObject $assignment -Path @('SignInName'))
            RoleDefinitionName  = $roleDetails.Name
            RoleDefinitionId    = $roleDetails.Id
            IsCustomRole        = $roleDetails.IsCustom
            Scope               = if ($scope) { $scope } else { $subscriptionScope }
            AssignmentId        = [string](Get-FirstValue -InputObject $assignment -Path @('RoleAssignmentId', 'Id'))
            ConditionVersion    = [string](Get-FirstValue -InputObject $assignment -Path @('ConditionVersion'))
            Condition           = [string](Get-FirstValue -InputObject $assignment -Path @('Condition'))
            Description         = [string](Get-FirstValue -InputObject $assignment -Path @('Description'))
            CanDelegate         = [string](Get-FirstValue -InputObject $assignment -Path @('CanDelegate'))
        }))
    }

    foreach ($assignment in $pimEligibleAssignments) {
        $roleDetails = Get-RoleDetails `
            -RoleDefinitionId (Get-FirstValue -InputObject $assignment -Path @('RoleDefinitionId')) `
            -FallbackName ([string](Get-FirstValue -InputObject $assignment -Path @(
                'ExpandedProperties.RoleDefinition.DisplayName'
            )))

        $reviewRows.Add((New-ReviewRow -Values @{
            RecordType          = 'AzurePimEligibility'
            AssignmentState     = 'Eligible'
            PrincipalId         = [string](Get-FirstValue -InputObject $assignment -Path @('PrincipalId'))
            PrincipalType       = [string](Get-FirstValue -InputObject $assignment -Path @('PrincipalType'))
            PrincipalDisplayName = [string](Get-FirstValue -InputObject $assignment -Path @(
                'ExpandedProperties.Principal.DisplayName'
            ))
            RoleDefinitionName  = $roleDetails.Name
            RoleDefinitionId    = $roleDetails.Id
            IsCustomRole        = $roleDetails.IsCustom
            Scope               = [string](Get-FirstValue -InputObject $assignment -Path @('Scope'))
            AssignmentId        = [string](Get-FirstValue -InputObject $assignment -Path @('Id', 'Name'))
            StartDateTime       = [string](Get-FirstValue -InputObject $assignment -Path @('StartDateTime'))
            EndDateTime         = [string](Get-FirstValue -InputObject $assignment -Path @('EndDateTime'))
            PimAssignmentType   = [string](Get-FirstValue -InputObject $assignment -Path @('AssignmentType'))
            PimMemberType       = [string](Get-FirstValue -InputObject $assignment -Path @('MemberType'))
            PimStatus           = [string](Get-FirstValue -InputObject $assignment -Path @('Status'))
        }))
    }

    foreach ($assignment in $pimActiveAssignments) {
        $roleDetails = Get-RoleDetails `
            -RoleDefinitionId (Get-FirstValue -InputObject $assignment -Path @('RoleDefinitionId')) `
            -FallbackName ([string](Get-FirstValue -InputObject $assignment -Path @(
                'ExpandedProperties.RoleDefinition.DisplayName'
            )))

        $reviewRows.Add((New-ReviewRow -Values @{
            RecordType          = 'AzurePimAssignment'
            AssignmentState     = 'PimActiveSchedule'
            PrincipalId         = [string](Get-FirstValue -InputObject $assignment -Path @('PrincipalId'))
            PrincipalType       = [string](Get-FirstValue -InputObject $assignment -Path @('PrincipalType'))
            PrincipalDisplayName = [string](Get-FirstValue -InputObject $assignment -Path @(
                'ExpandedProperties.Principal.DisplayName'
            ))
            RoleDefinitionName  = $roleDetails.Name
            RoleDefinitionId    = $roleDetails.Id
            IsCustomRole        = $roleDetails.IsCustom
            Scope               = [string](Get-FirstValue -InputObject $assignment -Path @('Scope'))
            AssignmentId        = [string](Get-FirstValue -InputObject $assignment -Path @('Id', 'Name'))
            StartDateTime       = [string](Get-FirstValue -InputObject $assignment -Path @('StartDateTime'))
            EndDateTime         = [string](Get-FirstValue -InputObject $assignment -Path @('EndDateTime'))
            PimAssignmentType   = [string](Get-FirstValue -InputObject $assignment -Path @('AssignmentType'))
            PimMemberType       = [string](Get-FirstValue -InputObject $assignment -Path @('MemberType'))
            PimStatus           = [string](Get-FirstValue -InputObject $assignment -Path @('Status'))
        }))
    }

    foreach ($assignment in $denyAssignments) {
        $principalIds = @(
            @(Get-FirstValue -InputObject $assignment -Path @('Principals')) |
                ForEach-Object {
                    Get-FirstValue -InputObject $_ -Path @('Id', 'ObjectId', 'PrincipalId')
                }
        )
        $excludedPrincipalIds = @(
            @(Get-FirstValue -InputObject $assignment -Path @('ExcludePrincipals')) |
                ForEach-Object {
                    Get-FirstValue -InputObject $_ -Path @('Id', 'ObjectId', 'PrincipalId')
                }
        )

        $denyActions = New-Object System.Collections.Generic.List[string]
        $denyNotActions = New-Object System.Collections.Generic.List[string]
        $denyDataActions = New-Object System.Collections.Generic.List[string]
        $denyNotDataActions = New-Object System.Collections.Generic.List[string]
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
            foreach ($value in @(Get-FirstValue -InputObject $permission -Path @('NotDataActions'))) {
                if ($null -ne $value) { $denyNotDataActions.Add([string]$value) }
            }
        }

        $reviewRows.Add((New-ReviewRow -Values @{
            RecordType                   = 'AzureDenyAssignment'
            AssignmentState              = 'Deny'
            PrincipalId                  = ConvertTo-FlatList $principalIds
            RoleDefinitionName           = 'Deny Assignment'
            Scope                        = [string](Get-FirstValue -InputObject $assignment -Path @('Scope'))
            AssignmentId                 = [string](Get-FirstValue -InputObject $assignment -Path @(
                'DenyAssignmentId',
                'Id',
                'Name'
            ))
            Description                  = [string](Get-FirstValue -InputObject $assignment -Path @('Description'))
            DenyActions                  = ConvertTo-FlatList $denyActions.ToArray()
            DenyNotActions               = ConvertTo-FlatList $denyNotActions.ToArray()
            DenyDataActions              = ConvertTo-FlatList $denyDataActions.ToArray()
            DenyNotDataActions           = ConvertTo-FlatList $denyNotDataActions.ToArray()
            DenyExcludePrincipals        = ConvertTo-FlatList $excludedPrincipalIds
            DenyDoNotApplyToChildScopes  = [string](Get-FirstValue -InputObject $assignment -Path @(
                'DoNotApplyToChildScopes'
            ))
            DenyIsSystemProtected        = [string](Get-FirstValue -InputObject $assignment -Path @(
                'IsSystemProtected'
            ))
            TenantTransferImpact         = 'ReviewAndRecreateIfRequired'
            ReviewReason                 = 'Review separately: deny assignments can override role grants and may be system managed.'
        }))
    }

    foreach ($policy in $legacyPolicyRows) {
        $rbacEnabled = [string]$policy.EnableRbacAuthorization -ieq 'true'
        $reviewRows.Add((New-ReviewRow -Values @{
            RecordType             = 'KeyVaultAccessPolicy'
            AssignmentState        = if ($rbacEnabled) { 'LegacyConfiguredInactive' } else { 'LegacyActive' }
            PrincipalId            = [string]$policy.PrincipalObjectId
            PrincipalType          = [string]$policy.PrincipalType
            PrincipalDisplayName   = [string]$policy.PrincipalDisplayName
            PrincipalAppId         = [string]$policy.PrincipalAppId
            RoleDefinitionName     = 'Legacy Key Vault Access Policy'
            Scope                  = [string]$policy.VaultId
            AssignmentId           = "legacy|$($policy.VaultId)|$($policy.PrincipalObjectId)|$($policy.ApplicationId)"
            Description            = [string]$policy.PermissionSignature
            KeyPermissions         = [string]$policy.KeyPermissions
            SecretPermissions      = [string]$policy.SecretPermissions
            CertificatePermissions = [string]$policy.CertificatePermissions
            StoragePermissions     = [string]$policy.StoragePermissions
            SameTenantMoveImpact   = 'MovesWithVaultConfiguration'
            TenantTransferImpact   = 'UpdateVaultTenantAndRemapPolicy'
            ReviewReason           = 'Map these data-plane permissions to approved RBAC intent or explicitly retain the legacy policy.'
        }))
    }

    $usedRoleDefinitionIds = @(
        $reviewRows |
            ForEach-Object { $_.RoleDefinitionId } |
            Where-Object { $_ } |
            Sort-Object -Unique
    )

    $roleDefinitionHeaders = @(
        'RoleDefinitionId',
        'RoleName',
        'IsCustom',
        'Description',
        'Actions',
        'NotActions',
        'DataActions',
        'NotDataActions',
        'AssignableScopes',
        'PermissionsJson'
    )
    $roleDefinitionRows = New-Object System.Collections.Generic.List[object]
    foreach ($roleDefinitionId in $usedRoleDefinitionIds) {
        if (-not $roleDefinitionByGuid.ContainsKey($roleDefinitionId.ToLowerInvariant())) {
            continue
        }

        $definition = $roleDefinitionByGuid[$roleDefinitionId.ToLowerInvariant()]
        $roleDefinitionRows.Add([pscustomobject]@{
            RoleDefinitionId = $roleDefinitionId
            RoleName         = [string](Get-FirstValue -InputObject $definition -Path @('RoleName', 'Name'))
            IsCustom         = [string](Get-FirstValue -InputObject $definition -Path @('IsCustom'))
            Description      = [string](Get-FirstValue -InputObject $definition -Path @('Description'))
            Actions          = Get-RolePermissionList -RoleDefinition $definition -PermissionName 'Actions'
            NotActions       = Get-RolePermissionList -RoleDefinition $definition -PermissionName 'NotActions'
            DataActions      = Get-RolePermissionList -RoleDefinition $definition -PermissionName 'DataActions'
            NotDataActions   = Get-RolePermissionList -RoleDefinition $definition -PermissionName 'NotDataActions'
            AssignableScopes = ConvertTo-FlatList (Get-FirstValue -InputObject $definition -Path @('AssignableScopes'))
            PermissionsJson  = ConvertTo-CompactJson (Get-FirstValue -InputObject $definition -Path @('Permissions'))
        })
    }

    $principalHeaders = @(
        'PrincipalId',
        'PrincipalType',
        'PrincipalDisplayName',
        'PrincipalSignInName',
        'PrincipalAppId',
        'TotalAuthorizationRecords',
        'ActiveRbacCount',
        'PimEligibleCount',
        'PimActiveCount',
        'LegacyPolicyCount',
        'DenyAssignmentCount',
        'TargetTenantPrincipalId',
        'Owner',
        'Disposition',
        'Notes'
    )
    $principalIndex = @{}
    foreach ($row in $reviewRows) {
        foreach ($principalId in @([string]$row.PrincipalId -split ';')) {
            if ([string]::IsNullOrWhiteSpace($principalId)) {
                continue
            }

            $key = $principalId.ToLowerInvariant()
            if (-not $principalIndex.ContainsKey($key)) {
                $principalIndex[$key] = [ordered]@{
                    PrincipalId              = $principalId
                    PrincipalType            = [string]$row.PrincipalType
                    PrincipalDisplayName     = [string]$row.PrincipalDisplayName
                    PrincipalSignInName      = [string]$row.PrincipalSignInName
                    PrincipalAppId           = [string]$row.PrincipalAppId
                    TotalAuthorizationRecords = 0
                    ActiveRbacCount          = 0
                    PimEligibleCount         = 0
                    PimActiveCount           = 0
                    LegacyPolicyCount        = 0
                    DenyAssignmentCount      = 0
                    TargetTenantPrincipalId  = ''
                    Owner                    = ''
                    Disposition              = ''
                    Notes                    = ''
                }
            }

            $principal = $principalIndex[$key]
            $principal.TotalAuthorizationRecords++
            if (-not $principal.PrincipalType -and $row.PrincipalType) {
                $principal.PrincipalType = [string]$row.PrincipalType
            }
            if (-not $principal.PrincipalDisplayName -and $row.PrincipalDisplayName) {
                $principal.PrincipalDisplayName = [string]$row.PrincipalDisplayName
            }
            if (-not $principal.PrincipalSignInName -and $row.PrincipalSignInName) {
                $principal.PrincipalSignInName = [string]$row.PrincipalSignInName
            }
            if (-not $principal.PrincipalAppId -and $row.PrincipalAppId) {
                $principal.PrincipalAppId = [string]$row.PrincipalAppId
            }

            switch ($row.RecordType) {
                'AzureRbacRoleAssignment' { $principal.ActiveRbacCount++ }
                'AzurePimEligibility' { $principal.PimEligibleCount++ }
                'AzurePimAssignment' { $principal.PimActiveCount++ }
                'KeyVaultAccessPolicy' { $principal.LegacyPolicyCount++ }
                'AzureDenyAssignment' { $principal.DenyAssignmentCount++ }
            }
        }
    }
    $principalRows = @(
        $principalIndex.Values |
            ForEach-Object { [pscustomobject]$_ } |
            Sort-Object PrincipalType, PrincipalDisplayName, PrincipalId
    )

    $scopeSummaryHeaders = @(
        'RecordType',
        'AssignmentState',
        'ScopeLevel',
        'RoleDefinitionName',
        'AssignmentCount',
        'UniquePrincipalCount',
        'ResourceGroupCount',
        'SameTenantMoveImpact'
    )
    $scopeSummaryRows = @(
        $reviewRows |
            Group-Object -Property RecordType, AssignmentState, ScopeLevel, RoleDefinitionName |
            ForEach-Object {
                $first = $_.Group[0]
                [pscustomobject]@{
                    RecordType          = $first.RecordType
                    AssignmentState     = $first.AssignmentState
                    ScopeLevel          = $first.ScopeLevel
                    RoleDefinitionName  = $first.RoleDefinitionName
                    AssignmentCount     = $_.Count
                    UniquePrincipalCount = @(
                        $_.Group.PrincipalId |
                            Where-Object { $_ } |
                            Sort-Object -Unique
                    ).Count
                    ResourceGroupCount  = @(
                        $_.Group.ResourceGroup |
                            Where-Object { $_ } |
                            Sort-Object -Unique
                    ).Count
                    SameTenantMoveImpact = $first.SameTenantMoveImpact
                }
            } |
            Sort-Object RecordType, ScopeLevel, RoleDefinitionName
    )

    $coverageHeaders = @('Component', 'Status', 'RecordCount', 'Notes')
    $errorHeaders = @('Component', 'ExceptionType', 'Message')

    Export-CsvRows `
        -Rows $reviewRows.ToArray() `
        -Headers $reviewHeaders `
        -Path (Join-Path $resolvedOutputPath '16-authorization-review.csv')
    Export-CsvRows `
        -Rows $roleDefinitionRows.ToArray() `
        -Headers $roleDefinitionHeaders `
        -Path (Join-Path $resolvedOutputPath '17-role-definitions-used.csv')
    Export-CsvRows `
        -Rows $principalRows `
        -Headers $principalHeaders `
        -Path (Join-Path $resolvedOutputPath '18-principal-summary.csv')
    Export-CsvRows `
        -Rows $scopeSummaryRows `
        -Headers $scopeSummaryHeaders `
        -Path (Join-Path $resolvedOutputPath '19-scope-summary.csv')
    Export-CsvRows `
        -Rows $script:CoverageRows.ToArray() `
        -Headers $coverageHeaders `
        -Path (Join-Path $resolvedOutputPath '20-inventory-coverage.csv')
    Export-CsvRows `
        -Rows $script:InventoryErrors.ToArray() `
        -Headers $errorHeaders `
        -Path (Join-Path $resolvedOutputPath '21-inventory-errors.csv')
}
finally {
    if ($originalContext) {
        try {
            Set-AzContext -Context $originalContext -ErrorAction Stop | Out-Null
        }
        catch {
            Write-Warning "Unable to restore the original Azure context: $($_.Exception.Message)"
        }
    }
}

$failedCoverage = @($script:CoverageRows | Where-Object { $_.Status -eq 'Failed' })
Write-Host (
    "Authorization inventory complete. Review rows: {0}; Coverage failures: {1}; Output: {2}" -f
    $reviewRows.Count,
    $failedCoverage.Count,
    $resolvedOutputPath
)

if ($failedCoverage.Count -gt 0 -and -not $AllowPartial) {
    throw "Authorization inventory is incomplete. Review 20-inventory-coverage.csv and 21-inventory-errors.csv, then rerun or use -AllowPartial to accept a partial export."
}
