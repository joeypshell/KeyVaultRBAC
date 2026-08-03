[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string] $MovePlanPath,
    [string] $OutputPath = (Join-Path (Get-Location) 'out'),
    [switch] $RunArmValidation
)

$ErrorActionPreference = 'Stop'

function Assert-CommandAvailable {
    param([string] $Name)

    if (-not (Get-Command -Name $Name -ErrorAction SilentlyContinue)) {
        throw "Required command '$Name' was not found. Install the relevant Az module and retry."
    }
}

function Get-RowValue {
    param(
        [object] $Row,
        [string] $Name
    )

    $property = $Row.PSObject.Properties[$Name]
    if ($property -and -not [string]::IsNullOrWhiteSpace([string]$property.Value)) {
        return ([string]$property.Value).Trim()
    }

    return ''
}

function ConvertTo-Array {
    param([object] $Value)

    if ($null -eq $Value) {
        return @()
    }

    return @($Value)
}

function New-VaultResourceId {
    param(
        [string] $SubscriptionId,
        [string] $ResourceGroup,
        [string] $VaultName
    )

    return "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroup/providers/Microsoft.KeyVault/vaults/$VaultName"
}

function Get-RoleGuid {
    param([string] $RoleDefinitionId)

    $match = [regex]::Match(
        [string]$RoleDefinitionId,
        '(?i)([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})$'
    )
    if ($match.Success) {
        return $match.Groups[1].Value
    }

    return [string]$RoleDefinitionId
}

function Get-SubscriptionRoleAssignments {
    param([string] $SubscriptionId)

    if (-not $script:SubscriptionRoleAssignmentCache.ContainsKey($SubscriptionId)) {
        $script:SubscriptionRoleAssignmentCache[$SubscriptionId] = @(Get-AzRoleAssignment -ErrorAction Stop)
    }

    return @($script:SubscriptionRoleAssignmentCache[$SubscriptionId])
}

function Get-RoleEffectKey {
    param([object] $Assignment)

    return "$([string]$Assignment.ObjectId)|$(Get-RoleGuid -RoleDefinitionId ([string]$Assignment.RoleDefinitionId))|$([string]$Assignment.ConditionVersion)|$([string]$Assignment.Condition)".ToLowerInvariant()
}

function Add-RoleRows {
    param(
        [object[]] $Assignments,
        [string] $VaultName,
        [string] $Relationship,
        [System.Collections.Generic.List[object]] $Destination
    )

    foreach ($assignment in $Assignments) {
        $Destination.Add([pscustomobject]@{
            VaultName            = $VaultName
            Relationship         = $Relationship
            AssignmentScope      = [string]$assignment.Scope
            PrincipalId          = [string]$assignment.ObjectId
            PrincipalType        = [string]$assignment.ObjectType
            PrincipalDisplayName = [string]$assignment.DisplayName
            RoleDefinitionName   = [string]$assignment.RoleDefinitionName
            RoleDefinitionId     = Get-RoleGuid -RoleDefinitionId ([string]$assignment.RoleDefinitionId)
            RoleAssignmentId     = [string]$assignment.RoleAssignmentId
            Description          = [string]$assignment.Description
            ConditionVersion     = [string]$assignment.ConditionVersion
            Condition            = [string]$assignment.Condition
            DelegatedManagedIdentityResourceId = [string]$assignment.DelegatedManagedIdentityResourceId
        })
    }
}

function Export-CsvWithHeader {
    param(
        [object[]] $Rows,
        [string] $Path,
        [string[]] $Headers
    )

    if ($Rows.Count -gt 0) {
        $Rows | Export-Csv -LiteralPath $Path -NoTypeInformation
        return
    }

    $headerLine = (($Headers | ForEach-Object { '"' + $_.Replace('"', '""') + '"' }) -join ',')
    Set-Content -LiteralPath $Path -Value $headerLine -Encoding UTF8
}

if (-not (Test-Path -LiteralPath $MovePlanPath)) {
    throw "Move plan file not found: $MovePlanPath"
}

Assert-CommandAvailable -Name 'Get-AzContext'
Assert-CommandAvailable -Name 'Get-AzSubscription'
Assert-CommandAvailable -Name 'Set-AzContext'
Assert-CommandAvailable -Name 'Get-AzResource'
Assert-CommandAvailable -Name 'Get-AzResourceGroup'
Assert-CommandAvailable -Name 'Get-AzResourceProvider'
Assert-CommandAvailable -Name 'Get-AzRoleAssignment'

if ($RunArmValidation) {
    Assert-CommandAvailable -Name 'Invoke-AzResourceAction'
}

$diagnosticCommandAvailable = [bool](Get-Command -Name 'Get-AzDiagnosticSetting' -ErrorAction SilentlyContinue)
$currentContext = Get-AzContext
if (-not $currentContext) {
    throw "No Azure context found. Run Connect-AzAccount first."
}

$subscriptions = @(Get-AzSubscription)
$subscriptionById = @{}
foreach ($subscription in $subscriptions) {
    $subscriptionById[[string]$subscription.Id] = $subscription
}

$moveRows = @(Import-Csv -LiteralPath $MovePlanPath)
$summaryRows = New-Object System.Collections.Generic.List[object]
$directRoleRows = New-Object System.Collections.Generic.List[object]
$parentRoleRows = New-Object System.Collections.Generic.List[object]
$script:SubscriptionRoleAssignmentCache = @{}

New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null

foreach ($move in $moveRows) {
    $environment = Get-RowValue -Row $move -Name 'Environment'
    $sourceSubscriptionId = Get-RowValue -Row $move -Name 'SourceSubscriptionId'
    $sourceResourceGroup = Get-RowValue -Row $move -Name 'SourceResourceGroup'
    $vaultName = Get-RowValue -Row $move -Name 'VaultName'
    $plannedDestinationTenantId = Get-RowValue -Row $move -Name 'DestinationTenantId'
    $destinationSubscriptionId = Get-RowValue -Row $move -Name 'DestinationSubscriptionId'
    $destinationResourceGroup = Get-RowValue -Row $move -Name 'DestinationResourceGroup'

    if (-not $sourceSubscriptionId -or -not $sourceResourceGroup -or -not $vaultName -or
        -not $destinationSubscriptionId -or -not $destinationResourceGroup) {
        throw "Every move-plan row requires SourceSubscriptionId, SourceResourceGroup, VaultName, DestinationSubscriptionId, and DestinationResourceGroup."
    }

    $sourceVaultId = New-VaultResourceId `
        -SubscriptionId $sourceSubscriptionId `
        -ResourceGroup $sourceResourceGroup `
        -VaultName $vaultName
    $destinationVaultId = New-VaultResourceId `
        -SubscriptionId $destinationSubscriptionId `
        -ResourceGroup $destinationResourceGroup `
        -VaultName $vaultName

    $blockingIssues = New-Object System.Collections.Generic.List[string]
    $warnings = New-Object System.Collections.Generic.List[string]
    $sourceTenantId = ''
    $destinationTenantId = ''
    $permissionModel = ''
    $accessPolicyCount = 0
    $privateEndpointCount = 0
    $diagnosticSettingCount = ''
    $diagnosticCheck = if ($diagnosticCommandAvailable) { 'Pending' } else { 'NotCheckedAzMonitorMissing' }
    $directAssignmentCount = 0
    $childAssignmentCount = 0
    $sourceParentAssignmentCount = 0
    $destinationParentAssignmentCount = 0
    $parentRoleDeltaCount = 0
    $sourceParentAssignments = @()
    $destinationParentAssignments = @()
    $providerRegistrationState = ''
    $armValidationStatus = if ($RunArmValidation) { 'Pending' } else { 'NotRun' }
    $armValidationMessage = ''
    $sourceVaultFound = $false
    $destinationResourceGroupFound = $false

    $sourceSubscription = $subscriptionById[$sourceSubscriptionId]
    $destinationSubscription = $subscriptionById[$destinationSubscriptionId]

    if (-not $sourceSubscription) {
        $blockingIssues.Add("Source subscription is not available to the current account: $sourceSubscriptionId")
    }
    else {
        $sourceTenantId = [string]$sourceSubscription.TenantId
    }

    if (-not $destinationSubscription) {
        $blockingIssues.Add("Destination subscription is not available to the current account: $destinationSubscriptionId")
    }
    else {
        $destinationTenantId = [string]$destinationSubscription.TenantId
    }

    if ($sourceTenantId -and $destinationTenantId -and $sourceTenantId -ine $destinationTenantId) {
        $blockingIssues.Add('Source and destination subscriptions are in different Microsoft Entra tenants.')
    }
    if ($plannedDestinationTenantId -and $destinationTenantId -and
        $plannedDestinationTenantId -ine $destinationTenantId) {
        $blockingIssues.Add("Move plan destination tenant '$plannedDestinationTenantId' does not match subscription tenant '$destinationTenantId'.")
    }

    $sourceVault = $null
    $sourceGroup = $null
    if ($sourceSubscription) {
        try {
            Set-AzContext -SubscriptionId $sourceSubscriptionId -Tenant $sourceTenantId -ErrorAction Stop | Out-Null
            $sourceGroup = Get-AzResourceGroup -Name $sourceResourceGroup -ErrorAction Stop
            $sourceVault = Get-AzResource -ResourceId $sourceVaultId -ExpandProperties -ErrorAction Stop
            $sourceVaultFound = [bool]$sourceVault

            $enableRbac = [string]$sourceVault.Properties.enableRbacAuthorization
            $permissionModel = if ($enableRbac -ieq 'true') { 'AzureRbac' } else { 'LegacyAccessPolicy' }
            $accessPolicyCount = @(ConvertTo-Array $sourceVault.Properties.accessPolicies).Count
            $privateEndpointCount = @(ConvertTo-Array $sourceVault.Properties.privateEndpointConnections).Count

            $subscriptionAssignments = @(Get-SubscriptionRoleAssignments -SubscriptionId $sourceSubscriptionId)
            $directAssignments = @($subscriptionAssignments | Where-Object { [string]$_.Scope -ieq $sourceVaultId })
            $childAssignments = @($subscriptionAssignments | Where-Object { [string]$_.Scope -like "$sourceVaultId/*" })
            $directAssignmentCount = $directAssignments.Count
            $childAssignmentCount = $childAssignments.Count
            Add-RoleRows -Assignments $directAssignments -VaultName $vaultName -Relationship 'DirectVaultAssignmentToRecreate' -Destination $directRoleRows
            Add-RoleRows -Assignments $childAssignments -VaultName $vaultName -Relationship 'ChildObjectAssignmentToRecreate' -Destination $directRoleRows

            $sourceParentAssignments = @(
                Get-AzRoleAssignment -Scope $sourceVaultId -ErrorAction Stop |
                    Where-Object { [string]$_.Scope -ine $sourceVaultId }
            )
            $sourceParentAssignmentCount = $sourceParentAssignments.Count
            Add-RoleRows -Assignments $sourceParentAssignments -VaultName $vaultName -Relationship 'SourceParentScope' -Destination $parentRoleRows

            if ($diagnosticCommandAvailable) {
                try {
                    $diagnosticSettings = @(Get-AzDiagnosticSetting -ResourceId $sourceVaultId -ErrorAction Stop)
                    $diagnosticSettingCount = $diagnosticSettings.Count
                    $diagnosticCheck = 'Checked'
                }
                catch {
                    $diagnosticCheck = 'CheckFailed'
                    $warnings.Add("Diagnostic settings could not be read: $($_.Exception.Message)")
                }
            }
        }
        catch {
            $blockingIssues.Add("Source vault preflight failed: $($_.Exception.Message)")
        }
    }

    $destinationGroup = $null
    if ($destinationSubscription) {
        try {
            Set-AzContext -SubscriptionId $destinationSubscriptionId -Tenant $destinationTenantId -ErrorAction Stop | Out-Null
            $destinationGroup = Get-AzResourceGroup -Name $destinationResourceGroup -ErrorAction Stop
            $destinationResourceGroupFound = [bool]$destinationGroup

            $provider = @(
                Get-AzResourceProvider -ProviderNamespace 'Microsoft.KeyVault' -ErrorAction Stop |
                    Select-Object -First 1
            )
            $providerRegistrationState = if ($provider.Count -gt 0) {
                [string]$provider[0].RegistrationState
            }
            else {
                'Unknown'
            }
            if ($providerRegistrationState -ine 'Registered') {
                $blockingIssues.Add("Microsoft.KeyVault provider state in destination subscription is '$providerRegistrationState'.")
            }

            $destinationSubscriptionScope = "/subscriptions/$destinationSubscriptionId"
            $destinationResourceGroupScope = "$destinationSubscriptionScope/resourceGroups/$destinationResourceGroup"
            $destinationParentAssignments = @(
                Get-AzRoleAssignment -Scope $destinationResourceGroupScope -ErrorAction Stop
            )
            $destinationParentAssignmentCount = $destinationParentAssignments.Count
            Add-RoleRows -Assignments $destinationParentAssignments -VaultName $vaultName -Relationship 'DestinationParentScope' -Destination $parentRoleRows
        }
        catch {
            $blockingIssues.Add("Destination subscription preflight failed: $($_.Exception.Message)")
        }
    }

    if ($sourceSubscription -and $destinationSubscription) {
        $sourceParentEffects = @($sourceParentAssignments | ForEach-Object { Get-RoleEffectKey -Assignment $_ } | Sort-Object -Unique)
        $destinationParentEffects = @($destinationParentAssignments | ForEach-Object { Get-RoleEffectKey -Assignment $_ } | Sort-Object -Unique)
        $removedEffects = @($sourceParentEffects | Where-Object { $destinationParentEffects -notcontains $_ })
        $addedEffects = @($destinationParentEffects | Where-Object { $sourceParentEffects -notcontains $_ })
        $parentRoleDeltaCount = $removedEffects.Count + $addedEffects.Count
    }

    if ($RunArmValidation -and $sourceVault -and $sourceGroup -and $destinationGroup -and $blockingIssues.Count -eq 0) {
        try {
            Set-AzContext -SubscriptionId $sourceSubscriptionId -Tenant $sourceTenantId -ErrorAction Stop | Out-Null
            Invoke-AzResourceAction `
                -Action 'validateMoveResources' `
                -ResourceId $sourceGroup.ResourceId `
                -Parameters @{
                    resources          = @($sourceVaultId)
                    targetResourceGroup = $destinationGroup.ResourceId
                } `
                -Force `
                -ErrorAction Stop | Out-Null
            $armValidationStatus = 'Passed'
        }
        catch {
            $armValidationStatus = 'Failed'
            $armValidationMessage = $_.Exception.Message
            $blockingIssues.Add("ARM move validation failed: $armValidationMessage")
        }
    }
    elseif ($RunArmValidation -and $blockingIssues.Count -gt 0) {
        $armValidationStatus = 'SkippedDueToPreflightFailure'
    }

    if ($directAssignmentCount -gt 0 -or $childAssignmentCount -gt 0) {
        $warnings.Add('Vault and child-object role assignments will not move; recreate them at the destination scope.')
    }
    if ($parentRoleDeltaCount -gt 0) {
        $warnings.Add('Inherited control-plane access changes because the destination subscription/resource group has a different parent RBAC set.')
    }
    if ($privateEndpointCount -gt 0) {
        $warnings.Add('Private endpoint connections exist; validate linked private endpoint and DNS behavior before moving.')
    }
    if ($diagnosticSettingCount -is [int] -and $diagnosticSettingCount -gt 0) {
        $warnings.Add('Diagnostic settings exist; export them and verify or recreate them after the resource ID changes.')
    }
    if ($permissionModel -eq 'LegacyAccessPolicy') {
        $warnings.Add('Pre-staged Key Vault data-plane RBAC remains inactive while the legacy access-policy model is enabled.')
    }
    $warnings.Add('Update IaC state, scripts, alerts, dashboards, and CMK references that store the old vault resource ID.')

    $preflightStatus = if ($blockingIssues.Count -gt 0) {
        'Blocked'
    }
    elseif ($RunArmValidation -and $armValidationStatus -eq 'Passed') {
        'Validated'
    }
    else {
        'ReadyForArmValidation'
    }

    $summaryRows.Add([pscustomobject]@{
        Environment                    = $environment
        VaultName                      = $vaultName
        SourceTenantId                 = $sourceTenantId
        DestinationTenantId            = $destinationTenantId
        TenantMatch                    = ($sourceTenantId -and $destinationTenantId -and $sourceTenantId -ieq $destinationTenantId)
        SourceSubscriptionId           = $sourceSubscriptionId
        SourceResourceGroup            = $sourceResourceGroup
        SourceVaultId                  = $sourceVaultId
        DestinationSubscriptionId      = $destinationSubscriptionId
        DestinationResourceGroup       = $destinationResourceGroup
        ExpectedDestinationVaultId     = $destinationVaultId
        SourceVaultFound               = $sourceVaultFound
        DestinationResourceGroupFound  = $destinationResourceGroupFound
        ProviderRegistrationState      = $providerRegistrationState
        PermissionModel                = $permissionModel
        AccessPolicyCount              = $accessPolicyCount
        DirectRoleAssignmentCount      = $directAssignmentCount
        ChildRoleAssignmentCount       = $childAssignmentCount
        SourceParentAssignmentCount    = $sourceParentAssignmentCount
        DestinationParentAssignmentCount = $destinationParentAssignmentCount
        ParentRoleDeltaCount           = $parentRoleDeltaCount
        PrivateEndpointConnectionCount = $privateEndpointCount
        DiagnosticSettingsCheck        = $diagnosticCheck
        DiagnosticSettingCount         = $diagnosticSettingCount
        ArmValidationStatus            = $armValidationStatus
        ArmValidationMessage           = $armValidationMessage
        PreflightStatus                = $preflightStatus
        BlockingIssues                 = ($blockingIssues -join ' | ')
        Warnings                       = ($warnings -join ' | ')
    })
}

$summaryPath = Join-Path $OutputPath '13-subscription-move-preflight.csv'
$directRolePath = Join-Path $OutputPath '14-role-assignments-to-recreate.csv'
$parentRolePath = Join-Path $OutputPath '15-parent-scope-role-delta.csv'

Export-CsvWithHeader -Rows $summaryRows.ToArray() -Path $summaryPath -Headers @(
    'Environment',
    'VaultName',
    'SourceTenantId',
    'DestinationTenantId',
    'TenantMatch',
    'SourceSubscriptionId',
    'SourceResourceGroup',
    'SourceVaultId',
    'DestinationSubscriptionId',
    'DestinationResourceGroup',
    'ExpectedDestinationVaultId',
    'SourceVaultFound',
    'DestinationResourceGroupFound',
    'ProviderRegistrationState',
    'PermissionModel',
    'AccessPolicyCount',
    'DirectRoleAssignmentCount',
    'ChildRoleAssignmentCount',
    'SourceParentAssignmentCount',
    'DestinationParentAssignmentCount',
    'ParentRoleDeltaCount',
    'PrivateEndpointConnectionCount',
    'DiagnosticSettingsCheck',
    'DiagnosticSettingCount',
    'ArmValidationStatus',
    'ArmValidationMessage',
    'PreflightStatus',
    'BlockingIssues',
    'Warnings'
)
Export-CsvWithHeader -Rows $directRoleRows.ToArray() -Path $directRolePath -Headers @(
    'VaultName',
    'Relationship',
    'AssignmentScope',
    'PrincipalId',
    'PrincipalType',
    'PrincipalDisplayName',
    'RoleDefinitionName',
    'RoleDefinitionId',
    'RoleAssignmentId',
    'Description',
    'ConditionVersion',
    'Condition',
    'DelegatedManagedIdentityResourceId'
)
Export-CsvWithHeader -Rows $parentRoleRows.ToArray() -Path $parentRolePath -Headers @(
    'VaultName',
    'Relationship',
    'AssignmentScope',
    'PrincipalId',
    'PrincipalType',
    'PrincipalDisplayName',
    'RoleDefinitionName',
    'RoleDefinitionId',
    'RoleAssignmentId',
    'Description',
    'ConditionVersion',
    'Condition',
    'DelegatedManagedIdentityResourceId'
)

$blockedCount = @($summaryRows | Where-Object { $_.PreflightStatus -eq 'Blocked' }).Count
Write-Host "Subscription move preflight complete. Blocked: $blockedCount; Summary: $summaryPath"
Write-Host 'This script validates and reports only. It does not move any resource.'
