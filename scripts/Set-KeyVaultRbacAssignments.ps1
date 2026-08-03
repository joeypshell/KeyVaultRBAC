[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
param(
    [string] $PlanPath = (Join-Path (Get-Location) 'out\11-rbac-assignment-plan.csv'),
    [string] $ResultPath = (Join-Path (Get-Location) 'out\12-rbac-assignment-results.csv'),
    [switch] $AllowUnapproved,
    [switch] $AllowRbacPermissionModel,
    [switch] $ValidatePlanOnly
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

function Get-RoleGuid {
    param([string] $RoleDefinitionId)

    if ([string]::IsNullOrWhiteSpace($RoleDefinitionId)) {
        return ''
    }

    $match = [regex]::Match($RoleDefinitionId, '(?i)([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})$')
    if ($match.Success) {
        return $match.Groups[1].Value.ToLowerInvariant()
    }

    return $RoleDefinitionId.ToLowerInvariant()
}

function New-VaultResourceId {
    param(
        [string] $SubscriptionId,
        [string] $ResourceGroup,
        [string] $VaultName
    )

    return "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroup/providers/Microsoft.KeyVault/vaults/$VaultName"
}

function Test-GuidValue {
    param([string] $Value)

    $parsed = [Guid]::Empty
    return [Guid]::TryParse($Value, [ref]$parsed)
}

function ConvertTo-Boolean {
    param([object] $Value)

    if ($Value -is [bool]) {
        return $Value
    }

    $parsed = $false
    if ([bool]::TryParse([string]$Value, [ref]$parsed)) {
        return $parsed
    }

    return $false
}

function Export-Results {
    param(
        [object[]] $Rows,
        [string] $Path
    )

    $parent = Split-Path -Parent $Path
    if ($parent) {
        New-Item -ItemType Directory -Path $parent -Force -WhatIf:$false -Confirm:$false | Out-Null
    }

    if ($Rows.Count -gt 0) {
        $Rows | Export-Csv -LiteralPath $Path -NoTypeInformation
        return
    }

    $headers = @(
        'TimestampUtc',
        'TargetTenantId',
        'TargetSubscriptionId',
        'TargetResourceGroup',
        'VaultName',
        'VaultId',
        'PermissionModel',
        'PrincipalId',
        'RoleDefinitionName',
        'RoleDefinitionId',
        'ApprovedBy',
        'Result',
        'RoleAssignmentId',
        'Message'
    )
    $headerLine = (($headers | ForEach-Object { '"' + $_ + '"' }) -join ',')
    Set-Content -LiteralPath $Path -Value $headerLine -Encoding UTF8
}

if (-not (Test-Path -LiteralPath $PlanPath)) {
    throw "RBAC staging plan not found: $PlanPath"
}

$planRows = @(Import-Csv -LiteralPath $PlanPath)
$requiredColumns = @(
    'TargetSubscriptionId',
    'TargetResourceGroup',
    'VaultName',
    'ExpectedTargetVaultId',
    'TargetPrincipalId',
    'RoleDefinitionId',
    'StageStatus'
)

$availableColumns = @()
if ($planRows.Count -gt 0) {
    $availableColumns = @($planRows[0].PSObject.Properties.Name)
}
else {
    $header = Get-Content -LiteralPath $PlanPath -TotalCount 1
    if ($header) {
        $availableColumns = @(
            $header -split ',' |
                ForEach-Object { $_.Trim().Trim('"') }
        )
    }
}

$missingColumns = @($requiredColumns | Where-Object { $availableColumns -notcontains $_ })
if ($missingColumns.Count -gt 0) {
    throw "RBAC staging plan is missing required columns: $($missingColumns -join ', ')"
}

if ($ValidatePlanOnly) {
    $readyRows = @($planRows | Where-Object {
        $_.StageStatus -eq 'ReadyToStage' -or ($AllowUnapproved -and $_.StageStatus -eq 'NeedsApproval')
    })
    $validationErrors = New-Object System.Collections.Generic.List[string]
    foreach ($row in $readyRows) {
        $subscriptionId = Get-RowValue -Row $row -Name 'TargetSubscriptionId'
        $tenantId = Get-RowValue -Row $row -Name 'TargetTenantId'
        $resourceGroup = Get-RowValue -Row $row -Name 'TargetResourceGroup'
        $vaultName = Get-RowValue -Row $row -Name 'VaultName'
        $vaultId = Get-RowValue -Row $row -Name 'ExpectedTargetVaultId'
        $principalId = Get-RowValue -Row $row -Name 'TargetPrincipalId'
        $roleId = Get-RowValue -Row $row -Name 'RoleDefinitionId'

        if (-not $subscriptionId -or -not $resourceGroup -or -not $vaultName -or
            -not $vaultId -or -not $principalId -or -not $roleId) {
            $validationErrors.Add("$vaultName has one or more blank required values.")
            continue
        }
        if (-not (Test-GuidValue -Value $subscriptionId) -or
            -not (Test-GuidValue -Value $principalId) -or
            -not (Test-GuidValue -Value $roleId) -or
            ($tenantId -and -not (Test-GuidValue -Value $tenantId))) {
            $validationErrors.Add("$vaultName has an invalid subscription, tenant, principal, or role definition GUID.")
            continue
        }

        $calculatedVaultId = New-VaultResourceId `
            -SubscriptionId $subscriptionId `
            -ResourceGroup $resourceGroup `
            -VaultName $vaultName
        if ($vaultId -ine $calculatedVaultId) {
            $validationErrors.Add("$vaultName has a mismatched ExpectedTargetVaultId.")
        }
    }

    if ($validationErrors.Count -gt 0) {
        throw "Plan validation failed: $($validationErrors -join ' | ')"
    }

    Write-Host "Plan validation passed. Eligible rows: $($readyRows.Count); Total rows: $($planRows.Count)."
    return
}

Assert-CommandAvailable -Name 'Get-AzContext'
Assert-CommandAvailable -Name 'Set-AzContext'
Assert-CommandAvailable -Name 'Get-AzResource'
Assert-CommandAvailable -Name 'Get-AzRoleAssignment'
Assert-CommandAvailable -Name 'New-AzRoleAssignment'

$currentContext = Get-AzContext
if (-not $currentContext) {
    throw "No Azure context found. Run Connect-AzAccount first."
}

$resultRows = New-Object System.Collections.Generic.List[object]
$activeContextKey = ''
$failureCount = 0

foreach ($plan in $planRows) {
    $targetSubscriptionId = Get-RowValue -Row $plan -Name 'TargetSubscriptionId'
    $targetTenantId = Get-RowValue -Row $plan -Name 'TargetTenantId'
    $targetResourceGroup = Get-RowValue -Row $plan -Name 'TargetResourceGroup'
    $vaultName = Get-RowValue -Row $plan -Name 'VaultName'
    $expectedVaultId = Get-RowValue -Row $plan -Name 'ExpectedTargetVaultId'
    $targetPrincipalId = Get-RowValue -Row $plan -Name 'TargetPrincipalId'
    $roleDefinitionId = Get-RowValue -Row $plan -Name 'RoleDefinitionId'
    $roleDefinitionName = Get-RowValue -Row $plan -Name 'RoleDefinitionName'
    $approvedBy = Get-RowValue -Row $plan -Name 'ApprovedBy'
    $stageStatus = Get-RowValue -Row $plan -Name 'StageStatus'

    $status = ''
    $message = ''
    $permissionModel = ''
    $assignmentId = ''

    try {
        $eligible = $stageStatus -eq 'ReadyToStage'
        if ($AllowUnapproved -and $stageStatus -eq 'NeedsApproval') {
            $eligible = $true
        }

        if (-not $eligible) {
            $status = 'SkippedPlanStatus'
            $message = "StageStatus is $stageStatus."
        }
        elseif (-not $approvedBy -and -not $AllowUnapproved) {
            $status = 'SkippedUnapproved'
            $message = 'ApprovedBy is blank.'
        }
        elseif (-not $targetSubscriptionId -or -not $targetResourceGroup -or -not $vaultName -or
            -not $expectedVaultId -or -not $targetPrincipalId -or -not $roleDefinitionId) {
            $status = 'FailedPlanValidation'
            $message = 'One or more required values are blank.'
            $failureCount++
        }
        elseif (-not (Test-GuidValue -Value $targetSubscriptionId) -or
            -not (Test-GuidValue -Value $targetPrincipalId) -or
            -not (Test-GuidValue -Value $roleDefinitionId) -or
            ($targetTenantId -and -not (Test-GuidValue -Value $targetTenantId))) {
            $status = 'FailedPlanValidation'
            $message = 'Subscription, tenant, principal, or role definition ID is not a valid GUID.'
            $failureCount++
        }
        elseif ($expectedVaultId -ine (New-VaultResourceId `
            -SubscriptionId $targetSubscriptionId `
            -ResourceGroup $targetResourceGroup `
            -VaultName $vaultName)) {
            $status = 'FailedPlanValidation'
            $message = 'ExpectedTargetVaultId does not match the target subscription, resource group, and vault name.'
            $failureCount++
        }
        else {
            $contextKey = "$targetTenantId|$targetSubscriptionId".ToLowerInvariant()
            if ($activeContextKey -ne $contextKey) {
                $contextParameters = @{
                    SubscriptionId = $targetSubscriptionId
                    ErrorAction    = 'Stop'
                }
                if ($targetTenantId) {
                    $contextParameters.Tenant = $targetTenantId
                }
                $contextParameters.WhatIf = $false
                $contextParameters.Confirm = $false

                $selectedContext = Set-AzContext @contextParameters
                $selectedTenantId = [string]$selectedContext.Tenant.Id
                if ($targetTenantId -and $selectedTenantId -ine $targetTenantId) {
                    throw "Selected context tenant '$selectedTenantId' does not match target tenant '$targetTenantId'."
                }

                $activeContextKey = $contextKey
            }

            $vault = Get-AzResource -ResourceId $expectedVaultId -ExpandProperties -ErrorAction Stop
            if (-not $vault -or [string]$vault.ResourceId -ine $expectedVaultId) {
                throw "Vault was not found at its expected post-move resource ID: $expectedVaultId"
            }
            if ([string]$vault.ResourceType -ine 'Microsoft.KeyVault/vaults') {
                throw "Resource at expected scope is not a Key Vault: $expectedVaultId"
            }

            $enableRbac = ConvertTo-Boolean $vault.Properties.enableRbacAuthorization
            $permissionModel = if ($enableRbac) { 'AzureRbac' } else { 'LegacyAccessPolicy' }
            if ($enableRbac -and -not $AllowRbacPermissionModel) {
                $status = 'SkippedAlreadyRbacModel'
                $message = 'Vault already uses the Azure RBAC data-plane permission model.'
            }
            else {
                $roleGuid = Get-RoleGuid -RoleDefinitionId $roleDefinitionId
                $existing = @(
                    Get-AzRoleAssignment -Scope $expectedVaultId -ObjectId $targetPrincipalId -ErrorAction Stop |
                        Where-Object {
                            ([string]$_.Scope -ieq $expectedVaultId) -and
                            ((Get-RoleGuid -RoleDefinitionId ([string]$_.RoleDefinitionId)) -eq $roleGuid)
                        }
                )

                if ($existing.Count -gt 0) {
                    $status = 'AlreadyAssigned'
                    $assignmentId = [string]$existing[0].RoleAssignmentId
                    $message = 'Matching vault-scoped role assignment already exists.'
                }
                elseif ($PSCmdlet.ShouldProcess(
                    "$vaultName ($expectedVaultId)",
                    "Assign $roleDefinitionName [$roleGuid] to principal $targetPrincipalId"
                )) {
                    $created = New-AzRoleAssignment `
                        -ObjectId $targetPrincipalId `
                        -RoleDefinitionId $roleGuid `
                        -Scope $expectedVaultId `
                        -ErrorAction Stop

                    $status = 'Created'
                    $assignmentId = [string]$created.RoleAssignmentId
                    $message = 'Role assignment created. The vault permission model was not changed.'
                }
                else {
                    $status = if ($WhatIfPreference) { 'WhatIf' } else { 'Declined' }
                    $message = 'Role assignment was not created.'
                }
            }
        }
    }
    catch {
        $status = 'Failed'
        $message = $_.Exception.Message
        $failureCount++
    }

    $resultRows.Add([pscustomobject]@{
        TimestampUtc         = [DateTime]::UtcNow.ToString('o')
        TargetTenantId       = $targetTenantId
        TargetSubscriptionId = $targetSubscriptionId
        TargetResourceGroup  = $targetResourceGroup
        VaultName            = $vaultName
        VaultId              = $expectedVaultId
        PermissionModel      = $permissionModel
        PrincipalId          = $targetPrincipalId
        RoleDefinitionName   = $roleDefinitionName
        RoleDefinitionId     = $roleDefinitionId
        ApprovedBy           = $approvedBy
        Result               = $status
        RoleAssignmentId     = $assignmentId
        Message              = $message
    })
}

try {
    Set-AzContext -Context $currentContext -WhatIf:$false -Confirm:$false -ErrorAction Stop | Out-Null
}
catch {
    Write-Warning "Unable to restore the original Azure context: $($_.Exception.Message)"
}

Export-Results -Rows $resultRows.ToArray() -Path $ResultPath
Write-Host "RBAC staging complete. Failures: $failureCount; Results: $ResultPath"
Write-Host 'No vault permission model was changed.'

if ($failureCount -gt 0) {
    throw "$failureCount RBAC staging operation(s) failed. Review $ResultPath."
}
