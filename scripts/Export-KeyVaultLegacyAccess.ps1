[CmdletBinding()]
param(
    [string] $OutputPath = (Join-Path (Get-Location) 'out'),
    [string[]] $SubscriptionId,
    [switch] $ResolvePrincipals,
    [switch] $IncludeRbac,
    [string[]] $ManagementGroupScope,
    [ValidateRange(1, 2147483647)]
    [int] $First = 1000,
    [switch] $SkipAzContextCheck
)

$ErrorActionPreference = 'Stop'

function Assert-CommandAvailable {
    param([string] $Name)

    if (-not (Get-Command -Name $Name -ErrorAction SilentlyContinue)) {
        throw "Required command '$Name' was not found. Install the relevant Az module and retry."
    }
}

function Search-AzGraphPaged {
    param(
        [Parameter(Mandatory)]
        [string] $Query,

        [string[]] $Subscription,

        [Parameter(Mandatory)]
        [int] $MaximumResults
    )

    $results = New-Object System.Collections.Generic.List[object]
    $skip = 0

    while ($results.Count -lt $MaximumResults) {
        $pageSize = [Math]::Min(1000, $MaximumResults - $results.Count)
        $parameters = @{
            Query = $Query
            First = $pageSize
            Skip  = $skip
        }

        if ($Subscription -and $Subscription.Count -gt 0) {
            $parameters.Subscription = $Subscription
        }

        $page = @(Search-AzGraph @parameters)
        foreach ($item in $page) {
            $results.Add($item)
        }

        if ($page.Count -lt $pageSize) {
            break
        }

        $skip += $page.Count
    }

    return $results.ToArray()
}

function ConvertTo-CompactJson {
    param([object] $Value)

    if ($null -eq $Value) {
        return ''
    }

    return ($Value | ConvertTo-Json -Depth 30 -Compress)
}

function ConvertTo-Array {
    param([object] $Value)

    if ($null -eq $Value) {
        return @()
    }

    if ($Value -is [array]) {
        return @($Value)
    }

    return @($Value)
}

function Join-Permission {
    param([object] $Value)

    return ((ConvertTo-Array $Value | Where-Object { $_ } | ForEach-Object { [string]$_ }) -join ';')
}

function Get-PolicyValue {
    param(
        [object] $Policy,
        [string] $Name
    )

    if ($null -eq $Policy) {
        return $null
    }

    $property = $Policy.PSObject.Properties[$Name]
    if ($property) {
        return $property.Value
    }

    return $null
}

function Get-PermissionValue {
    param(
        [object] $Policy,
        [string] $Name
    )

    $permissions = Get-PolicyValue -Policy $Policy -Name 'permissions'
    if ($null -eq $permissions) {
        return @()
    }

    $property = $permissions.PSObject.Properties[$Name]
    if ($property) {
        return ConvertTo-Array $property.Value
    }

    return @()
}

function New-PermissionSignature {
    param(
        [string[]] $Keys,
        [string[]] $Secrets,
        [string[]] $Certificates,
        [string[]] $Storage
    )

    $keyText = if ($Keys.Count) { (($Keys | Sort-Object) -join ',') } else { 'none' }
    $secretText = if ($Secrets.Count) { (($Secrets | Sort-Object) -join ',') } else { 'none' }
    $certText = if ($Certificates.Count) { (($Certificates | Sort-Object) -join ',') } else { 'none' }
    $storageText = if ($Storage.Count) { (($Storage | Sort-Object) -join ',') } else { 'none' }

    return "keys=$keyText|secrets=$secretText|certificates=$certText|storage=$storageText"
}

function Resolve-Principal {
    param([string] $ObjectId)

    if ([string]::IsNullOrWhiteSpace($ObjectId)) {
        return $null
    }

    if ($script:PrincipalCache.ContainsKey($ObjectId)) {
        return $script:PrincipalCache[$ObjectId]
    }

    $resolved = [pscustomobject]@{
        PrincipalId          = $ObjectId
        PrincipalType        = 'Unknown'
        PrincipalDisplayName = ''
        PrincipalAppId       = ''
        PrincipalUserType    = ''
        Mail                 = ''
        ResolutionStatus     = 'Unresolved'
        ResolutionError      = ''
    }

    try {
        $user = Get-AzADUser -ObjectId $ObjectId -ErrorAction Stop
        if ($user) {
            $resolved.PrincipalType = 'User'
            $resolved.PrincipalDisplayName = $user.DisplayName
            $resolved.PrincipalUserType = $user.UserType
            $resolved.Mail = $user.Mail
            $resolved.ResolutionStatus = 'Resolved'
            $script:PrincipalCache[$ObjectId] = $resolved
            return $resolved
        }
    }
    catch {
        $resolved.ResolutionError = $_.Exception.Message
    }

    try {
        $sp = Get-AzADServicePrincipal -ObjectId $ObjectId -ErrorAction Stop
        if ($sp) {
            $resolved.PrincipalType = 'ServicePrincipal'
            $resolved.PrincipalDisplayName = $sp.DisplayName
            $resolved.PrincipalAppId = $sp.AppId
            $resolved.ResolutionStatus = 'Resolved'
            $resolved.ResolutionError = ''
            $script:PrincipalCache[$ObjectId] = $resolved
            return $resolved
        }
    }
    catch {
        if (-not $resolved.ResolutionError) {
            $resolved.ResolutionError = $_.Exception.Message
        }
    }

    try {
        $group = Get-AzADGroup -ObjectId $ObjectId -ErrorAction Stop
        if ($group) {
            $resolved.PrincipalType = 'Group'
            $resolved.PrincipalDisplayName = $group.DisplayName
            $resolved.Mail = $group.Mail
            $resolved.ResolutionStatus = 'Resolved'
            $resolved.ResolutionError = ''
            $script:PrincipalCache[$ObjectId] = $resolved
            return $resolved
        }
    }
    catch {
        if (-not $resolved.ResolutionError) {
            $resolved.ResolutionError = $_.Exception.Message
        }
    }

    $script:PrincipalCache[$ObjectId] = $resolved
    return $resolved
}

function Get-ScopeKind {
    param(
        [string] $Scope,
        [string] $VaultId,
        [string] $SubscriptionId,
        [string] $ResourceGroup
    )

    if ($Scope -like '/providers/Microsoft.Management/managementGroups/*') {
        return 'ManagementGroup'
    }

    $subscriptionScope = "/subscriptions/$SubscriptionId"
    $resourceGroupScope = "$subscriptionScope/resourceGroups/$ResourceGroup"

    if ($Scope -ieq $subscriptionScope) {
        return 'Subscription'
    }

    if ($Scope -ieq $resourceGroupScope) {
        return 'ResourceGroup'
    }

    if ($Scope -ieq $VaultId) {
        return 'Vault'
    }

    if ($Scope -like "$VaultId/*") {
        return 'VaultChildObject'
    }

    return 'Other'
}

Assert-CommandAvailable -Name 'Search-AzGraph'
Assert-CommandAvailable -Name 'Get-AzContext'

if ($IncludeRbac) {
    Assert-CommandAvailable -Name 'Get-AzRoleAssignment'
    Assert-CommandAvailable -Name 'Set-AzContext'
}

if ($ResolvePrincipals) {
    Assert-CommandAvailable -Name 'Get-AzADUser'
    Assert-CommandAvailable -Name 'Get-AzADServicePrincipal'
    Assert-CommandAvailable -Name 'Get-AzADGroup'
}

if (-not $SkipAzContextCheck) {
    $context = Get-AzContext
    if (-not $context) {
        throw "No Azure context found. Run Connect-AzAccount first or pass -SkipAzContextCheck."
    }
}

New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null

$vaultQuery = @"
resources
| where type =~ 'microsoft.keyvault/vaults'
| project
    subscriptionId,
    resourceGroup,
    vaultName = name,
    vaultId = id,
    location,
    tenantId = tostring(properties.tenantId),
    enableRbacAuthorization = tostring(properties.enableRbacAuthorization),
    accessPolicies = properties.accessPolicies,
    tags,
    softDeleteEnabled = tostring(properties.enableSoftDelete),
    purgeProtectionEnabled = tostring(properties.enablePurgeProtection),
    networkAcls = properties.networkAcls,
    privateEndpointConnections = properties.privateEndpointConnections
| order by vaultId asc
"@

$vaults = @(
    Search-AzGraphPaged `
        -Query $vaultQuery `
        -Subscription $SubscriptionId `
        -MaximumResults $First
)

$script:PrincipalCache = @{}
$policyRows = New-Object System.Collections.Generic.List[object]
$vaultRows = New-Object System.Collections.Generic.List[object]
$rbacRows = New-Object System.Collections.Generic.List[object]
$principalRows = New-Object System.Collections.Generic.List[object]
$rbacRowKeys = @{}
$subscriptionRoleAssignmentCache = @{}
$activeRbacSubscriptionId = ''
$originalContext = Get-AzContext

foreach ($vault in $vaults) {
    $policies = ConvertTo-Array $vault.accessPolicies

    $vaultRows.Add([pscustomobject]@{
        SubscriptionId             = $vault.subscriptionId
        ResourceGroup              = $vault.resourceGroup
        VaultName                  = $vault.vaultName
        VaultId                    = $vault.vaultId
        Location                   = $vault.location
        TenantId                   = $vault.tenantId
        EnableRbacAuthorization    = $vault.enableRbacAuthorization
        AccessPolicyCount          = $policies.Count
        ExistingRbacAssignmentCount = ''
        TagsJson                   = ConvertTo-CompactJson $vault.tags
        SoftDeleteEnabled          = $vault.softDeleteEnabled
        PurgeProtectionEnabled     = $vault.purgeProtectionEnabled
        NetworkAclsJson            = ConvertTo-CompactJson $vault.networkAcls
        PrivateEndpointStatusJson  = ConvertTo-CompactJson $vault.privateEndpointConnections
        DiagnosticSettingsJson     = ''
    })

    foreach ($policy in $policies) {
        $principalId = [string](Get-PolicyValue -Policy $policy -Name 'objectId')
        $applicationId = [string](Get-PolicyValue -Policy $policy -Name 'applicationId')
        $keys = @(Get-PermissionValue -Policy $policy -Name 'keys')
        $secrets = @(Get-PermissionValue -Policy $policy -Name 'secrets')
        $certificates = @(Get-PermissionValue -Policy $policy -Name 'certificates')
        $storage = @(Get-PermissionValue -Policy $policy -Name 'storage')

        $resolved = $null
        if ($ResolvePrincipals -and $principalId) {
            $resolved = Resolve-Principal -ObjectId $principalId
        }

        $policyRows.Add([pscustomobject]@{
            SubscriptionId          = $vault.subscriptionId
            ResourceGroup           = $vault.resourceGroup
            VaultName               = $vault.vaultName
            VaultId                 = $vault.vaultId
            TenantId                = $vault.tenantId
            EnableRbacAuthorization = $vault.enableRbacAuthorization
            PrincipalObjectId       = $principalId
            ApplicationId           = $applicationId
            PrincipalType           = if ($resolved) { $resolved.PrincipalType } else { '' }
            PrincipalDisplayName    = if ($resolved) { $resolved.PrincipalDisplayName } else { '' }
            PrincipalAppId          = if ($resolved) { $resolved.PrincipalAppId } else { '' }
            KeyPermissions          = Join-Permission $keys
            SecretPermissions       = Join-Permission $secrets
            CertificatePermissions  = Join-Permission $certificates
            StoragePermissions      = Join-Permission $storage
            PermissionSignature     = New-PermissionSignature -Keys $keys -Secrets $secrets -Certificates $certificates -Storage $storage
            LastSeenOperation       = ''
            LastSeenTime            = ''
            AppOwner                = ''
        })
    }

    if ($IncludeRbac) {
        try {
            if ($activeRbacSubscriptionId -ine [string]$vault.subscriptionId) {
                Set-AzContext -SubscriptionId $vault.subscriptionId -ErrorAction Stop | Out-Null
                $activeRbacSubscriptionId = [string]$vault.subscriptionId
            }

            if (-not $subscriptionRoleAssignmentCache.ContainsKey($activeRbacSubscriptionId)) {
                $subscriptionRoleAssignmentCache[$activeRbacSubscriptionId] = @(Get-AzRoleAssignment -ErrorAction Stop)
            }

            $effectiveAssignments = @(Get-AzRoleAssignment -Scope $vault.vaultId -ErrorAction Stop)
            $childAssignments = @(
                $subscriptionRoleAssignmentCache[$activeRbacSubscriptionId] |
                    Where-Object { [string]$_.Scope -like "$($vault.vaultId)/*" }
            )

            foreach ($assignment in @($effectiveAssignments + $childAssignments)) {
                $assignmentScope = [string]$assignment.Scope
                $roleAssignmentId = [string]$assignment.RoleAssignmentId
                $rowKey = if ($roleAssignmentId) {
                    "$($vault.vaultId)|$roleAssignmentId".ToLowerInvariant()
                }
                else {
                    "$($vault.vaultId)|$assignmentScope|$($assignment.ObjectId)|$($assignment.RoleDefinitionId)".ToLowerInvariant()
                }

                if ($rbacRowKeys.ContainsKey($rowKey)) {
                    continue
                }
                $rbacRowKeys[$rowKey] = $true

                $principalId = [string]$assignment.ObjectId
                if ($ResolvePrincipals -and $principalId) {
                    [void](Resolve-Principal -ObjectId $principalId)
                }

                $rbacRows.Add([pscustomobject]@{
                    SubscriptionId       = $vault.subscriptionId
                    ResourceGroup        = $vault.resourceGroup
                    VaultName            = $vault.vaultName
                    VaultId              = $vault.vaultId
                    AssignmentScope      = $assignmentScope
                    ScopeKind            = Get-ScopeKind -Scope $assignmentScope -VaultId $vault.vaultId -SubscriptionId $vault.subscriptionId -ResourceGroup $vault.resourceGroup
                    RoleDefinitionName   = $assignment.RoleDefinitionName
                    RoleDefinitionId     = $assignment.RoleDefinitionId
                    RoleAssignmentId     = $roleAssignmentId
                    PrincipalId          = $principalId
                    PrincipalType        = $assignment.ObjectType
                    PrincipalDisplayName = $assignment.DisplayName
                    CanDelegate          = $assignment.CanDelegate
                    Description          = $assignment.Description
                    ConditionVersion     = $assignment.ConditionVersion
                    Condition            = $assignment.Condition
                    DelegatedManagedIdentityResourceId = $assignment.DelegatedManagedIdentityResourceId
                    Error                = ''
                })
            }
        }
        catch {
            $rbacRows.Add([pscustomobject]@{
                SubscriptionId       = $vault.subscriptionId
                ResourceGroup        = $vault.resourceGroup
                VaultName            = $vault.vaultName
                VaultId              = $vault.vaultId
                AssignmentScope      = $vault.vaultId
                ScopeKind            = 'Vault'
                RoleDefinitionName   = ''
                RoleDefinitionId     = ''
                RoleAssignmentId     = ''
                PrincipalId          = ''
                PrincipalType        = ''
                PrincipalDisplayName = ''
                CanDelegate          = ''
                Description          = ''
                ConditionVersion     = ''
                Condition            = ''
                DelegatedManagedIdentityResourceId = ''
                Error                = $_.Exception.Message
            })
        }
    }
}

if ($IncludeRbac -and $originalContext) {
    try {
        Set-AzContext -Context $originalContext -ErrorAction Stop | Out-Null
    }
    catch {
        Write-Warning "Unable to restore the original Azure context: $($_.Exception.Message)"
    }
}

foreach ($item in $script:PrincipalCache.GetEnumerator()) {
    $principalRows.Add($item.Value)
}

if (-not $ResolvePrincipals) {
    $principalIds = @(
        $policyRows | ForEach-Object { $_.PrincipalObjectId }
        $rbacRows | ForEach-Object { $_.PrincipalId }
    ) | Where-Object { $_ } | Sort-Object -Unique

    foreach ($principalId in $principalIds) {
        $principalRows.Add([pscustomobject]@{
            PrincipalId          = $principalId
            PrincipalType        = ''
            PrincipalDisplayName = ''
            PrincipalAppId       = ''
            PrincipalUserType    = ''
            Mail                 = ''
            ResolutionStatus     = 'NotRequested'
            ResolutionError      = ''
        })
    }
}

$rbacCounts = @{}
$groupedRbacCounts = $rbacRows |
    Where-Object { $_.PrincipalId } |
    Group-Object -Property VaultId -AsHashTable -AsString
if ($groupedRbacCounts) {
    $rbacCounts = $groupedRbacCounts
}

foreach ($row in $vaultRows) {
    $key = [string]$row.VaultId
    if ($rbacCounts.ContainsKey($key)) {
        $row.ExistingRbacAssignmentCount = @($rbacCounts[$key]).Count
    }
    else {
        $row.ExistingRbacAssignmentCount = 0
    }
}

$vaultRows.ToArray() | Export-Csv -LiteralPath (Join-Path $OutputPath '01-vault-inventory.csv') -NoTypeInformation
$policyRows.ToArray() | Export-Csv -LiteralPath (Join-Path $OutputPath '02-access-policy-inventory.csv') -NoTypeInformation
$rbacRows.ToArray() | Export-Csv -LiteralPath (Join-Path $OutputPath '03-existing-rbac-inventory.csv') -NoTypeInformation
$principalRows.ToArray() | Export-Csv -LiteralPath (Join-Path $OutputPath '04-principal-resolution.csv') -NoTypeInformation

Write-Host "Export complete. Output path: $OutputPath"
