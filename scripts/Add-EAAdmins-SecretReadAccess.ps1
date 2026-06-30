#requires -Modules Az.Accounts
#requires -Modules Az.KeyVault

<#
.SYNOPSIS
Adds or updates a legacy Azure Key Vault access policy for ea-admins to read/list secrets.

.DESCRIPTION
- Legacy Key Vault access-policy model only.
- Secrets only by default: Get,List.
- Dry-run by default; use -Apply to make changes.
- Scans only the configured subscriptions.
- Discovers vault resource groups automatically.
- Preserves existing broader permissions for the same principal.
- Writes a CSV audit report.

.REUSE
Change future runs by passing parameters rather than editing the script:

  .\Add-EAAdmins-SecretReadAccess.ps1 `
    -SubscriptionIds "sub-guid-1","sub-guid-2" `
    -VaultNames "kv1","kv2" `
    -SecretPermissions Get,List,Set `
    -Apply

Or place vault names / subscription IDs in files, one per line. Blank lines and # comments are ignored:

  .\Add-EAAdmins-SecretReadAccess.ps1 -VaultNameFile .\vaults.txt -SubscriptionIdFile .\subs.txt

.NOTES
The caller must have rights to update Key Vault access policies, such as permissions including:
Microsoft.KeyVault/vaults/write
#>

[CmdletBinding()]
param(
    [Parameter()]
    [string]$GroupObjectId = "a729596d-0067-4b98-a9dc-40c6f0ebf0b3",

    [Parameter()]
    [string]$GroupDisplayName = "ea-admins",

    # Defaults supplied by request:
    # dev  = 3df3368e-87ec-47e7-b8e0-9b167359367b
    # keys = 411471df-72d5-414b-b227-60d5bd0ddb78
    [Parameter()]
    [string[]]$SubscriptionIds,

    [Parameter()]
    [string]$SubscriptionIdFile,

    [Parameter()]
    [string[]]$VaultNames,

    [Parameter()]
    [string]$VaultNameFile,

    [Parameter()]
    [ValidateSet("Get", "List", "Set", "Delete", "Backup", "Restore", "Recover", "Purge")]
    [string[]]$SecretPermissions = @("Get", "List"),

    # Dry-run by default. Add -Apply to make changes.
    [Parameter()]
    [switch]$Apply,

    [Parameter()]
    [string]$OutputCsv = (Join-Path -Path (Get-Location) -ChildPath ("kv-secret-access-policy-results-{0}.csv" -f (Get-Date -Format "yyyyMMdd-HHmmss")) )
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version 2.0

$DefaultSubscriptionIds = @(
    "3df3368e-87ec-47e7-b8e0-9b167359367b", # dev
    "411471df-72d5-414b-b227-60d5bd0ddb78"  # keys
)

$DefaultVaultNamesText = @'
kv-d-sc-access-mgmt-01
kv-d-sc-bintang
kv-d-sc-calypso-01
kv-d-sc-capital-stock-01
kv-d-sc-ce01
kv-d-sc-cicd-code
kv-d-sc-cms-01
kv-d-sc-cop-01
kv-d-sc-creditrisk-ssis
kv-d-sc-ffc-01
kv-d-sc-github-sp
kv-d-sc-iis-webservice
kv-d-sc-letter-of-credit
kv-d-sc-memberprofile-01
kv-d-sc-money-transfer
kv-d-sc-openaitest01
kv-d-sc-pdp-01
kv-d-sc-rates-01
kv-d-sc-recaptcha
kv-d-sc-swaps-01
kv-d-sc-testdevops09
kv-d-sc-unsecuredcred-02
kv-d-sc-unsecuredcred-1
kv-d-sc-wire01
kvscdact01
kvscdado01
kvscdadv01
kvscdahp01
kvscdahpautomate
kvscdaim01
kvscdapp01
kvscdase01
kvscdavr01
kvscdbi01
kvscdcaf01
kvscdcap01
kvscdce01
kvscdch01
kvscdci01
kvscdcib01
kvscdcol01
kvscddda02
kvscdffc01
kvscdgcp01
kvscdgrt01
kvscdgs01
kvscdjob01
kvscdjobv01
kvscdjos01
kvscdloc01
kvscdma01
kvscdmds01
kvscdmed01
kvscdmi01
kvscdmy01
kvscdrat01
kvscdsas01
kvscdsch01
kvscdscp02
kvscdsel02
kvscdsso02
kvscduca01
kvscdumi01
kvsckdact01
kvsckdado01
kvsckdahp01
kvsckdcaf01
kvsckdcap01
kvsckdci01
kvsckdcib01
kvsckdcol01
kvsckdfc01
kvsckdgrt01
kvsckdgrt02
kvsckdgs01
kvsckdlab01
kvsckdloc01
kvsckdmed01
kvsckdmi01
kvsckdmy01
kvsckdrat01
kvsckdsas01
kvsckdsch01
kvsckdsk01
kvsckduca01
kvsckeag01
kvsckeag02
kvscsops01
kvscstest01
'@

function Normalize-StringList {
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [string[]]$Items
    )

    $seen = @{}
    $clean = New-Object System.Collections.Generic.List[string]

    foreach ($item in $Items) {
        if ($null -eq $item) {
            continue
        }

        # Allow inline comments in text files: value # comment
        $value = (($item -replace '\s+#.*$', '').Trim())

        if ([string]::IsNullOrWhiteSpace($value)) {
            continue
        }

        $key = $value.ToLowerInvariant()
        if (-not $seen.ContainsKey($key)) {
            $seen[$key] = $true
            $clean.Add($value)
        }
    }

    return $clean.ToArray()
}

function Get-ListFromFile {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    if (-not (Test-Path -Path $Path -PathType Leaf)) {
        throw "File not found: $Path"
    }

    return Normalize-StringList -Items (Get-Content -Path $Path -ErrorAction Stop)
}

function Get-PolicyPermissions {
    param(
        [Parameter()]
        [object]$Policy,

        [Parameter(Mandatory = $true)]
        [string[]]$PropertyNames
    )

    if ($null -eq $Policy) {
        return @()
    }

    foreach ($propertyName in $PropertyNames) {
        $property = $Policy.PSObject.Properties |
            Where-Object { $_.Name -ieq $propertyName } |
            Select-Object -First 1

        if ($null -ne $property -and $null -ne $property.Value) {
            return @($property.Value | ForEach-Object { ([string]$_).Trim() } | Where-Object { $_ })
        }
    }

    return @()
}

function Merge-Permissions {
    param(
        [Parameter()]
        [object[]]$Existing,

        [Parameter(Mandatory = $true)]
        [string[]]$Desired
    )

    $map = @{}

    foreach ($permission in @($Existing) + @($Desired)) {
        if ($null -eq $permission) {
            continue
        }

        $value = ([string]$permission).Trim()
        if ([string]::IsNullOrWhiteSpace($value)) {
            continue
        }

        $map[$value.ToLowerInvariant()] = $value
    }

    return @($map.Values | Sort-Object)
}

function Get-MissingPermissions {
    param(
        [Parameter()]
        [object[]]$Existing,

        [Parameter(Mandatory = $true)]
        [string[]]$Desired
    )

    $existingMap = @{}
    foreach ($permission in @($Existing)) {
        if ($null -eq $permission) {
            continue
        }

        $value = ([string]$permission).Trim()
        if (-not [string]::IsNullOrWhiteSpace($value)) {
            $existingMap[$value.ToLowerInvariant()] = $true
        }
    }

    # If someone already has All, do not report granular permissions as missing.
    if ($existingMap.ContainsKey("all")) {
        return @()
    }

    $missing = New-Object System.Collections.Generic.List[string]
    foreach ($permission in $Desired) {
        if (-not $existingMap.ContainsKey($permission.ToLowerInvariant())) {
            $missing.Add($permission)
        }
    }

    return $missing.ToArray()
}

$Results = New-Object System.Collections.Generic.List[object]
$FoundVaults = @{}
$HadSubscriptionScanFailure = $false

function Add-Result {
    param(
        [string]$VaultName,
        [string]$SubscriptionName,
        [string]$SubscriptionId,
        [string]$TenantId,
        [string]$ResourceGroupName,
        [string]$VaultTenantId,
        [string]$GroupDisplayName,
        [string]$GroupObjectId,
        [string]$DesiredSecretPermissions,
        [string]$ExistingSecretPermissions,
        [string]$FinalSecretPermissions,
        [string]$Action,
        [string]$Status,
        [string]$Detail
    )

    $script:Results.Add([pscustomobject]@{
        VaultName                = $VaultName
        SubscriptionName         = $SubscriptionName
        SubscriptionId           = $SubscriptionId
        SubscriptionTenantId     = $TenantId
        ResourceGroupName        = $ResourceGroupName
        VaultTenantId            = $VaultTenantId
        GroupDisplayName         = $GroupDisplayName
        GroupObjectId            = $GroupObjectId
        DesiredSecretPermissions = $DesiredSecretPermissions
        ExistingSecretPermissions = $ExistingSecretPermissions
        FinalSecretPermissions   = $FinalSecretPermissions
        Action                   = $Action
        Status                   = $Status
        Detail                   = $Detail
    })
}

if ($SubscriptionIdFile) {
    $SubscriptionIds = Get-ListFromFile -Path $SubscriptionIdFile
}
elseif (-not $PSBoundParameters.ContainsKey("SubscriptionIds") -or $null -eq $SubscriptionIds -or @($SubscriptionIds).Count -eq 0) {
    $SubscriptionIds = $DefaultSubscriptionIds
}
else {
    $SubscriptionIds = Normalize-StringList -Items $SubscriptionIds
}

if ($VaultNameFile) {
    $VaultNames = Get-ListFromFile -Path $VaultNameFile
}
elif (-not $PSBoundParameters.ContainsKey("VaultNames") -or $null -eq $VaultNames -or @($VaultNames).Count -eq 0) {
    $VaultNames = Normalize-StringList -Items ($DefaultVaultNamesText -split '\r?\n')
}
else {
    $VaultNames = Normalize-StringList -Items $VaultNames
}

$SecretPermissions = Normalize-StringList -Items $SecretPermissions

if (@($SubscriptionIds).Count -eq 0) {
    throw "No subscription IDs were supplied."
}

if (@($VaultNames).Count -eq 0) {
    throw "No Key Vault names were supplied."
}

if (@($SecretPermissions).Count -eq 0) {
    throw "No secret permissions were supplied."
}

$TargetVaultLookup = @{}
foreach ($vaultName in $VaultNames) {
    $TargetVaultLookup[$vaultName.ToLowerInvariant()] = $vaultName
}

if (-not (Get-AzContext -ErrorAction SilentlyContinue)) {
    Connect-AzAccount -ErrorAction Stop | Out-Null
}

Write-Host "Mode: $(if ($Apply) { 'APPLY' } else { 'DRY-RUN' })"
Write-Host "Group: $GroupDisplayName [$GroupObjectId]"
Write-Host "Subscriptions: $($SubscriptionIds -join ', ')"
Write-Host "Target vault count: $($VaultNames.Count)"
Write-Host "Desired secret permissions: $($SecretPermissions -join ',')"
Write-Host "Output CSV: $OutputCsv"
Write-Host ""

foreach ($subscriptionId in $SubscriptionIds) {
    $subscription = $null
    $subscriptionName = ""
    $tenantId = ""

    try {
        $subscription = Get-AzSubscription -SubscriptionId $subscriptionId -ErrorAction Stop
        $subscriptionName = $subscription.Name
        $tenantId = $subscription.TenantId

        Set-AzContext -Subscription $subscriptionId -Tenant $tenantId -ErrorAction Stop | Out-Null
    }
    catch {
        $HadSubscriptionScanFailure = $true

        Add-Result `
            -VaultName "" `
            -SubscriptionName $subscriptionName `
            -SubscriptionId $subscriptionId `
            -TenantId $tenantId `
            -ResourceGroupName "" `
            -VaultTenantId "" `
            -GroupDisplayName $GroupDisplayName `
            -GroupObjectId $GroupObjectId `
            -DesiredSecretPermissions ($SecretPermissions -join ',') `
            -ExistingSecretPermissions "" `
            -FinalSecretPermissions "" `
            -Action "SetSubscriptionContext" `
            -Status "Failed" `
            -Detail $_.Exception.Message

        continue
    }

    Write-Host "Scanning subscription: $subscriptionName [$subscriptionId]"

    try {
        $subscriptionVaults = @(Get-AzKeyVault -ErrorAction Stop)
    }
    catch {
        $HadSubscriptionScanFailure = $true

        Add-Result `
            -VaultName "" `
            -SubscriptionName $subscriptionName `
            -SubscriptionId $subscriptionId `
            -TenantId $tenantId `
            -ResourceGroupName "" `
            -VaultTenantId "" `
            -GroupDisplayName $GroupDisplayName `
            -GroupObjectId $GroupObjectId `
            -DesiredSecretPermissions ($SecretPermissions -join ',') `
            -ExistingSecretPermissions "" `
            -FinalSecretPermissions "" `
            -Action "ListKeyVaults" `
            -Status "Failed" `
            -Detail $_.Exception.Message

        continue
    }

    $matchedVaults = @(
        $subscriptionVaults | Where-Object {
            $_.VaultName -and $TargetVaultLookup.ContainsKey($_.VaultName.ToLowerInvariant())
        }
    )

    foreach ($vaultSummary in $matchedVaults) {
        $vaultName = $vaultSummary.VaultName
        $resourceGroupName = $vaultSummary.ResourceGroupName
        $FoundVaults[$vaultName.ToLowerInvariant()] = $true

        try {
            # Re-read the full vault object by name/RG for current access policy details.
            $vault = Get-AzKeyVault -VaultName $vaultName -ResourceGroupName $resourceGroupName -ErrorAction Stop
            $vaultTenantId = [string]$vault.TenantId

            if ($vault.EnableRbacAuthorization -eq $true) {
                Add-Result `
                    -VaultName $vaultName `
                    -SubscriptionName $subscriptionName `
                    -SubscriptionId $subscriptionId `
                    -TenantId $tenantId `
                    -ResourceGroupName $resourceGroupName `
                    -VaultTenantId $vaultTenantId `
                    -GroupDisplayName $GroupDisplayName `
                    -GroupObjectId $GroupObjectId `
                    -DesiredSecretPermissions ($SecretPermissions -join ',') `
                    -ExistingSecretPermissions "" `
                    -FinalSecretPermissions "" `
                    -Action "Skipped" `
                    -Status "Warning" `
                    -Detail "Vault has EnableRbacAuthorization=true. Script only handles legacy access policies."

                continue
            }

            $existingPolicy = @(
                $vault.AccessPolicies | Where-Object {
                    ([string]$_.ObjectId) -eq ([string]$GroupObjectId)
                }
            ) | Select-Object -First 1

            $existingSecretPermissions = Get-PolicyPermissions `
                -Policy $existingPolicy `
                -PropertyNames @("PermissionsToSecrets", "SecretPermissions", "Secrets")

            $missingSecretPermissions = Get-MissingPermissions `
                -Existing $existingSecretPermissions `
                -Desired $SecretPermissions

            $finalSecretPermissions = Merge-Permissions `
                -Existing $existingSecretPermissions `
                -Desired $SecretPermissions

            if (@($missingSecretPermissions).Count -eq 0) {
                Add-Result `
                    -VaultName $vaultName `
                    -SubscriptionName $subscriptionName `
                    -SubscriptionId $subscriptionId `
                    -TenantId $tenantId `
                    -ResourceGroupName $resourceGroupName `
                    -VaultTenantId $vaultTenantId `
                    -GroupDisplayName $GroupDisplayName `
                    -GroupObjectId $GroupObjectId `
                    -DesiredSecretPermissions ($SecretPermissions -join ',') `
                    -ExistingSecretPermissions ($existingSecretPermissions -join ',') `
                    -FinalSecretPermissions ($finalSecretPermissions -join ',') `
                    -Action "AlreadyCompliant" `
                    -Status "Success" `
                    -Detail "Existing access policy already includes desired secret permissions. No change needed."

                continue
            }

            # Optional pre-check for the Key Vault access policy limit when adding a brand-new policy.
            $policyCount = @($vault.AccessPolicies).Count
            if ($null -eq $existingPolicy -and $policyCount -ge 1024) {
                Add-Result `
                    -VaultName $vaultName `
                    -SubscriptionName $subscriptionName `
                    -SubscriptionId $subscriptionId `
                    -TenantId $tenantId `
                    -ResourceGroupName $resourceGroupName `
                    -VaultTenantId $vaultTenantId `
                    -GroupDisplayName $GroupDisplayName `
                    -GroupObjectId $GroupObjectId `
                    -DesiredSecretPermissions ($SecretPermissions -join ',') `
                    -ExistingSecretPermissions "" `
                    -FinalSecretPermissions ($finalSecretPermissions -join ',') `
                    -Action "PolicyLimitReached" `
                    -Status "Failed" `
                    -Detail "Vault already has 1024 access policies. Remove or consolidate an existing policy before adding this group."

                continue
            }

            $detail = "Missing secret permissions: $($missingSecretPermissions -join ','). Final secret permissions for this group would be: $($finalSecretPermissions -join ',')."

            if ($Apply) {
                Set-AzKeyVaultAccessPolicy `
                    -VaultName $vaultName `
                    -ResourceGroupName $resourceGroupName `
                    -ObjectId $GroupObjectId `
                    -PermissionsToSecrets $finalSecretPermissions `
                    -ErrorAction Stop | Out-Null

                Add-Result `
                    -VaultName $vaultName `
                    -SubscriptionName $subscriptionName `
                    -SubscriptionId $subscriptionId `
                    -TenantId $tenantId `
                    -ResourceGroupName $resourceGroupName `
                    -VaultTenantId $vaultTenantId `
                    -GroupDisplayName $GroupDisplayName `
                    -GroupObjectId $GroupObjectId `
                    -DesiredSecretPermissions ($SecretPermissions -join ',') `
                    -ExistingSecretPermissions ($existingSecretPermissions -join ',') `
                    -FinalSecretPermissions ($finalSecretPermissions -join ',') `
                    -Action "AccessPolicySet" `
                    -Status "Success" `
                    -Detail $detail
            }
            else {
                Add-Result `
                    -VaultName $vaultName `
                    -SubscriptionName $subscriptionName `
                    -SubscriptionId $subscriptionId `
                    -TenantId $tenantId `
                    -ResourceGroupName $resourceGroupName `
                    -VaultTenantId $vaultTenantId `
                    -GroupDisplayName $GroupDisplayName `
                    -GroupObjectId $GroupObjectId `
                    -DesiredSecretPermissions ($SecretPermissions -join ',') `
                    -ExistingSecretPermissions ($existingSecretPermissions -join ',') `
                    -FinalSecretPermissions ($finalSecretPermissions -join ',') `
                    -Action "WouldSetAccessPolicy" `
                    -Status "DryRun" `
                    -Detail $detail
            }
        }
        catch {
            Add-Result `
                -VaultName $vaultName `
                -SubscriptionName $subscriptionName `
                -SubscriptionId $subscriptionId `
                -TenantId $tenantId `
                -ResourceGroupName $resourceGroupName `
                -VaultTenantId "" `
                -GroupDisplayName $GroupDisplayName `
                -GroupObjectId $GroupObjectId `
                -DesiredSecretPermissions ($SecretPermissions -join ',') `
                -ExistingSecretPermissions "" `
                -FinalSecretPermissions "" `
                -Action "ProcessVault" `
                -Status "Failed" `
                -Detail $_.Exception.Message
        }
    }
}

foreach ($targetVaultName in $VaultNames) {
    if (-not $FoundVaults.ContainsKey($targetVaultName.ToLowerInvariant())) {
        $detail = if ($HadSubscriptionScanFailure) {
            "Vault was not found in successfully scanned subscriptions. At least one subscription scan failed, so verify manually."
        }
        else {
            "Vault was not found in the configured subscriptions."
        }

        Add-Result `
            -VaultName $targetVaultName `
            -SubscriptionName "" `
            -SubscriptionId "" `
            -TenantId "" `
            -ResourceGroupName "" `
            -VaultTenantId "" `
            -GroupDisplayName $GroupDisplayName `
            -GroupObjectId $GroupObjectId `
            -DesiredSecretPermissions ($SecretPermissions -join ',') `
            -ExistingSecretPermissions "" `
            -FinalSecretPermissions "" `
            -Action "NotFound" `
            -Status "Warning" `
            -Detail $detail
    }
}

$sortedResults = $Results | Sort-Object Status, Action, VaultName, SubscriptionName
$sortedResults | Format-Table -AutoSize
$sortedResults | Export-Csv -Path $OutputCsv -NoTypeInformation

Write-Host ""
Write-Host "Results written to: $OutputCsv"

if (-not $Apply) {
    Write-Host "Dry-run only. Re-run with -Apply to make changes."
}
