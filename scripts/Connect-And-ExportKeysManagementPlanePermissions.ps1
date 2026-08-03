<#
.SYNOPSIS
Connects to one Azure tenant, selects one subscription, and exports management-plane access.

.DESCRIPTION
Provides the interactive entrypoint for the management-plane inventory. The
script authenticates against only the requested tenant, obtains subscriptions
only from that tenant, resolves exactly one subscription, and passes its scalar
ID to Export-KeysManagementPlanePermissions.ps1.

It is read-only apart from writing the requested CSV and changing the current
process's Azure context. It does not change Key Vault authorization settings,
legacy access policies, or role assignments.
#>
[CmdletBinding()]
param(
    [string[]] $TenantId,

    [string[]] $Subscription,

    [ValidateNotNullOrEmpty()]
    [string] $OutputPath = (Join-Path (Get-Location) 'keys-management-plane-permissions.csv'),

    [switch] $UseDeviceAuthentication,

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

function Select-AzureSubscription {
    param(
        [Parameter(Mandatory)]
        [object[]] $AvailableSubscription,

        [string[]] $RequestedSubscription
    )

    $orderedSubscriptions = @(
        $AvailableSubscription |
            Sort-Object -Property Name, Id
    )

    if ($RequestedSubscription.Count -gt 0) {
        $selector = ConvertTo-SingleRequiredString `
            -Value $RequestedSubscription `
            -Name 'Subscription'
        $matches = @(
            $orderedSubscriptions |
                Where-Object {
                    [string]$_.Id -ieq $selector -or
                    [string]$_.Name -ieq $selector
                }
        )

        if ($matches.Count -eq 0) {
            throw "Subscription '$selector' was not found in the connected tenant."
        }
        if ($matches.Count -gt 1) {
            $details = $matches |
                ForEach-Object { "$($_.Name) [$($_.Id)]" }
            throw "Subscription '$selector' is ambiguous: $($details -join '; '). Pass its subscription ID instead."
        }

        return $matches[0]
    }

    if ($orderedSubscriptions.Count -eq 1) {
        return $orderedSubscriptions[0]
    }

    Write-Host 'Available subscriptions:'
    for ($index = 0; $index -lt $orderedSubscriptions.Count; $index++) {
        $candidate = $orderedSubscriptions[$index]
        Write-Host ("  [{0}] {1} [{2}]" -f ($index + 1), $candidate.Name, $candidate.Id)
    }

    while ($true) {
        $answer = Read-Host 'Enter the subscription number to export'
        $selection = 0
        if (
            [int]::TryParse($answer, [ref]$selection) -and
            $selection -ge 1 -and
            $selection -le $orderedSubscriptions.Count
        ) {
            return $orderedSubscriptions[$selection - 1]
        }

        Write-Warning "Enter a number from 1 to $($orderedSubscriptions.Count)."
    }
}

Assert-CommandAvailable -Name 'Connect-AzAccount'
Assert-CommandAvailable -Name 'Get-AzSubscription'

$resolvedTenantId = if (@($TenantId).Count -gt 0) {
    ConvertTo-SingleRequiredString -Value $TenantId -Name 'TenantId'
}
else {
    $enteredTenantId = Read-Host 'Enter the Azure tenant ID'
    ConvertTo-SingleRequiredString -Value $enteredTenantId -Name 'TenantId'
}
$parsedTenantId = [guid]::Empty
if (-not [guid]::TryParse($resolvedTenantId, [ref]$parsedTenantId)) {
    throw "TenantId must be one tenant GUID; received '$resolvedTenantId'."
}
$resolvedTenantId = $parsedTenantId.Guid

$connectParameters = @{
    Tenant      = $resolvedTenantId
    Scope       = 'Process'
    ErrorAction = 'Stop'
}
if ($UseDeviceAuthentication) {
    $connectParameters.UseDeviceAuthentication = $true
}

try {
    Connect-AzAccount @connectParameters | Out-Null
}
catch {
    throw "Connect-AzAccount failed for tenant '$resolvedTenantId': $($_.Exception.Message)"
}

try {
    $availableSubscriptions = @(
        Get-AzSubscription -TenantId $resolvedTenantId -ErrorAction Stop
    )
}
catch {
    throw "Unable to list subscriptions in tenant '$resolvedTenantId': $($_.Exception.Message)"
}

if ($availableSubscriptions.Count -eq 0) {
    throw "No subscriptions are available to the signed-in account in tenant '$resolvedTenantId'."
}

$selectedSubscription = Select-AzureSubscription `
    -AvailableSubscription $availableSubscriptions `
    -RequestedSubscription $Subscription
$selectedSubscriptionId = ConvertTo-SingleRequiredString `
    -Value $selectedSubscription.Id `
    -Name 'Selected subscription ID'
$selectedSubscriptionName = ConvertTo-SingleRequiredString `
    -Value $selectedSubscription.Name `
    -Name 'Selected subscription name'
$selectedTenantId = ConvertTo-SingleRequiredString `
    -Value $selectedSubscription.TenantId `
    -Name 'Selected subscription tenant ID'

if ($selectedTenantId -ine $resolvedTenantId) {
    throw "Selected subscription '$selectedSubscriptionName' belongs to tenant '$selectedTenantId', not '$resolvedTenantId'."
}

$exporterPath = Join-Path $PSScriptRoot 'Export-KeysManagementPlanePermissions.ps1'
if (-not (Test-Path -LiteralPath $exporterPath -PathType Leaf)) {
    throw "Management-plane exporter was not found at '$exporterPath'."
}

$exportParameters = @{
    TenantId     = $selectedTenantId
    Subscription = $selectedSubscriptionId
    OutputPath   = $OutputPath
}
if ($SkipPim) {
    $exportParameters.SkipPim = $true
}
if ($SkipDenyAssignments) {
    $exportParameters.SkipDenyAssignments = $true
}

Write-Host "Connected to tenant '$selectedTenantId'. Exporting subscription '$selectedSubscriptionName' [$selectedSubscriptionId]."
& $exporterPath @exportParameters
