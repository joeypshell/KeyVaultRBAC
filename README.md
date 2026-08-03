# Key Vault Subscription Move and Management-Plane RBAC Toolkit

This repository supports splitting Key Vault resources across `dev-keys`,
`qa-keys`, and production subscriptions while keeping Key Vault data-plane
authorization on legacy access policies.

The current workflow is intentionally report-first:

```text
Management IAM inventory -> Scope review -> Create subscriptions -> Assign approved management RBAC -> Move -> Validate
```

The management-plane inventory does not read or change Key Vault access
policies, does not enable the Key Vault RBAC data-plane model, and does not
create assignments. Older access-policy mapping tools remain available for
analysis but are outside the current execution scope.

## Files

```text
scripts/Export-KeysManagementPlanePermissions.ps1
scripts/Export-SubscriptionManagementPlaneAccess.ps1
scripts/Export-KeyVaultLegacyAccess.ps1
scripts/Resolve-KeyVaultRbacMapping.ps1
scripts/New-KeyVaultRbacStagingPlan.ps1
scripts/Set-KeyVaultRbacAssignments.ps1
scripts/Test-KeyVaultSubscriptionMove.ps1
config/access-policy-permission-map.json
config/built-in-role-map.json
config/custom-role-candidates.json
config/key-vault-subscription-move-plan.example.csv
config/principal-map.example.csv
docs/MANAGEMENT-BRIEF.md
docs/SUBSCRIPTION-TENANT-SEQUENCING.md
tests/Invoke-SmokeTests.ps1
tests/Invoke-ManagementPlaneInventoryTests.ps1
tests/fixtures/02-access-policy-inventory.csv
```

## Prerequisites

Install and authenticate with Azure PowerShell:

```powershell
Install-Module Az.Accounts,Az.Resources -Scope CurrentUser
Connect-AzAccount
```

`Az.ResourceGraph` is required only for the separate Key Vault resource and
legacy-policy inventory.
Install `Az.Monitor` if the subscription-move preflight should inventory diagnostic settings.

## 1. Export Management-Plane Access

### Standalone One-CSV Export

Connect to the tenant, then run the standalone exporter with one subscription
name or ID:

```powershell
Connect-AzAccount -Tenant '<tenant-id>'

.\scripts\Export-KeysManagementPlanePermissions.ps1 `
  -TenantId '<tenant-id>' `
  -Subscription '<keys-subscription-id>' `
  -OutputPath .\keys-management-plane-permissions.csv
```

`-Subscription` is a scalar `[string]` parameter. Pass one literal subscription
name or ID, not the array returned by an unfiltered `Get-AzSubscription` call.
The default subscription name is `keys`.

The CSV contains active and inherited RBAC, PIM eligible and active assignments,
management-plane deny assignments, exact role `Actions`, scope classification,
principal details, and blank decision columns. Assignments whose role definition
contains `DataActions` are excluded. The command fails without replacing the CSV
with partial results when a required Azure inventory call fails.

### Extended Review Package

Use the extended export before deciding which resource-group assignments
should become `dev-keys`, `qa-keys`, or production subscription assignments:

```powershell
.\scripts\Export-SubscriptionManagementPlaneAccess.ps1 `
  -SubscriptionId '<keys-subscription-id>' `
  -OutputPath .\out
```

By default, the script inventories:

- Active RBAC assignments below the subscription and assignments
  inherited from parent scopes.
- PIM eligible and active role-assignment schedule instances.
- Azure deny assignments.
- Exact role-definition `Actions` and `NotActions` used for management-plane
  authorization.
- Roles that can perform `Microsoft.KeyVault/vaults/write`, flagged because they
  can modify legacy access policies within their assigned scope.
- Role assignments containing `DataActions`, isolated in a separate exclusions
  report so they are not candidates for subscription-scope promotion.

This inventory does not expand transitive Entra group membership or entitlement
management access-package assignments. Use the exported principal IDs to review
those identity-governance relationships separately.

The spreadsheet-oriented output is:

```text
16-management-plane-access-review.csv
17-role-definition-classification.csv
18-management-principal-summary.csv
19-management-scope-summary.csv
20-management-inventory-coverage.csv
21-management-inventory-errors.csv
22-non-management-rbac-exclusions.csv
```

Open `16-management-plane-access-review.csv` in Excel and filter by `ScopeLevel`,
`ResourceGroup`, `RoleDefinitionName`, and `PrincipalId`. The blank
`Proposed*`, `Decision`, owner, approval, and notes columns are the working
review record. Use `17-role-definition-classification.csv` when a role name alone
is not enough to determine its effective control-plane permissions. Do not copy
rows from `22-non-management-rbac-exclusions.csv` into the new subscriptions
without a separate data-plane security decision.

`ManagementPlaneOnly` means the role has no direct `DataActions`; it does not
guarantee that the role cannot affect data-plane access. Treat
`CanModifyLegacyAccessPolicies=True` as an escalation risk while vaults use the
legacy access-policy model.

Check `20-management-inventory-coverage.csv` and
`21-management-inventory-errors.csv` before trusting the workbook. Investigate
every `Failed` or `ReviewRequired` coverage row. The command fails after writing
its reports if a requested inventory component failed. `-AllowPartial` accepts
those failures only when a deliberately incomplete export is required.
`-SkipPim` and `-SkipDenyAssignments` are explicit scope reductions and are
recorded in the coverage file.

## Optional Data-Plane Analysis

The following access-policy mapping and staging workflow is retained for future
analysis. It is not part of the current management-plane subscription work.

### Export Key Vault Legacy Access

```powershell
.\scripts\Export-KeyVaultLegacyAccess.ps1 `
  -OutputPath .\out `
  -ResolvePrincipals `
  -IncludeRbac
```

The export script writes:

```text
01-vault-inventory.csv
02-access-policy-inventory.csv
03-existing-rbac-inventory.csv
04-principal-resolution.csv
```

### Resolve Legacy-to-RBAC Mappings

```powershell
.\scripts\Resolve-KeyVaultRbacMapping.ps1 `
  -PolicyInventoryPath .\out\02-access-policy-inventory.csv `
  -PrincipalResolutionPath .\out\04-principal-resolution.csv `
  -ExistingRbacPath .\out\03-existing-rbac-inventory.csv `
  -OutputPath .\out
```

The mapping script writes:

```text
05-permission-signature-summary.csv
06-role-mapping-proposed.csv
07-custom-role-candidates.csv
08-likely-unused-access.csv
09-migration-wave-plan.csv
10-role-assignment-commands.ps1
```

`10-role-assignment-commands.ps1` contains static vault resource IDs and must be regenerated after a resource move. For move-aware and idempotent staging, use the assignment-plan workflow below.

### Build a Move-Aware Data-Plane RBAC Staging Plan

Copy `config/key-vault-subscription-move-plan.example.csv` to an untracked working file and replace the sample values. The move manifest translates source vault locations to their intended destination subscriptions and resource groups.

After setting `ApprovedBy` on approved rows in `06-role-mapping-proposed.csv`:

```powershell
.\scripts\New-KeyVaultRbacStagingPlan.ps1 `
  -MappingPath .\out\06-role-mapping-proposed.csv `
  -MovePlanPath .\config\key-vault-subscription-move-plan.csv `
  -OutputPath .\out\11-rbac-assignment-plan.csv
```

For a later cross-tenant reapplication, also supply a principal map based on `config/principal-map.example.csv`.

### Stage Data-Plane RBAC Without Changing the Vault Permission Model

Validate and preview:

```powershell
.\scripts\Set-KeyVaultRbacAssignments.ps1 `
  -PlanPath .\out\11-rbac-assignment-plan.csv `
  -ValidatePlanOnly

.\scripts\Set-KeyVaultRbacAssignments.ps1 `
  -PlanPath .\out\11-rbac-assignment-plan.csv `
  -WhatIf
```

Apply approved role assignments:

```powershell
.\scripts\Set-KeyVaultRbacAssignments.ps1 `
  -PlanPath .\out\11-rbac-assignment-plan.csv `
  -ResultPath .\out\12-rbac-assignment-results.csv
```

The script is idempotent and never changes `enableRbacAuthorization`. By default, it skips vaults that already use the Azure RBAC data-plane model.

## 2. Preflight a Same-Tenant Subscription Move

The preflight script is read-only. It checks tenant alignment, target resource-group readiness, provider registration, direct and inherited role assignments, diagnostic settings, private endpoint connections, and optional ARM move validation.

```powershell
.\scripts\Test-KeyVaultSubscriptionMove.ps1 `
  -MovePlanPath .\config\key-vault-subscription-move-plan.csv `
  -OutputPath .\out `
  -RunArmValidation
```

It does not call `Move-AzResource`.

Use [the management decision brief](docs/MANAGEMENT-BRIEF.md) to prepare the
recommended sequence, decision requests, risk controls, and pilot approval for
stakeholder review.

See [subscription and tenant sequencing](docs/SUBSCRIPTION-TENANT-SEQUENCING.md) before moving vaults or transferring subscriptions between tenants.

## Optional Data-Plane Review Model

Mapping statuses are:

```text
ExactBuiltIn
AcceptableOvergrant
CustomRoleCandidate
LikelyUnused
NeedsOwnerReview
DoNotMigrateYet
```

Static commands in `10-role-assignment-commands.ps1` are commented by default. `-EmitActiveCommands` enables the older static-command flow for `ExactBuiltIn` and `AcceptableOvergrant` rows, but the move-aware staging-plan workflow is preferred.

## Smoke Test

Run the full local suite without Azure:

```powershell
.\tests\Invoke-SmokeTests.ps1
```

## References

The mapping configuration was seeded from current Microsoft Learn guidance:

- [Key Vault RBAC guide](https://learn.microsoft.com/en-us/azure/key-vault/general/rbac-guide)
- [Key Vault RBAC migration](https://learn.microsoft.com/en-us/azure/key-vault/general/rbac-migration)
- [Azure built-in roles](https://learn.microsoft.com/en-us/azure/role-based-access-control/built-in-roles)
- [Azure custom roles](https://learn.microsoft.com/en-us/azure/role-based-access-control/custom-roles)
- [Move Azure resources to another subscription](https://learn.microsoft.com/en-us/azure/azure-resource-manager/management/move-resource-group-and-subscription)
- [Transfer a subscription to another Microsoft Entra directory](https://learn.microsoft.com/en-us/azure/role-based-access-control/transfer-subscription)
