# Key Vault Access Policy to RBAC Migration Toolkit

This repository contains a conservative starter toolkit for migrating Azure Key Vaults from legacy access policies to Azure RBAC.

The workflow is intentionally report-first:

```text
Inventory -> Normalize -> Map -> Exception Review -> Pre-stage RBAC -> Pilot Flip -> Validate -> Rollout -> Cleanup
```

The scripts do not enable RBAC on any vault. They inventory current state, classify access-policy permissions, flag over-grants, and generate reviewable role-assignment commands.

## Files

```text
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
docs/SUBSCRIPTION-TENANT-SEQUENCING.md
tests/Invoke-SmokeTests.ps1
tests/fixtures/02-access-policy-inventory.csv
```

## Prerequisites

Install and authenticate with Azure PowerShell:

```powershell
Install-Module Az.Accounts,Az.ResourceGraph,Az.Resources -Scope CurrentUser
Connect-AzAccount
```

Optional identity enrichment uses `Get-AzADUser`, `Get-AzADServicePrincipal`, and `Get-AzADGroup` from `Az.Resources`.
Install `Az.Monitor` if the subscription-move preflight should inventory diagnostic settings.

## 1. Export inventory

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

## 2. Resolve mappings

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

## 3. Build a Move-Aware RBAC Staging Plan

Copy `config/key-vault-subscription-move-plan.example.csv` to an untracked working file and replace the sample values. The move manifest translates source vault locations to their intended destination subscriptions and resource groups.

After setting `ApprovedBy` on approved rows in `06-role-mapping-proposed.csv`:

```powershell
.\scripts\New-KeyVaultRbacStagingPlan.ps1 `
  -MappingPath .\out\06-role-mapping-proposed.csv `
  -MovePlanPath .\config\key-vault-subscription-move-plan.csv `
  -OutputPath .\out\11-rbac-assignment-plan.csv
```

For a later cross-tenant reapplication, also supply a principal map based on `config/principal-map.example.csv`.

## 4. Stage RBAC Without Changing the Vault Permission Model

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

## 5. Preflight a Same-Tenant Subscription Move

The preflight script is read-only. It checks tenant alignment, target resource-group readiness, provider registration, direct and inherited role assignments, diagnostic settings, private endpoint connections, and optional ARM move validation.

```powershell
.\scripts\Test-KeyVaultSubscriptionMove.ps1 `
  -MovePlanPath .\config\key-vault-subscription-move-plan.csv `
  -OutputPath .\out `
  -RunArmValidation
```

It does not call `Move-AzResource`.

See [subscription and tenant sequencing](docs/SUBSCRIPTION-TENANT-SEQUENCING.md) before moving vaults or transferring subscriptions between tenants.

## Review Model

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

Run the local mapper test without Azure:

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
