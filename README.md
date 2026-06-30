# Key Vault Access Policy to RBAC Migration Toolkit

This repository contains a conservative starter toolkit for migrating Azure Key Vaults from legacy access policies to Azure RBAC.

The workflow is intentionally report-first:

```text
Inventory -> Normalize -> Map -> Exception Review -> Pre-stage RBAC -> Pilot Flip -> Validate -> Rollout -> Cleanup
```

The scripts do not enable RBAC on any vault. They inventory current state, classify access-policy permissions, flag over-grants, generate reviewable role-assignment commands, and support targeted legacy access-policy maintenance where needed.

## Files

```text
scripts/Export-KeyVaultLegacyAccess.ps1
scripts/Resolve-KeyVaultRbacMapping.ps1
scripts/Add-EAAdmins-SecretReadAccess.ps1
config/access-policy-permission-map.json
config/built-in-role-map.json
config/custom-role-candidates.json
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

## Targeted legacy access-policy maintenance

Use `scripts/Add-EAAdmins-SecretReadAccess.ps1` to add or update the `ea-admins` group with secret `Get,List` access on the configured dev Key Vaults while the vaults still use legacy access policies.

Dry-run first:

```powershell
.\scripts\Add-EAAdmins-SecretReadAccess.ps1
```

Apply after reviewing the output and generated CSV:

```powershell
.\scripts\Add-EAAdmins-SecretReadAccess.ps1 -Apply
```

The script is reusable. You can override subscriptions, vault names, group object ID, and secret permissions with parameters or input files:

```powershell
.\scripts\Add-EAAdmins-SecretReadAccess.ps1 `
  -SubscriptionIdFile .\subs.txt `
  -VaultNameFile .\vaults.txt `
  -SecretPermissions Get,List
```

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

Only `ExactBuiltIn` and `AcceptableOvergrant` rows are emitted as active `New-AzRoleAssignment` commands by default. Review/custom-role rows are written as comments in `10-role-assignment-commands.ps1`.

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
