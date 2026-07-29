# Key Vault Subscription and Tenant Sequencing

Reviewed against Microsoft Learn guidance on 2026-07-29.

## Decision

Build and approve the RBAC intent now, but create vault-scoped role assignments only after each planned same-tenant vault move.

For the dev and QA vaults:

```text
Inventory
  -> approve logical RBAC mappings
  -> validate the same-tenant resource move
  -> move vaults to dev-keys / qa-keys
  -> re-export the destination state
  -> stage vault-scoped RBAC
  -> verify assignments
  -> leave legacy access policies enabled
```

For vaults remaining in `keys`, RBAC can be staged now. However, if no vault will be switched to the RBAC permission model before the later tenant transfer, creating the assignments now is mainly a configuration rehearsal. Those assignments do not authorize Key Vault data-plane operations while legacy access policies are active, and the later tenant transfer deletes them.

The vault resource moves do have a hard deadline: complete them while `keys`, `dev-keys`, and `qa-keys` are still associated with the same tenant. Azure Resource Manager does not support moving a resource between subscriptions in different Microsoft Entra tenants.

## Two Different Moves

| Operation | What changes | Authorization impact |
| --- | --- | --- |
| Move a vault to another subscription in the same tenant | Vault resource ID changes because the subscription and usually the resource group change | Direct vault and child-object role assignments do not move. Source parent-scope RBAC stops applying; destination parent-scope RBAC begins applying. Existing principal object IDs and the vault tenant ID remain in the same tenant. |
| Transfer a subscription to a different tenant | The subscription remains the container, but its trusted Microsoft Entra directory changes | Azure deletes all role assignments and custom roles from the source directory. Managed identities must be re-enabled or recreated. Key Vault tenant IDs and legacy policies must be updated for target-tenant identities. |

For the first operation, use Azure Resource Manager resource-move tooling such as `Move-AzResource`. Treat the later tenant association or ownership transfer as a separate authorization cutover, regardless of the wrapper or internal command used to initiate it.

Moving the vaults now also establishes their final subscription-based resource IDs. Those IDs remain stable when the whole `dev-keys` or `qa-keys` subscription is later associated with another tenant, although the RBAC assignment objects at those scopes are deleted and must be recreated.

## Why Staging Before the Vault Move Is Rework

A vault-scoped role assignment stores the full vault resource ID as its scope:

```text
/subscriptions/<subscription-id>/resourceGroups/<resource-group>/providers/Microsoft.KeyVault/vaults/<vault-name>
```

Moving the vault changes that ID. Azure does not relocate a role assignment made directly on the vault or one of its child objects. The old assignment becomes orphaned and a new assignment must be created at the destination scope.

This means that assigning RBAC before moving dev and QA vaults is not dangerous to legacy data-plane access, but it is temporary work:

1. The role is inactive for Key Vault data-plane authorization while `enableRbacAuthorization` is false.
2. The move invalidates its scope.
3. The role must be recreated after the move.
4. The later tenant transfer deletes the recreated assignment again.

The durable artifact is therefore the approved assignment intent, not the Azure role-assignment object.

## What the Same-Tenant Move Can Affect

The move is more than an administrative rename:

- The vault's ARM resource ID changes. Update IaC state, scripts, dashboards, alerts, policy exemptions, diagnostic settings, CMK references, and any stored resource IDs.
- Direct vault and key/secret/certificate role assignments must be recreated.
- Any custom role used at the vault must have an `AssignableScopes` entry that covers the destination subscription before it can be reassigned there.
- Subscription- and resource-group-inherited RBAC changes. This can change who can manage the vault even while legacy data-plane access remains enabled.
- Destination Azure Policy applies and can block the move or alter compliance.
- Existing read-only locks on the source resource, source group, destination group, or either subscription can block the move.
- Diagnostic settings are not guaranteed to move with the resource. Export and verify or recreate them.
- Private endpoint and private DNS dependencies require explicit validation.
- A vault used for Azure Disk Encryption cannot be moved while disk encryption is enabled.
- Source and destination resource groups are locked against create, update, and delete operations while the move runs. Existing resources continue operating, but the lock can last up to four hours.
- The destination subscription must have `Microsoft.KeyVault` registered.

Microsoft describes a cross-subscription Key Vault move as a breaking change. Run ARM move validation and application checks even though the source and destination subscriptions share a tenant.

## What Pre-Staged RBAC Proves

While a vault still uses legacy access policies, pre-staging proves:

- the role definition exists;
- the principal exists in the current tenant;
- the assignment can be created at the intended scope;
- the desired assignment set is complete and idempotent.

It does not prove that the application can perform its required Key Vault data-plane operations through RBAC. Key Vault data-plane roles only take effect when the vault uses the Azure RBAC permission model. A real authorization test requires either a disposable test vault or an approved pilot flip.

## Current-Tenant Runbook

Export the source state:

```powershell
.\scripts\Export-KeyVaultLegacyAccess.ps1 `
  -OutputPath .\out `
  -ResolvePrincipals `
  -IncludeRbac
```

Resolve the legacy-to-RBAC mapping:

```powershell
.\scripts\Resolve-KeyVaultRbacMapping.ps1 `
  -PolicyInventoryPath .\out\02-access-policy-inventory.csv `
  -PrincipalResolutionPath .\out\04-principal-resolution.csv `
  -ExistingRbacPath .\out\03-existing-rbac-inventory.csv `
  -OutputPath .\out
```

Create a real move manifest from `config/key-vault-subscription-move-plan.example.csv`, then run read-only preflight:

```powershell
.\scripts\Test-KeyVaultSubscriptionMove.ps1 `
  -MovePlanPath .\config\key-vault-subscription-move-plan.csv `
  -OutputPath .\out `
  -RunArmValidation
```

Review:

```text
13-subscription-move-preflight.csv
14-role-assignments-to-recreate.csv
15-parent-scope-role-delta.csv
```

Before the move, add an approver to `ApprovedBy` in `06-role-mapping-proposed.csv` and build a destination-scoped assignment plan. Do not apply it yet:

```powershell
.\scripts\New-KeyVaultRbacStagingPlan.ps1 `
  -MappingPath .\out\06-role-mapping-proposed.csv `
  -MovePlanPath .\config\key-vault-subscription-move-plan.csv `
  -OutputPath .\out\11-rbac-assignment-plan.csv
```

After the approved move, re-export Azure state and reconcile it with the approved plan. The apply script resolves the expected destination resource ID and will fail if the vault is still at the source location.

Validate and preview the reconciled plan:

```powershell
.\scripts\Set-KeyVaultRbacAssignments.ps1 `
  -PlanPath .\out\11-rbac-assignment-plan.csv `
  -ValidatePlanOnly

.\scripts\Set-KeyVaultRbacAssignments.ps1 `
  -PlanPath .\out\11-rbac-assignment-plan.csv `
  -ResultPath .\out\12-rbac-assignment-results.csv `
  -WhatIf
```

Apply the approved plan:

```powershell
.\scripts\Set-KeyVaultRbacAssignments.ps1 `
  -PlanPath .\out\11-rbac-assignment-plan.csv `
  -ResultPath .\out\12-rbac-assignment-results.csv
```

The apply script contains no command that changes `enableRbacAuthorization`. By default, it skips vaults already using the RBAC data-plane model so this staging run remains explicitly legacy-first.

## Later Tenant Transfer

Do not count on current-tenant RBAC assignments as a bridge into the new tenant. Before transferring each subscription:

1. Export all role assignments, custom roles, Key Vault policies, managed identities, diagnostic settings, locks, and tenant-dependent resources.
2. Build an explicit source-to-target principal map. Object IDs are tenant-local; do not match identities by display name alone.
3. Confirm the target identities and custom role definitions exist.
4. Transfer the subscription.
5. Update each Key Vault tenant ID.
6. If legacy access policies are still the active permission model, remove the old-tenant policies and recreate them with target-tenant principal IDs before expecting data-plane access.
7. Recreate RBAC assignments using the target principal map, regardless of whether the vault still uses legacy policies.
8. Re-enable or recreate managed identities and restore their assignments.
9. Validate CMK consumers before restoring normal operations.

As of May 1, 2026, Microsoft Entra subscription-transfer policies default to blocking transfers into and out of a tenant until a Global Administrator explicitly permits them. Include that approval in the tenant-transfer runbook.

## Microsoft References

- [Move Azure resources to a new resource group or subscription](https://learn.microsoft.com/en-us/azure/azure-resource-manager/management/move-resource-group-and-subscription)
- [Azure resource types that support move operations](https://learn.microsoft.com/en-us/azure/azure-resource-manager/management/move-support-resources)
- [Move an Azure Key Vault to another subscription](https://learn.microsoft.com/en-us/azure/key-vault/general/move-subscription)
- [Troubleshoot Azure RBAC role assignments after a resource move](https://learn.microsoft.com/en-us/azure/role-based-access-control/troubleshooting)
- [Migrate Key Vault access policies to Azure RBAC](https://learn.microsoft.com/en-us/azure/key-vault/general/rbac-migration)
- [Transfer an Azure subscription to another Microsoft Entra directory](https://learn.microsoft.com/en-us/azure/role-based-access-control/transfer-subscription)
- [Manage Azure subscription transfer policies](https://learn.microsoft.com/en-us/azure/cost-management-billing/manage/manage-azure-subscription-policy)
- [Diagnostic settings after moving a resource](https://learn.microsoft.com/en-us/troubleshoot/azure/partner-solutions/diagnostic-settings)
