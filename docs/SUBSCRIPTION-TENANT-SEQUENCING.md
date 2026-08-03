# Key Vault Subscription and Tenant Sequencing

Reviewed against Microsoft Learn guidance on 2026-07-30.

## Current Scope

This phase establishes Azure management-plane access for `dev-keys`, `qa-keys`,
and the production subscription. Key Vault data-plane access remains on legacy
access policies.

The current phase does not:

- map access policies to Azure RBAC roles;
- assign roles containing `DataActions`;
- change `enableRbacAuthorization`; or
- remove or replace legacy access policies.

## Decision

For dev and QA:

```text
Inventory current management IAM at every scope
  -> classify each principal, role, and scope
  -> approve dev / QA / production management intent
  -> create dev-keys and qa-keys
  -> establish approved destination management RBAC
  -> validate the same-tenant resource move
  -> move the vaults
  -> re-export and validate management access
  -> verify legacy data-plane access is unchanged
```

Complete the vault resource moves while the source and destination
subscriptions are associated with the current tenant. Treat the later
subscription transfer to the new tenant as a separate identity and
authorization change.

## Two Different Moves

| Operation | What changes | Authorization impact |
| --- | --- | --- |
| Move a vault to another subscription in the same tenant | The vault resource ID changes because the subscription and usually the resource group change | Direct resource-scope role assignments do not move. Source parent-scope RBAC stops applying and destination parent-scope RBAC begins applying. Legacy Key Vault access policies remain the data-plane model. |
| Transfer a subscription to a different tenant | The subscription remains the container, but its trusted Microsoft Entra directory changes | Azure role assignments and custom roles from the source directory must be rebuilt for target-tenant identities. Key Vault tenant IDs, legacy policies, and managed identities require tenant-specific remediation. |

The same-tenant resource move and later tenant transfer need separate change
records, validation, and rollback decisions.

## Management Scope Review

Review each row in `16-management-plane-access-review.csv` using these rules:

1. Keep a resource-group assignment at resource-group scope when the principal
   should manage only that workload group.
2. Promote it to `dev-keys`, `qa-keys`, or production subscription scope only
   when the principal should have that role over every current and future
   resource in that environment subscription.
3. Keep exceptional vault or resource assignments narrow and recreate them at
   the destination resource ID only when still required.
4. Confirm management-group assignments will apply to the destination
   subscriptions through the intended hierarchy.
5. Treat `CanModifyLegacyAccessPolicies=True` as an escalation risk. A
   management role covering `Microsoft.KeyVault/vaults/write` can change legacy
   policies even when it has no `DataActions`.
6. Do not promote rows from `22-non-management-rbac-exclusions.csv`. Those roles
   contain `DataActions`, have no management grant actions, or otherwise fall
   outside this management-plane review.
7. Resolve every `UnknownRoleDefinition` before approval.

Subscription-scope promotion is a privilege expansion. Require an owner and
approver for each promoted assignment.

## Current-Tenant Runbook

Export management-plane access from the old `keys` subscription:

```powershell
Connect-AzAccount -Tenant '<current-tenant-id>'

.\scripts\Export-KeysManagementPlanePermissions.ps1 `
  -TenantId '<current-tenant-id>' `
  -Subscription '<keys-subscription-id>' `
  -OutputPath .\keys-management-plane-permissions.csv
```

Use the extended multi-file package when separate coverage, role, principal, and
scope summaries are required:

```powershell
.\scripts\Export-SubscriptionManagementPlaneAccess.ps1 `
  -SubscriptionId '<keys-subscription-id>' `
  -OutputPath .\out
```

Review completeness first:

```text
20-management-inventory-coverage.csv
21-management-inventory-errors.csv
```

Then review and approve:

```text
16-management-plane-access-review.csv
17-role-definition-classification.csv
18-management-principal-summary.csv
19-management-scope-summary.csv
22-non-management-rbac-exclusions.csv
```

Create `dev-keys` and `qa-keys`, place them in the approved management-group
hierarchy, and create only the approved management-plane assignments. Confirm
that administrators can read and manage the destination resource groups before
moving any vault.

Create a real move manifest from
`config/key-vault-subscription-move-plan.example.csv`, then run read-only
preflight:

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

After each move, rerun the management-plane export against the destination
subscription and compare actual access with the approved workbook. Separately
validate that applications still access keys, secrets, and certificates through
the unchanged legacy policies.

## Same-Tenant Move Considerations

- The vault ARM resource ID changes. Update IaC state, scripts, dashboards,
  alerts, policy exemptions, diagnostic settings, CMK references, and stored
  resource IDs.
- Direct resource-scope management assignments must be recreated at the new
  resource ID when they remain required.
- Source subscription and resource-group inheritance stops. Destination
  inheritance applies immediately.
- Destination Azure Policy, locks, provider registration, private endpoints,
  private DNS, diagnostics, and CMK dependencies require validation.
- The destination subscription must have `Microsoft.KeyVault` registered.
- A vault used for Azure Disk Encryption requires special move handling.

## Later Tenant Transfer

Do not treat current-tenant role assignments as a bridge into the new tenant.
Before transferring each subscription:

1. Export management-plane assignments, PIM, deny assignments, custom roles,
   Key Vault policies, managed identities, locks, diagnostics, and other
   tenant-dependent resources.
2. Build an explicit source-to-target principal map using immutable object IDs.
3. Confirm target identities and approved custom role definitions exist.
4. Approve the target-tenant management assignment plan.
5. Transfer the subscription.
6. Recreate management-plane assignments for target-tenant identities.
7. Update each Key Vault tenant ID and replace legacy access-policy principal
   IDs before expecting data-plane access.
8. Re-enable or recreate managed identities and restore their assignments.
9. Validate management access, legacy data-plane access, and CMK consumers.

## Microsoft References

- [Move Azure resources to a new resource group or subscription](https://learn.microsoft.com/en-us/azure/azure-resource-manager/management/move-resource-group-and-subscription)
- [Azure resource types that support move operations](https://learn.microsoft.com/en-us/azure/azure-resource-manager/management/move-support-resources)
- [Move an Azure Key Vault to another subscription](https://learn.microsoft.com/en-us/azure/key-vault/general/move-subscription)
- [Assign a Key Vault access policy and legacy-model security warning](https://learn.microsoft.com/en-us/azure/key-vault/general/assign-access-policy)
- [Troubleshoot Azure RBAC role assignments after a resource move](https://learn.microsoft.com/en-us/azure/role-based-access-control/troubleshooting)
- [Transfer an Azure subscription to another Microsoft Entra directory](https://learn.microsoft.com/en-us/azure/role-based-access-control/transfer-subscription)
- [Diagnostic settings after moving a resource](https://learn.microsoft.com/en-us/troubleshoot/azure/partner-solutions/diagnostic-settings)
