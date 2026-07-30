# Management Decision Brief: Key Vault Subscription and Management RBAC

Prepared: 2026-07-30

Status: The proposed approach and supporting scripts are ready for review. Live
environment inventory and move validation must be completed before execution is
authorized.

## Executive Recommendation

Approve a phased plan that separates three changes:

1. Inventory current management-plane Azure RBAC at every scope and approve
   which assignments should apply to `dev-keys`, `qa-keys`, production, or a
   narrower resource scope.
2. Create the destination subscriptions, establish approved management-plane
   access, and move dev and QA Key Vault resources while all subscriptions are
   still in the current tenant.
3. Transfer the completed subscriptions to the new tenant later as a separate
   identity and authorization change.

Key Vault data-plane authorization remains on legacy access policies. Do not
assign data-plane-bearing roles, enable the Key Vault RBAC permission model,
remove legacy access policies, or combine the resource move with the tenant
transfer during this phase.

## Decisions Requested

Management approval is requested for:

- The phased sequence above.
- Creation and funding of the `dev-keys` and `qa-keys` subscriptions in the
  current tenant.
- A read-only management-plane IAM inventory and move-preflight exercise.
- The target management-plane role and scope model for each new subscription.
- Selection of one low-risk dev vault and application as the pilot.
- Named business, application, IAM/security, Azure platform, and network
  approvers.
- Separate change records for destination management access, vault resource
  moves, and the later tenant transfers.

This meeting is not a request to authorize an unvalidated production move.

## Why This Sequence

- Azure Resource Manager requires source and destination subscriptions to be in
  the same Microsoft Entra tenant for a cross-subscription resource move.
- A vault move changes its ARM resource ID. Azure RBAC assignments made directly
  on the vault or an individual key, secret, or certificate do not move and must
  be recreated.
- RBAC inherited from the source resource group or subscription stops applying
  after the move. RBAC at the destination parent scope starts applying.
- Legacy Key Vault access policies remain part of the vault configuration during
  a same-tenant move, preserving the current data-plane authorization path.
- A later subscription transfer to another tenant permanently removes Azure
  role assignments and custom roles. Current-tenant RBAC is therefore not a
  bridge into the target tenant.
- Establishing destination management access before each move prevents the
  source subscription's inherited administration from being mistaken for
  destination access.

## Scope Boundaries

In scope:

- Current-state management-plane RBAC, PIM, deny-assignment, and role-definition
  inventory.
- Principal, role, scope, and owner review.
- Classification of resource-group assignments that might become environment
  subscription assignments.
- Creation of destination subscriptions and resource groups.
- Creation of approved management-plane assignments in those subscriptions.
- Same-tenant dev and QA vault moves.
- Validation while legacy authorization remains active.

Out of scope for this phase:

- Setting `enableRbacAuthorization` to `true`.
- Removing legacy access policies.
- Mapping legacy Key Vault permissions to data-plane RBAC roles.
- Assigning roles containing `DataActions` as part of this work.
- Transferring a subscription to the new tenant.
- Replacing identities with target-tenant identities.
- Automatically approving over-granted built-in roles or custom roles.
- Combining all vaults into one untested change window.

## Proposed Delivery Gates

| Gate | Work | Exit criteria |
| --- | --- | --- |
| 0. Architecture approval | Approve sequencing, scope, owners, and subscription model | Management decision recorded |
| 1. Discovery | Export management-plane RBAC, PIM, deny assignments, roles, vaults, dependencies, policies, locks, diagnostics, and networking | Every management assignment classified; unresolved roles and principals have owners |
| 2. Destination readiness | Create subscriptions/resource groups, register `Microsoft.KeyVault`, establish approved destination management access, and confirm policy/network readiness | Source and destination tenant IDs match; destination controls and IAM approved |
| 3. Pilot approval | Run ARM move validation and application-specific testing for one low-risk dev vault | No blockers; app owner and platform owner approve |
| 4. Pilot move | Move the vault, re-export state, and validate management access and unchanged legacy data-plane behavior | Success criteria met during observation period |
| 5. Dev/QA waves | Repeat the validated process in small groups | Every wave has evidence and owner signoff |
| 6. Later tenant transfer | Map target identities, export authorization, transfer subscription, update vault tenant data, and rebuild access | Separate runbook and change approval completed |

No gate advances solely because the previous script completed. Each gate requires
review of its output and named approval.

## Expected Operational Impact

Management-plane roles containing no `DataActions` do not directly grant key,
secret, or certificate operations. However, a role that includes
`Microsoft.KeyVault/vaults/write`, such as Contributor or Key Vault Contributor,
can modify legacy access policies within its scope and can therefore create an
indirect path to data-plane access. Treat those rows as privileged escalation
risk, prefer PIM and narrow scope, and require explicit security approval.

The vault resource move still requires a controlled change window because:

- The ARM resource ID changes.
- Source and destination resource groups can be locked against write and delete
  operations while the move runs.
- Inherited control-plane access changes.
- Azure Policy, locks, provider registration, private endpoints, private DNS,
  diagnostic settings, IaC state, CMK consumers, and stored resource IDs can
  block or be affected by the move.
- Vaults used for Azure Disk Encryption require special handling and cannot be
  moved while that use is active.

## Principal Risks and Controls

| Risk | Control |
| --- | --- |
| Application loses data-plane access | Keep legacy access policies active; require application validation after each move |
| Direct management RBAC is lost during the move | Export direct assignments and recreate only approved management assignments at the destination resource ID |
| Administrators lose control-plane access | Compare source and destination inherited RBAC before the move; establish destination administration first |
| An RG role is promoted too broadly at subscription scope | Require principal, role, environment, and blast-radius review before `ApprovedBy` |
| A data-plane-bearing role enters the management plan | Keep every role with `DataActions` in the exclusions report unless separately approved |
| A management role changes legacy access policies | Flag `Microsoft.KeyVault/vaults/write`, use narrow scope/PIM, and require security approval |
| Policy, lock, provider, or quota blocks the move | Run read-only preflight and ARM move validation before approval |
| Private endpoint, DNS, diagnostics, or CMK dependency fails | Record dependency owner and execute a service-specific validation checklist |
| Wrong tenant or subscription is used | Record immutable subscription and tenant IDs; do not rely on display names |
| Tenant transfer is treated as a normal resource move | Use a separate runbook that remaps identities and rebuilds all RBAC/custom roles |
| Too many changes obscure the failure cause | Separate management IAM setup, subscription move, and tenant transfer |

## Stop Conditions

Do not move a vault when any of the following is true:

- The source and destination subscriptions do not have the same tenant ID.
- The application or business owner is unknown.
- A principal cannot be resolved and has not been dispositioned.
- ARM move validation reports a blocker.
- The destination resource group, provider registration, inherited RBAC, policy,
  networking, or diagnostics plan is incomplete.
- A CMK, disk-encryption, private-endpoint, or automation dependency has no test
  owner.
- The source export and approved destination assignment plan are not archived.
- The rollback and escalation owners are unavailable during the change window.

If a move completes but validation fails, preserve legacy authorization, stop the
wave, and resolve the specific dependency. Moving the resource back is a separate
validated change, not the primary rollback mechanism.

## Evidence Required Before Each Move

- `01-vault-inventory.csv`
- `13-subscription-move-preflight.csv`
- `14-role-assignments-to-recreate.csv`
- `15-parent-scope-role-delta.csv`
- Approved `16-management-plane-access-review.csv`
- `17-role-definition-classification.csv`
- `18-management-principal-summary.csv`
- `19-management-scope-summary.csv`
- `20-management-inventory-coverage.csv`
- `21-management-inventory-errors.csv`
- Reviewed `22-non-management-rbac-exclusions.csv`
- Successful ARM move validation
- Application owner test plan
- Monitoring and dependency baseline
- Change record with approvers, window, stop conditions, and escalation contacts

## Current Readiness

Ready:

- Report-first management-plane IAM inventory and scope-classification toolkit.
- Read-only subscription-move preflight.
- Subscription-wide management-plane export with active RBAC, PIM,
  deny-assignment, role-definition, principal, exclusion, and coverage reports.
- Local smoke tests, including Resource Graph pagination beyond 1,000 records.
- Written subscription and tenant sequencing runbook.

Not yet complete:

- Confirmation of the authoritative current tenant and subscription inventory.
- Creation and validation of `dev-keys` and `qa-keys`.
- Production vault inventory and environment classification.
- Principal, application owner, and dependency disposition.
- A completed move manifest and ARM validation results.
- Pilot vault, change window, and success criteria.
- Target-tenant identity map and tenant-transfer runbook.

## Preparation Checklist

Bring the following facts to the meeting. Mark unknown items as open actions
rather than estimating them.

| Item | Value or owner |
| --- | --- |
| Current tenant ID | |
| Source subscription name and ID | |
| Is the source currently named `default` or `keys`? | |
| `dev-keys` subscription status | Existing / planned |
| `qa-keys` subscription status | Existing / planned |
| Number of dev vaults | |
| Number of QA vaults | |
| Number of vaults remaining in source | |
| Proposed pilot vault and application | |
| Business/application owner | |
| IAM/security approver | |
| Azure platform approver | |
| Network/private endpoint approver | |
| Billing/subscription creator | |
| Proposed pilot window | |
| Required observation period | |
| Later target-tenant owner | |

Before the meeting:

1. Confirm whether `default` is a subscription name or "Default Directory."
2. Capture subscription IDs and tenant IDs from Azure, not screenshots of names
   alone.
3. Run the source inventory if access is available.
4. Count vaults by dev, QA, and remaining workload.
5. Identify one low-risk dev pilot and its application owner.
6. List known private endpoints, CMK consumers, disk-encryption dependencies,
   diagnostics, automation, and IaC owners.
7. Decide who can approve an RG-to-subscription scope promotion and any custom
   management role.
8. Bring this document and the detailed sequencing runbook; do not lead with the
   scripts.

## Sixty-Second Talk Track

> I recommend that we first inventory the existing Azure management-plane roles
> and decide which access belongs in dev, QA, production, or a narrower resource
> scope. We then create `dev-keys` and `qa-keys`, establish that approved
> management access, and move the vaults while all subscriptions are still in the
> current tenant. Key Vault application access remains on the existing legacy
> access policies; data-plane RBAC is not part of this change. The later tenant
> transfer is a separate identity-remapping change because Azure role assignments
> do not transfer. I am asking for approval of the subscription model,
> management-access review, owners, and pilot preparation, not a data-plane
> authorization cutover or an unvalidated bulk move.

## Likely Questions

**Why move the vaults now?**

Because a direct cross-subscription resource move requires both subscriptions to
share a tenant. Moving them before tenant transfer establishes the final
subscription resource IDs and removes a schedule dependency from the later
tenant cutover.

**Why not copy every existing RG assignment to the new subscriptions?**

Subscription scope is broader than resource-group scope. Promote an assignment
only when the same principal genuinely needs the same management role over every
resource in that environment subscription.

**Does this turn off the current access model?**

No. The management inventory does not read or change access policies, does not
assign roles containing `DataActions`, and does not change
`enableRbacAuthorization`. Legacy access policies remain active.

**Does that mean there is no outage risk?**

No. It removes data-plane cutover risk, but the resource move can still affect ARM
references, inherited administration, policy, networking, diagnostics, CMK
dependencies, locks, and automation. That is why a pilot and change window are
required.

**What survives the later tenant transfer?**

The subscription and resources transfer, but Azure RBAC assignments and custom
roles do not. Key Vault tenant configuration, legacy policies, managed
identities, and role assignments must be remapped or rebuilt for target-tenant
identities.

**What is the rollback?**

The primary protection is to avoid changing the active authorization model and
to stop after any failed validation. A move back is possible only through
another supported and validated resource move; it should not be presented as an
instant rollback.

## References

- [Subscription and tenant sequencing](SUBSCRIPTION-TENANT-SEQUENCING.md)
- [Move Azure resources to another subscription](https://learn.microsoft.com/en-us/azure/azure-resource-manager/management/move-resource-group-and-subscription)
- [Move an Azure Key Vault to another subscription](https://learn.microsoft.com/en-us/azure/key-vault/general/move-subscription)
- [Assign a Key Vault access policy and legacy-model security warning](https://learn.microsoft.com/en-us/azure/key-vault/general/assign-access-policy)
- [Migrate Key Vault access policies to Azure RBAC](https://learn.microsoft.com/en-us/azure/key-vault/general/rbac-migration)
- [Transfer a subscription to another Microsoft Entra directory](https://learn.microsoft.com/en-us/azure/role-based-access-control/transfer-subscription)
