# Management Decision Brief: Key Vault Subscription and RBAC Sequencing

Prepared: 2026-07-29

Status: The proposed approach and supporting scripts are ready for review. Live
environment inventory and move validation must be completed before execution is
authorized.

## Executive Recommendation

Approve a phased plan that separates three changes:

1. Move dev and QA Key Vault resources into dedicated `dev-keys` and `qa-keys`
   subscriptions while all subscriptions are still in the current tenant.
2. Recreate and stage approved vault-level Azure RBAC assignments at the new
   resource scopes, while leaving legacy Key Vault access policies active.
3. Transfer the completed subscriptions to the new tenant later as a separate
   identity and authorization change.

Do not enable the Key Vault RBAC permission model, remove legacy access
policies, or combine the resource move with the tenant transfer during this
phase.

## Decisions Requested

Management approval is requested for:

- The phased sequence above.
- Creation and funding of the `dev-keys` and `qa-keys` subscriptions in the
  current tenant.
- A read-only discovery and move-preflight exercise.
- Selection of one low-risk dev vault and application as the pilot.
- Named business, application, IAM/security, Azure platform, and network
  approvers.
- Separate change records for the vault resource moves, the later tenant
  transfers, and the eventual RBAC authorization cutover.

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
  a same-tenant move, preserving the current data-plane authorization path while
  RBAC is prepared.
- A later subscription transfer to another tenant permanently removes Azure
  role assignments and custom roles. Current-tenant RBAC is therefore not a
  bridge into the target tenant.
- Moving the vaults first establishes their final subscription-based resource
  IDs before the tenant transfer and avoids rebuilding pre-move vault-level role
  assignments.

## Scope Boundaries

In scope:

- Current-state vault, legacy access-policy, and effective RBAC inventory.
- Principal resolution and owner review.
- Creation of destination subscriptions and resource groups.
- Same-tenant dev and QA vault moves.
- Re-creation of approved RBAC assignments at destination scopes.
- Validation while legacy authorization remains active.

Out of scope for this phase:

- Setting `enableRbacAuthorization` to `true`.
- Removing legacy access policies.
- Transferring a subscription to the new tenant.
- Replacing identities with target-tenant identities.
- Automatically approving over-granted built-in roles or custom roles.
- Combining all vaults into one untested change window.

## Proposed Delivery Gates

| Gate | Work | Exit criteria |
| --- | --- | --- |
| 0. Architecture approval | Approve sequencing, scope, owners, and subscription model | Management decision recorded |
| 1. Discovery | Export vaults, policies, RBAC, principals, dependencies, policies, locks, diagnostics, and networking | Every vault classified; unresolved access has an owner |
| 2. Destination readiness | Create subscriptions/resource groups, register `Microsoft.KeyVault`, establish destination admin access, and confirm policy/network readiness | Source and destination tenant IDs match; destination controls approved |
| 3. Pilot approval | Run ARM move validation and application-specific testing for one low-risk dev vault | No blockers; app owner and platform owner approve |
| 4. Pilot move | Move the vault, re-export state, recreate approved RBAC, and validate management/data-plane behavior | Success criteria met during observation period |
| 5. Dev/QA waves | Repeat the validated process in small groups | Every wave has evidence and owner signoff |
| 6. Later tenant transfer | Map target identities, export authorization, transfer subscription, update vault tenant data, and rebuild access | Separate runbook and change approval completed |
| 7. Eventual RBAC cutover | Pilot `enableRbacAuthorization`, validate, then roll out | Separate security and application approval |

No gate advances solely because the previous script completed. Each gate requires
review of its output and named approval.

## Expected Operational Impact

Adding RBAC assignments while legacy authorization is active does not change the
Key Vault data-plane permission model. It proves that principals, roles, and
scopes can be resolved, but it does not prove application access through RBAC.

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
| Vault-level RBAC is lost during the move | Export direct assignments and recreate only approved assignments at the destination resource ID |
| Administrators lose control-plane access | Compare source and destination inherited RBAC before the move; establish destination administration first |
| A broad built-in role expands privilege | Classify mappings as exact, over-granted, custom-role candidate, unused, or owner-review; require `ApprovedBy` |
| Policy, lock, provider, or quota blocks the move | Run read-only preflight and ARM move validation before approval |
| Private endpoint, DNS, diagnostics, or CMK dependency fails | Record dependency owner and execute a service-specific validation checklist |
| Wrong tenant or subscription is used | Record immutable subscription and tenant IDs; do not rely on display names |
| Tenant transfer is treated as a normal resource move | Use a separate runbook that remaps identities and rebuilds all RBAC/custom roles |
| Too many changes obscure the failure cause | Separate subscription move, RBAC staging, tenant transfer, and RBAC authorization cutover |

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
- `02-access-policy-inventory.csv`
- `03-existing-rbac-inventory.csv`
- `04-principal-resolution.csv`
- Approved `06-role-mapping-proposed.csv`
- `11-rbac-assignment-plan.csv`
- `13-subscription-move-preflight.csv`
- `14-role-assignments-to-recreate.csv`
- `15-parent-scope-role-delta.csv`
- `16-authorization-review.csv`
- `17-role-definitions-used.csv`
- `18-principal-summary.csv`
- `19-scope-summary.csv`
- `20-inventory-coverage.csv`
- `21-inventory-errors.csv`
- Successful ARM move validation
- Application owner test plan
- Monitoring and dependency baseline
- Change record with approvers, window, stop conditions, and escalation contacts

## Current Readiness

Ready:

- Report-first inventory and mapping toolkit.
- Move-aware RBAC assignment planning.
- Read-only subscription-move preflight.
- Idempotent RBAC assignment validation and apply workflow.
- Subscription-wide authorization export with scope classification, PIM,
  deny-assignment, role-definition, principal, and coverage reports.
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
7. Decide who can approve role over-grants and custom roles.
8. Bring this document and the detailed sequencing runbook; do not lead with the
   scripts.

## Sixty-Second Talk Track

> I recommend that we separate the work into three controlled changes. First, we
> move the dev and QA vaults into dedicated subscriptions while all subscriptions
> are still in the current tenant. Second, after each move, we recreate and
> validate the approved vault-level RBAC assignments, but we leave the existing
> access-policy model active, so this phase does not cut applications over to
> RBAC. Third, we transfer those completed subscriptions to the new tenant later
> using a separate identity-remapping runbook. This order matters because direct
> vault RBAC assignments do not follow a resource move, and all RBAC assignments
> are deleted during a tenant transfer. I am asking for approval of the sequence,
> destination subscriptions, owners, and a read-only pilot-preparation phase, not
> approval for an unvalidated bulk move.

## Likely Questions

**Why move the vaults now?**

Because a direct cross-subscription resource move requires both subscriptions to
share a tenant. Moving them before tenant transfer establishes the final
subscription resource IDs and removes a schedule dependency from the later
tenant cutover.

**Why not assign all vault-level RBAC first?**

The move changes the vault resource ID. Direct vault and child-object role
assignments do not move, so they would have to be recreated.

**Does this turn off the current access model?**

No. The scripts do not change `enableRbacAuthorization`, and legacy access
policies remain active during this phase.

**Does that mean there is no outage risk?**

No. It removes the RBAC-cutover risk, but the resource move can still affect ARM
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
- [Migrate Key Vault access policies to Azure RBAC](https://learn.microsoft.com/en-us/azure/key-vault/general/rbac-migration)
- [Transfer a subscription to another Microsoft Entra directory](https://learn.microsoft.com/en-us/azure/role-based-access-control/transfer-subscription)
