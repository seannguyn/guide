# Image Compliance & Signing Gate: Build Plan

## Goal

Every image running on the org's EKS clusters must be either:

- **Compliant**: built on an org base image that is less than 7 days old, then promoted and signed by the platform, or
- **Exempt**: covered by an approved, time-limited exemption, then promoted with an exemption attestation.

Kyverno `ImageValidatingPolicy` (ivpol) enforces this at admission on every cluster. Build stays tenant-owned. The gate, promotion and signing are platform-owned.

## Trust model

| Actor | Can do | Cannot do |
|---|---|---|
| Tenant workflow | Build any way it likes; push to its **staging** repo | Write to prod repos; access signing keys |
| Platform reusable workflow | Check compliance, promote to **prod** repo, sign, attest | n/a (pinned, tag-protected, audited) |
| Kyverno (clusters) | Admit only images signed by the platform workflow's identity | n/a |

The core rule is that **only the platform reusable workflow can get signing credentials and write to prod.** This is enforced through the GitHub OIDC `job_workflow_ref` claim, which tenants cannot forge.

## End-to-end flow

```
Tenant workflow (tenant-owned)
 ├─ build image (any tool/process)
 ├─ push → staging ECR repo  (Vault role: tenant-push-<team>)
 └─ uses: <org>/platform-workflows/.github/workflows/gate.yml@v1
        with: image digest
            │
            ▼
Platform reusable workflow (platform-owned, platform runners)
 ├─ auth to Vault via OIDC (role: platform-signer, bound to job_workflow_ref)
 ├─ base-image check (layer-prefix match)
 ├─ freshness check (base digest in approved list, < 7 days)
 ├─ compliant?
 │    ├─ yes → copy by digest to prod repo → Notation sign → attach attestations
 │    └─ no  → exemption lookup
 │              ├─ valid exemption → copy to prod → exemption attestation (separate identity)
 │              └─ none / expired  → FAIL
            │
            ▼
EKS clusters: Kyverno ivpol verifies signer identity / attestations at admission
```

## Components to build

### 1. Platform reusable workflow (`gate.yml`)

- Trigger: `workflow_call`. Inputs: `image-digest` and an optional `exemption-id`.
- Requires the caller to grant `id-token: write`. Fail with a clear error if it's missing.
- No `secrets: inherit`. All credentials come from Vault using the workflow's own OIDC identity.
- Runs on **platform-owned runners**: a runner group limited to this workflow only, or ephemeral GitHub-hosted runners.
- Operates on the **digest only**, never on tags.
- Released under semver tags (`v1`, `v1.2.0`). Tags are protected in the platform repo.

### 2. Compliance checker (CLI / container)

- **Base-image check:** the org base image's layer digests must be an exact prefix of the candidate image's layers. Do not trust `org.opencontainers.image.base.*` labels, because tenants can set them.
- **Freshness check:** the matched base digest must be in the platform-published list of approved bases built in the last 7 days.
- Outputs a machine-readable result (pass / fail / reason). It is published as an attestation.
- Packaged as a container so non-GitHub CI (Jenkins, GitLab) can reuse it later.

### 3. Base image pipeline (platform)

- Rebuilds org base images on a schedule (more often than every 7 days, e.g. daily).
- Signs each base image and publishes an **approved base digests** manifest/attestation with build timestamps.
- This manifest is the source of truth for the freshness check.

### 4. Vault configuration

JWT auth backed by GitHub OIDC (`token.actions.githubusercontent.com`).

| Role | Bound claims | Policy grants |
|---|---|---|
| `tenant-push-<team>` | `repository` = team repo(s) | Push to that team's staging ECR repo only |
| `platform-signer` | `job_workflow_ref` = `<org>/platform-workflows/.github/workflows/gate.yml@refs/tags/v*` | Sign via Transit/KMS, push to prod ECR repos |

- Short token TTLs (minutes), scoped to one job.
- **Signing key is non-exportable.** Use a Notation plugin that signs remotely (Vault Transit, AWS Signer or KMS). The workflow sends a digest and receives a signature, so the key never sits in runner memory.
- Audit logging on for all signing operations.

### 5. Registries (ECR)

- **Staging repos:** tenant-writable, not pullable by prod clusters.
- **Prod repos:** writable **only** by the `platform-signer` identity. Clusters pull only from here.
- Promotion is a copy by digest (e.g. `oras cp` / `crane copy`). Never rebuild during promotion.

### 6. Exemption store

- Central Git repo. Changes go through PR, with approval required from security (CODEOWNERS).
- Each entry has: image/repo scope, owner, reason, approver, **expiry date**.
- Expired exemptions fail the gate automatically.
- Exempted images get a **separately-signed exemption attestation** rather than going unsigned, so Kyverno can tell "compliant" from "exempt".

### 7. Attestations attached to every promoted image

- Compliance result (base digest, base age, check version)
- SBOM
- Build provenance (SLSA)
- Exemption attestation (exempt images only)

### 8. Kyverno ImageValidatingPolicy (all clusters)

- Verify Notation signatures against the platform trust store / certificate.
- Require the compliance attestation for normal workloads.
- Allow the exemption attestation only where policy permits (e.g. specific namespaces or clusters). Reject if the exemption has expired.
- Restrict image sources to prod repos only.
- Roll out in audit mode first, then enforce.

## Security controls checklist

- [ ] Vault `platform-signer` role bound to `job_workflow_ref` (tag-pinned)
- [ ] Tag protection on the platform-workflows repo
- [ ] Signing key non-exportable (Transit / KMS / AWS Signer plugin)
- [ ] Signing job runs only on platform-controlled or ephemeral runners
- [ ] Prod ECR write restricted to the platform identity
- [ ] No `secrets: inherit` into the reusable workflow
- [ ] Short-lived Vault tokens
- [ ] Exemptions have expiry and security approval
- [ ] Kyverno restricts registries to prod repos
- [ ] Audit logs on Vault, ECR and Kyverno policy reports

## Tenant integration (what teams add)

```yaml
jobs:
  build:
    # tenant-owned: build + push to staging, output digest
    outputs:
      digest: ${{ steps.push.outputs.digest }}

  gate:
    needs: build
    permissions:
      id-token: write
      contents: read
    uses: <org>/platform-workflows/.github/workflows/gate.yml@v1
    with:
      image-digest: ${{ needs.build.outputs.digest }}

  deploy:
    needs: gate
    # tenant-owned: deploy using the promoted prod digest
```

## Suggested delivery phases

1. **Foundations:** Vault JWT roles, staging/prod ECR split, KMS-backed Notation signing.
2. **Base image pipeline:** scheduled rebuilds plus the approved-digests manifest.
3. **Gate workflow + checker:** compliant path only. Pilot with 1–2 teams.
4. **Exemptions:** store, PR approval flow, exemption attestations.
5. **Kyverno:** audit mode across clusters, review policy reports, then enforce.
6. **Expansion:** onboard all teams; add non-GitHub CI support via the checker container plus a promotion service.

## Open questions

- Freshness checked at **build time** only, or also at **admission** (images going stale while running)?
- Exempt images allowed in all clusters, or limited to specific environments?
- Ownership and SLA for the base image rebuild pipeline.
- Handling for multi-arch image indexes (check and sign the index and/or every platform manifest).
