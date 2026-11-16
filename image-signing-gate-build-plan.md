# Image Compliance & Signing Gate: Build Plan

## Goal

Every image running on the org's EKS clusters must be either:

- **Compliant**: built on an org base image that is less than 7 days old, then promoted and signed by the platform, or
- **Exempt**: covered by an approved, time-limited exemption, then promoted with an exemption attestation.

Kyverno `ImageValidatingPolicy` (ivpol) enforces this at admission on every cluster. Build stays tenant-owned. The gate, the push to prod and signing are platform-owned.

## Ingest options: how the image reaches the gate

The gate supports two ways for a tenant to hand over the built image. The tenant picks one with the `source` input. Everything after ingest (checks, push to prod, sign, attest) is identical.

### Option A: Push to staging registry, platform promotes

```
Tenant job:   build → push to staging ECR (tenant creds) → pass digest
Gate:         pull by digest from staging → check → copy by digest to prod → sign
```

### Option B: OCI tarball as a workflow artifact, platform pushes

```
Tenant job:   build → export OCI layout tarball → actions/upload-artifact → pass artifact name + expected digest
Gate:         download-artifact → validate layout + digest → check → push to prod → sign
```

- Build output example: `docker buildx build --output type=oci,dest=image.tar .`
- The reusable workflow runs inside the caller's workflow run, so it can download the artifact by name.
- The gate checks, pushes and signs **the exact bytes it downloaded**, within one job. There is no window for the tarball to change between check and push.
- The gate recomputes the manifest digest from the tarball and fails if it doesn't match the `expected-digest` input.

### Comparison

| | A: Staging registry | B: OCI tarball |
|---|---|---|
| Tenant registry credentials | Needed (staging push) | **None.** Tenant never touches a registry |
| Infra to run | Staging repos, lifecycle cleanup, tenant Vault roles | Nothing extra |
| Large images | Good: layer dedup; base layers already in registry | Weaker: full image (incl. base layers) uploaded and downloaded every build |
| Speed | Fast for incremental builds | Slower as image size grows |
| Storage / quota | ECR storage (cheap, lifecycle-managed) | GitHub Actions artifact storage and retention quota |
| Debugging failed images | Image is pullable from staging | Tarball available for the artifact retention period |
| Multi-arch | Index in staging | OCI layout holds the index and all platform manifests |
| Attack surface | Staging repo access to manage | Smallest: one identity, one push path |

**Suggested default:** offer both.

- **B** for small and medium images and teams that want the simplest setup. Fewer credentials means less to manage and less to leak.
- **A** for large images (e.g. ML/CUDA) or high build frequency, where re-uploading full tarballs is too slow or costly.

Set a size threshold for B (e.g. images over ~2 GB should use A) and document it.

## Trust model

| Actor | Can do | Cannot do |
|---|---|---|
| Tenant workflow | Build any way it likes. **A:** push to its staging repo. **B:** upload an OCI artifact | Write to prod repos; access signing keys |
| Platform reusable workflow | Check compliance, push to **prod** repo, sign, attest | n/a (pinned, tag-protected, audited) |
| Kyverno (clusters) | Admit only images signed by the platform workflow's identity | n/a |

The core rule, under both options, is that **only the platform reusable workflow can get signing credentials and write to prod.** This is enforced through the GitHub OIDC `job_workflow_ref` claim, which tenants cannot forge.

## End-to-end flow

```
Tenant workflow (tenant-owned)
 ├─ build image (any tool/process)
 ├─ A: push → staging ECR          (Vault role: tenant-push-<team>)
 │  B: export OCI tarball → upload-artifact
 └─ uses: <org>/platform-workflows/.github/workflows/gate.yml@v1
        with: source, image-digest, [staging-ref | artifact-name]
            │
            ▼
Platform reusable workflow (platform-owned, platform runners)
 ├─ auth to Vault via OIDC (role: platform-signer, bound to job_workflow_ref)
 ├─ ingest:  A → pull by digest from staging
 │           B → download artifact, validate OCI layout, verify digest
 ├─ base-image check (layer-prefix match)
 ├─ freshness check (base digest in approved list, < 7 days)
 ├─ compliant?
 │    ├─ yes → push to prod repo (A: copy by digest, B: push from layout) → Notation sign → attestations
 │    └─ no  → exemption lookup
 │              ├─ valid exemption → push to prod → exemption attestation (separate identity)
 │              └─ none / expired  → FAIL
            │
            ▼
EKS clusters: Kyverno ivpol verifies signer identity / attestations at admission
```

## Components to build

### 1. Platform reusable workflow (`gate.yml`)

- Trigger: `workflow_call`.
- Inputs:
  - `source`: `registry` (Option A) or `oci-artifact` (Option B)
  - `image-digest`: expected manifest/index digest (required for both)
  - `staging-ref`: staging repo reference (A only)
  - `artifact-name`: uploaded artifact name (B only)
  - `target-repo`: prod repo name
  - `exemption-id`: optional
- Outputs: the prod image reference by digest, for tenant deploy jobs.
- Requires the caller to grant `id-token: write`. Fail with a clear error if it's missing.
- No `secrets: inherit`. All credentials come from Vault using the workflow's own OIDC identity.
- Runs on **platform-owned runners**: a runner group limited to this workflow only, or ephemeral GitHub-hosted runners.
- Operates on the **digest only**, never on tags.
- Released under semver tags (`v1`, `v1.2.0`). Tags are protected in the platform repo.

### 2. Compliance checker (CLI / container)

- Accepts either a registry reference (A) or a local OCI layout path (B), and runs the same checks against both.
- **Base-image check:** the org base image's layer digests must be an exact prefix of the candidate image's layers. Do not trust `org.opencontainers.image.base.*` labels, because tenants can set them.
- **Freshness check:** the matched base digest must be in the platform-published list of approved bases built in the last 7 days.
- **B only:** validate the OCI layout (well-formed `index.json`, all blobs present, digests match content) and enforce the size limit.
- Outputs a machine-readable result (pass / fail / reason). It is published as an attestation.
- Packaged as a container so non-GitHub CI (Jenkins, GitLab) can reuse it later.

### 3. Base image pipeline (platform)

- Rebuilds org base images on a schedule (more often than every 7 days, e.g. daily).
- Signs each base image and publishes an **approved base digests** manifest/attestation with build timestamps.
- This manifest is the source of truth for the freshness check.

### 4. Vault configuration

JWT auth backed by GitHub OIDC (`token.actions.githubusercontent.com`).

| Role | Bound claims | Policy grants | Needed for |
|---|---|---|---|
| `tenant-push-<team>` | `repository` = team repo(s) | Push to that team's staging ECR repo only | **A only** |
| `platform-signer` | `job_workflow_ref` = `<org>/platform-workflows/.github/workflows/gate.yml@refs/tags/v*` | Sign via Transit/KMS; push to prod ECR; (A) pull from staging | A and B |

- Short token TTLs (minutes), scoped to one job.
- **Signing key is non-exportable.** Use a Notation plugin that signs remotely (Vault Transit, AWS Signer or KMS). The workflow sends a digest and receives a signature, so the key never sits in runner memory.
- Audit logging on for all signing operations.

### 5. Registries (ECR)

- **Prod repos:** writable **only** by the `platform-signer` identity. Clusters pull only from here.
- **Staging repos (A only):** tenant-writable, not pullable by prod clusters. Add lifecycle policies to expire untagged and old images (e.g. after 14 days).
- Option A: promotion is a copy by digest (`oras cp` / `crane copy`). Never rebuild during promotion.
- Option B: push from the validated OCI layout (`oras cp --from-oci-layout` / `crane push`). The digest in prod must equal `image-digest`.

### 6. GitHub Actions artifacts (B only)

- Short retention for image artifacts (e.g. 1–3 days) to control storage quota.
- Document the size limit and recommend Option A above it.

### 7. Exemption store

- Central Git repo. Changes go through PR, with approval required from security (CODEOWNERS).
- Each entry has: image/repo scope, owner, reason, approver, **expiry date**.
- Expired exemptions fail the gate automatically.
- Exempted images get a **separately-signed exemption attestation** rather than going unsigned, so Kyverno can tell "compliant" from "exempt".

### 8. Attestations attached to every image pushed to prod

- Compliance result (base digest, base age, check version, ingest source)
- SBOM
- Build provenance (SLSA)
- Exemption attestation (exempt images only)

### 9. Kyverno ImageValidatingPolicy (all clusters)

- Verify Notation signatures against the platform trust store / certificate.
- Require the compliance attestation for normal workloads.
- Allow the exemption attestation only where policy permits (e.g. specific namespaces or clusters). Reject if the exemption has expired.
- Restrict image sources to prod repos only. Staging repos are never admitted.
- Roll out in audit mode first, then enforce.

## Security controls checklist

- [ ] Vault `platform-signer` role bound to `job_workflow_ref` (tag-pinned)
- [ ] Tag protection on the platform-workflows repo
- [ ] Signing key non-exportable (Transit / KMS / AWS Signer plugin)
- [ ] Signing job runs only on platform-controlled or ephemeral runners
- [ ] Prod ECR write restricted to the platform identity
- [ ] No `secrets: inherit` into the reusable workflow
- [ ] Short-lived Vault tokens
- [ ] (A) Staging repos never pullable by clusters; lifecycle cleanup on
- [ ] (B) Digest recomputed from tarball and matched; layout validated; size limit enforced
- [ ] (B) Check and push happen in the same job, from the same downloaded bytes
- [ ] Exemptions have expiry and security approval
- [ ] Kyverno restricts registries to prod repos
- [ ] Audit logs on Vault, ECR and Kyverno policy reports

## Tenant integration (what teams add)

### Option A: staging registry

```yaml
jobs:
  build:
    # tenant-owned: build + push to staging ECR (Vault role tenant-push-<team>)
    outputs:
      digest: ${{ steps.push.outputs.digest }}

  gate:
    needs: build
    permissions:
      id-token: write
      contents: read
    uses: <org>/platform-workflows/.github/workflows/gate.yml@v1
    with:
      source: registry
      staging-ref: <staging-ecr>/team-a/app
      image-digest: ${{ needs.build.outputs.digest }}
      target-repo: team-a/app

  deploy:
    needs: gate
    # tenant-owned: deploy using ${{ needs.gate.outputs.image-ref }}
```

### Option B: OCI tarball

```yaml
jobs:
  build:
    outputs:
      digest: ${{ steps.digest.outputs.digest }}
    steps:
      # tenant-owned build, exported as an OCI layout
      - run: docker buildx build --output type=oci,dest=image.tar .
      - id: digest
        run: echo "digest=$(tar -xOf image.tar index.json | jq -r '.manifests[0].digest')" >> "$GITHUB_OUTPUT"
      - uses: actions/upload-artifact@v4
        with:
          name: oci-image
          path: image.tar
          retention-days: 1

  gate:
    needs: build
    permissions:
      id-token: write
      contents: read
    uses: <org>/platform-workflows/.github/workflows/gate.yml@v1
    with:
      source: oci-artifact
      artifact-name: oci-image
      image-digest: ${{ needs.build.outputs.digest }}
      target-repo: team-a/app

  deploy:
    needs: gate
    # tenant-owned: deploy using ${{ needs.gate.outputs.image-ref }}
```

## Suggested delivery phases

1. **Foundations:** Vault `platform-signer` role, prod ECR write lockdown, KMS-backed Notation signing.
2. **Base image pipeline:** scheduled rebuilds plus the approved-digests manifest.
3. **Gate workflow + checker, Option B first:** fewest moving parts (no staging infra or tenant creds). Pilot with 1–2 teams.
4. **Option A:** staging repos, tenant push roles, lifecycle policies. Onboard teams with large images.
5. **Exemptions:** store, PR approval flow, exemption attestations.
6. **Kyverno:** audit mode across clusters, review policy reports, then enforce.
7. **Expansion:** onboard all teams; add non-GitHub CI support via the checker container plus a promotion service.

## Open questions

- Freshness checked at **build time** only, or also at **admission** (images going stale while running)?
- Exempt images allowed in all clusters, or limited to specific environments?
- Ownership and SLA for the base image rebuild pipeline.
- Handling for multi-arch image indexes (check and sign the index and/or every platform manifest).
- Size threshold for Option B, and whether to enforce it or only recommend it.
- GitHub Actions artifact storage quota across the org if many teams use Option B.
