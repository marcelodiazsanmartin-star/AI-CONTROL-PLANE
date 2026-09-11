# CONTROL-05R1.1 Trust Anchor contract

This implementation candidate requires independent review. It does not certify
CONTROL-05, authorize deployment, or enable ORACLE or real-money execution.

The production path is ORACLE -> authenticated proposal API -> separate
AI-CONTROL-PLANE Trust Anchor service -> Google Cloud KMS and Google Cloud Storage.
runtime.build_production_service is the production composition root. ORACLE's
client imports public contracts and verification only; it receives neither an
issuer object nor cloud credentials. The WSGI application has distinct ADMIN and
ORACLE routes with verified Google OIDC audience, issuer, expiry and pinned subject
checks. Both routes and operations enforce capabilities.

GoogleCloudKMSSigner signs raw canonical data using the pinned EC_SIGN_ED25519
KMS version. Each result is verified against the pinned public key and exact input.
No production module generates, reads, writes or exports a private key. KMS key
state, algorithm, public key, IAM policy hash and required/forbidden service
capabilities are attested before signing.

GoogleCloudMonotonicWitness stores immutable signed WitnessRecord objects at
journal/<deployment_identity>/<20-digit-global-sequence>.json. Each record binds
authority fingerprint, deployment/project/run/namespace/code/governance, sequence,
previous record hash, canonical payload/hash, UTC timestamp and KMS version.
One global chain covers all governed runs. Create-only uploads always require
ifGenerationMatch=0. Conflicting appends cannot overwrite a sequence slot.
Signature, continuity and semantic history checks precede acceptance. Ambiguous
timeouts fail closed; no retry skips to a different slot.

Every trusted read attests bucket name, project number, creation timestamp,
locked retention, uniform access, public access prevention, disabled versioning,
absence of lifecycle rules, IAM policy hash and effective service capabilities.
It enumerates all pages and reads exact object generations without caching.
Every record must remain inside retention. The oldest genesis record therefore
limits the deployment's trust horizon; expiry blocks and requires human review.
Finite retention is not described as permanent protection.

DeploymentIdentity.authority_fingerprint hashes canonical public KMS identity,
public-key DER hash, project/number, bucket/creation time, deployment/revision,
service identity, caller subjects/audience, governance version, retention and IAM
policy hashes. Genesis is pinned separately to avoid circular hashing. Identity
changes require governed migration, never rebinding an existing history.

## Genesis and capability separation

Startup requires an existing signed DEPLOYMENT_GENESIS at sequence zero matching
the release-pinned record hash. Its payload contains only approved_run_requests:
SHA-256 hashes of exact human-approved create requests. A separately authorized
operator provisions that object. Runtime has no method to create infrastructure,
a signer, deployment genesis or initial local cache.

A create request contains exactly action=CREATE_NEW_GOVERNED_RUN, project_id,
run_id, anchor_namespace_id, code_under_test_sha, governance_version and
human_approval_id. The ADMIN must authenticate AND submit a request matching the
preapproved genesis list. Invented approval references, changed code, duplicate
runs/namespaces and reused approval references are rejected. Provisioning must
validate the human decision before including any request; a string alone is not
approval evidence.

| Capability | ADMIN API | ORACLE API |
| --- | --- | --- |
| Create preapproved run | Yes | Denied |
| Renew authorization epoch | Yes | Denied |
| Read authorization/head | Core permits; HTTP routes reserved to ORACLE | Yes |
| Propose checkpoint | Denied | Yes |
| Arbitrary signing, replace genesis, reset, redirect | Denied | Denied |

Run creation appends epoch 1. Renewal appends the next epoch and invalidates older
authorization record hashes. ORACLE reads the current signed authorization.
Proposals bind that hash, run/namespace/code, next checkpoint sequence, previous
accepted hash and actual checkpoint/manifest bytes. Inputs are copied into bytes
before hashing and snapshotted at client/RPC boundaries. The service independently
decodes and hashes the data. It returns a signed witness record only after verified
external read-back and local-cache advancement.

## Local state and attacks

LocalState is an operational high-water cache containing fingerprint, sequence and
record hash. SQLite is not required. It is explicitly provisioned and compared
byte-for-byte with the externally verified tip at startup and before each request.
Missing, stale, divergent or corrupt state blocks. After an external append it
advances atomically. If that write fails, the external record remains and the call
fails closed.

LOCAL_AUTHORITY_STORAGE_CAN_BE_COMPLETELY_ROLLED_BACK_WITHOUT_REWRITING_THE_EXTERNAL_WITNESS

Restoring every local byte, including coordinated ORACLE rollback, is detected
against the external tip. A copied PC lacks the attached service identity/KMS
capability; a stale cache also fails reconciliation. ORACLE-only rollback cannot
replay a proposal against the current epoch/head. Redirection fails release-pin
checks; environment credential and metadata/emulator overrides are rejected.

The boundary assumes the governed service image, Google IAM/metadata/TLS, KMS and
retained GCS objects remain trusted. It does not claim protection against someone
who controls that image or can impersonate its service account through privileged
cloud administration. Independent deployment IAM review must exclude those
capabilities. Python object visibility is not process isolation.

## Production/test boundary and validation

testing.TestOnlyTrustAnchorAuthority preserves the old local SQLite/Ed25519
implementation solely for unchanged legacy tests. The historical package import
TrustAnchorAuthority lazily resolves to that named test class. Production runtime
never imports it and the service image must exclude testing.py. Legacy test passes
do not validate the new cloud boundary. New tests exercise production adapters
with offline cloud doubles and real local cryptographic token verification.

Run focused modules using explicit paths with python -m pytest. Run the full suite
through scripts/run_control05_validation.py --dependencies <directory> --label A
and repeat with label B. Each invocation creates an independent local clone,
overlays the candidate, retains logs outside the source and checks source hashes.
Existing crypto tests create signed commits only in disposable fixtures.
Canonical reports are not regenerated.

See [deployment specification](control05r1_1/DEPLOYMENT.md) and
[candidate provenance](control05r1_1/PROVENANCE.md).
