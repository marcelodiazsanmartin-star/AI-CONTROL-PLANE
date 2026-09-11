# CONTROL-05R1.1 deployment specification

This document is not provisioning authorization. No cloud resource, account,
key, IAM binding or Cloud Run service was created. Governance must select actual
resource names and retention duration. The 100-year retention in offline fixtures
is test data, not a selected production risk policy.

The separate service runs the WSGI factory
`src.trust_anchor.http_api:create_application()` behind authenticated Cloud Run
HTTPS. It uses Python 3.12 and requirements-control05.txt. Example process:
`gunicorn --bind 0.0.0.0:8080 --workers 1 --threads 1 'src.trust_anchor.http_api:create_application()'`.
Use one active instance with this operational-cache model. GCS create-only writes
still reject competing instances; a stale instance blocks for governed recovery.

The immutable image includes src/__init__.py and the production trust_anchor
modules. Exclude testing.py, tests, preserved candidate text, private material
and other project runtimes. Governance installs the public
src/trust_anchor/deployment_identity.json matching the DeploymentIdentity schema.
This file must be image-owned and read-only, never supplied by ORACLE, an
environment override or a writable cache mount. This candidate intentionally
ships no deployable identity manifest; absence fails closed.

The attached workload must match pinned service_email, numeric service_subject,
service_revision and audience. Runtime uses metadata-bound compute credentials,
not general ADC or service-account JSON. Google verifies caller tokens against
its certificate endpoint. ADMIN, ORACLE and service subjects must be distinct.
Callers must not impersonate the service or update its deployment.

## Resources required by a future authorized operator

| Resource | Required specification |
| --- | --- |
| GCP project | Governance-selected trust-domain project; project number pinned |
| GCS bucket | Dedicated witness; name and creation timestamp pinned |
| Retention | Approved duration locked before startup; all records unexpired |
| Bucket posture | Uniform access enabled; public access prevention enforced; versioning disabled; no lifecycle rules |
| KMS | Precreated key ring, ASYMMETRIC_SIGN key and enabled EC_SIGN_ED25519 version; version/public PEM pinned |
| Runtime identity | Dedicated attached Trust Anchor service account; no user-managed key |
| Caller identities | Distinct ORACLE and ADMIN numeric subjects; invoke only |
| Cloud Run | Separate service and pinned immutable revision/image; IAM invoker authentication mandatory |
| Operational cache | Explicitly provisioned writable /var/lib/trust-anchor/head.json; never the witness |

The runtime service needs a custom bucket role containing only
storage.buckets.get, storage.buckets.getIamPolicy, storage.objects.get,
storage.objects.list and storage.objects.create. Its key role contains only
cloudkms.cryptoKeys.getIamPolicy, cloudkms.cryptoKeyVersions.get,
cloudkms.cryptoKeyVersions.viewPublicKey and cloudkms.cryptoKeyVersions.useToSign.
ADMIN and ORACLE get run.routes.invoke only; application checks separate routes.
They get no GCS/KMS authority and no service-account impersonation rights.

A separately controlled provisioning principal alone may initially create the
resources, lock retention, install genesis/cache, set IAM or install release
material. All of those actions require separate authorization. Runtime is denied
object deletion/update/restore/move, retention/IAM changes, KMS creation/destruction/
rotation, infrastructure provisioning and impersonation. iam.py defines the
required and forbidden permissions checked on the actual pinned resources.

policy_hash computes SHA-256 over canonical policy JSON excluding only etag.
Bindings, conditions and version remain included. Pin the actual API output;
serialization/order changes intentionally block for review. Policy hashes alone
do not prove absence of inherited project/folder/organization grants or changed
custom roles. Independent deployment review MUST verify effective permissions
for all three subjects at every ancestor, role definitions, impersonation paths,
organization constraints and Cloud Run invocation/deployment policy. Runtime
also checks its effective required/forbidden bucket/key permissions. This phase
does not claim actual deployed IAM validation.

## Governed provisioning and startup

1. Obtain human authorization for actual resources, duration, identities,
   deployment and exact run requests. This document does not grant it.
2. The authorized operator creates/configures the bucket/KMS resources and locks
   the retention posture. Runtime exposes no such method.
3. Capture project number, bucket timestamp, KMS version/public key, resource IAM
   policy hashes, revision, caller/service subjects, audience and retention in
   DeploymentIdentity. Compute its authority fingerprint; genesis_record_hash is
   deliberately excluded from that computation to avoid circular hashing.
4. Build one DEPLOYMENT_GENESIS record at global sequence 0 with all-zero previous
   hash, pinned deployment/fingerprint/KMS bindings, governed project/run/namespace/
   code identifiers and UTC time. Its canonical payload contains only
   approved_run_requests: hashes of exact human-approved create requests including
   their real approval references. Sign the canonical unsigned record through KMS
   and create the sequence-zero object with generation match 0. This separate
   provisioning step is not implemented as a runtime API.
5. Pin the signed genesis record hash in the release manifest. Validate the full
   externally protected journal and install LocalState.snapshot(identity, records)
   as the initial operational cache. Do not import legacy SQLite history or keys.
6. Start the separate service. It checks attached identity, KMS key/permissions,
   bucket identity/retention/IAM, genesis, every signature and history transition,
   then compares the existing local cache to the external tip. Missing or
   contradictory evidence blocks; no automatic provisioning/repair occurs.
7. Authenticated ADMIN submits the exact preapproved create request. ORACLE may
   then read authorization and submit bounded checkpoint proposals.

## Recovery and operational limits

Cache loss, full local rollback, stale concurrent instance or an upload committed
externally but not locally blocks the service. Preserve its external record and
local diagnostics. A separately authorized operator validates the entire pinned
external history and installs the current cache before restart. Do not replace
genesis, overwrite cloud objects, generate a local key or adopt local history.
An ephemeral Cloud Run filesystem needs governed cache restoration after instance
replacement. Persistent cache handling and recovery automation require independent
operational review before deployment.

Retention is finite; object metadata/IAM are not protected like retained contents.
Expiry of any record blocks runtime even if its account cannot delete objects.
Any retention extension, identity/revision/key/policy migration needs governance
before the oldest genesis expires. No local-trust fallback, automatic rebasing,
retry to another sequence or in-process ORACLE issuer is supported.

Offline doubles model generation CAS, signed records, retention metadata,
permissions and outages. They do not establish actual resource protection, cloud
clock/TLS trust, inherited IAM or operational recovery readiness. Those require
a separately authorized integration exercise and independent review.

Sources: [GCS create-only preconditions](https://docs.cloud.google.com/storage/docs/request-preconditions),
[object/list consistency](https://docs.cloud.google.com/storage/docs/consistency),
[Bucket Lock retention/metadata limits](https://docs.cloud.google.com/storage/docs/bucket-lock),
[KMS PureEdDSA algorithms](https://docs.cloud.google.com/kms/docs/algorithms),
[KMS signing API](https://docs.cloud.google.com/kms/docs/reference/rpc/google.cloud.kms.v1),
[Cloud Run authentication](https://docs.cloud.google.com/run/docs/authenticating/service-to-service).
