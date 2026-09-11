# CONTROL-05R1.1 candidate provenance

The inherited witness.py was **UNTRUSTED_PREEXISTING_CANDIDATE**. Its author and
originating authorization remain unknown. Preexistence or resemblance to the
requested design is not acceptance evidence.

Before evaluation or modification in this implementation turn, its exact bytes
were copied with destination-existence protection and SHA-256 equality verification
to witness.py.preimplementation.txt in this directory. Size: 8,683 bytes.
SHA-256: d2117d0d6211922730eddabdfed638ccf432190385267869384b4736b78e18b4.
That copy is reference material and is never imported or executed.

Retained after inspection: canonical JSON with NaN forbidden; SHA-256; frozen
deployment/record contracts; public Ed25519 loading; unsigned record serialization
and signature verification; abstract signing/append-only witness methods; chained
sequence verification and run lookup.

Changed: added attached-service subject, revision, external genesis and resource
IAM policy pins. Fingerprint now includes service/caller identities, audience,
revision, retention and IAM hashes. Validation checks distinct numeric subjects,
revision, hash fields and bucket timestamp. Continuity requires a nonempty
externally provisioned pinned genesis and rejects replacement genesis. Record
types include deployment genesis. Diff the preserved bytes against the current
module for exact line changes.

Rejected assumptions: an empty journal is not a valid trust root; cloud-looking
configuration is not deployment identity evidence; the inherited abstraction
alone provides no atomic cloud append, retention/IAM attestation, authenticated
service boundary or rollback enforcement. No provenance or certification claim
was accepted from that file.

The old authority.py implementation moved to testing.py and was renamed
TestOnlyTrustAnchorAuthority. Local-key/SQLite behavior remains solely for the
unchanged legacy tests. Shared public contracts stay in authority.py with immutable
defensive checkpoint copies added. The old contract's local monotonic-authority
claims were replaced by the production R1.1 contract.

New production modules: google_cloud.py, iam.py, service.py, runtime.py, http_api.py
and public-only client.py. New tests cover functional behavior, rollback, clone,
redirection, genesis, immutability, outages, races, corrupt history and real JWT
verification. Runtime dependencies and the CI dependency-install line changed;
existing test assertions and CI gates remain unchanged.

Engineering self-assessments and test results require independent human review;
they are not certification or production authorization.
