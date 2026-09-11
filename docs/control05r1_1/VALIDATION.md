# CONTROL-05R1.1 local validation record

Engineering evidence only; not certification or production authorization.

Base: 33a1655a06e51dc5facfde2737ee0968c69ee27b.
Branch: codex/control-05-trust-anchor-authority.
Source: C:\Users\VD\Desktop\Antigravity\AI-CONTROL-PLANE-CODEX-TRUST-ANCHOR.

Both independent disposable checkouts used identical input file SHA-256 manifests.
Both completed with exit code 0 and source_modified_during_validation=[]:

| Run | Result | Duration | Retained artifact directory |
| --- | --- | --- | --- |
| A | 708 passed; no failures or skips | 145.38 seconds | C:\Users\VD\AppData\Local\Temp\control05-regression-A-dx45uxl7 |
| B | 708 passed; no failures or skips | 202.46 seconds | C:\Users\VD\AppData\Local\Temp\control05-regression-B-cyuaut0_ |

Each directory retains checkout/, pytest.log, junit.xml and validation.json.
The latter includes source input hashes and the source-integrity result.
The manifests were compared after both runs completed. This summary was added
after those runs and does not change executable code or test inputs.

Commands from the source root used Python 3.12.10:

```
python -B scripts/run_control05_validation.py --dependencies C:\Users\VD\AppData\Local\Temp\control05r1_1-cloud-deps-20260911 --label regression-A
python -B scripts/run_control05_validation.py --dependencies C:\Users\VD\AppData\Local\Temp\control05r1_1-cloud-deps-20260911 --label regression-B
```

The runner executed the complete tests/ suite with pytest -q, no cache provider,
and temporary basetemp/JUnit locations. It cloned local Git history without shared
object hardlinks, checked out the base detached, and overlaid the candidate. It
used a private copy of the embedded Python runtime with explicit checkout and
dependency paths, avoiding the installed interpreter's unrelated-worktree ._pth
entry. Git transport was restricted to file protocol. Legacy cryptographic tests
created signed commits only in temporary fixtures; no source commit/staging or
history operation occurred.

CONTROL-05 totals from the JUnit artifacts:

| Module | Tests |
| --- | ---: |
| test_control_05_trust_anchor.py (preserved) | 6 |
| test_control_05_trust_anchor_adversarial.py (preserved) | 16 |
| test_control_05_r1_1_functional.py | 6 |
| test_control_05_r1_1_attacks.py | 73 |
| test_control_05_r1_1_authentication.py | 21 |
| CONTROL-05 total | 122 |

Coverage includes whole local-cache rollback, coordinated ORACLE/cache rollback,
ORACLE replay, cloned storage/service identity rejection, configuration redirection,
preapproved genesis, immutable bytes, witness/KMS outages, retention and IAM
attestation, conflicting atomic appends, ambiguous upload outcomes, cache-write
failure, corrupted signed history, and real JWT signature/issuer/audience/expiry
checks against offline certificates. Other repository tests account for 586 cases.

Initial local tests passed 96 cases before authentication/capability additions.
The real-token suite then passed 21 cases. Final full runs above include every
addition. Dependency installation and early authentication collection encountered
Windows sandbox access failures; no tests were skipped or weakened to address
them. Authorized elevated runs used separate temporary directories. Dependency
versions used include pytest 9.1.1, cryptography 50.0.1, google-auth 2.58.0 and
requests 2.34.2. These were package downloads, not production/cloud-resource use.

Review scope consists of src/trust_anchor/, CONTROL-05 tests/support, the scoped
dependency file, validation runner, CONTROL-05 documentation/preserved candidate,
and the existing CI dependency-install line. No separate authoritative path
allowlist was provided. No other source module, CONTROL-TOWER, ORACLE, canonical
report/state/audit evidence or existing test assertion was changed. The source
Git status includes the two preexisting, unchanged, untracked legacy test files.

The six C05-REV remediations have local implementation and regression evidence.
Actual GCS retention, effective cloud IAM, KMS operation, attached identity and
Cloud Run deployment remain unprovisioned and untested against live resources.
Independent review is required before accepting these engineering assessments.
