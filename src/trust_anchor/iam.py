"""Required runtime capabilities and forbidden mutations, scoped to pinned resources."""

WITNESS_REQUIRED = frozenset({"storage.buckets.get", "storage.buckets.getIamPolicy",
    "storage.objects.get", "storage.objects.list", "storage.objects.create"})
WITNESS_FORBIDDEN = frozenset({"storage.buckets.update", "storage.buckets.delete", "storage.buckets.setIamPolicy",
    "storage.objects.delete", "storage.objects.update", "storage.objects.restore", "storage.objects.move",
    "storage.objects.overrideUnlockedRetention"})
KMS_REQUIRED = frozenset({"cloudkms.cryptoKeys.getIamPolicy", "cloudkms.cryptoKeyVersions.get",
    "cloudkms.cryptoKeyVersions.viewPublicKey", "cloudkms.cryptoKeyVersions.useToSign"})
KMS_FORBIDDEN = frozenset({"cloudkms.cryptoKeys.setIamPolicy", "cloudkms.cryptoKeys.update",
    "cloudkms.cryptoKeyVersions.create", "cloudkms.cryptoKeyVersions.destroy", "cloudkms.cryptoKeyVersions.update"})

# Caller identities receive Cloud Run invoke only. App-layer role checks split
# ADMIN/ORACLE endpoints. They get NONE of the above GCS/KMS permissions and no
# ability to impersonate the attached service or modify its deployment.
CALLER_GCP_CAPABILITIES = frozenset({"run.routes.invoke"})
