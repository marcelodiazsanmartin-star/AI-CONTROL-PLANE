"""Public contracts. Production starts only through trust_anchor.runtime.

The legacy TrustAnchorAuthority name is a compatibility alias for old local
tests, not a production authority capability. It is never loaded by runtime.
"""

from .authority import (AnchorAuthorization, AnchorAuthorizationVerifier,
                        AuthorityUnavailableError, CheckpointProposal,
                        GovernedRunIdentity, TrustAnchorError)


def __getattr__(name):
    if name == "TrustAnchorAuthority":
        from .testing import TestOnlyTrustAnchorAuthority
        return TestOnlyTrustAnchorAuthority
    raise AttributeError(name)

__all__ = ["AnchorAuthorization", "AnchorAuthorizationVerifier",
           "AuthorityUnavailableError", "CheckpointProposal",
           "GovernedRunIdentity", "TrustAnchorAuthority", "TrustAnchorError"]
