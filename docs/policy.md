# Challenge 04 — Find the dangerous assumption

**Optional code-review puzzle.** Play solo or ask a colleague to defend this design. No running policy editor required.

**Objective:** separate stored credential facts, trusted authenticator evidence and current policy eligibility.

## Predict

> “We store `isPostQuantum=true` when any PQ credential is registered. If the account has that flag, Secure accepts the user forever.”

How many failure cases can you find before opening the answer?

## Do

Review this deliberately flawed pseudocode—not code from either demo:

```text
onRegistration(account, credential):
    if credential.algorithm is PQ:
        account.isPostQuantum = true

allowSecureApp(account, session):
    return account.isPostQuantum
```

Try three attacks on the reasoning:

1. This session used a classical credential, although the account owns a PQ credential.
2. Approved algorithm policy changes after enrollment.
3. Secure also requires evidence of approved hardware.

Say what you would change. No PR or written submission required.

## Reveal

<details>
<summary>Compare your reasoning: three questions were collapsed into one flag</summary>

**What was used?** Evaluate verified authentication/session evidence, not the best credential in inventory. Treat SSO, enrollment-derived sessions, recovery and brokered logins explicitly. Missing provenance cannot become inferred PQ authentication.

**Is it accepted now?** Preserve the stored public-key algorithm. Compute eligibility against a versioned, approved policy. Monitoring informs governance; it does not authorize automatic production changes.

**What hardware evidence is trusted?** A PQ algorithm does not prove model, key protection or certification. Where required, separately validate attestation, trust chains and applicable metadata/status. An unvalidated AAGUID is insufficient.

Conceptual replacement—not a production implementation:

```text
decision = evaluate(
    verifiedAuthenticationEvidence,
    validatedAuthenticatorEvidence,
    approvedPolicyVersion,
    applicationAndSessionRequirements
)
```

</details>

## Optional deep dive — make the policy change personal

Imagine a proposed policy accepts only ML-DSA-65/87 for Secure. This is fictional, not a claim that ML-DSA-44 is weak or deprecated. A user has ES256 and ML-DSA-44 credentials. What will they see next time? Who approves the change, warns the user and enables re-enrollment or recovery?

Developers: trace evidence and enforcement in `MLDSAPolicyAuthenticator` from challenge 02. Architects: name the owners of acceptance, session/token treatment, exceptions and rollback. NIST, IANA, FIDO and WebAuthn sources inform standards and identifiers; IAM/security governance owns deployment. Neither a metadata entry nor a green test run makes that decision.

## Done when

**Win:** give a counterexample to the original rule and explain a better decision boundary. Distinguish “valid credential,” “trusted authenticator” and “allowed here, now.”

**Take it back to work:** locate the equivalent boundary in your own RP or IAM platform. These examples teach selected boundaries, not a complete production system.
