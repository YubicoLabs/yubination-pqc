# Challenge 03 — Upgrade without stranding the user

**Investigation + thought experiment.** Your user can sign in today. They want a PQ credential tomorrow. Preserve access—and notice when access is not enough.

**Objective:** distinguish observed coexistence/replacement from assumptions and separate account recovery from data recovery. Prerequisite: challenge 01 or 02. These demos do not implement automatic upgrade or extension-secret transfer.

## Predict

The same authenticator supports classical and PQ credentials. The RP uses identifier-first sign-in. Will a new registration preserve the old credential? Make a prediction before opening the hint.

## Do

1. Inspect the SimpleWebAuthn registration options from challenge 01. Find the RP ID, stable user handle, algorithms, resident-key preference and exclusion list. Inspect the discoverability report; missing evidence stays unknown.
2. Look for the old credential ID in the exclusion list. Predict whether registration on that authenticator would be blocked. Do not reset records or remove exclusions just to force it through.
3. Explain what would establish coexistence: successful assertions targeting each credential separately after enrollment—not two database rows. The demo's multi-credential Authenticate button alone does not establish this.
4. Take the twist below. Decide out loud what you would protect before retiring the old credential. No document to fill in.

<details>
<summary>Hint: identifier-first is not a storage guarantee</summary>

Sign-in UX does not establish replacement behavior. RP/user identity, discoverability, exclusions and device behavior matter. A controlled test needs a disposable account, an independent tested access path and single-credential requests before and after enrollment. That requires additional request control, not a built-in migration feature here. Never experiment on your only working credential.

</details>

## Reveal — sign-in works, but the files are unreadable

**Thought experiment:** your application encrypts files using a key derived from the old credential's PRF output. The new PQ credential signs in successfully. Can the user still decrypt the files?

<details>
<summary>Compare your reasoning</summary>

New enrollment does not promise the old PRF-derived secret. Before retirement, the application needs tested data-key migration or independent data recovery. A help desk that restores account access may still be unable to recover encrypted data.

Now introduce an interruption: credential creation succeeds, but RP persistence fails. Or the backup turns out to be on the same physical device. Test new authentication and independent recovery before retirement. Consumer support, employer/admin enrollment and regulated-account recovery have different owners and constraints.

</details>

## Optional deep dive — what else depends on this credential?

Investigate exact device/client/version support for PRF/hmac-secret, largeBlob, credBlob, credProtect, credProps and applicable minPinLength metadata. These are not all secrets or one transferable blob: distinguish data recovery, settings and client reports.

The [algorithm-upgrades explainer](https://github.com/w3c/webauthn/blob/main/explainers/alg-upgrades.md) proposes preserving relevant properties/secrets. It is not implemented by these demos and is not equivalent to new enrollment.

## Done when

**Win:** point to one observed property, identify one behavior needing a controlled test, and explain how successful sign-in can coexist with lost data. Protect a tested independent access path. No deletion is required to finish.

**Next:** [Find the dangerous assumption](policy.md).
