# Challenge 02 — Valid signature. Access denied.

**Live experiment · architect starting point.** Two applications, one identity platform. Predict where a valid sign-in stops being acceptable.

**Objective:** distinguish credential inventory from authentication evidence and enforce requirements across fresh login and SSO. **Prerequisite:** running supplied Keycloak demo and its two existing clients. This is a custom-provider example, not stock upstream PQ support.

## Predict

If a user has an ML-DSA credential somewhere in their account but signs in with ES256, should a PQ-required application accept that session?

## Do

1. Open the existing **Standard App** at http://localhost:8091. Click **Sign in with a passkey**, then **Register** on Keycloak's sign-in page. Enrollment asks for Username, Email, First name and Last name; use a unique synthetic username and email. Complete registration and the browser credential prompts yourself. Regular Chrome avoids the in-app browser's unsupported passkey-naming `prompt()` dialog.
2. Inspect the actual algorithm shown by the demo's authenticated claims. These are claims from the configured provider; inspect their provenance in the code, not just the UI label.
3. Visit **Secure App** at http://localhost:8092 in that same browser session and click **Sign in with a passkey**. Opening the app alone does not initiate SSO. Observe the outcome.
4. A session established with a classical credential must not enter the PQ-required client merely because the account has another PQ credential. Use separate synthetic classical/PQ accounts for the simplest first comparison.
5. Repeat with an eligible ML-DSA credential and a fresh sign-in. Compare fresh login and SSO separately. Log out using the existing client/Keycloak flow between independent trials.
6. Optional code/test investigation: check the missing-provenance regression test and provider. This case is not available as a participant UI control. The corrected local provider denies the PQ-required path rather than inferring the method from an account's sole stored credential.

## Reveal

<details>
<summary>Compare your predictions for Standard, Secure and SSO</summary>

| Credential evidence | Standard App | Secure App |
| --- | --- | --- |
| Valid ES256 fresh sign-in | Accept | Deny |
| Valid eligible ML-DSA fresh sign-in | Accept | Accept |
| SSO carrying classical authentication evidence | Per normal session rules | Deny |
| SSO carrying eligible PQ evidence | Per normal session rules | Evaluate and accept if otherwise valid |
| Missing provenance | Explicit normal-flow policy | Deny/step up; never infer from inventory |

Software tests cover the supplied fresh-login/SSO matrix. Hardware/browser results remain separate. The bundled clients and provider are a demo, not an assurance certification.

</details>

<details>
<summary>Hint: is owning a PQ credential enough?</summary>

Ask what established this session, not what exists in the account. The missing-provenance case requires the software harness; it has no UI toggle.

</details>

## Important distinction: registration sessions

The supplied provider stamps algorithm information during enrollment and permits a PQ enrollment session into the secure client. This is not evidence that a fresh assertion was performed. Keep registration-derived and assertion-derived session evidence distinct in explanations. Decide whether your production protected operation requires a fresh assertion and test it.

## Optional deep dive — find the enforcement point

In `extension/src/main/java/org/pqkc/keycloak/webauthn/mldsa/`, follow `MLDSAPolicyAuthenticator`, `CredentialAlgorithms`, and `MLDSAWebAuthnPasswordlessRegister`. Then inspect `realm/pq-realm.json` for client-specific flow bindings and session-note claim mappings. Include the cookie/SSO path, not only the WebAuthn form.

PQ OIDC token signing is a separate extension. A PQ-signed token does not turn classical user authentication into PQ authentication. It is not a prerequisite for this lesson.

Inspect the two algorithm fields separately: transport, recovery and other trust paths are not established by this display. The displayed claims are decoded by the client UI, not independently signature-verified by that display.

## Done when

Demonstrate the classical denial and eligible PQ acceptance, explain the SSO path, and identify where evidence originates. Document existing-session, recovery and brokered-login requirements for your own IAM platform.

**Win:** show classical denial and eligible PQ acceptance, then explain the SSO evidence. If you use software fixtures instead of hardware, label that evidence honestly.

**Next:** [Upgrade without stranding the user](migration.md).
