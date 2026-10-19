# Challenge 01 — What did you actually register?

**Live experiment · developer starting point.** Your mission: catch the difference between what the RP requests and what it can prove. Predict before inspecting the result.

**Objective:** distinguish request preference, verified credential algorithm and authenticator trust. **Prerequisite:** running demo; a supported browser and test authenticator. PQ hardware is needed only for the hardware PQ comparison.

## Predict

Does listing ML-DSA first guarantee a PQ credential? Does a returned AAGUID prove the private key is secured in a particular model?

## Do

1. Open http://localhost:8010. Read the server configuration: origin, RP ID, runtime, offered algorithms and user-verification requirement.
2. Click **Register**. Complete the browser/OS prompt yourself. There is no account-creation form; the inherited demo uses one synthetic user.
3. Read **Registration Options** and **Server Response** in the existing console. Compare `pubKeyCredParams` with the returned `algorithm`.
4. Click **Authenticate**, complete the prompt, and inspect the verification result. This exercises assertion verification; the demo does not issue a production application session.
5. To compare a platform authenticator and a PQ security key, register each using the browser's device choices, then authenticate. The local configuration does not force a cross-platform authenticator. Inspect the algorithm actually returned; never label a credential merely from the device's name.
6. If the browser chooses a different credential than expected, inspect `id` in **Authentication Response** and the verified `algorithm` in **Server Response**; the server response does not repeat the ID. Do not assume the first allow-list entry determines the choice. A precise single-credential request is a separate controlled test, not a reason to change the browser's result label.

## Reveal

<details>
<summary>Compare your prediction with the verified result</summary>

The public-key algorithm is obtained from the verified registration, not a client-provided PQ badge. ML-DSA IDs are -48/-49/-50; ES256 is -7. Registration and authentication are distinct observations.

The adaptation requests `credProps`; absent `rk` stays unknown. Returned `rk` is client-reported and is not signed model evidence. The default attestation request is `none`. Inspecting an attestation certificate is not equivalent to validating a trusted chain and metadata status. No hardware-protection/certification claim follows from this page.

</details>

<details>
<summary>Need a hint?</summary>

Compare `pubKeyCredParams` with the server's verified result. A device name is not an algorithm; an algorithm is not a hardware trust decision.

</details>

## If it fails

- **Authenticate before registration:** the demo should explain that a test credential must be registered first.
- **Cancel the browser prompt:** return to the demo and retry. Do not treat cancellation as a successful registration.
- **Already registered:** use another test authenticator; do not casually reset RP records to bypass exclusions.
- **PQ not available:** record exact browser/OS/firmware and requested/returned algorithm. Use the software path rather than claiming hardware support.
- **Server restarted:** in-memory credentials were lost. The authenticator may still hold them. See [setup](setup.md).

## Optional deep dive — follow the public API

In the supplied example's `app/index.ts`: `generateRegistrationOptions()`, `verifyRegistrationResponse()`, decoding `credential.publicKey`, and `verifyAuthenticationResponse()`. Follow the saved challenge and the identical offered/accepted algorithm list. The local adaptation adds a stable user handle, typed/expiring single-use challenges and user verification consistent with configuration; it does not add account management.

## Done when

Explain which result establishes the credential algorithm, what evidence is unknown/untrusted, and which additional work a production RP would need. Do not publish raw credential/attestation data.

**Win:** show your result and explain one claim it cannot support. No submission required.

**Next:** [Valid signature. Access denied.](keycloak.md) or [Upgrade without stranding the user](migration.md).
