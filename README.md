# YubiNation: post-quantum authentication in existing demos

**Hands-on challenges for developers and identity/security architects.**

Use the projects' own interfaces and implementations. Learn how to request and inspect a credential in SimpleWebAuthn, then how an identity platform enforces requirements across applications and SSO in Keycloak.

## Start with a demo

| Your goal | Existing demo | First action |
| --- | --- | --- |
| Build an application | [SimpleWebAuthn demo — localhost:8010](http://localhost:8010) | Select **Register**, complete the browser prompt, then **Authenticate**. No account creation or password: this example uses one shared synthetic user. |
| Integrate an identity platform | [Keycloak Standard App — localhost:8091](http://localhost:8091) | Follow its own sign-in/registration flow. Compare with the [Secure App — localhost:8092](http://localhost:8092). |

First follow [setup](docs/setup.md) to build the included examples. These URLs are local services on your machine. The SimpleWebAuthn example is adapted for PQ exploration. The Keycloak example uses a custom provider; it is not a stock Keycloak PQ release.

**[Application builder walkthrough](docs/simplewebauthn.md)** · **[Identity-platform walkthrough](docs/keycloak.md)** · **[Setup and recovery](docs/setup.md)**

## What you will learn

1. **Know what was registered:** separate requested algorithms, the verified public-key algorithm, discoverability reports and authenticator trust.
2. **Enforce the credential actually used:** distinguish a valid signature from acceptance by a protected application, including SSO.
3. **Plan a safe migration:** identify coexistence/replacement, backup and extension-data risks without making unsupported assumptions.
4. **Own policy changes:** separate stored facts from current acceptance, and identify who approves and communicates changes.

Complete one demo first. Use the second for its distinct learning objective.

## Choose your journey

**Developers:** [What did you actually register?](docs/simplewebauthn.md) → [Valid signature. Access denied.](docs/keycloak.md) → optional [migration investigation](docs/migration.md). Follow a real result into the code that verifies and enforces it.

**Architects:** [Valid signature. Access denied.](docs/keycloak.md) → [Upgrade without stranding the user](docs/migration.md) → [Find the dangerous assumption](docs/policy.md). Challenge session, recovery and policy assumptions. Visit challenge 01 to inspect the underlying evidence.

Predict first, try it, then reveal the explanation. Play solo or with a colleague. No worksheets, submissions or points.

## Four small challenges

| Challenge | Do | Done when |
| --- | --- | --- |
| **01 — What did you actually register?** | Live experiment: predict, register, inspect and authenticate. | Show the algorithm and one limit of its evidence. |
| **02 — Valid signature. Access denied.** | Live experiment: compare Standard, Secure and SSO. | Show the allow/deny boundary and its enforcement point. |
| **03 — Upgrade without stranding the user** | [Investigation](docs/migration.md): inspect the request, then confront a lost-data twist. | Separate observed behavior from assumptions and protect independent access. |
| **04 — Find the dangerous assumption** | [Code-review puzzle](docs/policy.md): challenge a plausible acceptance rule. | Replace a permanent badge with an evidence-based decision. |

Challenge 03 combines read-only inspection with a thought experiment; controlled replacement testing is optional. Challenge 04 is a thought experiment. No automatic upgrade, extension-secret transfer or self-service PQ-only opt-in feature is claimed for these demos.

## No PQ hardware?

Read the walkthroughs or run the [software tests](docs/testing.md). They exercise cryptography with software-generated credentials, not browser/YubiKey interoperability or secure hardware storage.

## Boundaries and provenance

- Local synthetic accounts only. Do not expose these demos publicly or use them for production authentication.
- The SimpleWebAuthn example shares one user and stores credentials in memory. Restart/reset loses RP records, not authenticator credentials.
- Keycloak has its own account/session model and custom provider. Its enrollment-session semantics differ from fresh-assertion evidence; see the walkthrough.
- Neither a PQ credential nor a PQ-signed token establishes end-to-end system PQ protection.
- [Implementation boundaries](docs/implementation.md), [testing](docs/testing.md), [security and limitations](SECURITY.md), and [third-party attribution](THIRD_PARTY_NOTICES.md).
