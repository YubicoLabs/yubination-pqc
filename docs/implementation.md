# Implementation boundaries

## SimpleWebAuthn

The example uses server 14.0.3 and browser helper 14.0.0. Public APIs perform registration and assertion verification. The UI displays requested options and verified algorithm diagnostics. It uses a shared synthetic user and in-memory credentials, not an application account/session system.

Adaptations include a stable user handle, `credProps`, typed/expiring single-use challenges, required user verification, a random per-process session secret and cross-origin mutation rejection. Automatic conditional UI is not enabled because this example uses one pending challenge per session. These changes do not constitute production hardening.

## Keycloak

The example targets Keycloak 26.4.7 and WebAuthn4J 0.29.3 with a custom ML-DSA provider. It accesses internal APIs; changing versions requires compatibility testing. This is not a claim of stock Keycloak PQ support.

Standard and Secure use different policy flows. The provider evaluates authentication/session evidence rather than inferring it from credential inventory. Enrollment-derived session metadata remains distinct from a fresh assertion. PQ token signing is a separate extension and does not establish whole-system PQ protection.

Both examples retain their existing interfaces. Migration, recovery and policy governance exercises describe additional production decisions, not hidden implemented features.
