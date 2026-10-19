# Test the examples

Tests establish different boundaries; none certifies production readiness or hardware support.

## Non-destructive guide and HTTP checks

With Node.js installed, from the repository root:

```sh
node scripts/check-guide.mjs
node scripts/check-demo-contracts.mjs
```

The second command needs the running examples at their default ports. It uses separate cookie-free sessions and checks options, discovery, served controls and rejection of missing challenges/cross-origin requests. It never creates accounts or resets credentials. It is not a browser ceremony or an authenticated SSO test.

## Software cryptography tests

Use a disposable example instance. **The SimpleWebAuthn harness resets its shared credential records. Do not run it against an instance containing records you want to keep.** With Node 24.22.0 or the included Node image:

```sh
cd examples/simplewebauthn/app
node e2e-mldsa.mjs http://localhost:8010
TEST_ALG=ML-DSA-65 node e2e-mldsa.mjs http://localhost:8010
TEST_ALG=ML-DSA-87 node e2e-mldsa.mjs http://localhost:8010
```

Keycloak provider unit tests run during its Docker build. Its software ceremony suite requires Java 21+, Docker and curl. From `examples/keycloak`, run `bash test.sh`. It creates synthetic test accounts, exercises classical/PQ signatures, forgery rejection and fresh-login/SSO policy paths. It does not replace real browser/YubiKey testing.

After building the Java software-authenticator JAR, run `node scripts/check-jar-notices.mjs` from the repository root (requires `unzip`). This checks the pinned dependency license/notice resources in the packaged JAR; it is not a legal-compliance certification.

## Hardware walkthrough

Use the challenge instructions. For each credential class, register, sign out, sign in freshly, enter Standard and then Secure, and verify the expected denial/acceptance. Test existing SSO separately from fresh authentication. Confirm logout by starting another sign-in. Record browser/OS/device versions; never share tokens or raw credential evidence publicly.
