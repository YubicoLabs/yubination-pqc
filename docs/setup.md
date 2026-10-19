# Run the examples

Prerequisites: Docker Engine with Compose v2, network access for initial image/dependency downloads, and free local ports 8010, 8085, 8091, 8092 and 9001. Use a supported regular browser and test authenticator for hardware ceremonies. The examples are for localhost, not public deployment.

From the repository root:

```sh
docker compose -p yubination-simplewebauthn -f examples/simplewebauthn/docker-compose.yml up -d --build --wait
docker compose -p yubination-keycloak -f examples/keycloak/docker-compose.yml up -d --build --wait
```

You can start either example independently. Open [SimpleWebAuthn](http://localhost:8010), or [Keycloak Standard](http://localhost:8091) and [Secure](http://localhost:8092).

SimpleWebAuthn uses one synthetic user: **Register → Authenticate**, no account/password. Keycloak uses its own account flow: **Sign in with a passkey → Register**. Use synthetic profile information. Regular Chrome avoids the unsupported naming popup seen in some embedded browsers. Browser/OS/device compatibility must be tested; offering ML-DSA is not proof that it was selected.

## Configuration

SimpleWebAuthn's Compose environment controls offered algorithms, user verification and discoverability. The default allows platform and roaming authenticators and offers classical/PQ algorithms. Setting `ALGORITHMS: "-7"` creates a classical-only control. Rebuilding/recreating the container loses its in-memory RP records, so configuration changes are not an in-place migration test.

Keycloak uses the included realm and experimental provider. The realm is imported on first startup; changing its JSON does not overwrite an existing realm. Do not delete your database volume to apply changes to an account you need.

## Stop and recover safely

```sh
docker compose -p yubination-simplewebauthn -f examples/simplewebauthn/docker-compose.yml stop
docker compose -p yubination-keycloak -f examples/keycloak/docker-compose.yml stop
```

Do not add `down -v` as routine troubleshooting. Keycloak data persists in its project volume. SimpleWebAuthn restart/reset loses RP records, not credentials held by the authenticator. Do not erase authenticator credentials blindly.

If a port is occupied, stop the conflicting demo deliberately; do not kill unrelated services. Never bypass certificate warnings. Remote hosting and Codespaces are not supported by these localhost instructions.
