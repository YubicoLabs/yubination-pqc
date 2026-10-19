#!/usr/bin/env bash
# End-to-end proof: register and authenticate a WebAuthn credential for each algorithm,
# then confirm forged assertions are rejected.
set -euo pipefail
cd "$(dirname "$0")"

BASE="${BASE:-http://localhost:8085}"
REALM="${REALM:-pq}"
CLIENT="${CLIENT:-test-app}"
REDIRECT="${REDIRECT:-$BASE/callback}"
JAR=virtual-authenticator/target/virtual-mldsa-authenticator.jar

if [ ! -f "$JAR" ]; then
  echo "building the virtual authenticator..."
  docker run --rm -v "$PWD/virtual-authenticator":/work -v kc-m2:/root/.m2 \
    -w /work maven:3.9-eclipse-temurin-21 mvn -B -q package
fi

echo "waiting for $BASE ..."
for i in $(seq 1 60); do
  curl -sf "$BASE/realms/$REALM" >/dev/null 2>&1 && break
  sleep 2
  [ "$i" = 60 ] && { echo "Keycloak did not come up"; exit 1; }
done

RUN="$(date +%s)"
FAILED=0
for ALG in ML-DSA-44 ML-DSA-65 ML-DSA-87 ES256; do
  echo
  echo "=============== $ALG ==============="
  TEST_USER="t${RUN}-$(echo "$ALG" | tr '[:upper:]' '[:lower:]')"
  if java -jar "$JAR" "$BASE" "$REALM" "$CLIENT" "$REDIRECT" "$TEST_USER" "$ALG"; then
    :
  else
    echo "FAILED: $ALG"
    FAILED=1
  fi
done

echo
echo "=============== PQ CREDENTIAL AND TOKEN SIGNATURES ==============="
if java -cp "$JAR" org.pqkc.webauthn.va.PqcTokenCheck "$BASE" "$REALM" "$RUN"; then
  :
else
  echo "FAILED: PQ credential/token checks"; FAILED=1
fi

echo
echo "=============== PER-APPLICATION POLICY ==============="
if java -cp "$JAR" org.pqkc.webauthn.va.AppMatrix "$BASE" "$REALM" "$RUN"; then
  :
else
  echo "FAILED: per-application policy"; FAILED=1
fi

echo
if [ "$FAILED" = 0 ]; then
  echo "ALL CHECKS PASSED"
  echo "  - ML-DSA-44/65/87 and ES256: register, authenticate, forgeries rejected"
  echo "  - app-secure admits only post-quantum credentials, app-standard admits any"
  echo "  - app-secure issues ML-DSA-signed tokens, verified against the published AKP JWK"
else
  echo "SOME CHECKS FAILED"; exit 1
fi
