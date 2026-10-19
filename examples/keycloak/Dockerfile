# syntax=docker/dockerfile:1

# Pinned on purpose. The extension reflects into webauthn4j internals, so if the floating "26.4"
# tag moved to a build carrying a different webauthn4j the provider would stop loading. Keep this
# in step with <keycloak.version> in extension/pom.xml; 26.4.7 ships webauthn4j 0.29.3 and
# BouncyCastle 1.82, which is what the extension is compiled and tested against.
ARG KEYCLOAK_VERSION=26.4.7

########## 1. build the ML-DSA provider ##########
FROM maven:3.9-eclipse-temurin-21 AS ext
WORKDIR /build
COPY extension/pom.xml .
RUN mvn -B -q dependency:go-offline
COPY extension/src ./src
RUN mvn -B -q package

########## 2. augment Keycloak with the provider ##########
FROM quay.io/keycloak/keycloak:${KEYCLOAK_VERSION} AS builder

ENV KC_DB=postgres
ENV KC_HEALTH_ENABLED=true
ENV KC_METRICS_ENABLED=true
ENV KC_FEATURES=web-authn

COPY --from=ext /build/target/keycloak-webauthn-mldsa.jar /opt/keycloak/providers/

# bake the provider into the Quarkus image so start --optimized needs no re-augmentation
RUN /opt/keycloak/bin/kc.sh build

########## 3. runtime ##########
FROM quay.io/keycloak/keycloak:${KEYCLOAK_VERSION}
COPY --from=builder /opt/keycloak/ /opt/keycloak/
COPY realm/pq-realm.json /opt/keycloak/data/import/pq-realm.json

ENTRYPOINT ["/opt/keycloak/bin/kc.sh"]
CMD ["start", "--optimized", "--import-realm"]
