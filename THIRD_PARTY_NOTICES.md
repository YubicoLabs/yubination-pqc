# Third-party components

The examples build on [SimpleWebAuthn](https://github.com/MasterKale/SimpleWebAuthn), [Keycloak](https://github.com/keycloak/keycloak), [WebAuthn4J](https://github.com/webauthn4j/webauthn4j), Bouncy Castle, Node.js, Express and PostgreSQL. Their dependencies retain their respective licenses and notices. Dependency versions are declared in the example package lockfile, Maven POM files and Dockerfiles.

Original contributions and modifications are licensed under the repository's [Apache License 2.0](LICENSE). Third-party portions retain their upstream licenses. The Keycloak extension and example-specific adaptations are not represented as upstream releases or endorsed implementations.

## Source attribution

The SimpleWebAuthn example adapts the [v14.0.0 example](https://github.com/MasterKale/SimpleWebAuthn/tree/v14.0.0/example). Copyright (c) 2020 Matthew Miller. The upstream [MIT license](licenses/SimpleWebAuthn-MIT.txt) applies to its upstream portions; it does not establish ownership of subsequent contributions.

The custom Keycloak registration provider adapts registration logic from Keycloak 26.4.7. Retain the upstream source notices and [Apache License 2.0](licenses/Apache-2.0.txt). Adaptations add ML-DSA algorithm handling and custom evidence/policy behavior; they are not an unmodified upstream release.

## Built artifacts

Installed npm packages and downloaded container images carry their own licenses; do not strip those notices when redistributing builds. The Java software-authenticator build preserves dependency license/notice resources in artifact-specific directories under `META-INF/dependency-notices` to avoid collisions between identically named files. Bouncy Castle's license is additionally provided as a readable resource there. The root LICENSE does not replace these third-party terms.
