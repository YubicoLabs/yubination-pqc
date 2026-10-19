# Security and compatibility

These are educational localhost examples, not production authentication services. Use synthetic accounts. Do not publish their ports or reuse their demonstration passwords. Keycloak and PostgreSQL have intentionally visible local demo credentials; replace the entire deployment design before any production use.

Do not commit private keys, tokens, authenticator exports, personal information or runtime databases. Report sensitive findings through your organization's established security reporting channel, not a public issue containing secrets.

Keep verified credential facts, validated authenticator evidence and policy eligibility separate. A PQ signature does not establish secure hardware storage, trusted model identity or PQ protection of transport/recovery/federation paths.

Browser and hardware compatibility varies. No comprehensive compatibility matrix is claimed. An embedded browser may reject Keycloak's passkey-naming popup after device credential creation; use a regular supported browser and inspect enrollment state before retrying. Do not remove your only working access method.
