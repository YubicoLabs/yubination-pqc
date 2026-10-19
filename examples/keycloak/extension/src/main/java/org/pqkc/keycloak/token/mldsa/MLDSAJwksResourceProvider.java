package org.pqkc.keycloak.token.mldsa;

import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import org.keycloak.Config;
import org.keycloak.crypto.KeyStatus;
import org.keycloak.crypto.KeyUse;
import org.keycloak.crypto.KeyWrapper;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.services.resource.RealmResourceProvider;
import org.keycloak.services.resource.RealmResourceProviderFactory;

import java.security.PublicKey;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * Publishes the realm's ML-DSA public keys as an RFC 9964 JWK Set at
 * {@code /realms/{realm}/pq-jwks}.
 *
 * <p>This exists because Keycloak's own JWKS builder cannot carry them.
 * {@code JWKSServerUtils.getRealmJwks} is a <em>static</em> method whose body is a closed
 * {@code if/else} over RSA, EC and OKP that maps anything else to {@code null}, so an AKP key is
 * silently dropped from {@code /protocol/openid-connect/certs}. There is no SPI in front of it, so
 * unlike everything else here this one genuinely needs either a patched Keycloak class or a
 * side-channel; a side-channel is the honest, non-invasive choice.
 *
 * <p>The consequence is that the keys are correct and standards-shaped but not discoverable at the
 * conventional location, so a relying party has to be pointed at this URL explicitly.
 */
public class MLDSAJwksResourceProvider implements RealmResourceProvider {

    private final KeycloakSession session;

    public MLDSAJwksResourceProvider(KeycloakSession session) {
        this.session = session;
    }

    @Override
    public Object getResource() {
        return this;
    }

    /** {@code @Path("")} is required: RESTEasy Reactive will not match a bare @GET here. */
    @GET
    @Path("")
    @Produces(MediaType.APPLICATION_JSON)
    public Response keys() {
        List<Map<String, Object>> keys = session.keys()
                .getKeysStream(session.getContext().getRealm())
                .filter(k -> MLDSAKeys.KEY_TYPE_AKP.equals(k.getType()))
                .filter(k -> k.getStatus() == KeyStatus.ACTIVE || k.getStatus() == KeyStatus.PASSIVE)
                .filter(k -> k.getPublicKey() != null)
                .map(MLDSAJwksResourceProvider::toJwk)
                .collect(Collectors.toList());
        return Response.ok(Map.of("keys", keys)).build();
    }

    /** RFC 9964 section 5: an AKP JWK carries the raw public key in {@code pub}, and {@code alg} is REQUIRED. */
    private static Map<String, Object> toJwk(KeyWrapper key) {
        Map<String, Object> jwk = new LinkedHashMap<>();
        jwk.put("kty", MLDSAKeys.KEY_TYPE_AKP);
        jwk.put("alg", key.getAlgorithmOrDefault());
        jwk.put("kid", key.getKid());
        jwk.put("use", (key.getUse() == null ? KeyUse.SIG : key.getUse()).getSpecName());
        jwk.put("pub", Base64.getUrlEncoder().withoutPadding()
                .encodeToString(MLDSAKeys.rawPublicKey((PublicKey) key.getPublicKey())));
        return jwk;
    }

    @Override
    public void close() { /* NOP */ }

    public static class Factory implements RealmResourceProviderFactory {
        public static final String ID = "pq-jwks";

        @Override
        public RealmResourceProvider create(KeycloakSession session) {
            return new MLDSAJwksResourceProvider(session);
        }

        @Override public String getId() { return ID; }
        @Override public void init(Config.Scope config) { MLDSAKeys.ensureBouncyCastle(); }
        @Override public void postInit(KeycloakSessionFactory factory) { /* NOP */ }
        @Override public void close() { /* NOP */ }
    }
}
