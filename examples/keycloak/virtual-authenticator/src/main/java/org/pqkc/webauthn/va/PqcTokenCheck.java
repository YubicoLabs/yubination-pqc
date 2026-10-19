package org.pqkc.webauthn.va;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.pqc.crypto.mldsa.MLDSAParameters;
import org.bouncycastle.pqc.crypto.mldsa.MLDSAPublicKeyParameters;
import org.bouncycastle.pqc.crypto.util.SubjectPublicKeyInfoFactory;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

/**
 * End-to-end post-quantum check: authenticate with an ML-DSA passkey, then verify that the ID token
 * Keycloak issues is itself signed with ML-DSA and validates against the published AKP public key.
 *
 * <p>The verification here is deliberately independent of Keycloak: the key is fetched from the
 * JWK Set, rebuilt from its raw FIPS 204 bytes, and the signature checked over the exact
 * {@code header.payload} octets - which is what any relying party would do.
 */
public class PqcTokenCheck {

    private static final Base64.Decoder B64URL = Base64.getUrlDecoder();
    private static final ObjectMapper JSON = new ObjectMapper();

    public static void main(String[] args) throws Exception {
        String base = args.length > 0 ? args[0] : "http://localhost:8085";
        String realm = args.length > 1 ? args[1] : "pq";
        String stamp = args.length > 2 ? args[2] : String.valueOf(System.currentTimeMillis());
        String clientId = "app-secure";
        String redirect = "http://localhost:8092/callback";

        Security.addProvider(new BouncyCastleProvider());
        String user = "pqtok" + stamp;

        Ceremony c = new Ceremony(base, realm, clientId, redirect);
        c.narrate = false;
        VirtualMLDSAAuthenticator auth = c.registerQuietly(user, "ML-DSA-44", -48L);
        if (!c.tryLogin(user, auth)) throw new IllegalStateException("login to " + clientId + " failed");
        System.out.println("authenticated with an ML-DSA-44 passkey");

        String jwt = c.lastRawIdToken();
        String[] parts = jwt.split("\\.");
        JsonNode header = JSON.readTree(B64URL.decode(parts[0]));
        String alg = header.path("alg").asText();
        String kid = header.path("kid").asText();
        byte[] signature = B64URL.decode(parts[2]);
        byte[] signedData = (parts[0] + "." + parts[1]).getBytes(StandardCharsets.US_ASCII);

        System.out.println("ID token JWS header: alg=" + alg + " kid=" + kid.substring(0, 12) + "...");
        System.out.println("  signature: " + signature.length + " bytes; whole token: " + jwt.length() + " chars");
        if (!alg.startsWith("ML-DSA")) {
            throw new IllegalStateException("token is not ML-DSA signed, alg=" + alg);
        }

        PublicKey publicKey = fetchAkpKey(base, realm, kid, alg);
        System.out.println("  fetched AKP JWK from /realms/" + realm + "/pq-jwks");

        Signature verifier = Signature.getInstance(alg, "BC");
        verifier.initVerify(publicKey);
        verifier.update(signedData);
        if (!verifier.verify(signature)) {
            throw new IllegalStateException("ID token signature did NOT verify");
        }
        System.out.println("  signature VERIFIED against the published ML-DSA public key");

        // a tampered payload must not verify
        byte[] tampered = signedData.clone();
        tampered[tampered.length - 1] ^= 0x01;
        Signature negative = Signature.getInstance(alg, "BC");
        negative.initVerify(publicKey);
        negative.update(tampered);
        if (negative.verify(signature)) {
            throw new IllegalStateException("SECURITY FAILURE: tampered token verified");
        }
        System.out.println("  tampered token rejected, as expected");

        JsonNode claims = JSON.readTree(B64URL.decode(parts[1]));
        System.out.println("  claims: webauthn_alg=" + claims.path("webauthn_alg").asText()
                + " webauthn_pq=" + claims.path("webauthn_pq").asText());

        System.out.println();
        System.out.println("PASS: post-quantum credential and token signatures; other trust paths not assessed.");
    }

    /** Rebuilds a JCA public key from an RFC 9964 AKP JWK. */
    private static PublicKey fetchAkpKey(String base, String realm, String kid, String alg) throws Exception {
        HttpResponse<String> res = HttpClient.newHttpClient().send(
                HttpRequest.newBuilder(URI.create(base + "/realms/" + realm + "/pq-jwks")).GET().build(),
                HttpResponse.BodyHandlers.ofString());
        for (JsonNode jwk : JSON.readTree(res.body()).path("keys")) {
            if (!kid.equals(jwk.path("kid").asText())) continue;
            if (!"AKP".equals(jwk.path("kty").asText())) {
                throw new IllegalStateException("expected kty=AKP, got " + jwk.path("kty").asText());
            }
            byte[] raw = B64URL.decode(jwk.path("pub").asText());
            MLDSAParameters params = switch (alg) {
                case "ML-DSA-44" -> MLDSAParameters.ml_dsa_44;
                case "ML-DSA-65" -> MLDSAParameters.ml_dsa_65;
                case "ML-DSA-87" -> MLDSAParameters.ml_dsa_87;
                default -> throw new IllegalArgumentException("unknown alg " + alg);
            };
            byte[] spki = SubjectPublicKeyInfoFactory
                    .createSubjectPublicKeyInfo(new MLDSAPublicKeyParameters(params, raw)).getEncoded();
            return KeyFactory.getInstance("ML-DSA", "BC").generatePublic(new X509EncodedKeySpec(spki));
        }
        throw new IllegalStateException("no AKP key with kid " + kid + " in the JWK set");
    }
}
