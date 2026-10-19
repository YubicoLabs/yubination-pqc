package org.pqkc.keycloak.token.mldsa;

import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.pqkc.keycloak.webauthn.mldsa.MLDSAParameterSet;

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

/**
 * ML-DSA key material for token signing, per RFC 9964.
 *
 * <p>The same RFC that registers the COSE identifiers used for WebAuthn credentials also registers
 * the JOSE side: JWS {@code alg} values {@code ML-DSA-44 / -65 / -87} and the JWK key type
 * {@code AKP} ("Algorithm Key Pair") whose public key travels in the {@code pub} member.
 *
 * <p>{@link MLDSAParameterSet} is reused from the WebAuthn side for the JCA names and BouncyCastle
 * parameter sets; only its COSE identifiers are specific to WebAuthn.
 */
public final class MLDSAKeys {

    /** JWK/Keycloak key type for ML-DSA keys. Keycloak's KeyType constants are plain Strings. */
    public static final String KEY_TYPE_AKP = "AKP";

    /** JCA name used to obtain a KeyFactory able to handle every ML-DSA parameter set. */
    private static final String KEY_FACTORY_ALGORITHM = "ML-DSA";

    private MLDSAKeys() {}

    public static void ensureBouncyCastle() {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    public static KeyPair generate(MLDSAParameterSet params) {
        ensureBouncyCastle();
        try {
            return KeyPairGenerator.getInstance(params.jcaName(), BouncyCastleProvider.PROVIDER_NAME)
                    .generateKeyPair();
        } catch (Exception e) {
            throw new IllegalStateException("Cannot generate an " + params.jcaName() + " key pair", e);
        }
    }

    public static String encodePrivate(PrivateKey key) {
        return Base64.getEncoder().encodeToString(key.getEncoded());   // PKCS#8
    }

    public static String encodePublic(PublicKey key) {
        return Base64.getEncoder().encodeToString(key.getEncoded());   // X.509 SubjectPublicKeyInfo
    }

    public static PrivateKey decodePrivate(String base64Pkcs8) {
        ensureBouncyCastle();
        try {
            return keyFactory().generatePrivate(new PKCS8EncodedKeySpec(Base64.getDecoder().decode(base64Pkcs8)));
        } catch (Exception e) {
            throw new IllegalStateException("Cannot decode the stored ML-DSA private key", e);
        }
    }

    public static PublicKey decodePublic(String base64Spki) {
        ensureBouncyCastle();
        try {
            return keyFactory().generatePublic(new X509EncodedKeySpec(Base64.getDecoder().decode(base64Spki)));
        } catch (Exception e) {
            throw new IllegalStateException("Cannot decode the stored ML-DSA public key", e);
        }
    }

    private static KeyFactory keyFactory() throws Exception {
        return KeyFactory.getInstance(KEY_FACTORY_ALGORITHM, BouncyCastleProvider.PROVIDER_NAME);
    }

    /** The raw FIPS 204 public key, i.e. the bytes carried in the JWK {@code pub} member. */
    public static byte[] rawPublicKey(PublicKey key) {
        return SubjectPublicKeyInfo.getInstance(key.getEncoded()).getPublicKeyData().getOctets();
    }

    /** Which parameter set a public key belongs to, decided by its unambiguous length. */
    public static MLDSAParameterSet parameterSetOf(PublicKey key) {
        return MLDSAParameterSet.fromPublicKeyLength(rawPublicKey(key).length);
    }

    /**
     * A stable key id. Keycloak's {@code KeyUtils.createKeyId} builds a JWK thumbprint, which is not
     * defined for AKP keys in a form Keycloak can produce, so this hashes the encoded public key -
     * deterministic, and stable across restarts for the same key.
     */
    public static String keyId(PublicKey key) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256").digest(key.getEncoded());
            return Base64.getUrlEncoder().withoutPadding().encodeToString(digest);
        } catch (Exception e) {
            throw new IllegalStateException("Cannot derive a key id", e);
        }
    }
}
