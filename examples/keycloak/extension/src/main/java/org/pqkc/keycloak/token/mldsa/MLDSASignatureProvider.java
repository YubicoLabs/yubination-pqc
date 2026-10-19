package org.pqkc.keycloak.token.mldsa;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.keycloak.common.VerificationException;
import org.keycloak.crypto.KeyUse;
import org.keycloak.crypto.KeyWrapper;
import org.keycloak.crypto.SignatureException;
import org.keycloak.crypto.SignatureProvider;
import org.keycloak.crypto.SignatureSignerContext;
import org.keycloak.crypto.SignatureVerifierContext;
import org.keycloak.models.KeycloakSession;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;

/**
 * Signs and verifies JWS with ML-DSA (FIPS 204), the JOSE algorithms registered by RFC 9964.
 *
 * <p>Keycloak's own {@code AsymmetricSignatureProvider} routes through
 * {@code JavaAlgorithm.getJavaAlgorithm}, a closed switch over the classical algorithms, so this
 * implements {@link SignatureProvider} directly and calls BouncyCastle by name instead. Everything
 * else - key lookup, JWS assembly, the {@code alg} header, discovery metadata - is stock Keycloak,
 * because it is all driven off the provider id.
 */
public class MLDSASignatureProvider implements SignatureProvider {

    private final KeycloakSession session;
    private final String algorithm;

    public MLDSASignatureProvider(KeycloakSession session, String algorithm) {
        this.session = session;
        this.algorithm = algorithm;
        MLDSAKeys.ensureBouncyCastle();
    }

    @Override
    public SignatureSignerContext signer() throws SignatureException {
        KeyWrapper key = session.keys().getActiveKey(session.getContext().getRealm(), KeyUse.SIG, algorithm);
        if (key == null) {
            throw new SignatureException("No active " + algorithm + " signing key in this realm. "
                    + "Add a key provider of type 'mldsa-generated'.");
        }
        return signer(key);
    }

    @Override
    public SignatureSignerContext signer(KeyWrapper key) throws SignatureException {
        SignatureProvider.checkKeyForSignature(key, algorithm, MLDSAKeys.KEY_TYPE_AKP);
        return new Signer(key, algorithm);
    }

    @Override
    public SignatureVerifierContext verifier(String kid) throws VerificationException {
        KeyWrapper key = session.keys().getKey(session.getContext().getRealm(), kid, KeyUse.SIG, algorithm);
        if (key == null) {
            throw new VerificationException("No " + algorithm + " key with kid " + kid);
        }
        return verifier(key);
    }

    @Override
    public SignatureVerifierContext verifier(KeyWrapper key) throws VerificationException {
        SignatureProvider.checkKeyForVerification(key, algorithm, MLDSAKeys.KEY_TYPE_AKP);
        return new Verifier(key, algorithm);
    }

    @Override
    public boolean isAsymmetricAlgorithm() {
        return true;
    }

    private static Signature jca(String algorithm) throws Exception {
        return Signature.getInstance(algorithm, BouncyCastleProvider.PROVIDER_NAME);
    }

    static final class Signer implements SignatureSignerContext {
        private final KeyWrapper key;
        private final String algorithm;

        Signer(KeyWrapper key, String algorithm) { this.key = key; this.algorithm = algorithm; }

        @Override public String getKid() { return key.getKid(); }
        @Override public String getAlgorithm() { return algorithm; }

        /**
         * ML-DSA is not hash-then-sign; it hashes internally with SHAKE. Nothing on the JWS path
         * consults this - only the SD-JWT/OID4VC builder does - so a stable placeholder is reported
         * rather than null, which that builder would not expect.
         */
        @Override public String getHashAlgorithm() { return "SHA-512"; }

        @Override
        public byte[] sign(byte[] data) throws SignatureException {
            try {
                Signature signature = jca(algorithm);
                signature.initSign((PrivateKey) key.getPrivateKey());
                signature.update(data);
                return signature.sign();
            } catch (Exception e) {
                throw new SignatureException("Signing failed for " + algorithm, e);
            }
        }
    }

    static final class Verifier implements SignatureVerifierContext {
        private final KeyWrapper key;
        private final String algorithm;

        Verifier(KeyWrapper key, String algorithm) { this.key = key; this.algorithm = algorithm; }

        @Override public String getKid() { return key.getKid(); }
        @Override public String getAlgorithm() { return algorithm; }

        @Override
        public boolean verify(byte[] data, byte[] signature) throws VerificationException {
            try {
                Signature verifier = jca(algorithm);
                verifier.initVerify((PublicKey) key.getPublicKey());
                verifier.update(data);
                return verifier.verify(signature);
            } catch (Exception e) {
                throw new VerificationException("Verification failed for " + algorithm, e);
            }
        }
    }
}
