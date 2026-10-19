package org.pqkc.keycloak.webauthn.mldsa;

import com.webauthn4j.data.SignatureAlgorithm;
import com.webauthn4j.data.attestation.statement.COSEAlgorithmIdentifier;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.jboss.logging.Logger;

import java.lang.reflect.Field;
import java.security.Security;
import java.util.EnumMap;
import java.util.Map;

/**
 * Teaches webauthn4j 0.29.3 about the three ML-DSA COSE algorithm identifiers.
 *
 * <p>webauthn4j resolves a COSE alg to a JCA signature in
 * {@code COSEAlgorithmIdentifier.toSignatureAlgorithm()}, which is a lookup in a
 * {@code private static final Map} that is initialised as a plain {@code HashMap}. Both
 * {@code COSEAlgorithmIdentifier.create(long)} and
 * {@code SignatureAlgorithm.create(jcaName, digestName)} are public and unvalidating, so the
 * only thing missing is the map entry. We add it by reading the field reflectively and
 * mutating the map it points at - the {@code final} field itself is never reassigned.
 *
 * <p>This is what makes the whole feature an extension rather than a patch: no webauthn4j or
 * Keycloak class file is modified.
 */
public final class MLDSAAlgorithms {

    private static final Logger logger = Logger.getLogger(MLDSAAlgorithms.class);

    /**
     * ML-DSA is not a hash-then-sign construction - it hashes internally with SHAKE. webauthn4j's
     * SignatureAlgorithm insists on an associated message digest, but only consults it for
     * RSASSA-PSS parameterisation and for attestation formats we do not use here, never on the
     * assertion path. SHA-512 is recorded as a harmless placeholder.
     */
    private static final String PLACEHOLDER_DIGEST = "SHA-512";

    private static final Map<MLDSAParameterSet, COSEAlgorithmIdentifier> COSE_IDS =
            new EnumMap<>(MLDSAParameterSet.class);
    private static final Map<MLDSAParameterSet, SignatureAlgorithm> SIG_ALGS =
            new EnumMap<>(MLDSAParameterSet.class);

    static {
        for (MLDSAParameterSet p : MLDSAParameterSet.values()) {
            COSE_IDS.put(p, COSEAlgorithmIdentifier.create(p.coseIdentifier()));
            SIG_ALGS.put(p, SignatureAlgorithm.create(p.jcaName(), PLACEHOLDER_DIGEST));
        }
    }

    private static volatile boolean installed = false;

    private MLDSAAlgorithms() {}

    public static COSEAlgorithmIdentifier coseAlgorithm(MLDSAParameterSet p) { return COSE_IDS.get(p); }
    public static SignatureAlgorithm signatureAlgorithm(MLDSAParameterSet p) { return SIG_ALGS.get(p); }

    /** Idempotent. Safe to call from every provider factory's init(). */
    public static synchronized void install() {
        if (installed) return;

        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
            logger.info("Registered BouncyCastle JCA provider for ML-DSA");
        }

        Map<Object, Object> algorithmMap = staticMap("algorithmMap");
        Map<Object, Object> reverseAlgorithmMap = staticMap("reverseAlgorithmMap");

        for (MLDSAParameterSet p : MLDSAParameterSet.values()) {
            COSEAlgorithmIdentifier cose = COSE_IDS.get(p);
            SignatureAlgorithm sig = SIG_ALGS.get(p);
            algorithmMap.put(cose, sig);
            reverseAlgorithmMap.put(sig, cose);
        }
        // NOTE: COSEAlgorithmIdentifier.keyTypeMap is deliberately NOT populated. It maps to
        // COSEKeyType, a closed enum with no AKP(7) constant, and nothing on the registration or
        // assertion path reads it. Adding AKP there is the one change that would need a real
        // webauthn4j patch, and it would buy nothing today.

        installed = true;
        logger.infof("Installed ML-DSA COSE algorithms into webauthn4j: %s",
                java.util.Arrays.stream(MLDSAParameterSet.values())
                        .map(p -> p.jcaName() + "(" + p.coseIdentifier() + ")").toList());
    }

    @SuppressWarnings("unchecked")
    private static Map<Object, Object> staticMap(String fieldName) {
        try {
            Field f = COSEAlgorithmIdentifier.class.getDeclaredField(fieldName);
            f.setAccessible(true);
            Object value = f.get(null);
            if (!(value instanceof Map)) {
                throw new IllegalStateException(fieldName + " is not a Map but " + value);
            }
            return (Map<Object, Object>) value;
        } catch (ReflectiveOperationException e) {
            throw new IllegalStateException(
                    "Incompatible webauthn4j: COSEAlgorithmIdentifier." + fieldName + " not found. "
                    + "This extension was built against webauthn4j 0.29.3.", e);
        }
    }

    /** True once the webauthn4j lookup tables actually resolve ML-DSA. Used by tests and health checks. */
    public static boolean verifyInstalled() {
        try {
            for (MLDSAParameterSet p : MLDSAParameterSet.values()) {
                SignatureAlgorithm sa = COSE_IDS.get(p).toSignatureAlgorithm();
                if (!p.jcaName().equals(sa.getJcaName())) return false;
            }
            return true;
        } catch (RuntimeException e) {
            return false;
        }
    }
}
