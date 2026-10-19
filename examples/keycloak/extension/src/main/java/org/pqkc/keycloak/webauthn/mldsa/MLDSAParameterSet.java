package org.pqkc.keycloak.webauthn.mldsa;

import org.bouncycastle.pqc.crypto.mldsa.MLDSAParameters;

/**
 * The three ML-DSA parameter sets of FIPS 204, together with the COSE algorithm
 * identifiers permanently registered for them by RFC 9964.
 *
 * <p>Sizes are the raw FIPS 204 encodings, i.e. exactly what travels in the COSE
 * AKP {@code pub} parameter (label -1) and in a WebAuthn assertion signature.
 */
public enum MLDSAParameterSet {

    ML_DSA_44(-48L, "ML-DSA-44", 1312, 2420, MLDSAParameters.ml_dsa_44),
    ML_DSA_65(-49L, "ML-DSA-65", 1952, 3309, MLDSAParameters.ml_dsa_65),
    ML_DSA_87(-50L, "ML-DSA-87", 2592, 4627, MLDSAParameters.ml_dsa_87);

    /** COSE "kty" value for Algorithm Key Pair (AKP) keys - RFC 9964 / COSE Key Types registry. */
    public static final int COSE_KTY_AKP = 7;

    private final long coseIdentifier;
    private final String jcaName;
    private final int publicKeyLength;
    private final int signatureLength;
    private final MLDSAParameters bcParameters;

    MLDSAParameterSet(long coseIdentifier, String jcaName, int publicKeyLength,
                      int signatureLength, MLDSAParameters bcParameters) {
        this.coseIdentifier = coseIdentifier;
        this.jcaName = jcaName;
        this.publicKeyLength = publicKeyLength;
        this.signatureLength = signatureLength;
        this.bcParameters = bcParameters;
    }

    public long coseIdentifier() { return coseIdentifier; }
    /** JCA algorithm name; BouncyCastle >= 1.78 registers Signature/KeyFactory under this name. */
    public String jcaName() { return jcaName; }
    public int publicKeyLength() { return publicKeyLength; }
    public int signatureLength() { return signatureLength; }
    public MLDSAParameters bcParameters() { return bcParameters; }

    public static MLDSAParameterSet fromCoseIdentifier(long id) {
        for (MLDSAParameterSet p : values()) {
            if (p.coseIdentifier == id) return p;
        }
        return null;
    }

    public static MLDSAParameterSet fromJcaName(String name) {
        for (MLDSAParameterSet p : values()) {
            if (p.jcaName.equalsIgnoreCase(name)) return p;
        }
        return null;
    }

    /** Length of a raw public key uniquely identifies the parameter set. */
    public static MLDSAParameterSet fromPublicKeyLength(int len) {
        for (MLDSAParameterSet p : values()) {
            if (p.publicKeyLength == len) return p;
        }
        return null;
    }
}
