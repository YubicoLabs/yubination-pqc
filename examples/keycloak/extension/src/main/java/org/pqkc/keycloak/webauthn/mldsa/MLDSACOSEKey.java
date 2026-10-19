package org.pqkc.keycloak.webauthn.mldsa;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.webauthn4j.data.attestation.authenticator.COSEKey;
import com.webauthn4j.data.attestation.statement.COSEAlgorithmIdentifier;
import com.webauthn4j.data.attestation.statement.COSEKeyOperation;
import com.webauthn4j.data.attestation.statement.COSEKeyType;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.pqc.crypto.mldsa.MLDSAPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.mldsa.MLDSAPublicKeyParameters;
import org.bouncycastle.pqc.crypto.util.PrivateKeyInfoFactory;
import org.bouncycastle.pqc.crypto.util.SubjectPublicKeyInfoFactory;

import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;

/**
 * COSE key of type AKP (Algorithm Key Pair, {@code kty = 7}) carrying an ML-DSA key,
 * as registered by RFC 9964.
 *
 * <p>webauthn4j 0.29.3 ships {@code EdDSACOSEKey} / {@code EC2COSEKey} / {@code RSACOSEKey}
 * and dispatches on the COSE {@code kty} label via
 * {@code @JsonTypeInfo(use = NAME, property = "1")}. This class is registered as an
 * additional subtype under the name {@code "7"} (see {@link MLDSAObjectConverters}), which
 * is why no modification of the webauthn4j jar is required.
 *
 * <p>Note {@link #getKeyType()} returns {@code null}: webauthn4j's {@code COSEKeyType} is a
 * closed enum {OKP, EC2, RSA, SYMMETRIC, RESERVED} with no AKP constant. This is safe because
 * nothing in webauthn4j's verification path nor in Keycloak calls it - the value is only ever
 * used for serialisation, which here is driven by the Jackson type id instead.
 */
public class MLDSACOSEKey implements COSEKey {

    @JsonProperty("2")
    private final byte[] keyId;

    @JsonProperty("3")
    private final COSEAlgorithmIdentifier algorithm;

    @JsonProperty("4")
    private final List<COSEKeyOperation> keyOps;

    @JsonProperty("5")
    private final byte[] baseIV;

    /** AKP "pub" - raw FIPS 204 public key. RFC 9964 label -1. */
    @JsonProperty("-1")
    private final byte[] pub;

    /** AKP "priv" - raw FIPS 204 private key seed. RFC 9964 label -2. Never present in WebAuthn traffic. */
    @JsonProperty("-2")
    private final byte[] priv;

    @JsonCreator
    public MLDSACOSEKey(
            @JsonProperty("2") byte[] keyId,
            @JsonProperty("3") COSEAlgorithmIdentifier algorithm,
            @JsonProperty("4") List<COSEKeyOperation> keyOps,
            @JsonProperty("5") byte[] baseIV,
            @JsonProperty("-1") byte[] pub,
            @JsonProperty("-2") byte[] priv) {
        this.keyId = clone(keyId);
        this.algorithm = algorithm;
        this.keyOps = keyOps;
        this.baseIV = clone(baseIV);
        this.pub = clone(pub);
        this.priv = clone(priv);
    }

    public MLDSACOSEKey(COSEAlgorithmIdentifier algorithm, byte[] pub) {
        this(null, algorithm, null, null, pub, null);
    }

    @Override public boolean hasPublicKey() { return pub != null; }
    @Override public boolean hasPrivateKey() { return priv != null; }

    /**
     * Rebuilds a JCA {@link PublicKey} from the raw AKP {@code pub} bytes by wrapping them in a
     * SubjectPublicKeyInfo with the correct FIPS 204 OID and handing that to BouncyCastle.
     */
    @Override
    @JsonIgnore
    public PublicKey getPublicKey() {
        if (pub == null) return null;
        MLDSAParameterSet params = parameterSet();
        if (params == null) return null;
        try {
            SubjectPublicKeyInfo spki = SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(
                    new MLDSAPublicKeyParameters(params.bcParameters(), pub));
            return KeyFactory.getInstance("ML-DSA", BouncyCastleProvider.PROVIDER_NAME)
                    .generatePublic(new java.security.spec.X509EncodedKeySpec(spki.getEncoded()));
        } catch (Exception e) {
            throw new IllegalStateException("Cannot rebuild ML-DSA public key from COSE AKP pub", e);
        }
    }

    @Override
    @JsonIgnore
    public PrivateKey getPrivateKey() {
        if (priv == null) return null;
        MLDSAParameterSet params = parameterSet();
        if (params == null) return null;
        try {
            var pki = PrivateKeyInfoFactory.createPrivateKeyInfo(
                    new MLDSAPrivateKeyParameters(params.bcParameters(), priv));
            return KeyFactory.getInstance("ML-DSA", BouncyCastleProvider.PROVIDER_NAME)
                    .generatePrivate(new java.security.spec.PKCS8EncodedKeySpec(pki.getEncoded()));
        } catch (Exception e) {
            throw new IllegalStateException("Cannot rebuild ML-DSA private key from COSE AKP priv", e);
        }
    }

    /**
     * @return {@code null} - webauthn4j's COSEKeyType enum has no AKP(7) constant.
     *         See the class javadoc; this value is never consumed.
     */
    @Override
    @JsonIgnore
    public COSEKeyType getKeyType() { return null; }

    /** The COSE kty value actually written for this key. Not a Jackson property: the type id carries it. */
    @JsonIgnore
    public int getCoseKeyType() { return MLDSAParameterSet.COSE_KTY_AKP; }

    @Override public byte[] getKeyId() { return clone(keyId); }
    @Override public COSEAlgorithmIdentifier getAlgorithm() { return algorithm; }
    @Override public List<COSEKeyOperation> getKeyOps() { return keyOps; }
    @Override public byte[] getBaseIV() { return clone(baseIV); }

    @JsonIgnore public byte[] getPub() { return clone(pub); }
    @JsonIgnore public byte[] getPriv() { return clone(priv); }

    @JsonIgnore
    public MLDSAParameterSet parameterSet() {
        if (algorithm != null) {
            MLDSAParameterSet byAlg = MLDSAParameterSet.fromCoseIdentifier(algorithm.getValue());
            if (byAlg != null) return byAlg;
        }
        return pub == null ? null : MLDSAParameterSet.fromPublicKeyLength(pub.length);
    }

    /**
     * Called by webauthn4j after deserialisation. Rejects keys whose declared algorithm and
     * key material disagree, which is what stops a caller from claiming ML-DSA-87 while
     * supplying an ML-DSA-44 key.
     */
    @Override
    public void validate() {
        if (algorithm == null) {
            throw new IllegalArgumentException("alg must not be null");
        }
        MLDSAParameterSet declared = MLDSAParameterSet.fromCoseIdentifier(algorithm.getValue());
        if (declared == null) {
            throw new IllegalArgumentException(
                    "alg " + algorithm.getValue() + " is not an ML-DSA COSE algorithm identifier");
        }
        if (pub == null) {
            throw new IllegalArgumentException("AKP pub (label -1) must not be null");
        }
        if (pub.length != declared.publicKeyLength()) {
            throw new IllegalArgumentException(String.format(
                    "AKP pub length %d does not match %s (expected %d)",
                    pub.length, declared.jcaName(), declared.publicKeyLength()));
        }
    }

    private static byte[] clone(byte[] b) { return b == null ? null : b.clone(); }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        MLDSACOSEKey that = (MLDSACOSEKey) o;
        return Arrays.equals(keyId, that.keyId)
                && Objects.equals(algorithm, that.algorithm)
                && Objects.equals(keyOps, that.keyOps)
                && Arrays.equals(baseIV, that.baseIV)
                && Arrays.equals(pub, that.pub)
                && Arrays.equals(priv, that.priv);
    }

    @Override
    public int hashCode() {
        int result = Objects.hash(algorithm, keyOps);
        result = 31 * result + Arrays.hashCode(keyId);
        result = 31 * result + Arrays.hashCode(baseIV);
        result = 31 * result + Arrays.hashCode(pub);
        result = 31 * result + Arrays.hashCode(priv);
        return result;
    }

    @Override
    public String toString() {
        MLDSAParameterSet p = parameterSet();
        return "MLDSACOSEKey(kty=AKP(7), alg=" + (algorithm == null ? "null" : algorithm.getValue())
                + ", " + (p == null ? "unknown" : p.jcaName()) + ", pub=" + (pub == null ? 0 : pub.length) + "B)";
    }
}
