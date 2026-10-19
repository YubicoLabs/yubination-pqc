package org.pqkc.webauthn.va;

import com.fasterxml.jackson.dataformat.cbor.CBORFactory;
import com.fasterxml.jackson.dataformat.cbor.CBORGenerator;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.*;

/**
 * A software FIDO2 authenticator whose credential key is ML-DSA (FIPS 204).
 *
 * <p>No shipping authenticator implements ML-DSA yet and no browser will negotiate it, so this
 * stands in for the hardware: it produces the exact byte structures a real authenticator would -
 * an attestation object with an AKP COSE public key, and assertions signed with ML-DSA - which is
 * what actually exercises the server side.
 *
 * <p>References: WebAuthn Level 3 sec. 6.5 (attested credential data), RFC 9964 (ML-DSA COSE
 * algorithms and the AKP key type), FIPS 204.
 */
public class VirtualMLDSAAuthenticator {

    /** COSE kty for Algorithm Key Pair. */
    private static final int COSE_KTY_AKP = 7;

    // authenticatorData flags, WebAuthn L3 sec 6.1
    private static final int FLAG_UP = 0x01;  // user present
    private static final int FLAG_UV = 0x04;  // user verified
    private static final int FLAG_BE = 0x08;  // backup eligible
    private static final int FLAG_BS = 0x10;  // backup state
    private static final int FLAG_AT = 0x40;  // attested credential data included

    /** Which credential key this authenticator holds. */
    public enum Kind { MLDSA, EC2_ES256 }

    private final Kind kind;
    private final String jcaName;
    private final String signatureJcaName;
    private final long coseAlgorithm;
    private final KeyPair keyPair;
    private final byte[] credentialId;
    private final byte[] aaguid;
    private int signCount = 0;

    /** An ES256 authenticator, used to prove the stock WebAuthn path still works. */
    public static VirtualMLDSAAuthenticator es256() throws GeneralSecurityException {
        return new VirtualMLDSAAuthenticator(Kind.EC2_ES256, "EC", "SHA256withECDSA", -7L);
    }

    public static VirtualMLDSAAuthenticator mldsa(String jcaName, long coseAlgorithm) throws GeneralSecurityException {
        return new VirtualMLDSAAuthenticator(Kind.MLDSA, jcaName, jcaName, coseAlgorithm);
    }

    public VirtualMLDSAAuthenticator(String jcaName, long coseAlgorithm) throws GeneralSecurityException {
        this(Kind.MLDSA, jcaName, jcaName, coseAlgorithm);
    }

    private VirtualMLDSAAuthenticator(Kind kind, String jcaName, String signatureJcaName, long coseAlgorithm)
            throws GeneralSecurityException {
        if (Security.getProvider("BC") == null) Security.addProvider(new BouncyCastleProvider());
        this.kind = kind;
        this.jcaName = jcaName;
        this.signatureJcaName = signatureJcaName;
        this.coseAlgorithm = coseAlgorithm;
        if (kind == Kind.EC2_ES256) {
            KeyPairGenerator g = KeyPairGenerator.getInstance("EC", "BC");
            g.initialize(new java.security.spec.ECGenParameterSpec("secp256r1"));
            this.keyPair = g.generateKeyPair();
        } else {
            this.keyPair = KeyPairGenerator.getInstance(jcaName, "BC").generateKeyPair();
        }
        this.credentialId = new byte[32];
        new SecureRandom().nextBytes(this.credentialId);
        // exactly 16 ASCII bytes, so these synthetic credentials are obvious in logs
        this.aaguid = "MLDSA-VIRTUAL-01".getBytes(StandardCharsets.US_ASCII);
    }

    public byte[] credentialId() { return credentialId.clone(); }
    public String jcaName() { return kind == Kind.EC2_ES256 ? "ES256" : jcaName; }
    public long coseAlgorithm() { return coseAlgorithm; }
    public Kind kind() { return kind; }

    /** A different authenticator of the same kind, for the wrong-key negative test. */
    public VirtualMLDSAAuthenticator freshImpostor() throws GeneralSecurityException {
        return new VirtualMLDSAAuthenticator(kind, jcaName, signatureJcaName, coseAlgorithm);
    }

    /** Raw FIPS 204 public key, i.e. the bytes carried in the COSE AKP {@code pub} parameter. */
    public byte[] rawPublicKey() {
        return SubjectPublicKeyInfo.getInstance(keyPair.getPublic().getEncoded()).getPublicKeyData().getOctets();
    }

    /**
     * COSE_Key with integer labels, as a real authenticator emits.
     * ML-DSA: {@code {1:7(AKP), 3:alg, -1:pub}}. ES256: {@code {1:2(EC2), 3:-7, -1:1, -2:x, -3:y}}.
     */
    public byte[] cosePublicKey() throws Exception {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        try (CBORGenerator g = new CBORFactory().createGenerator(out)) {
            g.writeStartObject();
            if (kind == Kind.EC2_ES256) {
                java.security.interfaces.ECPublicKey ec = (java.security.interfaces.ECPublicKey) keyPair.getPublic();
                g.writeFieldId(1);  g.writeNumber(2);            // kty = EC2
                g.writeFieldId(3);  g.writeNumber(coseAlgorithm);
                g.writeFieldId(-1); g.writeNumber(1);            // crv = P-256
                g.writeFieldId(-2); g.writeBinary(fixedWidth(ec.getW().getAffineX().toByteArray(), 32));
                g.writeFieldId(-3); g.writeBinary(fixedWidth(ec.getW().getAffineY().toByteArray(), 32));
            } else {
                g.writeFieldId(1);  g.writeNumber(COSE_KTY_AKP);
                g.writeFieldId(3);  g.writeNumber(coseAlgorithm);
                g.writeFieldId(-1); g.writeBinary(rawPublicKey());
            }
            g.writeEndObject();
        }
        return out.toByteArray();
    }

    /** BigInteger.toByteArray() may carry a sign byte or be short; COSE wants a fixed-width field. */
    private static byte[] fixedWidth(byte[] b, int width) {
        if (b.length == width) return b;
        byte[] out = new byte[width];
        if (b.length > width) System.arraycopy(b, b.length - width, out, 0, width);
        else System.arraycopy(b, 0, out, width - b.length, b.length);
        return out;
    }

    private static byte[] sha256(byte[] b) throws GeneralSecurityException {
        return MessageDigest.getInstance("SHA-256").digest(b);
    }

    /** authenticatorData for a registration: includes attested credential data. */
    public byte[] makeAuthenticatorData(String rpId) throws Exception {
        byte[] coseKey = cosePublicKey();
        byte[] rpIdHash = sha256(rpId.getBytes(StandardCharsets.UTF_8));
        int flags = FLAG_UP | FLAG_UV | FLAG_BE | FLAG_BS | FLAG_AT;

        ByteBuffer bb = ByteBuffer.allocate(32 + 1 + 4 + 16 + 2 + credentialId.length + coseKey.length);
        bb.put(rpIdHash).put((byte) flags).putInt(signCount);
        bb.put(aaguid).putShort((short) credentialId.length).put(credentialId).put(coseKey);
        return bb.array();
    }

    /** attestationObject with fmt "none", matching the realm's attestation preference. */
    public byte[] makeAttestationObject(String rpId) throws Exception {
        byte[] authData = makeAuthenticatorData(rpId);
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        try (CBORGenerator g = new CBORFactory().createGenerator(out)) {
            g.writeStartObject();
            g.writeFieldName("fmt");      g.writeString("none");
            g.writeFieldName("attStmt");  g.writeStartObject(); g.writeEndObject();
            g.writeFieldName("authData"); g.writeBinary(authData);
            g.writeEndObject();
        }
        return out.toByteArray();
    }

    /** authenticatorData for an assertion: no attested credential data, counter incremented. */
    public byte[] assertionAuthenticatorData(String rpId) throws Exception {
        signCount++;
        byte[] rpIdHash = sha256(rpId.getBytes(StandardCharsets.UTF_8));
        int flags = FLAG_UP | FLAG_UV | FLAG_BE | FLAG_BS;
        return ByteBuffer.allocate(32 + 1 + 4).put(rpIdHash).put((byte) flags).putInt(signCount).array();
    }

    /** ML-DSA signature over {@code authenticatorData || SHA-256(clientDataJSON)}. */
    public byte[] sign(byte[] authenticatorData, byte[] clientDataJson) throws Exception {
        byte[] clientDataHash = sha256(clientDataJson);
        byte[] signedData = ByteBuffer.allocate(authenticatorData.length + clientDataHash.length)
                .put(authenticatorData).put(clientDataHash).array();
        Signature s = Signature.getInstance(signatureJcaName, "BC");
        s.initSign(keyPair.getPrivate());
        s.update(signedData);
        return s.sign();
    }
}
