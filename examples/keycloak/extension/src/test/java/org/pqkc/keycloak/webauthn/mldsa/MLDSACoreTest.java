package org.pqkc.keycloak.webauthn.mldsa;

import com.fasterxml.jackson.dataformat.cbor.CBORFactory;
import com.fasterxml.jackson.dataformat.cbor.CBORGenerator;
import com.webauthn4j.converter.util.ObjectConverter;
import com.webauthn4j.data.SignatureAlgorithm;
import com.webauthn4j.data.attestation.authenticator.COSEKey;
import com.webauthn4j.data.attestation.statement.COSEAlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

import java.io.ByteArrayOutputStream;
import java.security.*;

import static org.junit.jupiter.api.Assertions.*;

class MLDSACoreTest {

    @BeforeAll
    static void setUp() {
        MLDSAAlgorithms.install();
        if (Security.getProvider("BC") == null) Security.addProvider(new BouncyCastleProvider());
    }

    /**
     * Encodes a COSE_Key exactly as an authenticator would: a CBOR map with *integer* labels
     * ({@code 1:7, 3:alg, -1:pub}), not string keys.
     */
    private static byte[] encodeAkpCoseKey(long alg, byte[] pub) throws Exception {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        try (CBORGenerator g = new CBORFactory().createGenerator(out)) {
            g.writeStartObject();
            g.writeFieldId(1);  g.writeNumber(MLDSAParameterSet.COSE_KTY_AKP); // kty = AKP
            g.writeFieldId(3);  g.writeNumber(alg);                            // alg
            g.writeFieldId(-1); g.writeBinary(pub);                            // AKP pub
            g.writeEndObject();
        }
        return out.toByteArray();
    }

    private static byte[] rawPublicKey(PublicKey pk) {
        return SubjectPublicKeyInfo.getInstance(pk.getEncoded()).getPublicKeyData().getOctets();
    }

    @Test
    @DisplayName("webauthn4j resolves ML-DSA COSE ids to JCA signature algorithms after install()")
    void algorithmsInstalled() {
        assertTrue(MLDSAAlgorithms.verifyInstalled());
        for (MLDSAParameterSet p : MLDSAParameterSet.values()) {
            SignatureAlgorithm sa = COSEAlgorithmIdentifier.create(p.coseIdentifier()).toSignatureAlgorithm();
            assertEquals(p.jcaName(), sa.getJcaName());
        }
    }

    @Test
    @DisplayName("stock algorithms are unaffected by the injection")
    void stockAlgorithmsUnaffected() {
        assertEquals("SHA256withECDSA", COSEAlgorithmIdentifier.ES256.toSignatureAlgorithm().getJcaName());
        assertEquals("SHA256withRSA",   COSEAlgorithmIdentifier.RS256.toSignatureAlgorithm().getJcaName());
        assertEquals("ed25519",         COSEAlgorithmIdentifier.EdDSA.toSignatureAlgorithm().getJcaName());
        assertEquals(COSEAlgorithmIdentifier.ES256,
                COSEAlgorithmIdentifier.create(SignatureAlgorithm.ES256));
    }

    @ParameterizedTest
    @EnumSource(MLDSAParameterSet.class)
    @DisplayName("authenticator-encoded AKP COSE key deserialises into MLDSACOSEKey")
    void deserialisesFromAuthenticatorCbor(MLDSAParameterSet p) throws Exception {
        KeyPair kp = KeyPairGenerator.getInstance(p.jcaName(), "BC").generateKeyPair();
        byte[] pub = rawPublicKey(kp.getPublic());
        assertEquals(p.publicKeyLength(), pub.length, "FIPS 204 public key size");

        ObjectConverter oc = MLDSAObjectConverters.create();
        COSEKey key = oc.getCborConverter()
                .readValue(encodeAkpCoseKey(p.coseIdentifier(), pub), COSEKey.class);

        assertInstanceOf(MLDSACOSEKey.class, key);
        assertEquals(p.coseIdentifier(), key.getAlgorithm().getValue());
        assertArrayEquals(pub, ((MLDSACOSEKey) key).getPub());
        assertDoesNotThrow(key::validate);
    }

    @ParameterizedTest
    @EnumSource(MLDSAParameterSet.class)
    @DisplayName("signature verifies through webauthn4j's exact assertion code path")
    void verifiesThroughWebauthn4jPath(MLDSAParameterSet p) throws Exception {
        KeyPair kp = KeyPairGenerator.getInstance(p.jcaName(), "BC").generateKeyPair();
        byte[] signedData = "authenticatorData||clientDataHash".getBytes();

        Signature signer = Signature.getInstance(p.jcaName(), "BC");
        signer.initSign(kp.getPrivate());
        signer.update(signedData);
        byte[] sig = signer.sign();
        assertEquals(p.signatureLength(), sig.length, "FIPS 204 signature size");

        ObjectConverter oc = MLDSAObjectConverters.create();
        COSEKey key = oc.getCborConverter()
                .readValue(encodeAkpCoseKey(p.coseIdentifier(), rawPublicKey(kp.getPublic())), COSEKey.class);

        // ---- this mirrors com.webauthn4j.verifier.internal.AssertionSignatureVerifier line for line ----
        PublicKey publicKey = key.getPublicKey();
        SignatureAlgorithm signatureAlgorithm = key.getAlgorithm().toSignatureAlgorithm();
        Signature verifier = com.webauthn4j.util.SignatureUtil.createSignature(signatureAlgorithm);
        verifier.initVerify(publicKey);
        verifier.update(signedData);
        assertTrue(verifier.verify(sig), "ML-DSA assertion signature must verify");

        // and a tampered payload must fail
        Signature bad = com.webauthn4j.util.SignatureUtil.createSignature(signatureAlgorithm);
        bad.initVerify(publicKey);
        bad.update("tampered".getBytes());
        assertFalse(bad.verify(sig), "tampered data must not verify");
    }

    @ParameterizedTest
    @EnumSource(MLDSAParameterSet.class)
    @DisplayName("credential survives the Keycloak store/reload round trip")
    void roundTripsThroughCredentialStorage(MLDSAParameterSet p) throws Exception {
        KeyPair kp = KeyPairGenerator.getInstance(p.jcaName(), "BC").generateKeyPair();
        ObjectConverter oc = MLDSAObjectConverters.create();

        COSEKey original = oc.getCborConverter()
                .readValue(encodeAkpCoseKey(p.coseIdentifier(), rawPublicKey(kp.getPublic())), COSEKey.class);

        // Keycloak persists the COSE key by re-serialising it, then reloads it at login time
        byte[] stored = oc.getCborConverter().writeValueAsBytes(original);
        COSEKey reloaded = oc.getCborConverter().readValue(stored, COSEKey.class);

        assertInstanceOf(MLDSACOSEKey.class, reloaded);
        assertEquals(original, reloaded);
        assertNotNull(reloaded.getPublicKey());
        assertEquals(p.jcaName(), reloaded.getPublicKey().getAlgorithm());
    }

    @Test
    @DisplayName("validate() rejects a key whose length contradicts its declared parameter set")
    void validateRejectsMismatch() throws Exception {
        KeyPair small = KeyPairGenerator.getInstance("ML-DSA-44", "BC").generateKeyPair();
        // claim ML-DSA-87 but supply an ML-DSA-44 key
        MLDSACOSEKey bogus = new MLDSACOSEKey(
                COSEAlgorithmIdentifier.create(MLDSAParameterSet.ML_DSA_87.coseIdentifier()),
                rawPublicKey(small.getPublic()));
        IllegalArgumentException e = assertThrows(IllegalArgumentException.class, bogus::validate);
        assertTrue(e.getMessage().contains("does not match"), e.getMessage());
    }

    @Test
    @DisplayName("a non-ML-DSA alg on an AKP key is rejected")
    void validateRejectsNonMldsaAlg() {
        MLDSACOSEKey bogus = new MLDSACOSEKey(COSEAlgorithmIdentifier.ES256, new byte[1312]);
        assertThrows(IllegalArgumentException.class, bogus::validate);
    }
}
