package org.pqkc.keycloak.webauthn.mldsa;

import com.webauthn4j.converter.util.ObjectConverter;
import com.webauthn4j.data.attestation.authenticator.COSEKey;
import org.jboss.logging.Logger;
import org.keycloak.common.util.Base64Url;
import org.keycloak.credential.CredentialModel;
import org.keycloak.models.credential.WebAuthnCredentialModel;

import java.util.Arrays;
import java.util.Base64;

/** Reads the COSE signature algorithm out of a stored WebAuthn credential. */
public final class CredentialAlgorithms {

    private static final Logger logger = Logger.getLogger(CredentialAlgorithms.class);

    private CredentialAlgorithms() {}

    public static WebAuthnCredentialModel toWebAuthn(CredentialModel model) {
        try {
            return WebAuthnCredentialModel.createFromCredentialModel(model);
        } catch (RuntimeException e) {
            logger.debugf(e, "Skipping unreadable WebAuthn credential %s", model.getId());
            return null;
        }
    }

    /** The COSE {@code alg} of a stored credential, or null if it cannot be read. */
    public static Long coseAlgorithm(WebAuthnCredentialModel model, ObjectConverter objectConverter) {
        try {
            byte[] cbor = Base64Url.decode(model.getWebAuthnCredentialData().getCredentialPublicKey());
            COSEKey key = objectConverter.getCborConverter().readValue(cbor, COSEKey.class);
            return key == null || key.getAlgorithm() == null ? null : key.getAlgorithm().getValue();
        } catch (RuntimeException e) {
            logger.warnf(e, "Could not read the COSE public key of credential %s", model.getId());
            return null;
        }
    }

    public static boolean sameCredentialId(String a, String b) {
        byte[] x = decodeBase64Any(a);
        return x != null && Arrays.equals(x, decodeBase64Any(b));
    }

    /**
     * Keycloak is not consistent about how it encodes a WebAuthn credential id: the authenticator
     * publishes it as unpadded base64url in the event detail, while the credential store keeps it as
     * padded standard base64. Comparing the decoded bytes sidesteps that entirely.
     */
    public static byte[] decodeBase64Any(String value) {
        if (value == null || value.isBlank()) return null;
        String normalised = value.trim().replace('-', '+').replace('_', '/');
        int padding = (4 - normalised.length() % 4) % 4;
        try {
            return Base64.getDecoder().decode(normalised + "=".repeat(padding));
        } catch (IllegalArgumentException e) {
            return null;
        }
    }
}
