package org.pqkc.keycloak.webauthn.mldsa;

/** Human-readable names for the COSE algorithm identifiers WebAuthn credentials use. */
public final class WebAuthnAlgorithms {

    private WebAuthnAlgorithms() {}

    public static String name(long coseIdentifier) {
        MLDSAParameterSet mldsa = MLDSAParameterSet.fromCoseIdentifier(coseIdentifier);
        if (mldsa != null) return mldsa.jcaName();
        return switch ((int) coseIdentifier) {
            case -7 -> "ES256";
            case -35 -> "ES384";
            case -36 -> "ES512";
            case -8 -> "EdDSA";
            case -37 -> "PS256";
            case -38 -> "PS384";
            case -39 -> "PS512";
            case -257 -> "RS256";
            case -258 -> "RS384";
            case -259 -> "RS512";
            case -65535 -> "RS1";
            default -> "COSE(" + coseIdentifier + ")";
        };
    }

    public static boolean isPostQuantum(long coseIdentifier) {
        return MLDSAParameterSet.fromCoseIdentifier(coseIdentifier) != null;
    }

    /** Same test, against a name previously recorded in a session note. */
    public static boolean isPostQuantum(String name) {
        return name != null && MLDSAParameterSet.fromJcaName(name) != null;
    }
}
