package org.pqkc.keycloak.token.mldsa;

import org.keycloak.Config;
import org.keycloak.crypto.SignatureProvider;
import org.keycloak.crypto.SignatureProviderFactory;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.pqkc.keycloak.webauthn.mldsa.MLDSAParameterSet;

/**
 * One factory per ML-DSA parameter set. The provider id <em>is</em> the JWS {@code alg} value, which
 * is what makes Keycloak advertise it in {@code id_token_signing_alg_values_supported} and accept it
 * as a realm or client signing algorithm without any further wiring.
 */
public abstract class MLDSASignatureProviderFactory implements SignatureProviderFactory {

    private final MLDSAParameterSet parameterSet;

    protected MLDSASignatureProviderFactory(MLDSAParameterSet parameterSet) {
        this.parameterSet = parameterSet;
    }

    @Override
    public String getId() {
        return parameterSet.jcaName();   // "ML-DSA-44" etc, the RFC 9964 JOSE alg value
    }

    @Override
    public SignatureProvider create(KeycloakSession session) {
        return new MLDSASignatureProvider(session, getId());
    }

    @Override
    public void init(Config.Scope config) {
        MLDSAKeys.ensureBouncyCastle();
    }

    @Override
    public void postInit(KeycloakSessionFactory factory) { /* NOP */ }

    @Override
    public void close() { /* NOP */ }

    public static class MLDSA44 extends MLDSASignatureProviderFactory {
        public MLDSA44() { super(MLDSAParameterSet.ML_DSA_44); }
    }

    public static class MLDSA65 extends MLDSASignatureProviderFactory {
        public MLDSA65() { super(MLDSAParameterSet.ML_DSA_65); }
    }

    public static class MLDSA87 extends MLDSASignatureProviderFactory {
        public MLDSA87() { super(MLDSAParameterSet.ML_DSA_87); }
    }
}
