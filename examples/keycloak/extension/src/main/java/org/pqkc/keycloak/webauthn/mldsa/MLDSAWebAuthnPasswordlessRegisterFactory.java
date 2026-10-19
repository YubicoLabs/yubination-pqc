package org.pqkc.keycloak.webauthn.mldsa;

import com.webauthn4j.converter.util.ObjectConverter;
import com.webauthn4j.verifier.attestation.trustworthiness.certpath.CertPathTrustworthinessVerifier;
import org.jboss.logging.Logger;
import org.keycloak.authentication.requiredactions.WebAuthnPasswordlessRegisterFactory;
import org.keycloak.authentication.requiredactions.WebAuthnRegister;
import org.keycloak.credential.CredentialProvider;
import org.keycloak.credential.WebAuthnCredentialProviderFactory;
import org.keycloak.credential.WebAuthnPasswordlessCredentialProviderFactory;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.provider.ProviderFactory;

import java.lang.reflect.Field;
import java.util.List;

/**
 * Registers the ML-DSA-capable passwordless registration action under its own provider id, so it
 * sits alongside the stock {@code webauthn-register-passwordless} rather than replacing it.
 *
 * <p>{@link #postInit(KeycloakSessionFactory)} additionally hands an ML-DSA-aware
 * {@link ObjectConverter} to the built-in WebAuthn credential provider factories. That is what lets
 * the <em>stock</em> authenticator and credential store persist and later verify an AKP credential:
 * Keycloak re-serialises the COSE key when saving it and deserialises it again on every login, and
 * both of those go through the converter held by
 * {@link WebAuthnCredentialProviderFactory}. Its {@code converter} field is private with only a
 * {@code protected} lazy accessor, so it is set reflectively - once, at boot, before any request
 * can have populated it.
 */
public class MLDSAWebAuthnPasswordlessRegisterFactory extends WebAuthnPasswordlessRegisterFactory {

    private static final Logger logger = Logger.getLogger(MLDSAWebAuthnPasswordlessRegisterFactory.class);

    public static final String PROVIDER_ID = "webauthn-register-passwordless-mldsa";

    private static final List<String> WEBAUTHN_CREDENTIAL_PROVIDER_IDS = List.of(
            WebAuthnCredentialProviderFactory.PROVIDER_ID,              // keycloak-webauthn
            WebAuthnPasswordlessCredentialProviderFactory.PROVIDER_ID   // keycloak-webauthn-passwordless
    );

    @Override
    protected WebAuthnRegister createProvider(KeycloakSession session, CertPathTrustworthinessVerifier trustVerifier) {
        return new MLDSAWebAuthnPasswordlessRegister(session, trustVerifier);
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public String getDisplayText() {
        return "Webauthn Register Passwordless (ML-DSA capable)";
    }

    public static final String CONF_WEBKIT_PQ_PREFERENCE = "webkit-pq-preference";

    private static final List<ProviderConfigProperty> CONFIG_METADATA = List.of(webkitPreferenceProperty());

    private static ProviderConfigProperty webkitPreferenceProperty() {
        ProviderConfigProperty p = new ProviderConfigProperty();
        p.setName(CONF_WEBKIT_PQ_PREFERENCE);
        p.setLabel("WebKit post-quantum preference");
        p.setType(ProviderConfigProperty.LIST_TYPE);
        p.setOptions(List.of("ignore", "honour"));
        p.setDefaultValue("ignore");
        p.setHelpText("WebKit (Safari, and every browser on iOS) selects ES256 whenever it appears in "
                + "pubKeyCredParams, regardless of the order the relying party asked for, so a "
                + "post-quantum authenticator silently enrols a classical credential. 'honour' sends "
                + "WebKit clients only the post-quantum algorithms so the preference is respected; the "
                + "cost is that an authenticator without ML-DSA can then no longer enrol from Safari "
                + "or iOS at all. 'ignore' keeps the standard list.");
        return p;
    }

    @Override
    public boolean isConfigurable() {
        return true;
    }

    @Override
    public List<ProviderConfigProperty> getConfigMetadata() {
        return CONFIG_METADATA;
    }

    @Override
    public void init(org.keycloak.Config.Scope config) {
        MLDSAAlgorithms.install();
    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {
        MLDSAAlgorithms.install();
        if (!MLDSAAlgorithms.verifyInstalled()) {
            logger.error("ML-DSA COSE algorithms did not install into webauthn4j; "
                    + "ML-DSA credentials will be rejected.");
            return;
        }

        ObjectConverter converter = MLDSAObjectConverters.create();
        for (String providerId : WEBAUTHN_CREDENTIAL_PROVIDER_IDS) {
            ProviderFactory<CredentialProvider> pf =
                    factory.getProviderFactory(CredentialProvider.class, providerId);
            if (pf == null) {
                logger.warnf("WebAuthn credential provider '%s' not found; skipping ML-DSA wiring", providerId);
                continue;
            }
            try {
                Field f = WebAuthnCredentialProviderFactory.class.getDeclaredField("converter");
                f.setAccessible(true);
                Object existing = f.get(pf);
                if (existing != null) {
                    logger.warnf("ObjectConverter for '%s' was already initialised; replacing it", providerId);
                }
                f.set(pf, converter);
                logger.infof("Installed ML-DSA-aware ObjectConverter into credential provider '%s'", providerId);
            } catch (ReflectiveOperationException | RuntimeException e) {
                logger.errorf(e, "Could not install ML-DSA ObjectConverter into '%s'. "
                        + "ML-DSA credentials will fail to store or verify. "
                        + "This extension targets Keycloak 26.4.x.", providerId);
            }
        }
    }
}
