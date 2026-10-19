package org.pqkc.keycloak.webauthn.mldsa;

import com.webauthn4j.converter.util.ObjectConverter;
import org.keycloak.Config;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.AuthenticatorFactory;
import org.keycloak.models.AuthenticationExecutionModel.Requirement;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.ProviderConfigProperty;

import java.util.List;

public class MLDSAPolicyAuthenticatorFactory implements AuthenticatorFactory {

    public static final String PROVIDER_ID = "webauthn-mldsa-policy";

    private static final Requirement[] REQUIREMENT_CHOICES = {
            Requirement.REQUIRED, Requirement.DISABLED
    };

    private volatile ObjectConverter objectConverter;

    @Override
    public Authenticator create(KeycloakSession session) {
        if (objectConverter == null) {
            synchronized (this) {
                if (objectConverter == null) objectConverter = MLDSAObjectConverters.create();
            }
        }
        return new MLDSAPolicyAuthenticator(objectConverter);
    }

    @Override public String getId() { return PROVIDER_ID; }
    @Override public String getDisplayType() { return "WebAuthn ML-DSA Policy"; }
    @Override public String getReferenceCategory() { return "webauthn"; }
    @Override public String getHelpText() {
        return "Records which signature algorithm the WebAuthn credential used, and can require it "
             + "to be post-quantum (ML-DSA). Place it immediately after a WebAuthn authenticator. "
             + "Bind the containing flow to a single client to make the requirement per-application.";
    }
    @Override public boolean isConfigurable() { return true; }
    @Override public boolean isUserSetupAllowed() { return false; }
    @Override public Requirement[] getRequirementChoices() { return REQUIREMENT_CHOICES; }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        ProviderConfigProperty mode = new ProviderConfigProperty();
        mode.setName(MLDSAPolicyAuthenticator.CONF_MODE);
        mode.setLabel("Mode");
        mode.setType(ProviderConfigProperty.LIST_TYPE);
        mode.setOptions(List.of(MLDSAPolicyAuthenticator.MODE_RECORD, MLDSAPolicyAuthenticator.MODE_REQUIRE));
        mode.setDefaultValue(MLDSAPolicyAuthenticator.MODE_RECORD);
        mode.setHelpText("'record' only publishes the algorithm to the token; "
                + "'require' additionally refuses logins that did not use ML-DSA.");

        ProviderConfigProperty onMissing = new ProviderConfigProperty();
        onMissing.setName(MLDSAPolicyAuthenticator.CONF_ON_MISSING);
        onMissing.setLabel("When the credential is not ML-DSA");
        onMissing.setType(ProviderConfigProperty.LIST_TYPE);
        onMissing.setOptions(List.of(MLDSAPolicyAuthenticator.ON_MISSING_DENY, MLDSAPolicyAuthenticator.ON_MISSING_ENROL));
        onMissing.setDefaultValue(MLDSAPolicyAuthenticator.ON_MISSING_DENY);
        onMissing.setHelpText("Only applies in 'require' mode. 'deny' refuses the login; "
                + "'enrol' lets the login continue but forces ML-DSA passkey enrolment first.");

        return List.of(mode, onMissing);
    }

    @Override public void init(Config.Scope config) { MLDSAAlgorithms.install(); }
    @Override public void postInit(KeycloakSessionFactory factory) { /* NOP */ }
    @Override public void close() { /* NOP */ }
}
