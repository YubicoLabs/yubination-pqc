package org.pqkc.keycloak.webauthn.mldsa;

import java.lang.reflect.Proxy;
import java.util.Map;
import java.util.concurrent.atomic.AtomicBoolean;
import org.junit.jupiter.api.Test;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.UserModel;
import org.keycloak.sessions.AuthenticationSessionModel;
import static org.junit.jupiter.api.Assertions.*;

class MissingProvenanceTest {
    @SuppressWarnings("unchecked")
    private static <T> T proxy(Class<T> type, java.lang.reflect.InvocationHandler handler) {
        return (T) Proxy.newProxyInstance(type.getClassLoader(), new Class<?>[]{type}, handler);
    }

    @Test
    void requireModeDeniesMissingProvenanceWithoutConsultingCredentialInventory() {
        AtomicBoolean denied = new AtomicBoolean(false);
        AtomicBoolean accepted = new AtomicBoolean(false);
        AuthenticatorConfigModel config = new AuthenticatorConfigModel();
        config.setConfig(Map.of("mode", "require", "on-missing", "deny"));
        UserModel user = proxy(UserModel.class, (p, m, a) -> {
            if (m.getName().equals("getUsername")) return "synthetic-user";
            if (m.getName().equals("credentialManager"))
                throw new AssertionError("Account inventory must not substitute for session authentication evidence");
            return null;
        });
        AuthenticationSessionModel session = proxy(AuthenticationSessionModel.class,
                (p, m, a) -> m.getName().equals("getUserSessionNotes") ? Map.of() : null);
        LoginFormsProvider form = proxy(LoginFormsProvider.class,
                (p, m, a) -> m.getName().equals("setError") ? p : null);
        AuthenticationFlowContext context = proxy(AuthenticationFlowContext.class, (p, m, a) -> {
            return switch (m.getName()) {
                case "getAuthenticatorConfig" -> config;
                case "getUser" -> user;
                case "getAuthenticationSession" -> session;
                case "getSession" -> throw new IllegalStateException("No usable SSO session");
                case "form" -> form;
                case "failureChallenge" -> { denied.set(true); yield null; }
                case "success" -> { accepted.set(true); yield null; }
                default -> null;
            };
        });
        new MLDSAPolicyAuthenticator(MLDSAObjectConverters.create()).authenticate(context);
        assertTrue(denied.get());
        assertFalse(accepted.get());
    }
}
