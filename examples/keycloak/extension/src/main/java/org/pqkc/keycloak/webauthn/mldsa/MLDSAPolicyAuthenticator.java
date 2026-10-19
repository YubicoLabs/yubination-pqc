package org.pqkc.keycloak.webauthn.mldsa;

import com.webauthn4j.converter.util.ObjectConverter;
import com.webauthn4j.data.attestation.authenticator.COSEKey;
import jakarta.ws.rs.core.Response;
import org.jboss.logging.Logger;
import org.keycloak.WebAuthnConstants;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.Authenticator;
import org.keycloak.common.util.Base64Url;
import org.keycloak.credential.CredentialModel;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.UserSessionModel;
import org.keycloak.models.credential.WebAuthnCredentialModel;
import org.keycloak.services.managers.AuthenticationManager;

import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * Inspects the WebAuthn credential the user just authenticated with, records which signature
 * algorithm it uses, and optionally refuses the login unless that algorithm is post-quantum.
 *
 * <p>Keycloak's WebAuthn policy - including the list of acceptable signature algorithms - is a
 * <em>realm</em> setting, so it cannot by itself make one application stricter than another. What
 * <em>is</em> per-client is the authentication flow: a client can override the browser flow. Putting
 * this authenticator in a flow, configured to require ML-DSA, and binding that flow to one client
 * gives a per-application requirement while other clients keep using the permissive flow.
 *
 * <p>The check is deliberately made against the credential actually used, resolved from the
 * credential id the WebAuthn authenticator recorded, rather than against "does the user own an
 * ML-DSA credential somewhere". A user holding both an ES256 and an ML-DSA passkey must not be able
 * to satisfy a post-quantum requirement by presenting the ES256 one.
 */
public class MLDSAPolicyAuthenticator implements Authenticator {

    private static final Logger logger = Logger.getLogger(MLDSAPolicyAuthenticator.class);

    /** Session note published to clients through a user-session-note protocol mapper. */
    public static final String ALG_SESSION_NOTE = "webauthn_alg";
    public static final String PQ_SESSION_NOTE = "webauthn_pq";

    public static final String CONF_MODE = "mode";
    public static final String CONF_ON_MISSING = "on-missing";

    public static final String MODE_REQUIRE = "require";
    public static final String MODE_RECORD = "record";
    public static final String ON_MISSING_DENY = "deny";
    public static final String ON_MISSING_ENROL = "enrol";

    private final ObjectConverter objectConverter;

    public MLDSAPolicyAuthenticator(ObjectConverter objectConverter) {
        this.objectConverter = objectConverter;
    }

    @Override
    public void authenticate(AuthenticationFlowContext context) {
        String mode = config(context, CONF_MODE, MODE_RECORD);
        String onMissing = config(context, CONF_ON_MISSING, ON_MISSING_DENY);

        Resolved resolved = resolve(context);

        if (resolved == null) {
            // No WebAuthn credential was resolved. In record mode that is simply nothing to record;
            // in require mode it must fail closed - we cannot prove a post-quantum key was used.
            if (MODE_REQUIRE.equals(mode)) {
                logger.warnf("Cannot determine which WebAuthn credential was used for user '%s'; "
                        + "denying because this flow requires ML-DSA. Is this execution placed after "
                        + "the WebAuthn authenticator?", username(context));
                context.failureChallenge(AuthenticationFlowError.ACCESS_DENIED,
                        errorPage(context, "This application requires a post-quantum passkey, "
                                + "but the credential used could not be identified."));
                return;
            }
            // nothing to record, and this mode does not enforce: let the login proceed.
            // (context.attempted() would abort the flow, since this execution is REQUIRED)
            context.success();
            return;
        }

        String name = resolved.name();
        boolean pq = resolved.postQuantum();

        context.getAuthenticationSession().setUserSessionNote(ALG_SESSION_NOTE, name);
        context.getAuthenticationSession().setUserSessionNote(PQ_SESSION_NOTE, Boolean.toString(pq));
        context.getEvent().detail("webauthn_algorithm", name);

        if (!MODE_REQUIRE.equals(mode)) {
            logger.debugf("User '%s' authenticated with %s (post-quantum=%s, via %s)",
                    username(context), name, pq, resolved.source());
            context.success();
            return;
        }

        if (pq) {
            logger.debugf("User '%s' satisfied the ML-DSA requirement with %s", username(context), name);
            context.success();
            return;
        }

        if (ON_MISSING_ENROL.equals(onMissing)) {
            logger.infof("User '%s' authenticated with %s; requiring ML-DSA enrolment", username(context), name);
            context.getAuthenticationSession()
                    .addRequiredAction(MLDSAWebAuthnPasswordlessRegisterFactory.PROVIDER_ID);
            context.success();
            return;
        }

        logger.infof("Denying '%s': authenticated with %s but this application requires ML-DSA",
                username(context), name);
        context.failureChallenge(AuthenticationFlowError.ACCESS_DENIED,
                errorPage(context, "This application requires a post-quantum (ML-DSA) passkey. "
                        + "You signed in with " + name + "."));
    }

    /** What algorithm this login rests on, and where that was established. */
    private record Resolved(String name, boolean postQuantum, String source) {}

    /**
     * Establishes the algorithm behind this login, in decreasing order of directness.
     *
     * <p>The SSO case matters: {@code auth-cookie} short-circuits the flow, so a session originally
     * established with ES256 would otherwise walk straight into an application that requires
     * post-quantum authentication. The algorithm is therefore recorded as a user-session note at
     * first authentication and re-checked here on every subsequent SSO entry.
     */
    private Resolved resolve(AuthenticationFlowContext context) {
        Long alg = algorithmOfCredentialJustUsed(context);
        if (alg != null) {
            return new Resolved(WebAuthnAlgorithms.name(alg), WebAuthnAlgorithms.isPostQuantum(alg), "credential");
        }

        Map<String, String> pending = context.getAuthenticationSession().getUserSessionNotes();
        if (pending != null && pending.get(ALG_SESSION_NOTE) != null) {
            String name = pending.get(ALG_SESSION_NOTE);
            return new Resolved(name, WebAuthnAlgorithms.isPostQuantum(name), "auth-session note");
        }

        UserSessionModel sso = existingSsoSession(context);
        if (sso != null && sso.getNote(ALG_SESSION_NOTE) != null) {
            String name = sso.getNote(ALG_SESSION_NOTE);
            return new Resolved(name, WebAuthnAlgorithms.isPostQuantum(name), "SSO session note");
        }

        // Credential inventory is not authentication provenance. Brokered, recovery and
        // legacy sessions may exist even when the account stores exactly one PQ key.
        return null;
    }

    private UserSessionModel existingSsoSession(AuthenticationFlowContext context) {
        try {
            AuthenticationManager.AuthResult result = AuthenticationManager
                    .authenticateIdentityCookie(context.getSession(), context.getRealm(), true);
            return result == null ? null : result.getSession();
        } catch (RuntimeException e) {
            logger.debug("No usable SSO session while resolving the WebAuthn algorithm", e);
            return null;
        }
    }

    /**
     * Resolves the COSE algorithm of the credential used in this authentication.
     *
     * <p>The WebAuthn authenticator records the credential id it verified as an event detail; the
     * flow processor runs subsequent executions in the same request, so it is still readable here.
     * The public key is then read from that stored credential, which is the same key material the
     * assertion was verified against - it cannot be influenced by the client.
     */
    private Long algorithmOfCredentialJustUsed(AuthenticationFlowContext context) {
        UserModel user = context.getUser();
        if (user == null) return null;

        String usedCredentialId = usedCredentialId(context);
        if (usedCredentialId == null) return null;

        return user.credentialManager()
                .getStoredCredentialsByTypeStream(WebAuthnCredentialModel.TYPE_PASSWORDLESS)
                .map(CredentialAlgorithms::toWebAuthn)
                .filter(m -> m != null && CredentialAlgorithms.sameCredentialId(
                        usedCredentialId, m.getWebAuthnCredentialData().getCredentialId()))
                .findFirst()
                .map(m -> CredentialAlgorithms.coseAlgorithm(m, objectConverter))
                .orElse(null);
    }

    private String usedCredentialId(AuthenticationFlowContext context) {
        if (context.getEvent() == null || context.getEvent().getEvent() == null) return null;
        Map<String, String> details = context.getEvent().getEvent().getDetails();
        if (details == null) return null;
        return details.get(WebAuthnConstants.PUBKEY_CRED_ID_ATTR);
    }



    private Response errorPage(AuthenticationFlowContext context, String message) {
        return context.form().setError(message).createErrorPage(Response.Status.FORBIDDEN);
    }

    private static String config(AuthenticationFlowContext context, String key, String fallback) {
        AuthenticatorConfigModel cfg = context.getAuthenticatorConfig();
        if (cfg == null || cfg.getConfig() == null) return fallback;
        String v = cfg.getConfig().get(key);
        return v == null || v.isBlank() ? fallback : v.trim();
    }

    private static String username(AuthenticationFlowContext context) {
        return context.getUser() == null ? "(unknown)" : context.getUser().getUsername();
    }

    @Override public void action(AuthenticationFlowContext context) { /* no interaction of its own */ }
    @Override public boolean requiresUser() { return true; }
    @Override public boolean configuredFor(KeycloakSession s, RealmModel r, UserModel u) { return true; }
    @Override public void setRequiredActions(KeycloakSession s, RealmModel r, UserModel u) { /* NOP */ }
    @Override public void close() { /* NOP */ }
}
