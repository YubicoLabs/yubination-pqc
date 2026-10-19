package org.pqkc.keycloak.webauthn.mldsa;

import com.webauthn4j.WebAuthnRegistrationManager;
import com.webauthn4j.data.AttestationConveyancePreference;
import com.webauthn4j.data.attestation.statement.COSEAlgorithmIdentifier;
import com.webauthn4j.verifier.attestation.statement.AttestationStatementVerifier;
import com.webauthn4j.verifier.attestation.statement.androidkey.AndroidKeyAttestationStatementVerifier;
import com.webauthn4j.verifier.attestation.statement.androidsafetynet.AndroidSafetyNetAttestationStatementVerifier;
import com.webauthn4j.verifier.attestation.statement.none.NoneAttestationStatementVerifier;
import com.webauthn4j.verifier.attestation.statement.packed.PackedAttestationStatementVerifier;
import com.webauthn4j.verifier.attestation.statement.tpm.TPMAttestationStatementVerifier;
import com.webauthn4j.verifier.attestation.statement.u2f.FIDOU2FAttestationStatementVerifier;
import com.webauthn4j.verifier.attestation.trustworthiness.certpath.CertPathTrustworthinessVerifier;
import com.webauthn4j.verifier.attestation.trustworthiness.self.DefaultSelfAttestationTrustworthinessVerifier;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import org.keycloak.WebAuthnConstants;
import org.keycloak.authentication.RequiredActionContext;
import org.keycloak.authentication.requiredactions.WebAuthnPasswordlessRegister;
import org.keycloak.common.util.Base64Url;
import org.keycloak.crypto.Algorithm;
import org.keycloak.http.HttpRequest;
import org.keycloak.models.Constants;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.UserModel;
import org.keycloak.models.WebAuthnPolicy;
import org.keycloak.credential.CredentialModel;
import org.keycloak.models.credential.WebAuthnCredentialModel;
import org.jboss.logging.Logger;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Collectors;

import com.webauthn4j.data.client.challenge.Challenge;
import com.webauthn4j.data.client.challenge.DefaultChallenge;

/**
 * Passwordless WebAuthn registration that can also enrol ML-DSA (FIPS 204) credentials.
 *
 * <p>Two things differ from the stock {@link WebAuthnPasswordlessRegister}:
 * <ol>
 *   <li>{@link #createWebAuthnRegistrationManager(String)} is given an {@link com.webauthn4j.converter.util.ObjectConverter}
 *       that understands COSE {@code kty = 7} (AKP), so an attestation object containing an
 *       ML-DSA credential public key parses instead of blowing up on an unknown key type;</li>
 *   <li>{@link #requiredActionChallenge(RequiredActionContext)} is re-implemented because the stock
 *       algorithm-name to COSE-identifier conversion lives in a {@code private} method whose
 *       {@code switch} silently drops anything it does not recognise - including ML-DSA. Without
 *       this the browser would never be offered {@code -48/-49/-50} in {@code pubKeyCredParams}.</li>
 * </ol>
 * Everything else - storage, the assertion ceremony, credential management - is stock Keycloak.
 */
public class MLDSAWebAuthnPasswordlessRegister extends WebAuthnPasswordlessRegister {

    private static final Logger logger = Logger.getLogger(MLDSAWebAuthnPasswordlessRegister.class);

    /** {@code WebAuthnRegister.certPathtrustVerifier} is private, so keep our own reference. */
    private final CertPathTrustworthinessVerifier certPathTrustworthinessVerifier;

    public MLDSAWebAuthnPasswordlessRegister(KeycloakSession session, CertPathTrustworthinessVerifier verifier) {
        super(session, verifier);
        this.certPathTrustworthinessVerifier = verifier;
    }

    @Override
    protected WebAuthnRegistrationManager createWebAuthnRegistrationManager(String attestationPreference) {
        List<AttestationStatementVerifier> verifiers = new ArrayList<>(6);
        if (attestationPreference == null
                || Constants.DEFAULT_WEBAUTHN_POLICY_NOT_SPECIFIED.equals(attestationPreference)
                || AttestationConveyancePreference.NONE.getValue().equals(attestationPreference)) {
            verifiers.add(new NoneAttestationStatementVerifier());
        }
        verifiers.add(new PackedAttestationStatementVerifier());
        verifiers.add(new TPMAttestationStatementVerifier());
        verifiers.add(new AndroidKeyAttestationStatementVerifier());
        verifiers.add(new AndroidSafetyNetAttestationStatementVerifier());
        verifiers.add(new FIDOU2FAttestationStatementVerifier());

        return new WebAuthnRegistrationManager(
                verifiers,
                certPathTrustworthinessVerifier,
                new DefaultSelfAttestationTrustworthinessVerifier(),
                Collections.emptyList(),
                MLDSAObjectConverters.create());   // <- the only substantive change
    }

    /**
     * The stock implementation, with {@link #convertSignatureAlgorithms(List)} swapped in for the
     * private original. Kept deliberately close to upstream so it is easy to diff against
     * {@code WebAuthnRegister#requiredActionChallenge} when Keycloak is upgraded.
     */
    @Override
    public void requiredActionChallenge(RequiredActionContext context) {
        String actionParameter = context.getAuthenticationSession().getClientNote(Constants.KC_ACTION_PARAMETER);
        UserModel userModel = context.getUser();
        if (Constants.KC_ACTION_PARAMETER_SKIP_IF_EXISTS.equals(actionParameter)
                && userModel.credentialManager().getStoredCredentialsByTypeStream(getCredentialType()).findAny().isPresent()) {
            context.success();
            return;
        }

        String userId = Base64Url.encode(userModel.getId().getBytes(StandardCharsets.UTF_8));
        String username = userModel.getUsername();
        Challenge challenge = new DefaultChallenge();
        String challengeValue = Base64Url.encode(challenge.getValue());
        context.getAuthenticationSession().setAuthNote(WebAuthnConstants.AUTH_CHALLENGE_NOTE, challengeValue);

        WebAuthnPolicy policy = getWebAuthnPolicy(context);
        List<Long> signatureAlgorithms =
                applyWebKitWorkaround(context, convertSignatureAlgorithms(policy.getSignatureAlgorithm()));
        String rpEntityName = policy.getRpEntityName();

        String rpId = policy.getRpId();
        if (rpId == null || rpId.isEmpty()) rpId = context.getUriInfo().getBaseUri().getHost();
        String attestationConveyancePreference = policy.getAttestationConveyancePreference();
        String authenticatorAttachment = policy.getAuthenticatorAttachment();
        String requireResidentKey = policy.getRequireResidentKey();
        String userVerificationRequirement = policy.getUserVerificationRequirement();
        long createTimeout = policy.getCreateTimeout();
        boolean avoidSameAuthenticatorRegister = policy.isAvoidSameAuthenticatorRegister();

        String excludeCredentialIds = "";
        if (avoidSameAuthenticatorRegister) {
            excludeCredentialIds = userModel.credentialManager().getStoredCredentialsByTypeStream(getCredentialType())
                    .map(credentialModel -> {
                        WebAuthnCredentialModel credModel = WebAuthnCredentialModel.createFromCredentialModel(credentialModel);
                        return Base64Url.encodeBase64ToBase64Url(credModel.getWebAuthnCredentialData().getCredentialId());
                    }).collect(Collectors.joining(","));
        }

        String isSetRetry = null;
        if (isFormDataRequest(context.getHttpRequest())) {
            isSetRetry = context.getHttpRequest().getDecodedFormParameters().getFirst(WebAuthnConstants.IS_SET_RETRY);
        }

        Response form = context.form()
                .setAttribute(WebAuthnConstants.CHALLENGE, challengeValue)
                .setAttribute(WebAuthnConstants.USER_ID, userId)
                .setAttribute(WebAuthnConstants.USER_NAME, username)
                .setAttribute(WebAuthnConstants.RP_ENTITY_NAME, rpEntityName)
                .setAttribute(WebAuthnConstants.SIGNATURE_ALGORITHMS, signatureAlgorithms)
                .setAttribute(WebAuthnConstants.RP_ID, rpId)
                .setAttribute(WebAuthnConstants.ATTESTATION_CONVEYANCE_PREFERENCE, attestationConveyancePreference)
                .setAttribute(WebAuthnConstants.AUTHENTICATOR_ATTACHMENT, authenticatorAttachment)
                .setAttribute(WebAuthnConstants.REQUIRE_RESIDENT_KEY, requireResidentKey)
                .setAttribute(WebAuthnConstants.USER_VERIFICATION_REQUIREMENT, userVerificationRequirement)
                .setAttribute(WebAuthnConstants.CREATE_TIMEOUT, createTimeout)
                .setAttribute(WebAuthnConstants.EXCLUDE_CREDENTIAL_IDS, excludeCredentialIds)
                .setAttribute(WebAuthnConstants.IS_SET_RETRY, isSetRetry)
                .createForm("webauthn-register.ftl");
        context.challenge(form);
    }

    /**
     * Records the algorithm of the credential just enrolled onto the session.
     *
     * <p>Without this, a session established by <em>registration</em> carries no evidence of which
     * algorithm backs it: no WebAuthn assertion took place, so there is no credential id in the event
     * details and no session note. An application that requires ML-DSA would then refuse the user
     * immediately after they enrolled an ML-DSA passkey - the check failing closed on a legitimate
     * path. Enrolling with user verification does prove possession of that authenticator, so the
     * enrolled algorithm is exactly the right thing to record here.
     */
    @Override
    public void processAction(RequiredActionContext context) {
        Set<String> before = storedCredentialIds(context);
        super.processAction(context);

        UserModel user = context.getUser();
        if (user == null) return;

        WebAuthnCredentialModel enrolled = user.credentialManager()
                .getStoredCredentialsByTypeStream(getCredentialType())
                .filter(c -> !before.contains(c.getId()))
                .map(CredentialAlgorithms::toWebAuthn)
                .filter(Objects::nonNull)
                .findFirst()
                .orElse(null);
        if (enrolled == null) {
            return;   // nothing new was stored, so the enrolment did not succeed
        }

        Long alg = CredentialAlgorithms.coseAlgorithm(enrolled, MLDSAObjectConverters.shared());
        if (alg == null) return;

        String name = WebAuthnAlgorithms.name(alg);
        boolean pq = WebAuthnAlgorithms.isPostQuantum(alg);
        context.getAuthenticationSession().setUserSessionNote(MLDSAPolicyAuthenticator.ALG_SESSION_NOTE, name);
        context.getAuthenticationSession().setUserSessionNote(MLDSAPolicyAuthenticator.PQ_SESSION_NOTE,
                Boolean.toString(pq));
        logger.infof("User '%s' enrolled a %s passkey (post-quantum=%s)", user.getUsername(), name, pq);

        guardAgainstWrappedSignatureCounter(context, enrolled);
    }

    /**
     * Signature counters above this at <em>registration</em> are treated as corrupt. A genuine
     * authenticator would have to have produced two billion signatures to reach it.
     */
    private static final long IMPLAUSIBLE_REGISTRATION_COUNTER = 1L << 31;

    /**
     * Neutralises a corrupt signature counter recorded at enrolment.
     *
     * <p>Windows' {@code webauthn.dll} has a USB HID counter-wrapping bug that manifests during
     * registration. That matters more than it sounds: WebAuthn's signature counter is the
     * cloned-credential defence, and webauthn4j's default
     * {@code DefaultCoreMaliciousCounterValueHandler} <em>throws</em> whenever a presented counter is
     * not greater than the stored one. So a credential registered with a wrapped, very large counter
     * authenticates once against a small counter, is judged a clone, and is refused for ever - as a
     * generic "invalid credentials", giving no hint of the cause.
     *
     * <p>Resetting the stored counter to zero costs almost nothing: Keycloak's own bookkeeping
     * (`WebAuthnCredentialProvider.isValid` does {@code updateCounter(stored + 1)}) advances the
     * stored value by one per login regardless of what the authenticator reports, so clone detection
     * resumes from the first authentication either way.
     */
    private void guardAgainstWrappedSignatureCounter(RequiredActionContext context, WebAuthnCredentialModel enrolled) {
        long counter = enrolled.getWebAuthnCredentialData().getCounter();
        if (counter < IMPLAUSIBLE_REGISTRATION_COUNTER) {
            return;
        }
        try {
            enrolled.updateCounter(0L);
            context.getUser().credentialManager().updateStoredCredential(enrolled);
            logger.warnf("Credential for '%s' registered with an implausible signature counter (%d); "
                    + "reset to 0. This is the Windows webauthn.dll USB HID counter-wrapping bug - "
                    + "left alone it would make every later login fail as a suspected cloned credential.",
                    context.getUser().getUsername(), counter);
        } catch (RuntimeException e) {
            logger.errorf(e, "Could not reset the wrapped signature counter (%d) for '%s'; "
                    + "logins with this credential are likely to fail as suspected clones.",
                    counter, context.getUser().getUsername());
        }
    }

    /**
     * WebKit picks ES256 out of {@code pubKeyCredParams} whenever it is present, disregarding the
     * order the relying party asked for. Since every browser on iOS is WebKit, a post-quantum
     * authenticator there silently enrols a classical credential instead.
     *
     * <p>When {@code webkit-pq-preference} is set to {@code honour}, WebKit clients are sent only the
     * post-quantum entries, so the RP's stated preference is actually respected. The cost is real and
     * unavoidable: on those clients an authenticator that cannot do ML-DSA then fails to enrol at all
     * rather than falling back. There is no third option - the bug makes preference and fallback
     * mutually exclusive on WebKit.
     */
    private List<Long> applyWebKitWorkaround(RequiredActionContext context, List<Long> algorithms) {
        if (!"honour".equalsIgnoreCase(configOption(context, "webkit-pq-preference", "ignore"))) {
            return algorithms;
        }
        List<Long> postQuantum = algorithms.stream()
                .filter(WebAuthnAlgorithms::isPostQuantum)
                .collect(Collectors.toList());
        if (postQuantum.isEmpty() || postQuantum.size() == algorithms.size() || !isWebKit(context)) {
            return algorithms;
        }
        logger.infof("WebKit client detected; offering only %s so the post-quantum preference is not "
                + "reordered away", postQuantum);
        return postQuantum;
    }

    /** True for Safari and for every browser on iOS, all of which are WebKit. */
    private boolean isWebKit(RequiredActionContext context) {
        String ua = context.getHttpRequest().getHttpHeaders().getRequestHeaders().getFirst("User-Agent");
        if (ua == null || !ua.contains("AppleWebKit")) return false;
        // iOS: Chrome/Firefox/Edge are WebKit too, and identify themselves with these tokens
        if (ua.contains("CriOS") || ua.contains("FxiOS") || ua.contains("EdgiOS")) return true;
        // desktop: Blink-based browsers also say AppleWebKit, so exclude them
        return !ua.contains("Chrome") && !ua.contains("Chromium") && !ua.contains("Android");
    }

    private static String configOption(RequiredActionContext context, String key, String fallback) {
        var config = context.getConfig();
        if (config == null || config.getConfig() == null) return fallback;
        String value = config.getConfig().get(key);
        return value == null || value.isBlank() ? fallback : value.trim();
    }

    private Set<String> storedCredentialIds(RequiredActionContext context) {
        UserModel user = context.getUser();
        if (user == null) return Set.of();
        return user.credentialManager()
                .getStoredCredentialsByTypeStream(getCredentialType())
                .map(CredentialModel::getId)
                .collect(Collectors.toSet());
    }

    /**
     * Same mapping as upstream plus the three RFC 9964 ML-DSA identifiers. Unknown names are
     * dropped, exactly as upstream does.
     */
    static List<Long> convertSignatureAlgorithms(List<String> signatureAlgorithmsList) {
        List<Long> algs = new ArrayList<>();
        if (signatureAlgorithmsList == null || signatureAlgorithmsList.isEmpty()) return algs;

        for (String s : signatureAlgorithmsList) {
            MLDSAParameterSet mldsa = MLDSAParameterSet.fromJcaName(s);
            if (mldsa != null) {
                algs.add(mldsa.coseIdentifier());
                continue;
            }
            switch (s) {
                case Algorithm.ES256 -> algs.add(COSEAlgorithmIdentifier.ES256.getValue());
                case Algorithm.RS256 -> algs.add(COSEAlgorithmIdentifier.RS256.getValue());
                case Algorithm.ES384 -> algs.add(COSEAlgorithmIdentifier.ES384.getValue());
                case Algorithm.RS384 -> algs.add(COSEAlgorithmIdentifier.RS384.getValue());
                case Algorithm.ES512 -> algs.add(COSEAlgorithmIdentifier.ES512.getValue());
                case Algorithm.RS512 -> algs.add(COSEAlgorithmIdentifier.RS512.getValue());
                case Algorithm.Ed25519 -> algs.add(COSEAlgorithmIdentifier.EdDSA.getValue());
                case "RS1" -> algs.add(COSEAlgorithmIdentifier.RS1.getValue());
                default -> { /* NOP, as upstream */ }
            }
        }
        return algs;
    }

    private boolean isFormDataRequest(HttpRequest request) {
        MediaType mediaType = request.getHttpHeaders().getMediaType();
        return mediaType != null && mediaType.isCompatible(MediaType.APPLICATION_FORM_URLENCODED_TYPE);
    }
}
