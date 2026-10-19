package org.pqkc.webauthn.va;

import java.net.CookieHandler;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Drives a complete WebAuthn registration and authentication ceremony against a running Keycloak,
 * substituting {@link VirtualMLDSAAuthenticator} for the browser + security key.
 *
 * <p>Everything the server sees is byte-identical to what a real ML-DSA authenticator would send,
 * so a green run here means Keycloak genuinely parsed an AKP COSE key, stored it, and later
 * verified a FIPS 204 signature over {@code authenticatorData || SHA-256(clientDataJSON)}.
 *
 * <pre>usage: Ceremony &lt;baseUrl&gt; &lt;realm&gt; &lt;clientId&gt; &lt;redirectUri&gt; &lt;username&gt; &lt;ML-DSA-44|65|87&gt;</pre>
 */
public class Ceremony {

    private static final Base64.Encoder B64URL = Base64.getUrlEncoder().withoutPadding();

    private final HttpClient http;
    private final String base, realm, clientId, redirectUri, origin;
    /** The demo clients require PKCE, as a public client should. */
    private final String codeVerifier;
    private final String codeChallenge;

    Ceremony(String base, String realm, String clientId, String redirectUri) {
        this.base = base; this.realm = realm; this.clientId = clientId; this.redirectUri = redirectUri;
        this.origin = base;
        this.codeVerifier = randomVerifier();
        this.codeChallenge = challengeFor(this.codeVerifier);
        this.http = HttpClient.newBuilder()
                .cookieHandler(new LocalhostCookieJar())
                .followRedirects(HttpClient.Redirect.NORMAL)
                .build();
    }

    /**
     * Keycloak marks its session cookies {@code Secure} because it also sets {@code SameSite=None},
     * which the cookie spec requires. Browsers still accept those over {@code http://localhost}
     * because localhost is a trustworthy origin - the same reason WebAuthn works there - but
     * {@link java.net.CookieManager} enforces {@code Secure} strictly and drops them, which breaks
     * the login session. This jar reproduces the browser's localhost behaviour: single host, all
     * cookies replayed. It is a test client, not a general-purpose cookie store.
     */
    static final class LocalhostCookieJar extends CookieHandler {
        private final Map<String, String> jar = new java.util.concurrent.ConcurrentHashMap<>();

        @Override
        public Map<String, java.util.List<String>> get(URI uri, Map<String, java.util.List<String>> request) {
            if (jar.isEmpty()) return Map.of();
            StringBuilder sb = new StringBuilder();
            jar.forEach((k, v) -> {
                if (sb.length() > 0) sb.append("; ");
                sb.append(k).append('=').append(v);
            });
            return Map.of("Cookie", java.util.List.of(sb.toString()));
        }

        @Override
        public void put(URI uri, Map<String, java.util.List<String>> responseHeaders) {
            responseHeaders.forEach((header, values) -> {
                if (header == null || !header.equalsIgnoreCase("Set-Cookie")) return;
                for (String setCookie : values) {
                    String pair = setCookie.split(";", 2)[0].trim();
                    int eq = pair.indexOf('=');
                    if (eq <= 0) continue;
                    String name = pair.substring(0, eq);
                    String value = pair.substring(eq + 1);
                    if (value.isEmpty()) jar.remove(name); else jar.put(name, value);
                }
            });
        }
    }

    // ---------------------------------------------------------------- http helpers

    private HttpResponse<String> get(String url) throws Exception {
        return http.send(HttpRequest.newBuilder(URI.create(url)).GET().build(),
                HttpResponse.BodyHandlers.ofString());
    }

    private HttpResponse<String> postForm(String url, Map<String, String> form) throws Exception {
        StringBuilder sb = new StringBuilder();
        form.forEach((k, v) -> {
            if (sb.length() > 0) sb.append('&');
            sb.append(URLEncoder.encode(k, StandardCharsets.UTF_8)).append('=')
              .append(URLEncoder.encode(v == null ? "" : v, StandardCharsets.UTF_8));
        });
        return http.send(HttpRequest.newBuilder(URI.create(url))
                .header("Content-Type", "application/x-www-form-urlencoded")
                .POST(HttpRequest.BodyPublishers.ofString(sb.toString()))
                .build(), HttpResponse.BodyHandlers.ofString());
    }

    // ---------------------------------------------------------------- page scraping

    private static String unescape(String s) {
        return s.replace("&amp;", "&").replace("&quot;", "\"").replace("&#39;", "'").replace("&lt;", "<").replace("&gt;", ">");
    }

    private String absolute(String url) { return url.startsWith("http") ? url : base + url; }

    private String find(String html, String regex, String what) {
        Matcher m = Pattern.compile(regex).matcher(html);
        if (!m.find()) throw new IllegalStateException("could not find " + what + " in page:\n" + excerpt(html));
        return unescape(m.group(1));
    }

    static String excerpt(String html) {
        Matcher t = Pattern.compile("<title>([^<]*)</title>").matcher(html);
        String title = t.find() ? t.group(1) : "(no title)";
        Matcher e = Pattern.compile("(?s)id=\"kc-error-message\".*?<p[^>]*>(.*?)</p>").matcher(html);
        String err = e.find() ? e.group(1).trim() : "";
        Matcher f = Pattern.compile("(?s)class=\"[^\"]*kc-feedback-text[^\"]*\"[^>]*>(.*?)<").matcher(html);
        String fb = f.find() ? f.group(1).trim() : "";
        return "  title: " + title + (err.isEmpty() ? "" : "\n  error: " + err) + (fb.isEmpty() ? "" : "\n  feedback: " + fb);
    }

    private String formAction(String html, String contains) {
        return absolute(find(html, "action=\"([^\"]*" + Pattern.quote(contains) + "[^\"]*)\"", "form action containing " + contains));
    }

    private String jsAttr(String html, String name) {
        return find(html, name + "\\s*:\\s*'([^']*)'", "JS attribute " + name);
    }

    private String authUrl() { return authUrl(clientId, redirectUri); }

    private String authUrl(String client, String redirect) {
        return base + "/realms/" + realm + "/protocol/openid-connect/auth?client_id=" + client
                + "&response_type=code&scope=openid&redirect_uri="
                + URLEncoder.encode(redirect, StandardCharsets.UTF_8)
                + "&code_challenge=" + codeChallenge + "&code_challenge_method=S256";
    }

    private static String randomVerifier() {
        byte[] bytes = new byte[32];
        new java.security.SecureRandom().nextBytes(bytes);
        return B64URL.encodeToString(bytes);
    }

    private static String challengeFor(String verifier) {
        try {
            return B64URL.encodeToString(java.security.MessageDigest.getInstance("SHA-256")
                    .digest(verifier.getBytes(StandardCharsets.US_ASCII)));
        } catch (java.security.NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    /** Claims from the ID token of the most recent {@link #tryLogin}. */
    String lastIdTokenClaims() throws Exception {
        String jwt = lastRawIdToken();
        return jwt == null ? null : new String(Base64.getUrlDecoder().decode(jwt.split("\\.")[1]),
                StandardCharsets.UTF_8);
    }

    /** The compact ID token (header.payload.signature) of the most recent {@link #tryLogin}. */
    String lastRawIdToken() throws Exception {
        if (lastSession == null || lastLanding == null) return null;
        return lastSession.idToken(lastLanding);
    }

    /** The access token of the most recent {@link #tryLogin}. */
    String lastAccessToken() throws Exception {
        if (lastSession == null || lastLanding == null) return null;
        return lastSession.token(lastLanding, "access_token");
    }

    String idToken(String landedUrl) throws Exception { return token(landedUrl, "id_token"); }

    /** Redeems an authorization code and returns one token from the response. */
    String token(String landedUrl, String which) throws Exception {
        String code = null;
        for (String kv : URI.create(landedUrl).getQuery().split("&")) {
            if (kv.startsWith("code=")) { code = kv.substring(5); break; }
        }
        if (code == null) return null;
        Map<String, String> form = new LinkedHashMap<>();
        form.put("grant_type", "authorization_code");
        form.put("client_id", clientId);
        form.put("code", code);
        form.put("redirect_uri", redirectUri);
        form.put("code_verifier", codeVerifier);
        String body = postForm(base + "/realms/" + realm + "/protocol/openid-connect/token", form).body();
        Matcher m = Pattern.compile("\"" + which + "\"\\s*:\\s*\"([^\"]+)\"").matcher(body);
        if (!m.find()) throw new IllegalStateException("no " + which + " in token response: " + body);
        return m.group(1);
    }

    private String clientData(String type, String challenge) {
        // built by hand: these exact bytes are what gets hashed and signed
        return "{\"type\":\"" + type + "\",\"challenge\":\"" + challenge
                + "\",\"origin\":\"" + origin + "\",\"crossOrigin\":false}";
    }

    // ---------------------------------------------------------------- ceremonies

    /** Same as {@link #register} but without the narration, for the matrix test. */
    VirtualMLDSAAuthenticator registerQuietly(String username, String jcaName, long coseAlg) throws Exception {
        java.io.PrintStream real = System.out;
        System.setOut(new java.io.PrintStream(java.io.OutputStream.nullOutputStream()));
        try { return register(username, jcaName, coseAlg); } finally { System.setOut(real); }
    }

    /** Self-register a user, then enrol an ML-DSA passkey through the required action. */
    VirtualMLDSAAuthenticator register(String username, String jcaName, long coseAlg) throws Exception {
        System.out.println("== REGISTRATION ==");
        String login = get(authUrl()).body();
        String regLink = absolute(find(login, "href=\"([^\"]*login-actions/registration[^\"]*)\"", "registration link"));

        String regPage = get(regLink).body();
        if (regPage.contains("type=\"password\"")) throw new IllegalStateException("registration form asked for a password");
        System.out.println("  registration form served, no password field");

        String regAction = formAction(regPage, "login-actions/registration");
        Map<String, String> f = new LinkedHashMap<>();
        f.put("username", username);
        f.put("email", username + "@example.com");
        f.put("firstName", "PQ");
        f.put("lastName", "User");
        String enrol = postForm(regAction, f).body();

        String algs = find(enrol, "signatureAlgorithms\\s*:\\s*\\[([^\\]]*)\\]", "signatureAlgorithms");
        System.out.println("  server offered pubKeyCredParams: [" + algs + "]");
        if (!algs.contains(String.valueOf(coseAlg)))
            throw new IllegalStateException("server did not offer " + jcaName + " (" + coseAlg + ")");

        String challenge = jsAttr(enrol, "challenge");
        String rpId = jsAttr(enrol, "rpId");
        String action = formAction(enrol, "login-actions/required-action");
        System.out.println("  challenge=" + challenge + " rpId=" + rpId);

        VirtualMLDSAAuthenticator auth = "ES256".equals(jcaName)
                ? VirtualMLDSAAuthenticator.es256()
                : VirtualMLDSAAuthenticator.mldsa(jcaName, coseAlg);
        byte[] clientDataJson = clientData("webauthn.create", challenge).getBytes(StandardCharsets.UTF_8);
        byte[] attestationObject = auth.makeAttestationObject(rpId);
        System.out.println("  built attestationObject: " + attestationObject.length + " bytes ("
                + auth.jcaName() + ")");

        Map<String, String> reg = new LinkedHashMap<>();
        reg.put("clientDataJSON", B64URL.encodeToString(clientDataJson));
        reg.put("attestationObject", B64URL.encodeToString(attestationObject));
        reg.put("publicKeyCredentialId", B64URL.encodeToString(auth.credentialId()));
        reg.put("authenticatorLabel", "virtual-" + jcaName);
        reg.put("transports", "internal");
        HttpResponse<String> res = postForm(action, reg);

        String body = res.body();
        boolean landed = res.uri().toString().startsWith(redirectUri) || body.contains("code=");
        if (!landed && (body.contains("kc-error-message") || body.contains("webauthn-register")))
            throw new IllegalStateException("registration rejected:\n" + excerpt(body));
        System.out.println("  registration ACCEPTED -> " + res.uri());
        return auth;
    }

    /** How to corrupt an assertion, for the negative tests. */
    enum Tamper {
        NONE("valid assertion"),
        WRONG_KEY("assertion signed by a different credential key"),
        FLIPPED_SIGNATURE("one bit flipped in the signature"),
        TAMPERED_AUTHDATA("authenticatorData modified after signing");
        final String description;
        Tamper(String d) { this.description = d; }
    }

    /** Log in from a clean session using only the ML-DSA credential. */
    void authenticate(String username, VirtualMLDSAAuthenticator auth) throws Exception {
        System.out.println("== AUTHENTICATION (fresh session) ==");
        String uri = attempt(username, auth, Tamper.NONE);
        if (uri == null || !uri.startsWith(redirectUri) || !uri.contains("code="))
            throw new IllegalStateException("authentication failed; landed on " + uri);
        System.out.println("  authentication ACCEPTED, authorization code issued");
        System.out.println("  -> " + uri.replaceAll("code=[^&]*", "code=<redacted>"));
    }

    /** A corrupted assertion must not authenticate. */
    void authenticateMustFail(String username, VirtualMLDSAAuthenticator auth, Tamper tamper) throws Exception {
        String uri = attempt(username, auth, tamper);
        boolean authenticated = uri != null && uri.startsWith(redirectUri) && uri.contains("code=");
        if (authenticated)
            throw new IllegalStateException("SECURITY FAILURE: " + tamper.description + " was ACCEPTED");
        System.out.println("  rejected as expected: " + tamper.description);
    }

    /** Set false to run attempts without narration (the application matrix does its own). */
    boolean narrate = true;
    /** Where the most recent tryLogin ended up, so callers can redeem the code. */
    String lastLanding;
    /** The throwaway session that actually performed it - it holds the matching PKCE verifier. */
    private Ceremony lastSession;
    /** Body of the last assertion response, so a denial's reason can be shown. */
    String lastBody;

    /** Runs one assertion attempt in a fresh session; returns the final URL. */
    String attempt(String username, VirtualMLDSAAuthenticator auth, Tamper tamper) throws Exception {
        Ceremony fresh = new Ceremony(base, realm, clientId, redirectUri);
        this.lastSession = fresh;
        String login = fresh.get(fresh.authUrl()).body();
        if (login.contains("type=\"password\"")) throw new IllegalStateException("login form offered a password");
        if (tamper == Tamper.NONE && narrate) System.out.println("  login form served, no password field");

        String loginAction = fresh.formAction(login, "login-actions/authenticate");
        String page = fresh.postForm(loginAction, Map.of("username", username)).body();

        String challenge = fresh.jsAttr(page, "challenge");
        String rpId = fresh.jsAttr(page, "rpId");
        String action = fresh.formAction(page, "login-actions/authenticate");

        byte[] clientDataJson = fresh.clientData("webauthn.get", challenge).getBytes(StandardCharsets.UTF_8);
        byte[] authenticatorData = auth.assertionAuthenticatorData(rpId);

        byte[] signature;
        if (tamper == Tamper.WRONG_KEY) {
            signature = auth.freshImpostor().sign(authenticatorData, clientDataJson);
        } else {
            signature = auth.sign(authenticatorData, clientDataJson);
        }

        if (tamper == Tamper.FLIPPED_SIGNATURE) {
            signature = signature.clone();
            signature[signature.length / 2] ^= 0x01;
        }
        if (tamper == Tamper.TAMPERED_AUTHDATA) {
            authenticatorData = authenticatorData.clone();
            authenticatorData[33] ^= 0x01;   // perturb the signature counter, post-signing
        }

        if (tamper == Tamper.NONE && narrate)
            System.out.println("  " + auth.jcaName() + " signature: " + signature.length + " bytes");

        Map<String, String> a = new LinkedHashMap<>();
        a.put("clientDataJSON", B64URL.encodeToString(clientDataJson));
        a.put("authenticatorData", B64URL.encodeToString(authenticatorData));
        a.put("signature", B64URL.encodeToString(signature));
        a.put("credentialId", B64URL.encodeToString(auth.credentialId()));
        a.put("userHandle", "");
        HttpResponse<String> response = fresh.postForm(action, a);
        this.lastBody = response.body();
        return response.uri().toString();
    }

    /** Full login in a fresh session; true when an authorization code came back. */
    boolean tryLogin(String username, VirtualMLDSAAuthenticator auth) throws Exception {
        lastLanding = attempt(username, auth, Tamper.NONE);
        return lastLanding != null && lastLanding.startsWith(redirectUri) && lastLanding.contains("code=");
    }

    /**
     * Request authorization for a different client on the SAME browser session, exercising SSO.
     * Returns true when Keycloak issued a code without re-authenticating.
     */
    boolean ssoInto(String otherClientId, String otherRedirect) throws Exception {
        String landed = get(authUrl(otherClientId, otherRedirect)).uri().toString();
        return landed.startsWith(otherRedirect) && landed.contains("code=");
    }

    /** Establishes an SSO session by logging in normally, keeping this instance's cookies. */
    boolean loginKeepingSession(String username, VirtualMLDSAAuthenticator auth) throws Exception {
        String login = get(authUrl()).body();
        String loginAction = formAction(login, "login-actions/authenticate");
        String page = postForm(loginAction, Map.of("username", username)).body();
        String challenge = jsAttr(page, "challenge");
        String rpId = jsAttr(page, "rpId");
        String action = formAction(page, "login-actions/authenticate");

        byte[] clientDataJson = clientData("webauthn.get", challenge).getBytes(StandardCharsets.UTF_8);
        byte[] authenticatorData = auth.assertionAuthenticatorData(rpId);
        byte[] signature = auth.sign(authenticatorData, clientDataJson);

        Map<String, String> a = new LinkedHashMap<>();
        a.put("clientDataJSON", B64URL.encodeToString(clientDataJson));
        a.put("authenticatorData", B64URL.encodeToString(authenticatorData));
        a.put("signature", B64URL.encodeToString(signature));
        a.put("credentialId", B64URL.encodeToString(auth.credentialId()));
        a.put("userHandle", "");
        String landed = postForm(action, a).uri().toString();
        return landed.startsWith(redirectUri) && landed.contains("code=");
    }

    public static void main(String[] args) throws Exception {
        String base = args.length > 0 ? args[0] : "http://localhost:8085";
        String realm = args.length > 1 ? args[1] : "pq";
        String clientId = args.length > 2 ? args[2] : "test-app";
        String redirect = args.length > 3 ? args[3] : "http://localhost:8085/callback";
        String user = args.length > 4 ? args[4] : "pq-" + System.currentTimeMillis();
        String alg = args.length > 5 ? args[5] : "ML-DSA-44";

        long cose = switch (alg) {
            case "ML-DSA-44" -> -48L;
            case "ML-DSA-65" -> -49L;
            case "ML-DSA-87" -> -50L;
            case "ES256"     -> -7L;   // stock algorithm, used as the regression control
            default -> throw new IllegalArgumentException("unknown algorithm " + alg);
        };

        System.out.println("Keycloak : " + base + " realm=" + realm);
        System.out.println("User     : " + user);
        System.out.println("Algorithm: " + alg + " (COSE " + cose + ")\n");

        Ceremony c = new Ceremony(base, realm, clientId, redirect);
        VirtualMLDSAAuthenticator auth = c.register(user, alg, cose);
        System.out.println();
        c.authenticate(user, auth);

        System.out.println("\n== NEGATIVE TESTS (each must be rejected) ==");
        for (Tamper t : new Tamper[]{Tamper.WRONG_KEY, Tamper.FLIPPED_SIGNATURE, Tamper.TAMPERED_AUTHDATA}) {
            c.authenticateMustFail(user, auth, t);
        }
        System.out.println("\nPASS: " + alg + " registered, authenticated, and forgeries rejected.");
    }
}
