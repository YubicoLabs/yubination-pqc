package org.pqkc.webauthn.va;

/**
 * Proves that two applications behind the same Keycloak can differ in what they demand of a
 * credential: {@code app-standard} accepts any passkey, {@code app-secure} accepts only ML-DSA.
 *
 * <p>Three columns are checked per user, because a per-application requirement that only holds on
 * a fresh login is not a requirement at all - single sign-on must not be a way around it.
 */
public class AppMatrix {

    private record Case(String label, String algorithm, long cose, boolean postQuantum) {}

    public static void main(String[] args) throws Exception {
        String base = args.length > 0 ? args[0] : "http://localhost:8085";
        String realm = args.length > 1 ? args[1] : "pq";
        String stamp = args.length > 2 ? args[2] : String.valueOf(System.currentTimeMillis());

        String standardId = "app-standard", standardRedirect = "http://localhost:8091/callback";
        String secureId = "app-secure", secureRedirect = "http://localhost:8092/callback";

        Case[] cases = {
                new Case("post-quantum passkey", "ML-DSA-44", -48L, true),
                new Case("classical passkey", "ES256", -7L, false),
        };

        System.out.printf("%-22s %-12s %-13s %-13s %-15s %s%n",
                "USER", "CREDENTIAL", "app-standard", "app-secure", "secure via SSO", "secure after enrol");
        System.out.println("-".repeat(104));

        boolean allOk = true;
        for (Case c : cases) {
            String user = "m" + stamp + "-" + c.algorithm().toLowerCase().replace("-", "");

            Ceremony standard = new Ceremony(base, realm, standardId, standardRedirect);
            standard.narrate = false;
            VirtualMLDSAAuthenticator auth = standard.registerQuietly(user, c.algorithm(), c.cose());

            // straight from enrolment into the strict app, on the session registration created.
            // No assertion has happened yet on this session, which is exactly the case that used to
            // fail closed even for a legitimately enrolled ML-DSA passkey.
            boolean afterEnrol = standard.ssoInto(secureId, secureRedirect);

            boolean onStandard = standard.tryLogin(user, auth);
            String claims = onStandard ? standard.lastIdTokenClaims() : null;

            Ceremony secure = new Ceremony(base, realm, secureId, secureRedirect);
            secure.narrate = false;
            boolean onSecure = secure.tryLogin(user, auth);

            // one browser session: sign in to the standard app, then walk over to the secure one
            Ceremony sso = new Ceremony(base, realm, standardId, standardRedirect);
            sso.narrate = false;
            sso.loginKeepingSession(user, auth);
            boolean onSecureViaSso = sso.ssoInto(secureId, secureRedirect);

            boolean expectedStandard = true;
            boolean expectedSecure = c.postQuantum();
            boolean ok = onStandard == expectedStandard
                    && onSecure == expectedSecure
                    && onSecureViaSso == expectedSecure
                    && afterEnrol == expectedSecure;
            allOk &= ok;

            System.out.printf("%-22s %-12s %-13s %-13s %-15s %-11s %s%n",
                    c.label(), c.algorithm(),
                    verdict(onStandard), verdict(onSecure), verdict(onSecureViaSso), verdict(afterEnrol),
                    ok ? "as expected" : "UNEXPECTED");
            if (claims != null) System.out.println("    token claims: " + algClaims(claims));
            if (!onSecure) {
                String why = Ceremony.excerpt(secure.lastBody).replace("\n", " | ").trim();
                System.out.println("    app-secure said: " + why);
            }
        }

        System.out.println();
        if (allOk) {
            System.out.println("PASS: app-secure admits only post-quantum credentials, on fresh logins and over SSO;");
            System.out.println("      app-standard admits both.");
        } else {
            System.out.println("FAIL: the per-application requirement did not hold.");
            System.exit(1);
        }
    }

    private static String verdict(boolean allowed) { return allowed ? "allowed" : "DENIED"; }

    /** Pulls just the two WebAuthn claims out of the ID token payload. */
    private static String algClaims(String json) {
        StringBuilder sb = new StringBuilder();
        for (String key : new String[]{"webauthn_alg", "webauthn_pq"}) {
            java.util.regex.Matcher m = java.util.regex.Pattern
                    .compile("\"" + key + "\"\\s*:\\s*(\"[^\"]*\"|true|false)").matcher(json);
            if (m.find()) sb.append(sb.length() > 0 ? ", " : "").append(key).append('=').append(m.group(1));
        }
        return sb.length() == 0 ? "(no webauthn claims present)" : sb.toString();
    }
}
