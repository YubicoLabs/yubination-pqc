package org.pqkc.webauthn.va;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;

/** Checks what the user's Account Console "Applications" page actually lists. */
public class AccountApps {

    public static void main(String[] args) throws Exception {
        String base = args.length > 0 ? args[0] : "http://localhost:8085";
        String realm = args.length > 1 ? args[1] : "pq";
        String user = "acct" + (args.length > 2 ? args[2] : String.valueOf(System.currentTimeMillis()));

        // the account console is itself an OIDC client in the realm
        Ceremony c = new Ceremony(base, realm, "account-console", base + "/realms/" + realm + "/account/");
        c.narrate = false;
        VirtualMLDSAAuthenticator auth = c.registerQuietly(user, "ML-DSA-44", -48L);
        if (!c.tryLogin(user, auth)) throw new IllegalStateException("could not sign in to the account console");

        HttpResponse<String> res = HttpClient.newHttpClient().send(
                HttpRequest.newBuilder(URI.create(base + "/realms/" + realm + "/account/applications"))
                        .header("Authorization", "Bearer " + c.lastAccessToken())
                        .header("Accept", "application/json")
                        .GET().build(),
                HttpResponse.BodyHandlers.ofString());

        System.out.println("Account Console -> Applications, as user " + user + ":");
        JsonNode body = new ObjectMapper().readTree(res.body());
        for (JsonNode app : body) {
            System.out.printf("  %-18s inUse=%-5s url=%s%n",
                    app.path("clientId").asText(),
                    app.path("inUse").asText(),
                    app.path("effectiveUrl").asText(app.path("baseUrl").asText("-")));
        }
    }
}
