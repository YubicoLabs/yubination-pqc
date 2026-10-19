/* Minimal OIDC Authorization Code + PKCE client. No dependencies, no backend. */
(() => {
  const cfg = window.APP;
  const $ = (id) => document.getElementById(id);
  const authz = `${cfg.authority}/protocol/openid-connect/auth`;
  const token = `${cfg.authority}/protocol/openid-connect/token`;
  const endSession = `${cfg.authority}/protocol/openid-connect/logout`;

  document.title = cfg.name;
  $("app-name").textContent = cfg.name;
  $("app-rule").textContent = cfg.rule;
  $("badge").textContent = cfg.badge;
  if (cfg.accent) document.documentElement.style.setProperty("--accent", cfg.accent);

  const b64url = (bytes) =>
    btoa(String.fromCharCode(...new Uint8Array(bytes)))
      .replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");

  const randomVerifier = () => b64url(crypto.getRandomValues(new Uint8Array(32)));
  const challengeFor = async (verifier) =>
    b64url(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier)));

  const decodeJwtPart = (jwt, index) => {
    const part = jwt.split(".")[index].replace(/-/g, "+").replace(/_/g, "/");
    return JSON.parse(decodeURIComponent(escape(atob(part))));
  };
  const decodeJwt = (jwt) => decodeJwtPart(jwt, 1);
  const jwtHeader = (jwt) => decodeJwtPart(jwt, 0);
  const isPostQuantum = (alg) => typeof alg === "string" && alg.startsWith("ML-DSA");

  const show = (id) => {
    for (const s of ["anon", "error", "signed-in"]) $(s).hidden = s !== id;
  };

  async function login() {
    const verifier = randomVerifier();
    const state = randomVerifier();
    sessionStorage.setItem("pkce_verifier", verifier);
    sessionStorage.setItem("oidc_state", state);
    const params = new URLSearchParams({
      client_id: cfg.clientId, response_type: "code", scope: "openid profile email",
      redirect_uri: cfg.redirectUri, state,
      code_challenge: await challengeFor(verifier), code_challenge_method: "S256",
    });
    location.assign(`${authz}?${params}`);
  }

  async function exchange(code) {
    const verifier = sessionStorage.getItem("pkce_verifier");
    const res = await fetch(token, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        grant_type: "authorization_code", client_id: cfg.clientId,
        code, redirect_uri: cfg.redirectUri, code_verifier: verifier,
      }),
    });
    if (!res.ok) throw new Error(`token endpoint returned ${res.status}: ${await res.text()}`);
    return res.json();
  }

  function render(idToken) {
    const claims = decodeJwt(idToken);
    const header = jwtHeader(idToken);
    $("who").textContent = claims.preferred_username || claims.sub;

    const credAlg = claims.webauthn_alg || "unknown";
    const tokenAlg = header.alg || "unknown";
    $("alg").textContent = credAlg;
    $("token-alg").textContent = tokenAlg;

    const credPq = claims.webauthn_pq === true || claims.webauthn_pq === "true";
    const tokenPq = isPostQuantum(tokenAlg);

    let text, cls;
    if (credPq && tokenPq) {
      text = "ML-DSA passkey and token signatures; other system trust paths are not assessed here";
      cls = "yes";
    } else if (credPq) {
      text = "Passkey is post-quantum, but the token is signed with a classical algorithm";
      cls = "part";
    } else if (tokenPq) {
      text = "Token is post-quantum signed, but the passkey is classical";
      cls = "part";
    } else {
      text = "Classical throughout - not quantum resistant";
      cls = "no";
    }
    $("pq").textContent = text;
    $("pq").className = `pq ${cls}`;

    $("claims").textContent =
      "// JWS header\n" + JSON.stringify(header, null, 2) +
      "\n\n// claims\n" + JSON.stringify(claims, null, 2);
    show("signed-in");
  }

  async function boot() {
    const url = new URL(location.href);
    const code = url.searchParams.get("code");
    const err = url.searchParams.get("error");

    if (err) {
      $("error-text").textContent =
        `${url.searchParams.get("error_description") || err}. ` +
        `This application requires ${cfg.requirement}.`;
      show("error");
      history.replaceState({}, "", cfg.redirectUri);
      return;
    }

    if (code) {
      if (url.searchParams.get("state") !== sessionStorage.getItem("oidc_state")) {
        $("error-text").textContent = "State mismatch - the response did not match this request.";
        show("error");
        return;
      }
      try {
        const tokens = await exchange(code);
        sessionStorage.setItem("id_token", tokens.id_token);
        history.replaceState({}, "", cfg.redirectUri);
        render(tokens.id_token);
      } catch (e) {
        $("error-text").textContent = String(e);
        show("error");
      }
      return;
    }

    const stored = sessionStorage.getItem("id_token");
    if (stored) {
      try { render(stored); return; } catch { sessionStorage.removeItem("id_token"); }
    }
    show("anon");
  }

  $("login").addEventListener("click", login);
  $("retry").addEventListener("click", login);
  $("logout").addEventListener("click", () => {
    const idToken = sessionStorage.getItem("id_token");
    sessionStorage.clear();
    const params = new URLSearchParams({ post_logout_redirect_uri: cfg.redirectUri });
    if (idToken) params.set("id_token_hint", idToken);
    location.assign(`${endSession}?${params}`);
  });

  boot();
})();
