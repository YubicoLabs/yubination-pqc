// HTTP contracts only. Never resets, registers or deletes a credential/account.
// Requests have no browser cookies; generated challenges belong to new test sessions.
import assert from 'node:assert/strict';
const results = [];
async function check(id, fn) {
  try { await fn(); results.push({ id, status: 'PASS' }); }
  catch (e) { results.push({ id, status: 'FAIL', reason: e.message }); }
}
const sw = 'http://localhost:8010';
const kc = 'http://localhost:8085/realms/pq';
async function get(url) { return fetch(url, {signal: AbortSignal.timeout(10000), redirect: 'error'}); }
await check('SW-configuration', async () => {
  const r = await get(`${sw}/config`); assert.equal(r.status, 200);
  const c = await r.json();
  assert.equal(c.rpID, 'localhost'); assert.equal(c.expectedOrigin, sw);
  assert.equal(c.userVerification, 'required'); assert.equal(c.residentKey, 'discouraged');
  assert.equal(c.attestation, 'none'); assert.equal(c.authenticatorAttachment, 'any');
  for (const id of [-48, -49, -50, -7]) assert(c.algorithms.some(a => a.id === id));
});
await check('SW-migration-inspection-fields', async () => {
  const r = await get(`${sw}/generate-registration-options`); assert.equal(r.status, 200);
  const o = await r.json();
  assert.equal(o.rp.id, 'localhost'); assert(o.user.id); assert(o.challenge);
  assert.equal(o.extensions.credProps, true); assert(Array.isArray(o.excludeCredentials));
  assert.equal(o.authenticatorSelection.userVerification, 'required');
  assert(o.pubKeyCredParams.some(a => a.alg === -48));
  // Deliberately do not print challenge, user handle or credential IDs.
});
await check('SW-authentication-options-or-empty-recovery', async () => {
  const r = await get(`${sw}/generate-authentication-options`); const o = await r.json();
  if (r.status === 409) assert.equal(o.error, 'Register a test credential first.');
  else { assert.equal(r.status, 200); assert(o.challenge); assert(o.allowCredentials.length > 0); assert.equal(o.userVerification, 'required'); }
});
for (const ceremony of ['registration', 'authentication']) {
  await check(`SW-${ceremony}-missing-challenge`, async () => {
    const r = await fetch(`${sw}/verify-${ceremony}`, {method:'POST', headers:{Origin:sw,'Content-Type':'application/json'}, body:'{}',signal:AbortSignal.timeout(10000)});
    assert.equal(r.status,400); assert.equal((await r.json()).error,`Start a new ${ceremony} request.`);
  });
  await check(`SW-${ceremony}-reject-cross-origin`, async () => {
    const r = await fetch(`${sw}/verify-${ceremony}`, {method:'POST', headers:{Origin:'https://example.invalid','Content-Type':'application/json'}, body:'{}',signal:AbortSignal.timeout(10000)});
    assert.equal(r.status,403);
  });
}
await check('KC-discovery', async () => {
  const r = await get(`${kc}/.well-known/openid-configuration`); assert.equal(r.status,200);
  const d = await r.json(); assert.equal(d.issuer,kc);
  assert.equal(d.authorization_endpoint,`${kc}/protocol/openid-connect/auth`);
  assert.equal(d.end_session_endpoint,`${kc}/protocol/openid-connect/logout`);
});
for (const [port,client] of [[8091,'app-standard'],[8092,'app-secure']]) {
  await check(`KC-${client}-served-controls`, async () => {
    const r=await get(`http://localhost:${port}/`); assert.equal(r.status,200);
    const html=await r.text(); for(const id of ['login','logout','claims','alg','token-alg']) assert(html.includes(`id="${id}"`));
    const config=await (await get(`http://localhost:${port}/config.js`)).text();
    assert(config.includes(`clientId: "${client}"`));
  });
}
console.log(JSON.stringify({suite:'HTTP guide contracts',results,limits:'No browser ceremony, signature verification, SSO enforcement or logout completion is established.'},null,2));
if(results.some(r=>r.status==='FAIL')) process.exitCode=1;
