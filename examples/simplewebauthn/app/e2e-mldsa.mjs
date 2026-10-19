/**
 * End-to-end check that the container really registers *and* authenticates an ML-DSA passkey.
 *
 * Acts as a software authenticator: generates an ML-DSA key with WebCrypto, assembles a
 * WebAuthn "none"-attestation registration response around it, then signs an assertion with it.
 * Requires Node 24.7.0+ (same ML-DSA requirement as the server).
 *
 *   node e2e-mldsa.mjs http://localhost:8010
 */
// @peculiar/x509 2.x (via tsyringe) needs this before it is evaluated
import 'reflect-metadata';
import { webcrypto } from 'node:crypto';
import * as x509 from '@peculiar/x509';
import { AsnParser, AsnSerializer } from '@peculiar/asn1-schema';
import { AlgorithmIdentifier, Certificate } from '@peculiar/asn1-x509';
import { isoCBOR } from '@simplewebauthn/server/helpers';

const base = process.argv[2] ?? 'http://localhost:8010';
const origin = base;
const rpID = new URL(base).hostname;

const b64url = (bytes) => Buffer.from(bytes).toString('base64url');
const fromB64url = (str) => new Uint8Array(Buffer.from(str, 'base64url'));

let cookie = '';
async function call(path, init = {}) {
  const resp = await fetch(`${base}${path}`, {
    ...init,
    headers: { Origin: origin, ...(init.headers ?? {}), ...(cookie ? { cookie } : {}) },
  });
  const setCookie = resp.headers.getSetCookie?.()[0];
  if (setCookie) cookie = setCookie.split(';')[0];
  const body = await resp.json();
  if (!resp.ok) throw new Error(`${path} -> ${resp.status} ${JSON.stringify(body)}`);
  return body;
}

const sha256 = async (data) => new Uint8Array(await webcrypto.subtle.digest('SHA-256', data));

const concat = (...chunks) => {
  const out = new Uint8Array(chunks.reduce((n, c) => n + c.length, 0));
  let offset = 0;
  for (const chunk of chunks) {
    out.set(chunk, offset);
    offset += chunk.length;
  }
  return out;
};

async function buildAuthData({ flags, counter, credentialID, cosePublicKey }) {
  const rpIdHash = await sha256(new TextEncoder().encode(rpID));
  const counterBytes = new Uint8Array(4);
  new DataView(counterBytes.buffer).setUint32(0, counter, false);

  if (!credentialID) {
    return concat(rpIdHash, new Uint8Array([flags]), counterBytes);
  }

  const credIDLen = new Uint8Array(2);
  new DataView(credIDLen.buffer).setUint16(0, credentialID.length, false);

  return concat(
    rpIdHash,
    new Uint8Array([flags]),
    counterBytes,
    new Uint8Array(16), // all-zero AAGUID
    credIDLen,
    credentialID,
    cosePublicKey,
  );
}

/** DER-encode one ECDSA signature component as an ASN.1 INTEGER */
function derInteger(bytes) {
  let start = 0;
  while (start < bytes.length - 1 && bytes[start] === 0) start += 1;
  let value = bytes.subarray(start);
  if (value[0] & 0x80) value = concat(new Uint8Array([0]), value);
  return concat(new Uint8Array([0x02, value.length]), value);
}

/** WebCrypto emits raw r||s; WebAuthn wants the DER SEQUENCE */
function derEcdsaSignature(raw) {
  const half = raw.length / 2;
  const body = concat(derInteger(raw.subarray(0, half)), derInteger(raw.subarray(half)));
  return concat(new Uint8Array([0x30, body.length]), body);
}

/** RFC 9881 X.509 algorithm OIDs for ML-DSA */
const ML_DSA_X509_OID = {
  'ML-DSA-44': '2.16.840.1.101.3.4.3.17',
  'ML-DSA-65': '2.16.840.1.101.3.4.3.18',
  'ML-DSA-87': '2.16.840.1.101.3.4.3.19',
};

/**
 * Build a self-signed attestation certificate whose own public key and signature are ML-DSA -
 * the shape Yubico's FIDO Preview CA issues. @peculiar/x509 can't sign with ML-DSA, so an ECDSA
 * certificate provides the structure (name, validity, extensions, v3) and the key material and
 * signature are swapped out at the ASN.1 level.
 */
async function buildMLDSAAttestationCert(mldsaAlg, subjectName) {
  x509.cryptoProvider.set(webcrypto);
  const ecAlg = { name: 'ECDSA', namedCurve: 'P-256', hash: 'SHA-256' };
  const template = await x509.X509CertificateGenerator.createSelfSigned({
    serialNumber: '01',
    name: subjectName,
    notBefore: new Date(Date.now() - 3_600_000),
    notAfter: new Date(Date.now() + 3_600_000),
    signingAlgorithm: ecAlg,
    keys: await webcrypto.subtle.generateKey(ecAlg, false, ['sign', 'verify']),
    extensions: [new x509.BasicConstraintsExtension(false, undefined, true)],
  });

  const cert = AsnParser.parse(new Uint8Array(template.rawData), Certificate);
  const oid = ML_DSA_X509_OID[mldsaAlg];

  const attKeys = await webcrypto.subtle.generateKey({ name: mldsaAlg }, true, ['sign', 'verify']);
  const attJWK = await webcrypto.subtle.exportKey('jwk', attKeys.publicKey);
  const rawPub = fromB64url(attJWK.pub);

  cert.tbsCertificate.subjectPublicKeyInfo.algorithm = new AlgorithmIdentifier({ algorithm: oid });
  cert.tbsCertificate.subjectPublicKeyInfo.subjectPublicKey = rawPub.buffer.slice(
    rawPub.byteOffset,
    rawPub.byteOffset + rawPub.byteLength,
  );
  cert.tbsCertificate.signature = new AlgorithmIdentifier({ algorithm: oid });
  cert.signatureAlgorithm = new AlgorithmIdentifier({ algorithm: oid });

  const tbsDER = new Uint8Array(AsnSerializer.serialize(cert.tbsCertificate));
  cert.signatureValue = await webcrypto.subtle.sign({ name: mldsaAlg }, attKeys.privateKey, tbsDER);

  return { der: new Uint8Array(AsnSerializer.serialize(cert)), keys: attKeys };
}

/**
 * Build a `packed` attestation statement with a self-signed ECDSA attestation certificate, the
 * same shape a YubiKey produces under `attestation: "direct"`. The attestation signature is
 * classical even when the credential is ML-DSA - that split is the point of the exercise.
 */
async function buildPackedAttStmt(authData, clientDataHash) {
  x509.cryptoProvider.set(webcrypto);
  const ecAlg = { name: 'ECDSA', namedCurve: 'P-256', hash: 'SHA-256' };
  const keys = await webcrypto.subtle.generateKey(ecAlg, false, ['sign', 'verify']);

  // The packed verifier is strict about the leaf: OU, CN, O, two-letter C, CA:false, v3
  const cert = await x509.X509CertificateGenerator.createSelfSigned({
    serialNumber: '01',
    name:
      'C=SE, O=SimpleWebAuthn PQC Rig, OU=Authenticator Attestation, CN=Software Test Authenticator',
    notBefore: new Date(Date.now() - 3_600_000),
    notAfter: new Date(Date.now() + 3_600_000),
    signingAlgorithm: ecAlg,
    keys,
    extensions: [new x509.BasicConstraintsExtension(false, undefined, true)],
  });

  const rawSig = new Uint8Array(
    await webcrypto.subtle.sign(ecAlg, keys.privateKey, concat(authData, clientDataHash)),
  );

  return new Map([
    ['alg', -7],
    ['sig', derEcdsaSignature(rawSig)],
    ['x5c', [new Uint8Array(cert.rawData)]],
  ]);
}

const alg = process.env.TEST_ALG ?? 'ML-DSA-44';
const COSE_ALG = { 'ML-DSA-44': -48, 'ML-DSA-65': -49, 'ML-DSA-87': -50 }[alg];

console.log(`Testing ${base} with a software ${alg} authenticator\n`);

// The RP should be offering this algorithm before we bother pretending to support it
const config = await call('/config');
console.log(`  server runtime:  ${config.runtime}`);
console.log(`  runtime PQC:     ${config.runtimeSupportsPQC}`);
console.log(`  offering:        ${config.algorithms.map((a) => a.name).join(', ')}`);
if (!config.algorithms.some((a) => a.id === COSE_ALG)) {
  throw new Error(`Server is not offering ${alg}`);
}

// --- Registration -----------------------------------------------------------
const regOptions = await call('/generate-registration-options');
const preferred = regOptions.pubKeyCredParams[0];
console.log(`\n  most-preferred pubKeyCredParams entry: ${preferred.alg}`);
if (preferred.alg !== config.algorithms[0].id) {
  throw new Error(
    `Expected ${config.algorithms[0].name} (${config.algorithms[0].id}) to be listed first, ` +
      `got ${preferred.alg}`,
  );
}

const keyPair = await webcrypto.subtle.generateKey({ name: alg }, true, ['sign', 'verify']);
const publicJWK = await webcrypto.subtle.exportKey('jwk', keyPair.publicKey);
const rawPublicKey = fromB64url(publicJWK.pub);
console.log(`  generated ${alg} key, ${rawPublicKey.length}-byte raw public key`);

// COSE_Key for AKP: kty(1)=AKP(7), alg(3)=COSE_ALG, pub(-1)=raw key bytes
const cosePublicKey = isoCBOR.encode(
  new Map([[1, 7], [3, COSE_ALG], [-1, rawPublicKey]]),
);

const credentialID = webcrypto.getRandomValues(new Uint8Array(32));
const regAuthData = await buildAuthData({
  flags: 0x45, // UP | UV | AT
  counter: 0,
  credentialID,
  cosePublicKey: new Uint8Array(cosePublicKey),
});

const regClientData = new TextEncoder().encode(
  JSON.stringify({
    type: 'webauthn.create',
    challenge: regOptions.challenge,
    origin,
    crossOrigin: false,
  }),
);

const attMode = process.env.ATT_MODE ?? 'none';
let attStmt = new Map();

if (attMode === 'packed') {
  attStmt = await buildPackedAttStmt(regAuthData, await sha256(regClientData));
} else if (attMode === 'packed-mldsa') {
  // Attestation certificate that is itself ML-DSA, as a PQC-capable YubiKey produces
  const { der, keys } = await buildMLDSAAttestationCert(
    alg,
    'C=SE, O=SimpleWebAuthn PQC Rig, OU=Authenticator Attestation, CN=Software Test Authenticator',
  );
  const attSig = new Uint8Array(
    await webcrypto.subtle.sign(
      { name: alg },
      keys.privateKey,
      concat(regAuthData, await sha256(regClientData)),
    ),
  );
  attStmt = new Map([['alg', COSE_ALG], ['sig', attSig], ['x5c', [der]]]);
  console.log(`  built ${alg} attestation cert (${der.length} bytes), ${attSig.length}-byte att sig`);
}

const cborFmt = attMode === 'packed-mldsa' ? 'packed' : attMode;
console.log(`  attestation format: ${cborFmt}`);

const attestationObject = isoCBOR.encode(
  new Map([
    ['fmt', cborFmt],
    ['attStmt', attStmt],
    ['authData', regAuthData],
  ]),
);

const regResult = await call('/verify-registration', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({
    id: b64url(credentialID),
    rawId: b64url(credentialID),
    response: {
      clientDataJSON: b64url(regClientData),
      attestationObject: b64url(new Uint8Array(attestationObject)),
      transports: ['usb'],
    },
    type: 'public-key',
    clientExtensionResults: {},
    authenticatorAttachment: 'cross-platform',
  }),
});

console.log(`  /verify-registration -> ${JSON.stringify(regResult)}`);
if (regResult.attestation?.fmt !== cborFmt) {
  throw new Error(`Server reported fmt ${regResult.attestation?.fmt}, expected ${cborFmt}`);
}
if (!regResult.verified) throw new Error('Registration was not verified');
if (regResult.algorithm.id !== COSE_ALG) {
  throw new Error(`Server reported ${regResult.algorithm.name}, expected ${alg}`);
}
if (!regResult.isPQC) throw new Error('Server did not flag the credential as PQC');

// --- Authentication ---------------------------------------------------------
const authOptions = await call('/generate-authentication-options');
if (!authOptions.allowCredentials.some((c) => c.id === b64url(credentialID))) {
  throw new Error('Registered credential missing from allowCredentials');
}

const authAuthData = await buildAuthData({ flags: 0x05, counter: 1 }); // UP | UV
const authClientData = new TextEncoder().encode(
  JSON.stringify({
    type: 'webauthn.get',
    challenge: authOptions.challenge,
    origin,
    crossOrigin: false,
  }),
);

const signature = new Uint8Array(
  await webcrypto.subtle.sign(
    { name: alg },
    keyPair.privateKey,
    concat(authAuthData, await sha256(authClientData)),
  ),
);
console.log(`\n  signed assertion, ${signature.length}-byte signature`);

const authResult = await call('/verify-authentication', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({
    id: b64url(credentialID),
    rawId: b64url(credentialID),
    response: {
      clientDataJSON: b64url(authClientData),
      authenticatorData: b64url(authAuthData),
      signature: b64url(signature),
      userHandle: null,
    },
    type: 'public-key',
    clientExtensionResults: {},
  }),
});

console.log(`  /verify-authentication -> ${JSON.stringify(authResult)}`);
if (!authResult.verified) throw new Error('Authentication was not verified');

await call('/reset', { method: 'POST' });
console.log(`\n✅ ${alg} registration and authentication both verified by the container`);
