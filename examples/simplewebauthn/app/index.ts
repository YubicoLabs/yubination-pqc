/**
 * An Express server showing off @simplewebauthn/server v14 with PQC ML-DSA passkeys enabled.
 *
 * Adapted from the official example project at tag v14.0.0:
 * https://github.com/MasterKale/SimpleWebAuthn/tree/v14.0.0/example
 *
 * Differences from upstream, all in service of testing a PQC authenticator:
 *
 * - `supportedAlgorithmIDs` offers ML-DSA-44/65/87 ahead of the classical algorithms instead of
 *   hardcoding `[-7, -257]`, and the same list is passed to `verifyRegistrationResponse()`
 * - `/verify-registration` reports which algorithm the authenticator actually picked
 * - `/config` reports the server's view of the world, including runtime PQC support
 * - `/reset` forgets stored credentials so the same key can be registered again
 * - Everything is configurable by environment variable, and the server binds 0.0.0.0
 */

import fs from 'node:fs';
import http from 'node:http';
import https from 'node:https';
import { randomBytes } from 'node:crypto';

import express from 'express';
import session from 'express-session';
import memoryStore from 'memorystore';

import {
  generateAuthenticationOptions,
  generateRegistrationOptions,
  SettingsService,
  verifyAuthenticationResponse,
  verifyRegistrationResponse,
} from '@simplewebauthn/server';
import type {
  AuthenticationResponseJSON,
  AuthenticatorAttachment,
  GenerateAuthenticationOptionsOpts,
  GenerateRegistrationOptionsOpts,
  RegistrationResponseJSON,
  ResidentKeyRequirement,
  UserVerificationRequirement,
  VerifiedAuthenticationResponse,
  VerifiedRegistrationResponse,
  VerifyAuthenticationResponseOpts,
  Uint8Array_,
  VerifyRegistrationResponseOpts,
  WebAuthnCredential,
} from '@simplewebauthn/server';
import {
  cose,
  COSEALG,
  decodeAttestationObject,
  decodeCredentialPublicKey,
  getCertificateInfo,
} from '@simplewebauthn/server/helpers';

import type { LoggedInUser } from './types.js';

const {
  RP_ID = 'localhost',
  RP_NAME = 'SimpleWebAuthn PQC Example',
  PORT = '8000',
  ORIGIN,
  ALGORITHMS,
  RESIDENT_KEY = 'discouraged',
  USER_VERIFICATION = 'preferred',
  ATTESTATION = 'none',
  AUTHENTICATOR_ATTACHMENT = 'cross-platform',
  TLS_CERT,
  TLS_KEY,
} = process.env;

/**
 * The algorithms this Relying Party is willing to accept, most preferred first. An authenticator
 * receives these preferences through the browser/OS. Preference order does not prove the
 * returned algorithm: inspect the verified credential public key.
 *
 * Override with e.g. ALGORITHMS=-7 to force a classical credential for an A/B comparison.
 */
const defaultAlgorithmIDs: COSEALG[] = [
  COSEALG.ML_DSA_44,
  COSEALG.ML_DSA_65,
  COSEALG.ML_DSA_87,
  COSEALG.EdDSA,
  COSEALG.ES256,
  COSEALG.RS256,
];

const supportedAlgorithmIDs: number[] = ALGORITHMS
  ? ALGORITHMS.split(',').map((id) => Number(id.trim())).filter((id) => Number.isInteger(id))
  : defaultAlgorithmIDs;

/** Turn a COSE algorithm ID into something a human can read, e.g. -48 -> "ML-DSA-44" */
function algName(alg: number | undefined): string {
  const name = COSEALG[alg as COSEALG] as string | undefined;
  return name ? name.replace(/_/g, '-') : 'unknown';
}

/**
 * Signature algorithm OIDs seen on attestation certificates. The ML-DSA entries are here so a
 * genuinely post-quantum attestation chain would be named rather than shown as a bare OID.
 */
const SIGNATURE_ALGORITHM_OIDS: Record<string, string> = {
  '1.2.840.10045.4.3.2': 'ecdsa-with-SHA256',
  '1.2.840.10045.4.3.3': 'ecdsa-with-SHA384',
  '1.2.840.10045.4.3.4': 'ecdsa-with-SHA512',
  '1.2.840.113549.1.1.11': 'sha256WithRSAEncryption',
  '1.2.840.113549.1.1.12': 'sha384WithRSAEncryption',
  '1.2.840.113549.1.1.10': 'RSASSA-PSS',
  '1.3.101.112': 'Ed25519',
  '2.16.840.1.101.3.4.3.17': 'ML-DSA-44',
  '2.16.840.1.101.3.4.3.18': 'ML-DSA-65',
  '2.16.840.1.101.3.4.3.19': 'ML-DSA-87',
};

/**
 * Describe the attestation statement itself, which is signed independently of the credential. A
 * PQC credential can still be vouched for by a classical (ECDSA/RSA) attestation chain, and that
 * distinction is invisible unless you look.
 */
function describeAttestation(attestationObject: Uint8Array_) {
  const decoded = decodeAttestationObject(attestationObject);
  const fmt = decoded.get('fmt');
  const attStmt = decoded.get('attStmt');
  const alg = attStmt.get('alg');
  const x5c = attStmt.get('x5c');

  const chain = (x5c ?? []).map((cert) => {
    try {
      const info = getCertificateInfo(cert);
      const oid = info.parsedCertificate.signatureAlgorithm.algorithm;
      return {
        subject: info.subject.combined,
        issuer: info.issuer.combined,
        signatureAlgorithm: SIGNATURE_ALGORITHM_OIDS[oid] ?? oid,
        signatureAlgorithmOID: oid,
      };
    } catch (error) {
      return { error: (error as Error).message };
    }
  });

  return {
    fmt,
    /** The algorithm signing the attestation statement, NOT the credential's algorithm */
    alg: alg === undefined ? null : { id: alg, name: algName(alg) },
    x5cLength: x5c?.length ?? 0,
    chain,
  };
}

const port = Number(PORT);
const tlsEnabled = Boolean(TLS_CERT && TLS_KEY);
const scheme = tlsEnabled ? 'https' : 'http';
const isDefaultPort = (scheme === 'https' && port === 443) || (scheme === 'http' && port === 80);

export const rpID = RP_ID;
export const expectedOrigin = ORIGIN ?? `${scheme}://${rpID}${isDefaultPort ? '' : `:${port}`}`;

const app = express();
const MemoryStore = memoryStore(session);

app.use(express.static('./public/'));
app.use(express.json());
// Keep this shared-user demonstration local. No account-management API is added.
app.use((req, res, next) => {
  if (req.headers['sec-fetch-site'] === 'cross-site' ||
      (req.method === 'POST' && req.headers.origin !== expectedOrigin)) {
    return res.status(403).json({ error: 'Use the configured local demo origin.' });
  }
  next();
});
app.use(
  session({
    secret: randomBytes(32).toString('hex'),
    saveUninitialized: true,
    resave: false,
    cookie: {
      maxAge: 86400000,
      httpOnly: true, // Ensure to not expose session cookies to clientside scripts
      sameSite: 'strict',
    },
    store: new MemoryStore({
      checkPeriod: 86_400_000, // prune expired entries every 24h
    }),
  }),
);

/**
 * As in the upstream example, a single hardcoded user stands in for "whoever is logged in".
 */
const loggedInUserId = 'internalUserId';

const inMemoryUserDB: { [loggedInUserId: string]: LoggedInUser } = {
  [loggedInUserId]: {
    id: loggedInUserId,
    username: `user@${rpID}`,
    credentials: [],
  },
};

/**
 * What this server thinks it is. Handy for confirming ML-DSA is actually on the table before
 * blaming the authenticator for handing back an ES256 credential.
 */
app.get('/config', (_req, res) => {
  res.send({
    rpID,
    rpName: RP_NAME,
    expectedOrigin,
    runtime: `Node ${process.version} (OpenSSL ${process.versions.openssl})`,
    runtimeSupportsPQC: SettingsService.runtimeSupportsPQC(),
    algorithms: supportedAlgorithmIDs.map((id) => ({ id, name: algName(id) })),
    residentKey: RESIDENT_KEY,
    userVerification: USER_VERIFICATION,
    attestation: ATTESTATION,
    authenticatorAttachment: AUTHENTICATOR_ATTACHMENT || 'any',
    registeredCredentials: inMemoryUserDB[loggedInUserId].credentials.length,
  });
});

/**
 * Forget every stored credential, so the same authenticator can be registered again without
 * tripping over `excludeCredentials`.
 */
app.post('/reset', (_req, res) => {
  inMemoryUserDB[loggedInUserId].credentials = [];
  res.send({ reset: true });
});

/**
 * Registration
 */
app.get('/generate-registration-options', async (req, res) => {
  const user = inMemoryUserDB[loggedInUserId];
  const { username, credentials } = user;

  const opts: GenerateRegistrationOptionsOpts = {
    rpName: RP_NAME,
    rpID,
    userName: username,
    userID: new TextEncoder().encode(user.id),
    extensions: { credProps: true },
    timeout: 60000,
    attestationType: ATTESTATION as 'none' | 'direct' | 'enterprise',
    excludeCredentials: credentials.map((cred) => ({
      id: cred.id,
      type: 'public-key',
      transports: cred.transports,
    })),
    authenticatorSelection: {
      residentKey: RESIDENT_KEY as ResidentKeyRequirement,
      userVerification: USER_VERIFICATION as UserVerificationRequirement,
      /**
       * Defaults to "cross-platform" so a roaming security key is targeted directly instead of
       * the browser offering a platform authenticator or a passkey provider. Set
       * AUTHENTICATOR_ATTACHMENT="" to let the browser offer everything.
       */
      ...(AUTHENTICATOR_ATTACHMENT
        ? { authenticatorAttachment: AUTHENTICATOR_ATTACHMENT as AuthenticatorAttachment }
        : {}),
    },
    supportedAlgorithmIDs,
  };

  const options = await generateRegistrationOptions(opts);

  req.session.currentChallenge = options.challenge;
  req.session.currentCeremony = 'registration';
  req.session.challengeExpires = Date.now() + 300000;

  res.send(options);
});

app.post('/verify-registration', async (req, res) => {
  const body: RegistrationResponseJSON = req.body;

  const user = inMemoryUserDB[loggedInUserId];
  const expectedChallenge = req.session.currentChallenge;
  const validChallenge = req.session.currentCeremony === 'registration' &&
    (req.session.challengeExpires ?? 0) > Date.now();
  req.session.currentChallenge = undefined;
  req.session.currentCeremony = undefined;
  if (!expectedChallenge || !validChallenge) return res.status(400).json({ error: 'Start a new registration request.' });

  let verification: VerifiedRegistrationResponse;
  try {
    const opts: VerifyRegistrationResponseOpts = {
      response: body,
      expectedChallenge: `${expectedChallenge}`,
      expectedOrigin,
      expectedRPID: rpID,
      requireUserVerification: USER_VERIFICATION === 'required',
      /**
       * Must mirror the list passed to `generateRegistrationOptions()`, otherwise a credential
       * using an algorithm outside the v14 defaults would be rejected here.
       */
      supportedAlgorithmIDs,
    };
    verification = await verifyRegistrationResponse(opts);
  } catch (error) {
    const _error = error as Error;
    console.error(_error);
    return res.status(400).send({ error: _error.message });
  }

  const { verified, registrationInfo } = verification;

  if (!verified || !registrationInfo) {
    return res.send({ verified });
  }

  const { credential, aaguid, credentialDeviceType, credentialBackedUp, userVerified, fmt } =
    registrationInfo;

  const existingCredential = user.credentials.find((cred) => cred.id === credential.id);

  if (!existingCredential) {
    const newCredential: WebAuthnCredential = {
      id: credential.id,
      publicKey: credential.publicKey,
      counter: credential.counter,
      transports: body.response.transports,
    };
    user.credentials.push(newCredential);
  }

  req.session.currentChallenge = undefined;

  /**
   * The whole point of this fork: report the algorithm the authenticator actually chose, rather
   * than just "verified: true". A PQC key that quietly fell back to ES256 looks identical
   * otherwise.
   */
  const decodedPublicKey = decodeCredentialPublicKey(credential.publicKey);
  const alg = decodedPublicKey.get(cose.COSEKEYS.alg);

  const attestation = describeAttestation(registrationInfo.attestationObject);

  const result = {
    verified,
    algorithm: { id: alg, name: algName(alg) },
    isPQC: alg === COSEALG.ML_DSA_44 || alg === COSEALG.ML_DSA_65 || alg === COSEALG.ML_DSA_87,
    publicKeyBytes: credential.publicKey.length,
    aaguid,
    fmt,
    attestation,
    /** From the credProps extension: did the authenticator make it discoverable? */
    discoverable: body.clientExtensionResults?.credProps?.rk ?? null,
    credentialDeviceType,
    credentialBackedUp,
    userVerified,
    transports: body.response.transports,
  };

  console.log(
    `✅ Registered ${result.algorithm.name} (${alg}) credential, ` +
      `${result.publicKeyBytes}-byte public key, aaguid ${aaguid}, ` +
      `discoverable=${result.discoverable}`,
  );
  console.log(
    `   attestation: fmt=${attestation.fmt}, ` +
      `signed with ${attestation.alg?.name ?? 'n/a'}, ` +
      `${attestation.x5cLength} cert(s) in x5c`,
  );
  for (const cert of attestation.chain) {
    console.log(`     ${cert.subject ?? cert.error} (sigalg ${cert.signatureAlgorithm})`);
  }

  res.send(result);
});

/**
 * Login (a.k.a. "Authentication")
 */
app.get('/generate-authentication-options', async (req, res) => {
  const user = inMemoryUserDB[loggedInUserId];
  if (!user.credentials.length) return res.status(409).json({ error: 'Register a test credential first.' });

  const opts: GenerateAuthenticationOptionsOpts = {
    timeout: 60000,
    allowCredentials: user.credentials.map((cred) => ({
      id: cred.id,
      type: 'public-key',
      transports: cred.transports,
    })),
    userVerification: USER_VERIFICATION as UserVerificationRequirement,
    rpID,
  };

  const options = await generateAuthenticationOptions(opts);

  req.session.currentChallenge = options.challenge;
  req.session.currentCeremony = 'authentication';
  req.session.challengeExpires = Date.now() + 300000;

  res.send(options);
});

app.post('/verify-authentication', async (req, res) => {
  const body: AuthenticationResponseJSON = req.body;

  const user = inMemoryUserDB[loggedInUserId];
  const expectedChallenge = req.session.currentChallenge;
  const validChallenge = req.session.currentCeremony === 'authentication' &&
    (req.session.challengeExpires ?? 0) > Date.now();
  req.session.currentChallenge = undefined;
  req.session.currentCeremony = undefined;
  if (!expectedChallenge || !validChallenge) return res.status(400).json({ error: 'Start a new authentication request.' });

  let dbCredential: WebAuthnCredential | undefined;
  // "Query the DB" here for a credential matching `cred.id`
  for (const cred of user.credentials) {
    if (cred.id === body.id) {
      dbCredential = cred;
      break;
    }
  }

  if (!dbCredential) {
    return res.status(400).send({
      error: 'Authenticator is not registered with this site',
    });
  }

  let verification: VerifiedAuthenticationResponse;
  try {
    const opts: VerifyAuthenticationResponseOpts = {
      response: body,
      expectedChallenge: `${expectedChallenge}`,
      expectedOrigin,
      expectedRPID: rpID,
      credential: dbCredential,
      requireUserVerification: USER_VERIFICATION === 'required',
    };
    verification = await verifyAuthenticationResponse(opts);
  } catch (error) {
    const _error = error as Error;
    console.error(_error);
    return res.status(400).send({ error: _error.message });
  }

  const { verified, authenticationInfo } = verification;

  if (verified) {
    dbCredential.counter = authenticationInfo.newCounter;
  }

  req.session.currentChallenge = undefined;

  const alg = decodeCredentialPublicKey(dbCredential.publicKey).get(cose.COSEKEYS.alg);

  if (verified) {
    console.log(`✅ Verified ${algName(alg)} assertion, new counter ${authenticationInfo.newCounter}`);
  }

  res.send({
    verified,
    algorithm: { id: alg, name: algName(alg) },
    newCounter: authenticationInfo.newCounter,
    userVerified: authenticationInfo.userVerified,
  });
});

const host = '0.0.0.0';

function onListening() {
  console.log(`🚀 Server ready at ${expectedOrigin} (listening on ${host}:${port})`);
  console.log(`   RP ID: ${rpID}`);
  console.log(`   Runtime PQC support: ${SettingsService.runtimeSupportsPQC() ? 'yes' : 'NO'}`);
  console.log(
    `   Offering: ${supportedAlgorithmIDs.map((id) => `${algName(id)} (${id})`).join(', ')}`,
  );
}

if (tlsEnabled) {
  https
    .createServer(
      { key: fs.readFileSync(TLS_KEY as string), cert: fs.readFileSync(TLS_CERT as string) },
      app,
    )
    .listen(port, host, onListening);
} else {
  http.createServer(app).listen(port, host, onListening);
}
