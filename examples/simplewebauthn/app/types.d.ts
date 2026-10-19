import type { WebAuthnCredential } from '@simplewebauthn/server';

/**
 * The example server keeps everything in memory. A real Relying Party needs a database for users,
 * their in-flight challenges, and their credentials. Note that ML-DSA public keys are 1,312 -
 * 2,592 bytes, so size the `publicKey` column accordingly.
 */
export interface LoggedInUser {
  id: string;
  username: string;
  credentials: WebAuthnCredential[];
}

declare module 'express-session' {
  interface SessionData {
    /**
     * A simple way of storing a user's current challenge being signed by registration or
     * authentication. It should be expired after `timeout` milliseconds.
     */
    currentChallenge?: string;
    currentCeremony?: 'registration' | 'authentication';
    challengeExpires?: number;
  }
}
