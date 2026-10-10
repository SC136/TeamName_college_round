/**
 * Incognito Cryptographic Core: Member Identity & Credential Derivation
 *
 * Each member holds a secret identity tuple (identityNullifier, identityTrapdoor).
 * The public credential is:
 *   secret = Poseidon(identityNullifier, identityTrapdoor)
 *   commitment = Poseidon(secret)
 *
 * The commitment is published to the organization Merkle tree during enrollment.
 * The secrets remain strictly on the member's client device.
 */

import * as crypto from 'crypto';
import { poseidonHash1, poseidonHash2, mod, SNARK_FIELD_PRIME, stringToFieldElement } from './poseidon';

export interface IdentityData {
  identityNullifier: string; // Hex string
  identityTrapdoor: string;  // Hex string
  secret: string;            // Hex string
  commitment: string;        // Hex string
}

export class MemberIdentity {
  public readonly nullifier: bigint;
  public readonly trapdoor: bigint;
  public readonly secret: bigint;
  public readonly commitment: bigint;

  constructor(nullifier?: bigint, trapdoor?: bigint) {
    if (nullifier !== undefined && trapdoor !== undefined) {
      this.nullifier = mod(nullifier);
      this.trapdoor = mod(trapdoor);
    } else {
      this.nullifier = MemberIdentity.randomFieldElement();
      this.trapdoor = MemberIdentity.randomFieldElement();
    }

    this.secret = poseidonHash2(this.nullifier, this.trapdoor);
    this.commitment = poseidonHash1(this.secret);
  }

  /**
   * Deterministically derive an identity from a seed or username (useful for demo/testing)
   */
  public static fromSeed(seed: string): MemberIdentity {
    const hash = crypto.createHash('sha256').update(seed).digest();
    const nullifierBuf = crypto.createHash('sha256').update(Buffer.concat([hash, Buffer.from('_nullifier')])).digest();
    const trapdoorBuf = crypto.createHash('sha256').update(Buffer.concat([hash, Buffer.from('_trapdoor')])).digest();

    const nullifier = mod(BigInt('0x' + nullifierBuf.toString('hex')));
    const trapdoor = mod(BigInt('0x' + trapdoorBuf.toString('hex')));

    return new MemberIdentity(nullifier, trapdoor);
  }

  /**
   * Generate a cryptographically secure random field element
   */
  public static randomFieldElement(): bigint {
    const bytes = crypto.randomBytes(32);
    return mod(BigInt('0x' + bytes.toString('hex')));
  }

  /**
   * Serialize identity secrets (never shared with administrators!)
   */
  public exportPrivateKey(): string {
    const payload = JSON.stringify({
      n: this.nullifier.toString(16),
      t: this.trapdoor.toString(16)
    });
    return Buffer.from(payload).toString('base64');
  }

  /**
   * Import identity from exported base64 key
   */
  public static importPrivateKey(encoded: string): MemberIdentity {
    const raw = Buffer.from(encoded, 'base64').toString('utf8');
    const parsed = JSON.parse(raw);
    const nullifier = BigInt('0x' + parsed.n);
    const trapdoor = BigInt('0x' + parsed.t);
    return new MemberIdentity(nullifier, trapdoor);
  }

  /**
   * Export public identity commitment for enrollment
   */
  public getPublicCommitment(): bigint {
    return this.commitment;
  }

  public toJSON(): IdentityData {
    return {
      identityNullifier: '0x' + this.nullifier.toString(16),
      identityTrapdoor: '0x' + this.trapdoor.toString(16),
      secret: '0x' + this.secret.toString(16),
      commitment: '0x' + this.commitment.toString(16)
    };
  }
}
