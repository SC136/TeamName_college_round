/**
 * Incognito Cryptographic Core: Rate-Limiting Nullifiers (RLN)
 *
 * Implements Shamir's Secret Sharing based Rate-Limiting Nullifiers (RLN).
 *
 * Guarantees:
 * - 1 submission per epoch/topic: Reporter identity remains cryptographically private.
 * - >1 submissions per epoch/topic (Spam/Abuse): 2 shares on polynomial f(x) are revealed,
 *   allowing ANY verifier to reconstruct the abuser's identity secret and automatically
 *   slash / revoke their membership credential from the Merkle tree!
 */

import { poseidonHash1, poseidonHash2, poseidonHash3, mod, modInverse, SNARK_FIELD_PRIME, stringToFieldElement } from './poseidon';

export interface RLNShare {
  x: string;         // Message hash (evaluation point)
  y: string;         // Polynomial evaluation y = a0 + a1 * x
  nullifier: string; // Rate-limiting nullifier
  epoch: number;
}

export interface SlashingResult {
  slashed: boolean;
  recoveredIdentitySecret?: string;
  recoveredCommitment?: string;
  message?: string;
}

export class RLNSystem {
  /**
   * Compute a 1-degree polynomial share for a message
   * f(x) = a0 + a1 * x
   * where a0 = identitySecret, a1 = Poseidon(identitySecret, topicField, epoch)
   */
  public static generateShare(
    identitySecret: bigint,
    topicId: string,
    epoch: number,
    messageContent: string
  ): RLNShare {
    const topicField = stringToFieldElement(topicId);
    const a0 = mod(identitySecret);
    const a1 = poseidonHash3(identitySecret, topicField, BigInt(epoch));

    // Message evaluation point x
    const x = stringToFieldElement(messageContent);

    // y = a0 + a1 * x (mod p)
    const y = mod(a0 + mod(a1 * x));

    // RLN Nullifier = Poseidon(a1)
    const nullifier = poseidonHash1(a1);

    return {
      x: '0x' + x.toString(16),
      y: '0x' + y.toString(16),
      nullifier: '0x' + nullifier.toString(16),
      epoch
    };
  }

  /**
   * Verify if two shares with the same nullifier constitute double-sign abuse,
   * and if so, mathematically recover the identity secret via Lagrange interpolation!
   */
  public static detectAndSlash(
    share1: RLNShare,
    share2: RLNShare
  ): SlashingResult {
    if (share1.nullifier.toLowerCase() !== share2.nullifier.toLowerCase()) {
      return {
        slashed: false,
        message: 'Shares belong to different nullifiers. No double-submission.'
      };
    }

    const x1 = BigInt(share1.x);
    const y1 = BigInt(share1.y);
    const x2 = BigInt(share2.x);
    const y2 = BigInt(share2.y);

    if (x1 === x2) {
      return {
        slashed: false,
        message: 'Identical message submitted; duplicate submission detected by nullifier.'
      };
    }

    // Two distinct messages with identical nullifier!
    // Solve for slope a1: a1 = (y2 - y1) / (x2 - x1) mod p
    const dy = mod(y2 - y1);
    const dx = mod(x2 - x1);
    const dxInv = modInverse(dx);
    const a1 = mod(dy * dxInv);

    // Solve for secret a0: a0 = y1 - a1 * x1 mod p
    const a0 = mod(y1 - mod(a1 * x1));

    // Verify recovery: Poseidon(a1) must equal nullifier
    const recomputedNullifier = poseidonHash1(a1);
    const expectedNullifier = BigInt(share1.nullifier);

    if (recomputedNullifier !== expectedNullifier) {
      return {
        slashed: false,
        message: 'Invalid shares, mathematical recovery did not match nullifier.'
      };
    }

    // Compute public commitment of the abusive member
    const recoveredCommitment = poseidonHash1(a0);

    return {
      slashed: true,
      recoveredIdentitySecret: '0x' + a0.toString(16),
      recoveredCommitment: '0x' + recoveredCommitment.toString(16),
      message: 'Abusive rate-limit violation confirmed! Member identity secret mathematically extracted via Shamir Secret Sharing.'
    };
  }
}
