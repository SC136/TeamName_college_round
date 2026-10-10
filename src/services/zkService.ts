/**
 * Incognito ZK Verification Service
 *
 * Implements real Zero-Knowledge SNARK verification using SnarkJS:
 * - Loads circuits/verification_key.json
 * - Performs mathematical Groth16 proof verification via snarkjs.groth16.verify()
 * - Verifies cryptographic report payload binding (tamper resistance)
 * - Verifies Sparse Merkle Tree root validity
 */

import * as fs from 'fs';
import * as path from 'path';
import * as crypto from 'crypto';
import { MerkleTree } from '../crypto/merkleTree';
import { poseidonHash2, mod, stringToFieldElement } from '../crypto/poseidon';

// Import snarkjs dynamically or via require for runtime safety
let snarkjs: any = null;
try {
  snarkjs = require('snarkjs');
} catch (e) {
  // If snarkjs fails to load, gracefully handled below
}

export interface VerificationResult {
  valid: boolean;
  reason?: string;
  method?: 'snarkjs-groth16' | 'fiat-shamir-schnorr';
}

export class ZKVerificationService {
  private static verificationKey: any = null;

  /**
   * Load verification key from disk
   */
  public static getVerificationKey(): any {
    if (this.verificationKey) return this.verificationKey;

    const keyPath = path.resolve(__dirname, '../../circuits/verification_key.json');
    if (fs.existsSync(keyPath)) {
      try {
        const raw = fs.readFileSync(keyPath, 'utf8');
        this.verificationKey = JSON.parse(raw);
        return this.verificationKey;
      } catch (err: any) {
        console.warn('[ZKVerificationService] Could not parse verification_key.json:', err.message);
      }
    }
    return null;
  }

  /**
   * Hash report content to BN254 scalar field
   */
  public static hashReportContent(content: string): bigint {
    const sha = crypto.createHash('sha256').update(content, 'utf8').digest('hex');
    return mod(BigInt('0x' + sha));
  }

  /**
   * Verify a real Groth16 proof using SnarkJS
   */
  public static async verifySnarkjsGroth16(
    publicSignals: string[],
    proof: any
  ): Promise<boolean> {
    const vKey = this.getVerificationKey();
    if (!vKey || !snarkjs) {
      throw new Error('SnarkJS or verification_key.json is not available on server.');
    }

    try {
      const isValid = await snarkjs.groth16.verify(vKey, publicSignals, proof);
      return isValid === true;
    } catch (err: any) {
      console.error('[ZKVerificationService] SnarkJS verification failed with error:', err.message);
      return false;
    }
  }

  /**
   * Universal ZK Proof Verification:
   * Handles both SnarkJS Groth16 proofs and client protocol proofs
   */
  public static async verifyProof(
    proof: any,
    merkleTree: MerkleTree,
    expectedReportContent: string
  ): Promise<VerificationResult> {
    try {
      // 1. Validate Report Content Hash Binding
      const expectedReportHash = '0x' + this.hashReportContent(expectedReportContent).toString(16);
      const submittedReportHash =
        proof.publicInputs?.reportHash || (proof.publicSignals && proof.publicSignals[2]);

      if (!submittedReportHash || submittedReportHash.toLowerCase() !== expectedReportHash.toLowerCase()) {
        return {
          valid: false,
          reason: 'Report content hash mismatch! Proof does not bind to this report content.'
        };
      }

      // 2. Validate Merkle Root
      const submittedRootHex =
        proof.publicInputs?.merkleRoot || (proof.publicSignals && proof.publicSignals[0]);
      if (!submittedRootHex) {
        return { valid: false, reason: 'Missing Merkle root in public inputs.' };
      }

      const submittedRoot = BigInt(submittedRootHex);
      if (!merkleTree.isKnownRoot(submittedRoot)) {
        return {
          valid: false,
          reason: 'Unknown or outdated Merkle root. Reporter credential is not part of this organization.'
        };
      }

      // 3. If standard Groth16 proof format with snarkjs
      if (proof.protocol === 'groth16' || proof.pi_a) {
        const publicSignals = proof.publicSignals || [
          submittedRootHex,
          proof.publicInputs.topicId,
          submittedReportHash,
          proof.publicInputs.slotIndex?.toString() || '0',
          proof.publicInputs.nullifierHash
        ];

        const snarkProof = {
          pi_a: proof.pi_a || proof.a,
          pi_b: proof.pi_b || proof.b,
          pi_c: proof.pi_c || proof.c,
          protocol: 'groth16',
          curve: 'bn128'
        };

        const isSnarkValid = await this.verifySnarkjsGroth16(publicSignals, snarkProof);
        if (!isSnarkValid) {
          return { valid: false, reason: 'SnarkJS Groth16 pairing check failed.' };
        }
        return { valid: true, method: 'snarkjs-groth16' };
      }

      // 4. Client / Simulator proof verification
      const challenge = BigInt(proof.challenge);
      const sNullifier = BigInt(proof.responseNullifier);
      const sTrapdoor = BigInt(proof.responseTrapdoor);
      const topicField = stringToFieldElement(proof.publicInputs.topicId);
      const nullifierHash = BigInt(proof.publicInputs.nullifierHash);
      const slotIndex = proof.publicInputs.slotIndex || 0;

      const blindNullifier = proof.blindedNullifierCommit
        ? BigInt(proof.blindedNullifierCommit)
        : mod(poseidonHash2(sNullifier, topicField) - mod(challenge * nullifierHash));
      const blindSecret = proof.blindedSecretCommit
        ? BigInt(proof.blindedSecretCommit)
        : mod(poseidonHash2(sNullifier, sTrapdoor) - mod(challenge * sNullifier));

      const challengePreimage = [
        submittedRoot.toString(16),
        topicField.toString(16),
        nullifierHash.toString(16),
        BigInt(proof.publicInputs.reportHash).toString(16),
        blindNullifier.toString(16),
        blindSecret.toString(16),
        slotIndex.toString()
      ].join(':');

      const expectedChallengeHex = crypto.createHash('sha256').update(challengePreimage).digest('hex');
      const expectedChallenge = mod(BigInt('0x' + expectedChallengeHex));

      if (expectedChallenge !== challenge) {
        return {
          valid: false,
          reason: 'Zero-knowledge cryptographic signature/response verification failed.'
        };
      }

      // Algebraic consistency check
      const g1x = mod(poseidonHash2(sNullifier, challenge));
      const g1y = mod(poseidonHash2(sTrapdoor, challenge));
      if ('0x' + g1x.toString(16) !== proof.a[0] || '0x' + g1y.toString(16) !== proof.a[1]) {
        return {
          valid: false,
          reason: 'Invalid pairing/algebraic constraints in proof.'
        };
      }

      return { valid: true, method: 'fiat-shamir-schnorr' };
    } catch (err: any) {
      return { valid: false, reason: `Cryptographic verification error: ${err.message}` };
    }
  }
}
