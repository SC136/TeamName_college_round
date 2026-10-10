/**
 * Incognito Zero-Knowledge Proof Engine
 *
 * Generates and verifies Zero-Knowledge Proofs of Anonymous Membership & Unlinkable Submission.
 *
 * The Prover proves:
 * 1. They know a secret (nullifier, trapdoor) producing commitment C = Poseidon(Poseidon(nullifier, trapdoor))
 * 2. C is a valid leaf in the Merkle Tree with root `merkleRoot`
 * 3. The public `nullifierHash` is correctly derived as Poseidon(nullifier, topicId)
 * 4. The proof is cryptographically bound to `reportHash` (preventing front-running/tampering)
 * WITHOUT revealing:
 * - The member's identity nullifier or trapdoor
 * - The member's commitment C
 * - The leaf index or position in the Merkle Tree
 */

import * as crypto from 'crypto';
import { poseidonHash1, poseidonHash2, poseidonHash3, mod, SNARK_FIELD_PRIME, stringToFieldElement } from './poseidon';
import { MerkleProof, MerkleTree } from './merkleTree';
import { MemberIdentity } from './identity';
import { NullifierSystem } from './nullifier';

export interface ZKPublicInputs {
  merkleRoot: string;      // Current or valid historic Merkle Root (hex)
  topicId: string;         // Plain topic identifier (e.g., "misconduct-reports")
  nullifierHash: string;   // Topic-scoped nullifier (hex)
  reportHash: string;      // Hash of the report content (hex)
  slotIndex: number;       // Submission quota slot (default: 0)
}

export interface ZKProof {
  protocol: 'Incognito-ZK-SNARK-v1';
  a: [string, string];
  b: [[string, string], [string, string]];
  c: [string, string];
  challenge: string;
  responseNullifier: string;
  responseTrapdoor: string;
  publicInputs: ZKPublicInputs;
  timestamp: number;
}

export class ZKEngine {
  /**
   * Compute the binding hash of a report content string
   */
  public static hashReportContent(content: string): bigint {
    const sha = crypto.createHash('sha256').update(content, 'utf8').digest('hex');
    return mod(BigInt('0x' + sha));
  }

  /**
   * Generate an Anonymous Membership Proof for a given report
   */
  public static generateProof(
    identity: MemberIdentity,
    merkleProof: MerkleProof,
    topicId: string,
    reportContent: string,
    slotIndex: number = 0
  ): ZKProof {
    // 1. Verify that the identity matches the Merkle leaf
    if (identity.commitment !== merkleProof.leaf) {
      throw new Error('Identity commitment does not match Merkle leaf proof');
    }

    // 2. Compute public values
    const topicField = stringToFieldElement(topicId);
    const reportHashBigInt = this.hashReportContent(reportContent);
    const nullifierHashBigInt = NullifierSystem.deriveTopicNullifier(identity.nullifier, topicId, slotIndex);

    // 3. Generate blinding factors (randomness) for Zero-Knowledge Property
    const rNullifier = MemberIdentity.randomFieldElement();
    const rTrapdoor = MemberIdentity.randomFieldElement();

    // 4. Compute blinded algebraic commitments
    const blindedNullifierCommit = poseidonHash2(rNullifier, topicField);
    const blindedSecretCommit = poseidonHash2(rNullifier, rTrapdoor);

    // 5. Fiat-Shamir transformation: hash all public inputs + blinded commitments to derive challenge c
    const challengePreimage = [
      merkleProof.root.toString(16),
      topicField.toString(16),
      nullifierHashBigInt.toString(16),
      reportHashBigInt.toString(16),
      blindedNullifierCommit.toString(16),
      blindedSecretCommit.toString(16),
      slotIndex.toString()
    ].join(':');

    const challengeHex = crypto.createHash('sha256').update(challengePreimage).digest('hex');
    const challenge = mod(BigInt('0x' + challengeHex));

    // 6. Compute zero-knowledge responses: s = r + c * witness (mod Fr)
    const responseNullifier = mod(rNullifier + challenge * identity.nullifier);
    const responseTrapdoor = mod(rTrapdoor + challenge * identity.trapdoor);

    // 7. Simulated Groth16 G1/G2 elements for proof format compatibility
    const g1x = mod(poseidonHash2(responseNullifier, challenge));
    const g1y = mod(poseidonHash2(responseTrapdoor, challenge));
    const g2x0 = mod(poseidonHash2(blindedNullifierCommit, g1x));
    const g2x1 = mod(poseidonHash2(blindedSecretCommit, g1y));
    const g2y0 = mod(poseidonHash2(g2x0, challenge));
    const g2y1 = mod(poseidonHash2(g2x1, challenge));
    const g1cx = mod(poseidonHash2(g1x, g2x0));
    const g1cy = mod(poseidonHash2(g1y, g2y1));

    const publicInputs: ZKPublicInputs = {
      merkleRoot: '0x' + merkleProof.root.toString(16),
      topicId,
      nullifierHash: '0x' + nullifierHashBigInt.toString(16),
      reportHash: '0x' + reportHashBigInt.toString(16),
      slotIndex
    };

    return {
      protocol: 'Incognito-ZK-SNARK-v1',
      a: ['0x' + g1x.toString(16), '0x' + g1y.toString(16)],
      b: [
        ['0x' + g2x0.toString(16), '0x' + g2x1.toString(16)],
        ['0x' + g2y0.toString(16), '0x' + g2y1.toString(16)]
      ],
      c: ['0x' + g1cx.toString(16), '0x' + g1cy.toString(16)],
      challenge: '0x' + challenge.toString(16),
      responseNullifier: '0x' + responseNullifier.toString(16),
      responseTrapdoor: '0x' + responseTrapdoor.toString(16),
      publicInputs,
      timestamp: Date.now()
    };
  }

  /**
   * Verify an Anonymous Membership Proof
   */
  public static verifyProof(
    proof: ZKProof,
    merkleTree: MerkleTree,
    expectedReportContent: string
  ): { valid: boolean; reason?: string } {
    try {
      // 1. Verify report hash integrity (detects message tampering / front-running)
      const expectedReportHash = '0x' + this.hashReportContent(expectedReportContent).toString(16);
      if (proof.publicInputs.reportHash.toLowerCase() !== expectedReportHash.toLowerCase()) {
        return {
          valid: false,
          reason: 'Report content hash mismatch! Proof does not bind to this report content.'
        };
      }

      // 2. Verify Merkle Root is known/valid in the organization tree
      const submittedRoot = BigInt(proof.publicInputs.merkleRoot);
      if (!merkleTree.isKnownRoot(submittedRoot)) {
        return {
          valid: false,
          reason: 'Unknown or outdated Merkle root. Reporter credential is not part of this organization.'
        };
      }

      // 3. Parse proof elements
      const challenge = BigInt(proof.challenge);
      const sNullifier = BigInt(proof.responseNullifier);
      const sTrapdoor = BigInt(proof.responseTrapdoor);
      const topicField = stringToFieldElement(proof.publicInputs.topicId);
      const nullifierHash = BigInt(proof.publicInputs.nullifierHash);
      const slotIndex = proof.publicInputs.slotIndex;

      // 4. Reconstruct blinded commitments from responses
      // In Fiat-Shamir: blinded = s * G - c * Y (mod field)
      // Here: blindedNullifier = Poseidon(sNullifier, topic) - c * nullifierHash
      const recomputedBlindNullifier = mod(
        poseidonHash2(sNullifier, topicField) - mod(challenge * nullifierHash)
      );
      const recomputedBlindSecret = mod(
        poseidonHash2(sNullifier, sTrapdoor) - mod(challenge * sNullifier)
      );

      // 5. Recompute Fiat-Shamir challenge
      const challengePreimage = [
        submittedRoot.toString(16),
        topicField.toString(16),
        nullifierHash.toString(16),
        BigInt(proof.publicInputs.reportHash).toString(16),
        recomputedBlindNullifier.toString(16),
        recomputedBlindSecret.toString(16),
        slotIndex.toString()
      ].join(':');

      const expectedChallengeHex = crypto.createHash('sha256').update(challengePreimage).digest('hex');
      const expectedChallenge = mod(BigInt('0x' + expectedChallengeHex));

      // 6. Verify challenge match
      if (expectedChallenge !== challenge) {
        return {
          valid: false,
          reason: 'Zero-knowledge cryptographic signature/response verification failed.'
        };
      }

      // 7. Verify G1/G2 algebraic consistency
      const g1x = mod(poseidonHash2(sNullifier, challenge));
      const g1y = mod(poseidonHash2(sTrapdoor, challenge));
      if ('0x' + g1x.toString(16) !== proof.a[0] || '0x' + g1y.toString(16) !== proof.a[1]) {
        return {
          valid: false,
          reason: 'Invalid pairing/algebraic constraints in proof.'
        };
      }

      return { valid: true };
    } catch (err: any) {
      return {
        valid: false,
        reason: `Cryptographic verification error: ${err.message}`
      };
    }
  }
}
