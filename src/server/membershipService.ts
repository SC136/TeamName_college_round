/**
 * Incognito Membership Service
 *
 * Manages the organization Merkle Tree of member commitments,
 * enrollment verification, and Merkle inclusion proof distribution.
 */

import { MerkleTree, MerkleProof } from '../crypto/merkleTree';
import { IncognitoStorage, EnrolledMember } from './storage';
import { mod, SNARK_FIELD_PRIME } from '../crypto/poseidon';

export class MembershipService {
  private merkleTree: MerkleTree;
  private storage: IncognitoStorage;

  constructor(merkleTree: MerkleTree, storage: IncognitoStorage) {
    this.merkleTree = merkleTree;
    this.storage = storage;
  }

  /**
   * Enroll a new member commitment
   */
  public enrollMember(commitmentHex: string): { success: boolean; index?: number; root: string; error?: string } {
    try {
      const commitmentBigInt = BigInt(commitmentHex);
      if (commitmentBigInt <= 0n || commitmentBigInt >= SNARK_FIELD_PRIME) {
        return { success: false, root: '0x' + this.merkleTree.getRoot().toString(16), error: 'Invalid field element for commitment' };
      }

      // Check if already enrolled
      const existing = this.storage.getMember(commitmentHex);
      if (existing) {
        if (existing.status === 'REVOKED') {
          return { success: false, root: '0x' + this.merkleTree.getRoot().toString(16), error: 'Credential has been permanently revoked' };
        }
        return {
          success: true,
          index: existing.index,
          root: '0x' + this.merkleTree.getRoot().toString(16)
        };
      }

      // Insert into Merkle Tree
      const index = this.merkleTree.insert(commitmentBigInt);

      // Record in storage
      this.storage.enrollMember(commitmentHex, index);

      return {
        success: true,
        index,
        root: '0x' + this.merkleTree.getRoot().toString(16)
      };
    } catch (err: any) {
      return {
        success: false,
        root: '0x' + this.merkleTree.getRoot().toString(16),
        error: err.message
      };
    }
  }

  /**
   * Get current Merkle Root and tree depth
   */
  public getRootInfo(): { root: string; depth: number; totalMembers: number } {
    return {
      root: '0x' + this.merkleTree.getRoot().toString(16),
      depth: this.merkleTree.depth,
      totalMembers: this.merkleTree.getNumberOfLeaves()
    };
  }

  /**
   * Get Merkle inclusion proof for a member commitment so they can generate ZK proofs client-side
   */
  public getProofForCommitment(commitmentHex: string): { success: boolean; proof?: MerkleProof; error?: string } {
    const member = this.storage.getMember(commitmentHex);
    if (!member) {
      return { success: false, error: 'Commitment not found in membership registry' };
    }

    if (member.status === 'REVOKED') {
      return { success: false, error: 'Membership credential has been revoked' };
    }

    try {
      const proof = this.merkleTree.generateProof(member.index);
      return { success: true, proof };
    } catch (err: any) {
      return { success: false, error: err.message };
    }
  }

  /**
   * Check if a given Merkle root is valid (current or in valid history window)
   */
  public isValidRoot(rootHex: string): boolean {
    try {
      const rootBigInt = BigInt(rootHex);
      return this.merkleTree.isKnownRoot(rootBigInt);
    } catch {
      return false;
    }
  }

  public getTree(): MerkleTree {
    return this.merkleTree;
  }
}
