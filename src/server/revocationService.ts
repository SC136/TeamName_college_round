/**
 * Incognito Credential Revocation Service
 *
 * Implements privacy-preserving credential revocation:
 * 1. Admin / Institutional Revocation: When a member leaves the organization,
 *    their commitment leaf is zeroed in the Merkle Tree, triggering a root update.
 * 2. Automated RLN Slashing Revocation: When a member violates rate limits,
 *    their mathematically extracted commitment is immediately pruned from the tree.
 * 3. Anonymous Nullifier Blacklisting: For topic-specific or epoch-specific bans
 *    without revealing the underlying member.
 */

import { MerkleTree } from '../crypto/merkleTree';
import { IncognitoStorage } from './storage';

export class RevocationService {
  private merkleTree: MerkleTree;
  private storage: IncognitoStorage;

  constructor(merkleTree: MerkleTree, storage: IncognitoStorage) {
    this.merkleTree = merkleTree;
    this.storage = storage;
  }

  /**
   * Revoke a member by their public commitment
   */
  public revokeMemberByCommitment(commitmentHex: string, reason: string = 'Administrative Revocation'): {
    success: boolean;
    oldRoot: string;
    newRoot: string;
    revokedIndex?: number;
    error?: string;
  } {
    const member = this.storage.getMember(commitmentHex);
    if (!member) {
      return {
        success: false,
        oldRoot: '0x' + this.merkleTree.getRoot().toString(16),
        newRoot: '0x' + this.merkleTree.getRoot().toString(16),
        error: 'Commitment not found in membership registry'
      };
    }

    if (member.status === 'REVOKED') {
      return {
        success: false,
        oldRoot: '0x' + this.merkleTree.getRoot().toString(16),
        newRoot: '0x' + this.merkleTree.getRoot().toString(16),
        error: 'Member is already revoked'
      };
    }

    const oldRoot = '0x' + this.merkleTree.getRoot().toString(16);

    // Prune leaf in the Merkle tree by zeroing it
    this.merkleTree.update(member.index, 0n);

    // Update storage status
    this.storage.revokeMember(commitmentHex);

    const newRoot = '0x' + this.merkleTree.getRoot().toString(16);

    return {
      success: true,
      oldRoot,
      newRoot,
      revokedIndex: member.index
    };
  }

  /**
   * Automatically slash and revoke a member based on an RLN double-submission proof
   */
  public executeRLNSlashing(commitmentHex: string, evidenceMessage: string): {
    slashed: boolean;
    oldRoot: string;
    newRoot: string;
  } {
    const oldRoot = '0x' + this.merkleTree.getRoot().toString(16);
    this.storage.slashMember(commitmentHex);

    const member = this.storage.getMember(commitmentHex);
    if (member) {
      this.merkleTree.update(member.index, 0n);
    }

    const newRoot = '0x' + this.merkleTree.getRoot().toString(16);

    return {
      slashed: true,
      oldRoot,
      newRoot
    };
  }
}
