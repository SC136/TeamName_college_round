/**
 * Incognito Cryptographic Core: Topic-Scoped Nullifiers & Unlinkability
 *
 * Implements topic-scoped cryptographic nullifiers that ensure:
 * 1. Double-submission prevention within the same topic.
 * 2. Complete cryptographic unlinkability across different topics.
 * 3. Configurable submission quotas per topic using deterministic slot indices.
 */

import { poseidonHash2, poseidonHash3, stringToFieldElement, mod } from './poseidon';

export class NullifierSystem {
  /**
   * Derive a topic-scoped cryptographic nullifier
   * N = Poseidon(identityNullifier, topicFieldElement)
   */
  public static deriveTopicNullifier(
    identityNullifier: bigint,
    topicId: string,
    slotIndex: number = 0
  ): bigint {
    const topicField = typeof topicId === 'string' ? stringToFieldElement(topicId) : BigInt(topicId);
    if (slotIndex === 0) {
      return poseidonHash2(identityNullifier, topicField);
    }
    return poseidonHash3(identityNullifier, topicField, BigInt(slotIndex));
  }

  /**
   * Derive an epoch-scoped nullifier for time-windowed reporting
   */
  public static deriveEpochNullifier(
    identityNullifier: bigint,
    topicId: string,
    epoch: number,
    slotIndex: number = 0
  ): bigint {
    const topicField = stringToFieldElement(topicId);
    const combinedScope = poseidonHash2(topicField, BigInt(epoch));
    if (slotIndex === 0) {
      return poseidonHash2(identityNullifier, combinedScope);
    }
    return poseidonHash3(identityNullifier, combinedScope, BigInt(slotIndex));
  }

  /**
   * Verify nullifier derivation given public inputs and secret nullifier
   */
  public static verifyNullifier(
    nullifierHash: bigint,
    identityNullifier: bigint,
    topicId: string,
    slotIndex: number = 0
  ): boolean {
    const expected = NullifierSystem.deriveTopicNullifier(identityNullifier, topicId, slotIndex);
    return expected === nullifierHash;
  }
}

/**
 * Topic Nullifier Registry (Maintained by the Server / Verifier)
 */
export class TopicNullifierRegistry {
  // Map of topicId -> Set of spent nullifier hex strings
  private spentNullifiers: Map<string, Set<string>>;

  constructor() {
    this.spentNullifiers = new Map<string, Set<string>>();
  }

  private getTopicSet(topicId: string): Set<string> {
    if (!this.spentNullifiers.has(topicId)) {
      this.spentNullifiers.set(topicId, new Set<string>());
    }
    return this.spentNullifiers.get(topicId)!;
  }

  /**
   * Check if a nullifier has already been spent in a topic
   */
  public isSpent(topicId: string, nullifier: bigint): boolean {
    const set = this.getTopicSet(topicId);
    return set.has(nullifier.toString(16));
  }

  /**
   * Record a nullifier as spent. Returns false if already spent.
   */
  public spend(topicId: string, nullifier: bigint): boolean {
    const set = this.getTopicSet(topicId);
    const hex = nullifier.toString(16);
    if (set.has(hex)) {
      return false; // Duplicate submission!
    }
    set.add(hex);
    return true;
  }

  /**
   * Get total number of submissions recorded for a topic
   */
  public getCount(topicId: string): number {
    return this.getTopicSet(topicId).size;
  }

  /**
   * Export all spent nullifiers (e.g. for audit or zero-knowledge public bulletin board)
   */
  public exportRegistry(): Record<string, string[]> {
    const result: Record<string, string[]> = {};
    for (const [topic, set] of this.spentNullifiers.entries()) {
      result[topic] = Array.from(set);
    }
    return result;
  }

  /**
   * Clear spent nullifiers (for testing)
   */
  public clear(): void {
    this.spentNullifiers.clear();
  }
}
