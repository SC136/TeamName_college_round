/**
 * Incognito Cryptographic Core: Sparse / Incremental Merkle Tree with Poseidon Hash
 *
 * Implements a fixed-depth binary Merkle Tree over BN254 field for anonymous
 * membership verification. Supports insertion, deletion (revocation),
 * proof generation, and root history tracking.
 */

import { poseidonHash2, mod } from './poseidon';

export interface MerkleProof {
  root: bigint;
  leaf: bigint;
  index: number;
  pathElements: bigint[]; // Siblings from bottom to top
  pathIndices: number[];  // 0 = leaf/subtree was left child, 1 = right child
}

export class MerkleTree {
  public readonly depth: number;
  public readonly capacity: number;
  public readonly zeroValues: bigint[];
  private leaves: bigint[];
  private layers: bigint[][];
  private rootHistory: Set<bigint>;
  private maxHistorySize: number;

  constructor(depth: number = 16, maxHistorySize: number = 100) {
    if (depth < 1 || depth > 32) {
      throw new Error(`Tree depth must be between 1 and 32, got ${depth}`);
    }
    this.depth = depth;
    this.capacity = 2 ** depth;
    this.maxHistorySize = maxHistorySize;
    this.leaves = [];
    this.zeroValues = this.computeZeroValues(depth);
    this.layers = [];
    this.rootHistory = new Set<bigint>();

    this.initEmptyTree();
  }

  private computeZeroValues(depth: number): bigint[] {
    const zeros: bigint[] = [0n];
    for (let i = 1; i <= depth; i++) {
      zeros.push(poseidonHash2(zeros[i - 1], zeros[i - 1]));
    }
    return zeros;
  }

  private initEmptyTree(): void {
    this.layers = [];
    for (let i = 0; i <= this.depth; i++) {
      this.layers.push([]);
    }
    // Initial root is the top zero value
    this.recordRoot(this.zeroValues[this.depth]);
  }

  private recordRoot(root: bigint): void {
    this.rootHistory.add(root);
    if (this.rootHistory.size > this.maxHistorySize) {
      const oldest = this.rootHistory.values().next().value;
      if (oldest !== undefined) {
        this.rootHistory.delete(oldest);
      }
    }
  }

  public getRoot(): bigint {
    const topLayer = this.layers[this.depth];
    return topLayer && topLayer.length > 0 ? topLayer[0] : this.zeroValues[this.depth];
  }

  public isKnownRoot(root: bigint): boolean {
    return this.rootHistory.has(root) || this.getRoot() === root;
  }

  public getLeaves(): bigint[] {
    return [...this.leaves];
  }

  public getNumberOfLeaves(): number {
    return this.leaves.length;
  }

  public indexOf(leaf: bigint): number {
    return this.leaves.indexOf(leaf);
  }

  /**
   * Insert a new member commitment into the tree
   */
  public insert(leaf: bigint): number {
    if (this.leaves.length >= this.capacity) {
      throw new Error(`Merkle tree is full (capacity: ${this.capacity})`);
    }

    const index = this.leaves.length;
    this.leaves.push(mod(leaf));
    this.updatePath(index, mod(leaf));
    this.recordRoot(this.getRoot());
    return index;
  }

  /**
   * Update or revoke a leaf at a specific index (e.g. setting to 0n for revocation)
   */
  public update(index: number, newLeaf: bigint): bigint {
    if (index < 0 || index >= this.leaves.length) {
      throw new Error(`Invalid leaf index ${index}`);
    }

    this.leaves[index] = mod(newLeaf);
    this.updatePath(index, mod(newLeaf));
    const newRoot = this.getRoot();
    this.recordRoot(newRoot);
    return newRoot;
  }

  /**
   * Update hashes along the path from leaf to root
   */
  private updatePath(index: number, leaf: bigint): void {
    let currentIndex = index;
    let currentHash = leaf;

    this.layers[0][currentIndex] = currentHash;

    for (let level = 0; level < this.depth; level++) {
      const isRight = currentIndex % 2 === 1;
      const siblingIndex = isRight ? currentIndex - 1 : currentIndex + 1;
      const parentIndex = Math.floor(currentIndex / 2);

      const siblingHash =
        this.layers[level][siblingIndex] !== undefined
          ? this.layers[level][siblingIndex]
          : this.zeroValues[level];

      const left = isRight ? siblingHash : currentHash;
      const right = isRight ? currentHash : siblingHash;

      currentHash = poseidonHash2(left, right);
      this.layers[level + 1][parentIndex] = currentHash;
      currentIndex = parentIndex;
    }
  }

  /**
   * Generate Merkle inclusion proof for a leaf at given index
   */
  public generateProof(index: number): MerkleProof {
    if (index < 0 || index >= this.leaves.length) {
      throw new Error(`Leaf index ${index} out of bounds (total leaves: ${this.leaves.length})`);
    }

    const leaf = this.leaves[index];
    const pathElements: bigint[] = [];
    const pathIndices: number[] = [];

    let currentIndex = index;

    for (let level = 0; level < this.depth; level++) {
      const isRight = currentIndex % 2 === 1;
      const siblingIndex = isRight ? currentIndex - 1 : currentIndex + 1;

      const siblingHash =
        this.layers[level][siblingIndex] !== undefined
          ? this.layers[level][siblingIndex]
          : this.zeroValues[level];

      pathElements.push(siblingHash);
      pathIndices.push(isRight ? 1 : 0);

      currentIndex = Math.floor(currentIndex / 2);
    }

    return {
      root: this.getRoot(),
      leaf,
      index,
      pathElements,
      pathIndices
    };
  }

  /**
   * Verify a Merkle inclusion proof independently
   */
  public static verifyProof(proof: MerkleProof): boolean {
    let currentHash = proof.leaf;

    for (let i = 0; i < proof.pathElements.length; i++) {
      const sibling = proof.pathElements[i];
      const isRight = proof.pathIndices[i] === 1;

      const left = isRight ? sibling : currentHash;
      const right = isRight ? currentHash : sibling;

      currentHash = poseidonHash2(left, right);
    }

    return currentHash === proof.root;
  }
}
