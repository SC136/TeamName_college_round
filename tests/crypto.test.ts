/**
 * Incognito Test Suite: Cryptographic Primitives & Merkle Tree
 */

import { poseidonHash1, poseidonHash2, poseidonHash3, mod, stringToFieldElement } from '../src/crypto/poseidon';
import { MerkleTree } from '../src/crypto/merkleTree';
import { MemberIdentity } from '../src/crypto/identity';
import { NullifierSystem, TopicNullifierRegistry } from '../src/crypto/nullifier';

export function runCryptoTests() {
  console.log('\n--- Running Cryptographic Primitives Tests ---');

  // Test 1: Poseidon Hash Determinism & Non-Trivial Output
  const h1 = poseidonHash2(123n, 456n);
  const h2 = poseidonHash2(123n, 456n);
  if (h1 !== h2) throw new Error('Poseidon hash is not deterministic!');
  if (h1 === 0n) throw new Error('Poseidon hash produced trivial zero output!');
  console.log('✓ Poseidon hash determinism verified.');

  // Test 2: Merkle Tree Insertions & Proof Verification
  const tree = new MerkleTree(16);
  const leaf1 = poseidonHash1(111n);
  const leaf2 = poseidonHash1(222n);
  const leaf3 = poseidonHash1(333n);

  const idx0 = tree.insert(leaf1);
  const idx1 = tree.insert(leaf2);
  const idx2 = tree.insert(leaf3);

  if (idx0 !== 0 || idx1 !== 1 || idx2 !== 2) throw new Error('Leaf index mismatch in Merkle Tree!');

  const root = tree.getRoot();
  const proof0 = tree.generateProof(0);
  const proof1 = tree.generateProof(1);

  if (!MerkleTree.verifyProof(proof0)) throw new Error('Merkle proof 0 failed verification!');
  if (!MerkleTree.verifyProof(proof1)) throw new Error('Merkle proof 1 failed verification!');
  console.log('✓ Merkle Tree inclusion proof generation & verification verified.');

  // Test 3: Member Identity Key Derivation
  const alice = MemberIdentity.fromSeed('alice_test_seed');
  const bob = MemberIdentity.fromSeed('bob_test_seed');

  if (alice.commitment === bob.commitment) throw new Error('Different seeds produced identical commitments!');
  if (alice.nullifier === alice.trapdoor) throw new Error('Nullifier and trapdoor collided!');
  console.log('✓ Member Identity generation & commitment derivation verified.');

  // Test 4: Topic-Scoped Nullifiers & Unlinkability
  const topicA = 'topic-management-review';
  const topicB = 'topic-workplace-harassment';

  const nAliceA = NullifierSystem.deriveTopicNullifier(alice.nullifier, topicA);
  const nAliceA_repeat = NullifierSystem.deriveTopicNullifier(alice.nullifier, topicA);
  const nAliceB = NullifierSystem.deriveTopicNullifier(alice.nullifier, topicB);
  const nBobA = NullifierSystem.deriveTopicNullifier(bob.nullifier, topicA);

  if (nAliceA !== nAliceA_repeat) throw new Error('Topic nullifier not deterministic for same topic!');
  if (nAliceA === nAliceB) throw new Error('Nullifiers across different topics should never collide!');
  if (nAliceA === nBobA) throw new Error('Different users on same topic should never collide!');
  console.log('✓ Topic-Scoped Nullifier derivation & unlinkability verified.');

  // Test 5: Topic Nullifier Registry Duplicate Prevention
  const registry = new TopicNullifierRegistry();
  const spend1 = registry.spend(topicA, nAliceA);
  const spend2 = registry.spend(topicA, nAliceA); // Duplicate spend attempt

  if (!spend1) throw new Error('First spend should succeed!');
  if (spend2) throw new Error('Duplicate spend should be rejected!');
  console.log('✓ Nullifier Registry double-submission defense verified.');
}
