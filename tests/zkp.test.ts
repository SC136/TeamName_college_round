/**
 * Incognito Test Suite: Zero-Knowledge Proofs & RLN Engine
 */

import { MerkleTree } from '../src/crypto/merkleTree';
import { MemberIdentity } from '../src/crypto/identity';
import { ZKEngine } from '../src/crypto/zkEngine';
import { RLNSystem } from '../src/crypto/rln';
import { ContentSanitizer } from '../src/crypto/sanitization';

export function runZkpTests() {
  console.log('\n--- Running Zero-Knowledge Proof & RLN Tests ---');

  // Setup tree and member
  const tree = new MerkleTree(16);
  const alice = MemberIdentity.fromSeed('alice_zkp_test_seed');
  tree.insert(alice.commitment);

  const merkleProof = tree.generateProof(0);
  const topicId = 'misconduct-investigation';
  const reportContent = 'Observed unfair labor practice on floor 3.';

  // Test 1: Valid ZK Proof Generation & Verification
  const proof = ZKEngine.generateProof(alice, merkleProof, topicId, reportContent);
  const verifyResult = ZKEngine.verifyProof(proof, tree, reportContent);

  if (!verifyResult.valid) {
    throw new Error(`Valid ZK proof failed verification: ${verifyResult.reason}`);
  }
  console.log('✓ Valid Zero-Knowledge Proof generated and verified.');

  // Test 2: Tampered Report Content Rejection (Binding Test)
  const tamperedContent = 'ALTERED REPORT: Everything on floor 3 is completely fine.';
  const tamperedVerify = ZKEngine.verifyProof(proof, tree, tamperedContent);

  if (tamperedVerify.valid) {
    throw new Error('Verifier accepted tampered report content! Binding failed.');
  }
  console.log('✓ Report payload tampering correctly detected and rejected.');

  // Test 3: Forged / Fake Root Rejection
  const fakeTree = new MerkleTree(16);
  const fakeVerify = ZKEngine.verifyProof(proof, fakeTree, reportContent);

  if (fakeVerify.valid) {
    throw new Error('Verifier accepted proof against unauthorized Merkle root!');
  }
  console.log('✓ Outdated/unauthorized Merkle root rejected.');

  // Test 4: Rate-Limiting Nullifiers (RLN) Shamir Secret Sharing & Slashing
  const spamMsg1 = 'Buy cheap discount products now!';
  const spamMsg2 = 'Click here for free coupons!';

  const share1 = RLNSystem.generateShare(alice.secret, topicId, 1, spamMsg1);
  const share2 = RLNSystem.generateShare(alice.secret, topicId, 1, spamMsg2);

  const slashResult = RLNSystem.detectAndSlash(share1, share2);

  if (!slashResult.slashed) {
    throw new Error('RLN failed to detect double-submission abuse!');
  }

  const expectedCommitment = '0x' + alice.commitment.toString(16);
  if (slashResult.recoveredCommitment?.toLowerCase() !== expectedCommitment.toLowerCase()) {
    throw new Error(`RLN recovered wrong commitment! Expected ${expectedCommitment}, got ${slashResult.recoveredCommitment}`);
  }
  console.log('✓ RLN Shamir Secret Sharing successfully extracted abusive member identity commitment.');

  // Test 5: Content Sanitizer & PII Redaction
  const dirtyText = 'Contact me at reporter@hospital.org or 555-123-4567. Employee EMP-99214. Also ​zero‌width.';
  const sanitized = ContentSanitizer.sanitize(dirtyText);

  if (!sanitized.piiRedacted) throw new Error('PII was not marked as redacted!');
  if (sanitized.cleanedText.includes('reporter@hospital.org')) throw new Error('Email was not redacted!');
  if (sanitized.cleanedText.includes('555-123-4567')) throw new Error('Phone was not redacted!');
  if (sanitized.watermarksRemoved !== 2) throw new Error('Zero-width tracking characters were not stripped!');
  console.log('✓ Content sanitization, PII masking, and tracking watermark removal verified.');
}
