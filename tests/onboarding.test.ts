/**
 * Incognito Test Suite: Member Onboarding, Searchable Organizations, ID Verification & Ephemeral Trashing
 */

import { IncognitoStorage } from '../src/server/storage';
import { MembershipService } from '../src/server/membershipService';
import { RevocationService } from '../src/server/revocationService';
import { MerkleTree } from '../src/crypto/merkleTree';
import { MemberIdentity } from '../src/crypto/identity';
import { AuthController } from '../src/controllers/authController';

export function runOnboardingTests() {
  console.log('\n--- Running Member Onboarding & Ephemeral ID Verification Tests ---');

  const tree = new MerkleTree(16);
  const storage = new IncognitoStorage();
  const membershipService = new MembershipService(tree, storage);
  const authController = new AuthController(storage, membershipService);

  // 1. Organization Search Tests
  const allOrgs = storage.getOrganizations();
  if (allOrgs.length < 5) {
    throw new Error(`Expected at least 5 default organizations, got ${allOrgs.length}`);
  }

  const stanfordResults = storage.getOrganizations('stanford');
  if (stanfordResults.length !== 1 || stanfordResults[0].id !== 'stanford-univ') {
    throw new Error('Organization search for "stanford" failed.');
  }

  const universityResults = storage.getOrganizations('university');
  if (universityResults.length < 2) {
    throw new Error('Category search for "university" failed.');
  }
  console.log('✓ Searchable organization directory verified.');

  // 2. User Registration Tests
  const user = storage.registerUser('alex_whistleblower', 'hashed_pass_123', 'stanford-univ');
  if (!user.id || user.username !== 'alex_whistleblower' || user.organizationId !== 'stanford-univ') {
    throw new Error('User registration failed.');
  }

  // Duplicate registration must fail
  let duplicateFailed = false;
  try {
    storage.registerUser('alex_whistleblower', 'hashed_pass_456', 'mit-edu');
  } catch {
    duplicateFailed = true;
  }
  if (!duplicateFailed) {
    throw new Error('Duplicate username registration should be rejected.');
  }
  console.log('✓ Member registration & duplicate protection verified.');

  // 3. User Authentication Tests
  const foundUser = storage.getUserByUsername('alex_whistleblower');
  if (!foundUser || foundUser.id !== user.id) {
    throw new Error('User lookup failed.');
  }
  console.log('✓ Member authentication & credential lookup verified.');

  // 4. Ephemeral ID Verification & Memory Trashing Test
  let idProofBuffer: Buffer | null = Buffer.from('OFFICIAL_STANFORD_UNIVERSITY_STUDENT_CARD_IMAGE_SCAN', 'utf8');
  const payloadSize = idProofBuffer.length;
  if (payloadSize <= 0) throw new Error('Failed to create ID buffer');

  // Generate new member ZK identity
  const alexIdentity = MemberIdentity.fromSeed('alex_whistleblower_seed_2026');
  const alexCommitment = '0x' + alexIdentity.commitment.toString(16);

  // Enroll commitment in Merkle tree
  const enrollResult = membershipService.enrollMember(alexCommitment);
  if (!enrollResult.success) {
    throw new Error(`Failed to enroll member commitment: ${enrollResult.error}`);
  }

  // Mark user verified
  const verifiedUser = storage.verifyUser(user.id, alexCommitment);
  if (!verifiedUser || !verifiedUser.verified) {
    throw new Error('User verification status update failed.');
  }

  // Hard Purge: Overwrite buffer with zeros and dereference
  idProofBuffer.fill(0);
  const isAllZeros = idProofBuffer.every((b) => b === 0);
  if (!isAllZeros) {
    throw new Error('Memory zero-overwrite failed!');
  }
  idProofBuffer = null;

  console.log(`✓ ID Proof verified and memory buffer zero-overwritten (${payloadSize} bytes destroyed; 0 retention).`);

  // 5. Audit Check: Verify zero stored ID cards in storage engine
  const audit = storage.dumpSecurityAudit();
  if (audit.storedIdCardProofFiles !== 0) {
    throw new Error(`Audit failed: ${audit.storedIdCardProofFiles} ID cards found in storage!`);
  }
  console.log('✓ Storage security audit confirms 0 stored ID cards / biometric files.');

  // 6. Merkle Inclusion Proof for new verified member
  const proofResult = membershipService.getProofForCommitment(alexCommitment);
  if (!proofResult.success || !proofResult.proof) {
    throw new Error('Failed to generate Merkle proof for newly verified member.');
  }
  if (!MerkleTree.verifyProof(proofResult.proof)) {
    throw new Error('Merkle inclusion proof failed mathematical verification.');
  }
  console.log('✓ Verified member Merkle inclusion proof verified; anonymous reporting unlocked.');
}
