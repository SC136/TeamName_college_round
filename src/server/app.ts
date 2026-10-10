/**
 * Incognito: Main Server & API Router
 *
 * Implements REST endpoints for:
 * - Member Enrollment & Merkle Inclusion Proofs
 * - Anonymous Report Submission & ZK Verification
 * - Administrator Review (without identity recovery)
 * - Credential Revocation & RLN Slashing
 * - Security Evaluation & Attack Simulation
 */

import express, { Request, Response } from 'express';
import cors from 'cors';
import path from 'path';
import * as dotenv from 'dotenv';

dotenv.config();
import { MerkleTree } from '../crypto/merkleTree';
import { IncognitoStorage } from './storage';
import { MembershipService } from './membershipService';
import { RevocationService } from './revocationService';
import { TopicNullifierRegistry } from '../crypto/nullifier';
import { ReportService } from './reportService';
import { MetadataProtector } from './metadataProtector';
import { MemberIdentity } from '../crypto/identity';
import { createApiRouter } from '../routes';

export function createIncognitoApp() {
  const app = express();

  // Basic middleware
  app.use(cors());
  app.use(express.json({ limit: '10mb' }));
  app.use(express.urlencoded({ extended: true }));

  // Metadata protection & privacy middleware
  app.use(MetadataProtector.middleware());

  // Instantiate core components
  const merkleTree = new MerkleTree(16); // Depth 16 = up to 65,536 members
  const storage = new IncognitoStorage();
  const nullifierRegistry = new TopicNullifierRegistry();
  const membershipService = new MembershipService(merkleTree, storage);
  const revocationService = new RevocationService(merkleTree, storage);
  const reportService = new ReportService(storage, merkleTree, nullifierRegistry, revocationService);

  // Enroll initial default demo members
  ['alice_secret_seed_2026', 'bob_secret_seed_2026', 'charlie_secret_seed_2026'].forEach((seed) => {
    const m = MemberIdentity.fromSeed(seed);
    membershipService.enrollMember('0x' + m.commitment.toString(16));
  });

  // Mount modular API routes under /api
  app.use(
    '/api',
    createApiRouter({
      storage,
      nullifierRegistry,
      membershipService,
      revocationService,
      reportService
    })
  );

  // Serve static files from client directory
  const clientPublicDir = path.resolve(__dirname, '../client/public');
  app.use(express.static(clientPublicDir));

  // Catch-all to serve index.html for SPA
  app.get('*', (req: Request, res: Response) => {
    res.sendFile(path.join(clientPublicDir, 'index.html'));
  });

  return { app, merkleTree, storage, nullifierRegistry, membershipService, revocationService, reportService };
}

// Start server if executed directly
if (require.main === module) {
  const PORT = process.env.PORT || 3000;
  const { app } = createIncognitoApp();
  app.listen(PORT, () => {
    console.log(`=======================================================`);
    console.log(`  INCOGNITO: SPEAK WITHOUT BEING SEEN`);
    console.log(`  Zero-Knowledge Privacy-Preserving Reporting System`);
    console.log(`  Server running at http://localhost:${PORT}`);
    console.log(`=======================================================`);
  });
}
