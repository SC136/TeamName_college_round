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
import { MerkleTree } from '../crypto/merkleTree';
import { IncognitoStorage } from './storage';
import { MembershipService } from './membershipService';
import { RevocationService } from './revocationService';
import { TopicNullifierRegistry } from '../crypto/nullifier';
import { ReportService } from './reportService';
import { MetadataProtector } from './metadataProtector';
import { SecurityEvaluator } from '../security/evaluator';

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

  // Health check
  app.get('/api/health', (req: Request, res: Response) => {
    res.json({
      status: 'UP',
      system: 'Incognito Privacy Reporting',
      version: '1.0.0',
      timestamp: Date.now()
    });
  });

  // Topics API
  app.get('/api/topics', (req: Request, res: Response) => {
    res.json({ success: true, topics: storage.getTopics() });
  });

  app.post('/api/topics', (req: Request, res: Response) => {
    const { id, title, category, description, allowedQuotaPerMember } = req.body;
    if (!id || !title || !description) {
      return res.status(400).json({ success: false, error: 'Missing required topic fields.' });
    }
    const topic = {
      id: id.toLowerCase().replace(/[^a-z0-9_-]/g, '-'),
      title,
      category: category || 'GENERAL',
      description,
      allowedQuotaPerMember: allowedQuotaPerMember || 1,
      active: true,
      createdAt: Date.now()
    };
    storage.addTopic(topic);
    res.json({ success: true, topic });
  });

  // Membership & Merkle API
  app.get('/api/membership/root', (req: Request, res: Response) => {
    res.json({ success: true, ...membershipService.getRootInfo() });
  });

  app.post('/api/membership/enroll', (req: Request, res: Response) => {
    const { commitment } = req.body;
    if (!commitment) {
      return res.status(400).json({ success: false, error: 'Commitment is required.' });
    }
    const result = membershipService.enrollMember(commitment);
    if (!result.success) {
      return res.status(400).json(result);
    }
    res.json(result);
  });

  app.get('/api/membership/proof/:commitment', (req: Request, res: Response) => {
    const { commitment } = req.params;
    const result = membershipService.getProofForCommitment(commitment);
    if (!result.success) {
      return res.status(404).json(result);
    }
    // Convert BigInts in proof to hex strings for JSON transport
    const proof = result.proof!;
    const serializedProof = {
      root: '0x' + proof.root.toString(16),
      leaf: '0x' + proof.leaf.toString(16),
      index: proof.index,
      pathElements: proof.pathElements.map((p) => '0x' + p.toString(16)),
      pathIndices: proof.pathIndices
    };
    res.json({ success: true, proof: serializedProof });
  });

  app.get('/api/membership/members', (req: Request, res: Response) => {
    const members = storage.getAllMembers();
    res.json({
      success: true,
      count: members.length,
      members
    });
  });

  app.post('/api/membership/revoke', (req: Request, res: Response) => {
    const { commitment, reason } = req.body;
    if (!commitment) {
      return res.status(400).json({ success: false, error: 'Commitment is required.' });
    }
    const result = revocationService.revokeMemberByCommitment(commitment, reason);
    if (!result.success) {
      return res.status(400).json(result);
    }
    res.json(result);
  });

  // Report Submission & Retrieval API
  app.post('/api/reports/submit', async (req: Request, res: Response) => {
    try {
      const { topicId, content, zkProof, rlnShare, attachments } = req.body;
      if (!topicId || !content || !zkProof) {
        return res.status(400).json({ success: false, error: 'Missing required report or ZK proof fields.' });
      }

      const result = await reportService.submitReport({
        topicId,
        content,
        zkProof,
        rlnShare,
        attachments
      });

      if (!result.success) {
        return res.status(400).json(result);
      }

      res.status(201).json(result);
    } catch (err: any) {
      res.status(500).json({ success: false, error: err.message });
    }
  });

  app.get('/api/reports', (req: Request, res: Response) => {
    const { topicId } = req.query;
    const reports = storage.getReports(topicId as string | undefined);
    res.json({
      success: true,
      count: reports.length,
      reports: reports.map((r) => ({
        id: r.id,
        topicId: r.topicId,
        content: r.sanitizedContent,
        nullifierHash: r.nullifierHash,
        quantizedTimestamp: r.quantizedTimestamp,
        moderationCategory: r.moderationCategory,
        moderationSeverity: r.moderationSeverity,
        piiRedacted: r.piiRedacted,
        status: r.status,
        attachmentCount: r.attachments ? r.attachments.length : 0
      }))
    });
  });

  app.get('/api/reports/:id', (req: Request, res: Response) => {
    const report = storage.getReport(req.params.id);
    if (!report) {
      return res.status(404).json({ success: false, error: 'Report not found.' });
    }
    res.json({ success: true, report });
  });

  app.patch('/api/reports/:id/status', (req: Request, res: Response) => {
    const { status } = req.body;
    if (!status) {
      return res.status(400).json({ success: false, error: 'Status is required.' });
    }
    const updated = storage.updateReportStatus(req.params.id, status);
    if (!updated) {
      return res.status(404).json({ success: false, error: 'Report not found.' });
    }
    res.json({ success: true, id: req.params.id, status });
  });

  // Security Evaluation & Audit Dump API
  app.get('/api/security/audit-dump', (req: Request, res: Response) => {
    const audit = storage.dumpSecurityAudit();
    const spentNullifiers = nullifierRegistry.exportRegistry();
    res.json({
      success: true,
      audit,
      spentNullifiers,
      securityGuarantee: 'Zero Identity Disclosure: Database contains zero IP addresses, zero identities, and zero linkage tables.'
    });
  });

  app.post('/api/security/run-simulation', async (req: Request, res: Response) => {
    try {
      const results = await SecurityEvaluator.runAllSimulations();
      res.json({ success: true, results });
    } catch (err: any) {
      res.status(500).json({ success: false, error: err.message });
    }
  });

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
