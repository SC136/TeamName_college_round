/**
 * Incognito Report Ingestion & Verification Service
 *
 * Coordinates zero-knowledge verification, topic nullifier duplicate control,
 * RLN abuse prevention, content sanitization, and anonymous storage.
 */

import * as crypto from 'crypto';
import { IncognitoStorage, StoredReport } from './storage';
import { MerkleTree } from '../crypto/merkleTree';
import { TopicNullifierRegistry } from '../crypto/nullifier';
import { ZKEngine, ZKProof } from '../crypto/zkEngine';
import { ZKVerificationService } from '../services/zkService';
import { ContentSanitizer } from '../crypto/sanitization';
import { ModerationService } from './moderationService';
import { RLNShare, RLNSystem } from '../crypto/rln';
import { RevocationService } from './revocationService';
import { MetadataProtector } from './metadataProtector';

export interface SubmitReportRequest {
  topicId: string;
  content: string;
  zkProof: ZKProof;
  rlnShare?: RLNShare;
  attachments?: { filename: string; payloadBase64: string }[];
}

export interface SubmitReportResponse {
  success: boolean;
  reportId?: string;
  nullifierHash?: string;
  quantizedTimestamp?: number;
  piiRedacted?: boolean;
  moderationSeverity?: string;
  error?: string;
  slashed?: boolean;
  slashingDetails?: any;
}

export class ReportService {
  private storage: IncognitoStorage;
  private merkleTree: MerkleTree;
  private nullifierRegistry: TopicNullifierRegistry;
  private revocationService: RevocationService;
  private rlnSharesMap: Map<string, RLNShare[]>; // Keyed by rln nullifier

  constructor(
    storage: IncognitoStorage,
    merkleTree: MerkleTree,
    nullifierRegistry: TopicNullifierRegistry,
    revocationService: RevocationService
  ) {
    this.storage = storage;
    this.merkleTree = merkleTree;
    this.nullifierRegistry = nullifierRegistry;
    this.revocationService = revocationService;
    this.rlnSharesMap = new Map<string, RLNShare[]>();
  }

  /**
   * Process and verify an anonymous report submission
   */
  public async submitReport(req: SubmitReportRequest): Promise<SubmitReportResponse> {
    // Apply network timing jitter to disrupt packet-timing correlation
    await MetadataProtector.applyTimingJitter(50, 150);

    // 1. Validate topic existence and status
    const topic = this.storage.getTopic(req.topicId);
    if (!topic) {
      return { success: false, error: `Topic '${req.topicId}' not found.` };
    }
    if (!topic.active) {
      return { success: false, error: `Topic '${req.topicId}' is currently closed.` };
    }

    if (!req.content || req.content.trim().length === 0) {
      return { success: false, error: 'Report content cannot be empty.' };
    }

    // 2. Content Sanitization (PII, zero-width tracking watermarks)
    const sanitization = ContentSanitizer.sanitize(req.content);
    const moderation = ModerationService.analyze(sanitization.cleanedText);

    if (moderation.isSpam) {
      return {
        success: false,
        error: 'Report rejected by automated moderation: detected spam / commercial content.'
      };
    }

    // 3. Zero-Knowledge Cryptographic Verification
    // Verify proof matches the original submitted text (integrity binding)
    const verification = await ZKVerificationService.verifyProof(req.zkProof, this.merkleTree, req.content);
    if (!verification.valid) {
      MetadataProtector.logPrivacyEvent('ZKP_VERIFICATION_FAILED', {
        topicId: req.topicId,
        reason: verification.reason
      });
      return {
        success: false,
        error: `Zero-Knowledge Verification Failed: ${verification.reason}`
      };
    }

    // 4. Topic-Scoped Nullifier Check (Duplicate Control)
    const nullifierBigInt = BigInt(req.zkProof.publicInputs.nullifierHash);
    const isAlreadySpent = this.nullifierRegistry.isSpent(req.topicId, nullifierBigInt);

    if (isAlreadySpent) {
      MetadataProtector.logPrivacyEvent('DUPLICATE_SUBMISSION_REJECTED', {
        topicId: req.topicId,
        nullifierHash: req.zkProof.publicInputs.nullifierHash
      });
      return {
        success: false,
        error: 'DUPLICATE_SUBMISSION_DETECTED: A report has already been submitted under this member quota slot for this topic.'
      };
    }

    // 5. Rate-Limiting Nullifiers (RLN) Double-Sign & Slashing Check
    if (req.rlnShare) {
      const rlnNullifier = req.rlnShare.nullifier;
      const existingShares = this.rlnSharesMap.get(rlnNullifier) || [];

      for (const priorShare of existingShares) {
        const slashResult = RLNSystem.detectAndSlash(priorShare, req.rlnShare);
        if (slashResult.slashed && slashResult.recoveredCommitment) {
          // Double submission within same rate-limit window!
          // Execute automatic revocation/slashing of member's commitment
          this.revocationService.executeRLNSlashing(
            slashResult.recoveredCommitment,
            req.content
          );

          MetadataProtector.logPrivacyEvent('RLN_SLASHING_TRIGGERED', {
            slashedCommitment: slashResult.recoveredCommitment
          });

          return {
            success: false,
            slashed: true,
            slashingDetails: slashResult,
            error: 'RATE_LIMIT_EXCEEDED: RLN double-submission detected! Member credential has been mathematically slashed and revoked.'
          };
        }
      }

      existingShares.push(req.rlnShare);
      this.rlnSharesMap.set(rlnNullifier, existingShares);
      this.storage.getSupabaseService().insertRlnShare(req.rlnShare as any).catch(() => {});
    }

    // 6. Record Nullifier in spent registry
    this.nullifierRegistry.spend(req.topicId, nullifierBigInt);
    this.storage.getSupabaseService().recordSpentNullifier(req.topicId, req.zkProof.publicInputs.nullifierHash).catch(() => {});

    // 7. Sanitize attachments if present
    const cleanAttachments = (req.attachments || []).map((att) =>
      ContentSanitizer.sanitizeAttachmentMetadata(att.filename, att.payloadBase64)
    );

    // 8. Generate Anonymous Report Record
    const reportId = 'rep_' + crypto.randomBytes(8).toString('hex');
    const quantizedTimestamp = ContentSanitizer.quantizeTimestamp();

    const storedReport: StoredReport = {
      id: reportId,
      topicId: req.topicId,
      sanitizedContent: sanitization.cleanedText,
      nullifierHash: req.zkProof.publicInputs.nullifierHash,
      quantizedTimestamp,
      moderationCategory: moderation.category,
      moderationSeverity: moderation.severity,
      piiRedacted: sanitization.piiRedacted,
      status: 'PENDING',
      zkProof: req.zkProof,
      attachments: cleanAttachments.map((a) => ({
        filename: a.safeFilename,
        payloadBase64: a.sanitizedBase64
      }))
    };

    this.storage.addReport(storedReport);

    MetadataProtector.logPrivacyEvent('REPORT_SUBMITTED_SUCCESSFULLY', {
      reportId,
      topicId: req.topicId,
      quantizedTimestamp,
      severity: moderation.severity
    });

    return {
      success: true,
      reportId,
      nullifierHash: req.zkProof.publicInputs.nullifierHash,
      quantizedTimestamp,
      piiRedacted: sanitization.piiRedacted,
      moderationSeverity: moderation.severity
    };
  }

  public getNullifierRegistry(): TopicNullifierRegistry {
    return this.nullifierRegistry;
  }
}
