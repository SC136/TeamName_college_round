import { Request, Response } from 'express';
import { ReportService } from '../server/reportService';
import { IncognitoStorage } from '../server/storage';

export class ReportController {
  constructor(
    private reportService: ReportService,
    private storage: IncognitoStorage
  ) {}

  public submitReport = async (req: Request, res: Response) => {
    try {
      const { topicId, content, zkProof, rlnShare, attachments } = req.body;
      if (!topicId || !content || !zkProof) {
        return res.status(400).json({ success: false, error: 'Missing required report or ZK proof fields.' });
      }

      const result = await this.reportService.submitReport({
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
  };

  public getReports = (req: Request, res: Response) => {
    const { topicId } = req.query;
    const reports = this.storage.getReports(topicId as string | undefined);
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
  };

  public getReportById = (req: Request, res: Response) => {
    const report = this.storage.getReport(req.params.id);
    if (!report) {
      return res.status(404).json({ success: false, error: 'Report not found.' });
    }
    res.json({ success: true, report });
  };

  public updateReportStatus = (req: Request, res: Response) => {
    const { status } = req.body;
    if (!status) {
      return res.status(400).json({ success: false, error: 'Status is required.' });
    }
    const updated = this.storage.updateReportStatus(req.params.id, status);
    if (!updated) {
      return res.status(404).json({ success: false, error: 'Report not found.' });
    }
    res.json({ success: true, id: req.params.id, status });
  };
}
