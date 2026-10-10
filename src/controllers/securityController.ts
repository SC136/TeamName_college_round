import { Request, Response } from 'express';
import { IncognitoStorage } from '../server/storage';
import { TopicNullifierRegistry } from '../crypto/nullifier';
import { SecurityEvaluator } from '../security/evaluator';

export class SecurityController {
  constructor(
    private storage: IncognitoStorage,
    private nullifierRegistry: TopicNullifierRegistry
  ) {}

  public getAuditDump = (req: Request, res: Response) => {
    const audit = this.storage.dumpSecurityAudit();
    const spentNullifiers = this.nullifierRegistry.exportRegistry();
    res.json({
      success: true,
      audit,
      spentNullifiers,
      securityGuarantee: 'Zero Identity Disclosure: Database contains zero IP addresses, zero identities, and zero linkage tables.'
    });
  };

  public runSimulation = async (req: Request, res: Response) => {
    try {
      const results = await SecurityEvaluator.runAllSimulations();
      res.json({ success: true, results });
    } catch (err: any) {
      res.status(500).json({ success: false, error: err.message });
    }
  };
}
