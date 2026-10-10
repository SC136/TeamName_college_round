import { Request, Response } from 'express';
import { MembershipService } from '../server/membershipService';
import { RevocationService } from '../server/revocationService';
import { IncognitoStorage } from '../server/storage';

export class MembershipController {
  constructor(
    private membershipService: MembershipService,
    private revocationService: RevocationService,
    private storage: IncognitoStorage
  ) {}

  public getRootInfo = (req: Request, res: Response) => {
    res.json({ success: true, ...this.membershipService.getRootInfo() });
  };

  public enrollMember = (req: Request, res: Response) => {
    const { commitment } = req.body;
    if (!commitment) {
      return res.status(400).json({ success: false, error: 'Commitment is required.' });
    }
    const result = this.membershipService.enrollMember(commitment);
    if (!result.success) {
      return res.status(400).json(result);
    }
    res.json(result);
  };

  public getProofForCommitment = (req: Request, res: Response) => {
    const { commitment } = req.params;
    const result = this.membershipService.getProofForCommitment(commitment);
    if (!result.success) {
      return res.status(404).json(result);
    }
    const proof = result.proof!;
    const serializedProof = {
      root: '0x' + proof.root.toString(16),
      leaf: '0x' + proof.leaf.toString(16),
      index: proof.index,
      pathElements: proof.pathElements.map((p) => '0x' + p.toString(16)),
      pathIndices: proof.pathIndices
    };
    res.json({ success: true, proof: serializedProof });
  };

  public getAllMembers = (req: Request, res: Response) => {
    const members = this.storage.getAllMembers();
    res.json({
      success: true,
      count: members.length,
      members
    });
  };

  public revokeMember = (req: Request, res: Response) => {
    const { commitment, reason } = req.body;
    if (!commitment) {
      return res.status(400).json({ success: false, error: 'Commitment is required.' });
    }
    const result = this.revocationService.revokeMemberByCommitment(commitment, reason);
    if (!result.success) {
      return res.status(400).json(result);
    }
    res.json(result);
  };
}
