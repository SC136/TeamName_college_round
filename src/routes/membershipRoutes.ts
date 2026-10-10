import { Router } from 'express';
import { MembershipController } from '../controllers/membershipController';

export function createMembershipRouter(controller: MembershipController): Router {
  const router = Router();
  router.get('/root', controller.getRootInfo);
  router.post('/enroll', controller.enrollMember);
  router.get('/proof/:commitment', controller.getProofForCommitment);
  router.get('/members', controller.getAllMembers);
  router.post('/revoke', controller.revokeMember);
  return router;
}
