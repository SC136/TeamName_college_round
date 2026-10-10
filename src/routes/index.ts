import { Router, Request, Response } from 'express';
import { TopicController } from '../controllers/topicController';
import { MembershipController } from '../controllers/membershipController';
import { ReportController } from '../controllers/reportController';
import { SecurityController } from '../controllers/securityController';
import { createTopicRouter } from './topicRoutes';
import { createMembershipRouter } from './membershipRoutes';
import { createReportRouter } from './reportRoutes';
import { createSecurityRouter } from './securityRoutes';
import { IncognitoStorage } from '../server/storage';
import { MembershipService } from '../server/membershipService';
import { RevocationService } from '../server/revocationService';
import { ReportService } from '../server/reportService';
import { TopicNullifierRegistry } from '../crypto/nullifier';

export interface RouteDependencies {
  storage: IncognitoStorage;
  nullifierRegistry: TopicNullifierRegistry;
  membershipService: MembershipService;
  revocationService: RevocationService;
  reportService: ReportService;
}

export function createApiRouter(deps: RouteDependencies): Router {
  const router = Router();

  const topicController = new TopicController(deps.storage);
  const membershipController = new MembershipController(
    deps.membershipService,
    deps.revocationService,
    deps.storage
  );
  const reportController = new ReportController(deps.reportService, deps.storage);
  const securityController = new SecurityController(deps.storage, deps.nullifierRegistry);

  // Health check
  router.get('/health', (req: Request, res: Response) => {
    res.json({
      status: 'UP',
      system: 'Incognito Privacy Reporting',
      version: '1.0.0',
      timestamp: Date.now()
    });
  });

  // Mount modular route handlers
  router.use('/topics', createTopicRouter(topicController));
  router.use('/membership', createMembershipRouter(membershipController));
  router.use('/reports', createReportRouter(reportController));
  router.use('/security', createSecurityRouter(securityController));

  return router;
}
