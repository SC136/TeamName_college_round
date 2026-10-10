import { Router } from 'express';
import { SecurityController } from '../controllers/securityController';

export function createSecurityRouter(controller: SecurityController): Router {
  const router = Router();
  router.get('/audit-dump', controller.getAuditDump);
  router.post('/run-simulation', controller.runSimulation);
  return router;
}
