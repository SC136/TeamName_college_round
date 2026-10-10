import { Router } from 'express';
import { ReportController } from '../controllers/reportController';

export function createReportRouter(controller: ReportController): Router {
  const router = Router();
  router.post('/submit', controller.submitReport);
  router.get('/', controller.getReports);
  router.get('/:id', controller.getReportById);
  router.patch('/:id/status', controller.updateReportStatus);
  return router;
}
