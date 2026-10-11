import { Router } from 'express';
import { AuthController } from '../controllers/authController';

export function createAuthRouter(controller: AuthController): Router {
  const router = Router();

  router.post('/register', controller.register);
  router.post('/login', controller.login);
  router.get('/session/:userId', controller.getSession);
  router.post('/verify-id', controller.verifyIdAndTrash);

  return router;
}

export function createOrganizationRouter(controller: AuthController): Router {
  const router = Router();

  router.get('/', controller.getOrganizations);

  return router;
}
