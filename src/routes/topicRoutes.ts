import { Router } from 'express';
import { TopicController } from '../controllers/topicController';

export function createTopicRouter(controller: TopicController): Router {
  const router = Router();
  router.get('/', controller.getTopics);
  router.post('/', controller.createTopic);
  return router;
}
