import { Request, Response } from 'express';
import { IncognitoStorage } from '../server/storage';

export class TopicController {
  constructor(private storage: IncognitoStorage) {}

  public getTopics = (req: Request, res: Response) => {
    res.json({ success: true, topics: this.storage.getTopics() });
  };

  public createTopic = (req: Request, res: Response) => {
    const { id, title, category, description, allowedQuotaPerMember } = req.body;
    if (!id || !title || !description) {
      return res.status(400).json({ success: false, error: 'Missing required topic fields.' });
    }
    const topic = {
      id: id.toLowerCase().replace(/[^a-z0-9_-]/g, '-'),
      title,
      category: category || 'GENERAL',
      description,
      allowedQuotaPerMember: allowedQuotaPerMember || 1,
      active: true,
      createdAt: Date.now()
    };
    this.storage.addTopic(topic);
    res.json({ success: true, topic });
  };
}
