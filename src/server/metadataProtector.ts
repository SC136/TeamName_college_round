/**
 * Incognito Metadata Protection & Traffic Sanitization Middleware
 *
 * Implements defensive measures against traffic analysis & metadata correlation:
 * 1. Zero IP logging & header scrubbing.
 * 2. Fingerprint stripping (User-Agent, client hints, cookies).
 * 3. Timing-jitter delay to disrupt network arrival correlation.
 * 4. Audit-grade privacy logging.
 */

import { Request, Response, NextFunction } from 'express';

export class MetadataProtector {
  // Disallowed headers that could enable fingerprinting
  private static readonly IDENTIFYING_HEADERS = [
    'user-agent',
    'x-forwarded-for',
    'x-real-ip',
    'cf-connecting-ip',
    'true-client-ip',
    'x-client-ip',
    'forwarded',
    'sec-ch-ua',
    'sec-ch-ua-mobile',
    'sec-ch-ua-platform',
    'sec-ch-ua-model',
    'cookie',
    'referer'
  ];

  /**
   * Express middleware to scrub headers and isolate network identity
   */
  public static middleware() {
    return (req: Request, res: Response, next: NextFunction) => {
      // 1. Strip identifying incoming headers
      for (const h of MetadataProtector.IDENTIFYING_HEADERS) {
        delete req.headers[h];
      }

      // 2. Anonymize request socket IP
      try {
        Object.defineProperty(req, 'ip', { value: '127.0.0.1 (ANONYMOUS_RELAY)', configurable: true });
        Object.defineProperty(req, 'ips', { value: [], configurable: true });
      } catch {
        // Fallback if property is frozen
      }

      // 3. Set strict privacy headers on responses
      res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, private');
      res.setHeader('Pragma', 'no-cache');
      res.setHeader('Expires', '0');
      res.setHeader('X-Content-Type-Options', 'nosniff');
      res.setHeader('X-Frame-Options', 'DENY');
      res.setHeader('Referrer-Policy', 'no-referrer');
      res.setHeader('Permissions-Policy', 'interest-cohort=()');

      next();
    };
  }

  /**
   * Apply randomized delay jitter to prevent millisecond network correlation attacks
   */
  public static async applyTimingJitter(minMs: number = 50, maxMs: number = 200): Promise<void> {
    const jitter = Math.floor(Math.random() * (maxMs - minMs + 1)) + minMs;
    return new Promise((resolve) => setTimeout(resolve, jitter));
  }

  /**
   * Privacy-preserving audit logger: logs zero user identifiers or network metadata
   */
  public static logPrivacyEvent(event: string, details: Record<string, any> = {}): void {
    const safeLog = {
      timestamp: new Date().toISOString(),
      event,
      networkOrigin: '[STRIPPED_BY_INCOGNITO_RELAY]',
      ...details
    };
    // Format as clean audit log
    const line = `[INCOGNITO-PRIVACY-AUDIT] ${safeLog.timestamp} | ${event} | ${JSON.stringify(details)}`;
    // Output to stdout
    console.log(line);
  }
}
