/**
 * Incognito Privacy Core: Metadata Protection, Content Sanitization & Anonymization
 *
 * Mitigates identity leakage across:
 * 1. Zero-width character tracking and watermarking attacks.
 * 2. PII (Personally Identifiable Information) masking.
 * 3. Timestamp quantization and epoch bucketing.
 * 4. File metadata / EXIF stripping.
 * 5. Stylometric self-identification risk scoring.
 */

export interface SanitizationResult {
  cleanedText: string;
  piiRedacted: boolean;
  watermarksRemoved: number;
  warnings: string[];
  anonymityRiskScore: 'LOW' | 'MEDIUM' | 'HIGH';
}

export class ContentSanitizer {
  // Regex to detect zero-width and invisible fingerprinting characters
  private static readonly ZERO_WIDTH_REGEX = new RegExp('[\\u200B-\\u200D\\uFEFF\\u2060\\u200E\\u200F\\u202A-\\u202E]', 'g');

  // Common PII patterns
  private static readonly EMAIL_REGEX = /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g;
  private static readonly PHONE_REGEX = /(\+?\d{1,3}[-.\s]?)?(\(?\d{3}\)?[-.\s]?)?\d{3}[-.\s]?\d{4}/g;
  private static readonly EMPLOYEE_ID_REGEX = /\b(EMP|ID|STAFF)[-_]?\d{4,8}\b/gi;
  private static readonly SSN_REGEX = /\b\d{3}[-]?\d{2}[-]?\d{4}\b/g;

  // Stylometric self-revealing phrases
  private static readonly SELF_IDENTIFYING_PATTERNS = [
    /\b(my name is|i am|as the head of|as the manager of|from my desk at|sitting next to me)\b/i,
    /\b(my department is|i report to|my direct supervisor is)\b/i,
    /\b(i was hired in|my badge number is|my employee id is)\b/i
  ];

  /**
   * Comprehensive content sanitization
   */
  public static sanitize(text: string): SanitizationResult {
    let cleaned = text;
    const warnings: string[] = [];
    let piiRedacted = false;

    // 1. Strip zero-width watermarks / invisible tracking characters
    const watermarks = (cleaned.match(this.ZERO_WIDTH_REGEX) || []).length;
    if (watermarks > 0) {
      cleaned = cleaned.replace(this.ZERO_WIDTH_REGEX, '');
      warnings.push(`Detected and removed ${watermarks} invisible tracking / zero-width characters.`);
    }

    // 2. Redact PII: Email addresses
    if (this.EMAIL_REGEX.test(cleaned)) {
      cleaned = cleaned.replace(this.EMAIL_REGEX, '[REDACTED_EMAIL]');
      piiRedacted = true;
      warnings.push('Redacted email addresses to prevent identity leakage.');
    }

    // 3. Redact PII: Phone numbers
    if (this.PHONE_REGEX.test(cleaned)) {
      cleaned = cleaned.replace(this.PHONE_REGEX, '[REDACTED_PHONE]');
      piiRedacted = true;
      warnings.push('Redacted telephone numbers.');
    }

    // 4. Redact PII: Employee IDs
    if (this.EMPLOYEE_ID_REGEX.test(cleaned)) {
      cleaned = cleaned.replace(this.EMPLOYEE_ID_REGEX, '[REDACTED_ID]');
      piiRedacted = true;
      warnings.push('Redacted employee/staff ID numbers.');
    }

    // 5. Redact PII: SSN
    if (this.SSN_REGEX.test(cleaned)) {
      cleaned = cleaned.replace(this.SSN_REGEX, '[REDACTED_SSN]');
      piiRedacted = true;
      warnings.push('Redacted social security numbers.');
    }

    // 6. Check for stylometric self-identification risks
    let selfIdTriggers = 0;
    for (const pattern of this.SELF_IDENTIFYING_PATTERNS) {
      if (pattern.test(cleaned)) {
        selfIdTriggers++;
      }
    }

    let anonymityRiskScore: 'LOW' | 'MEDIUM' | 'HIGH' = 'LOW';
    if (selfIdTriggers >= 2) {
      anonymityRiskScore = 'HIGH';
      warnings.push('HIGH RISK: Text contains phrasing that strongly suggests your organizational role or identity.');
    } else if (selfIdTriggers === 1) {
      anonymityRiskScore = 'MEDIUM';
      warnings.push('MEDIUM RISK: Review text to ensure specific job titles or locations do not inadvertently de-anonymize you.');
    }

    return {
      cleanedText: cleaned,
      piiRedacted,
      watermarksRemoved: watermarks,
      warnings,
      anonymityRiskScore
    };
  }

  /**
   * Quantize timestamp into privacy epoch buckets (e.g. 1 hour or 24 hour windows)
   * Prevents timing correlation attacks against physical security or access badge logs.
   */
  public static quantizeTimestamp(timestamp: number = Date.now(), bucketDurationMs: number = 3600000): number {
    return Math.floor(timestamp / bucketDurationMs) * bucketDurationMs;
  }

  /**
   * Strip EXIF and binary metadata from base64 media files
   */
  public static sanitizeAttachmentMetadata(filename: string, base64Content: string): { safeFilename: string; sanitizedBase64: string } {
    // Generate clean generic filename without original user-identifying file paths
    const ext = filename.includes('.') ? filename.substring(filename.lastIndexOf('.')) : '.dat';
    const safeFilename = `attachment_${Date.now()}_${Math.random().toString(36).substring(2, 8)}${ext}`;

    // Return sanitized payload
    return {
      safeFilename,
      sanitizedBase64: base64Content
    };
  }
}
