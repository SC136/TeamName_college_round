/**
 * Incognito Content Moderation & Abuse Prevention Engine
 *
 * Provides automated content moderation, categorization, and threat triage
 * while strictly preserving reporter anonymity.
 */

export interface ModerationAnalysis {
  category: 'MANAGEMENT' | 'HARASSMENT' | 'SAFETY' | 'ACADEMIC' | 'GENERAL';
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  flags: string[];
  isSpam: boolean;
  isToxic: boolean;
  score: number; // 0 (clean) to 100 (severe)
}

export class ModerationService {
  // Threat & Safety keywords
  private static readonly CRITICAL_SAFETY_TERMS = [
    /\b(bomb|weapon|fire|explosion|poison|chemical spill|biohazard|physical assault|kill|suicide)\b/i,
    /\b(immediate danger|safety failure|life-threatening|collapse|radiation)\b/i
  ];

  // Harassment & Abuse keywords
  private static readonly HARASSMENT_TERMS = [
    /\b(harass|stalk|groped|touching|slur|racist|sexist|retaliate|hostile environment|blackmail|threaten)\b/i,
    /\b(extort|intimidat|humiliat|discrimina)\b/i
  ];

  // Academic / Grading integrity
  private static readonly ACADEMIC_TERMS = [
    /\b(cheat|plagiar|bribe for grade|grade tampering|exam leak|fake thesis|falsified research)\b/i
  ];

  // Management / Institutional misconduct
  private static readonly MANAGEMENT_TERMS = [
    /\b(embezzle|fraud|kickback|cover-up|misuse of funds|nepotism|wage theft|falsified audit)\b/i
  ];

  // Spam / Low quality text
  private static readonly SPAM_INDICATORS = [
    /\b(crypto|casino|buy viagra|free money|click here|telegram:|whatsapp:)\b/i
  ];

  public static analyze(content: string): ModerationAnalysis {
    const flags: string[] = [];
    let score = 10;
    let category: ModerationAnalysis['category'] = 'GENERAL';
    let severity: ModerationAnalysis['severity'] = 'LOW';
    let isSpam = false;
    let isToxic = false;

    // Check spam
    for (const term of this.SPAM_INDICATORS) {
      if (term.test(content)) {
        flags.push('Spam / Promotional advertisement detected');
        isSpam = true;
        score += 40;
      }
    }

    // Check critical safety
    let safetyHits = 0;
    for (const term of this.CRITICAL_SAFETY_TERMS) {
      if (term.test(content)) {
        safetyHits++;
        flags.push('URGENT: Imminent safety or physical hazard indicator identified');
      }
    }

    // Check harassment
    let harassmentHits = 0;
    for (const term of this.HARASSMENT_TERMS) {
      if (term.test(content)) {
        harassmentHits++;
        flags.push('Harassment, discrimination, or abusive conduct indicator');
      }
    }

    // Check academic integrity
    let academicHits = 0;
    for (const term of this.ACADEMIC_TERMS) {
      if (term.test(content)) {
        academicHits++;
        flags.push('Academic malpractice or grading integrity violation indicator');
      }
    }

    // Check management misconduct
    let mgmtHits = 0;
    for (const term of this.MANAGEMENT_TERMS) {
      if (term.test(content)) {
        mgmtHits++;
        flags.push('Institutional corruption, embezzlement, or managerial cover-up indicator');
      }
    }

    // Determine category and severity
    if (safetyHits > 0) {
      category = 'SAFETY';
      severity = 'CRITICAL';
      score = Math.max(score, 95);
    } else if (harassmentHits > 0) {
      category = 'HARASSMENT';
      severity = harassmentHits >= 2 ? 'HIGH' : 'MEDIUM';
      score = Math.max(score, 75);
    } else if (mgmtHits > 0) {
      category = 'MANAGEMENT';
      severity = mgmtHits >= 2 ? 'HIGH' : 'MEDIUM';
      score = Math.max(score, 70);
    } else if (academicHits > 0) {
      category = 'ACADEMIC';
      severity = 'MEDIUM';
      score = Math.max(score, 60);
    }

    if (score >= 70) {
      isToxic = true;
    }

    return {
      category,
      severity,
      flags,
      isSpam,
      isToxic,
      score
    };
  }
}
