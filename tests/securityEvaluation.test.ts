/**
 * Incognito Test Suite: Automated Adversarial Security Evaluation
 */

import { SecurityEvaluator } from '../src/security/evaluator';

export async function runSecurityEvaluationTests() {
  console.log('\n--- Running Adversarial Security Evaluation Matrix ---');

  const report = await SecurityEvaluator.runAllSimulations();

  console.log(`Simulations completed: ${report.totalTests} total tests.`);
  console.log(`Defenses passed: ${report.passedDefenses} / ${report.totalTests}`);

  if (report.failedDefenses > 0) {
    throw new Error(`Security evaluation failed! ${report.failedDefenses} attacks succeeded against defenses.`);
  }

  for (const t of report.tests) {
    console.log(`✓ [${t.testId}] ${t.name}: DEFENSE VERIFIED`);
  }

  console.log('✓ All 7 adversarial attack vectors successfully resisted.');
}
