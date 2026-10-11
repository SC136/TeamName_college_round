/**
 * Incognito: Master Automated Test Runner
 */

import { runCryptoTests } from './crypto.test';
import { runZkpTests } from './zkp.test';
import { runSecurityEvaluationTests } from './securityEvaluation.test';
import { runOnboardingTests } from './onboarding.test';

async function main() {
  console.log('=============================================================');
  console.log('       INCOGNITO AUTOMATED VERIFICATION SUITE');
  console.log('=============================================================');

  try {
    runCryptoTests();
    runZkpTests();
    await runSecurityEvaluationTests();
    runOnboardingTests();

    console.log('\n=============================================================');
    console.log('  ALL TEST SUITES PASSED WITH 100% SUCCESSFUL DEFENSES!');
    console.log('=============================================================\n');
    process.exit(0);
  } catch (err: any) {
    console.error('\n❌ TEST FAILURE:', err.message);
    if (err.stack) console.error(err.stack);
    process.exit(1);
  }
}

main();
