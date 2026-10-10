/**
 * Incognito: Zero-Knowledge Privacy-Preserving Reporting System
 *
 * Refactored Express Server bootstrapped from modular architecture:
 * - src/routes/ (API Endpoints: /topics, /membership, /reports, /security)
 * - src/controllers/ (Request handling logic)
 * - src/services/ (SupabaseService PostgreSQL & ZKVerificationService with SnarkJS)
 * - src/crypto/ (BN254 Poseidon, Merkle Tree, Nullifiers, RLN)
 */

require('dotenv').config();

let createIncognitoApp;

try {
  require('ts-node/register');
  createIncognitoApp = require('./src/server/app').createIncognitoApp;
} catch (e) {
  createIncognitoApp = require('./dist/server/app').createIncognitoApp;
}

const { app } = createIncognitoApp();
const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
  console.log(`=======================================================`);
  console.log(`  INCOGNITO: SPEAK WITHOUT BEING SEEN`);
  console.log(`  Zero-Knowledge Privacy-Preserving Reporting System`);
  console.log(`  Modular Express Server running at http://localhost:${PORT}`);
  console.log(`=======================================================`);
});
