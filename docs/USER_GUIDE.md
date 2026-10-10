# Incognito: User & Evaluator Guide

## 1. Quick Start

### Prerequisites
- **Node.js** (v18.0.0 or higher recommended)
- **npm** or **pnpm** / **yarn**

### Installation
```bash
# Clone and enter directory
cd bnb26

# Install dependencies
npm install
```

### Running the Application
```bash
# Start the production server
npm start

# Or run with live TypeScript execution
npm run dev
```

The application will start at:
👉 **`http://localhost:3000`**

---

## 2. Walkthrough: Interactive Portals

### 2.1 Member Portal (Whistleblower Submissions)
1. **Choose an Identity Profile**:
   - In the left panel, select from preset identities (`Alice`, `Bob`, `Charlie`) or generate a new random identity.
   - Click **"Enroll to Merkle Tree"** to publish your public commitment to the institution's Sparse Merkle Tree.
   - Note that your **Secret Nullifier** and **Trapdoor** stay strictly inside your browser memory.
2. **Author an Anonymous Report**:
   - Select a topic channel (e.g. *Executive & Management Leadership Feedback*, *Workplace & Academic Harassment*, *Workplace Safety & Lab Compliance Violations*).
   - Enter your report text in the editor.
   - Watch the **Live Content & PII Sanitizer**:
     - Typing an email address (e.g., `alice@corp.com`) or phone number (`555-123-4567`) triggers real-time redaction warnings.
     - Inserting zero-width tracking characters triggers immediate removal warnings.
     - Self-identifying linguistic phrases trigger **Anonymity Risk: MEDIUM/HIGH** advisories.
3. **Generate Zero-Knowledge Proof & Submit**:
   - Click **"Generate ZK Proof & Submit Anonymously"**.
   - Watch the animated 5-stage ZK pipeline:
     1. *Computing Secret Witness*
     2. *Fetching Merkle Path*
     3. *Deriving Topic Nullifier*
     4. *Proving SNARK Constraints*
     5. *Blind Relay Delivery*
   - Once verified, inspect the **Submission Receipt** displaying your report ID, topic nullifier, and quantized epoch timestamp.

### 2.2 Administrator Dashboard (Institutional Review)
1. Navigate to the **"Admin Dashboard"** tab in the top navigation bar.
2. View key metrics:
   - Total Enrolled Members in the Merkle Tree.
   - Total Reports Received.
   - Spent Topic Nullifiers.
   - Active Reporting Channels.
3. **Report Inbox & ZK Inspector**:
   - Select any submitted report in the inbox.
   - Inspect the verified Zero-Knowledge Proof parameters, the public inputs, the topic nullifier, and the automated severity categorization.
4. **Database Dump & Privacy Auditor**:
   - Click **"Dump Database & Audit Privacy"**.
   - Review the raw database audit output proving **0 IP addresses, 0 user-agents, and 0 links to member commitments** are stored anywhere on the server.
5. **Credential Revocation**:
   - Click **"Revoke Member Credential"**.
   - Select a member commitment to revoke.
   - Confirm revocation: the member's leaf is zeroed in the Merkle tree, and a new root is published. The revoked member can no longer submit reports!

### 2.3 Security Playground (Adversarial Simulations)
1. Navigate to the **"Security Playground"** tab.
2. Click **"Execute All Security Simulations"**.
3. Watch the system execute live cryptographic attacks:
   - **TEST-1: Forged Credentials**: Outsider with fake witness is rejected.
   - **TEST-2: Duplicate Submissions**: Member attempting double-voting is rejected.
   - **TEST-3: Cross-Topic Correlation**: Calculates Hamming distance and correlation across topics ($r \approx 0.000$).
   - **TEST-4: Rogue Admin DB Dump**: Demonstrates zero identity leakage.
   - **TEST-5: Payload Tampering**: Detects modified report content.
   - **TEST-6: Revoked Credential**: Former employee rejected after tree update.
   - **TEST-7: RLN Slashing**: Spammer double-signing triggers Shamir polynomial recovery, de-anonymizing the spammer!
4. Inspect the **Collusion Scenarios Matrix** covering Admin + Insider, Target Manager + HR, and ISP + Admin collusion models.

---

## 3. Running Automated Tests

Run the full automated test suite from the terminal:

```bash
# Execute master test suite (Crypto, ZKP, and Security Evaluator)
npm test

# Or run security evaluation suite directly
npm run test:security
```

Expected output:
```
=============================================================
       INCOGNITO AUTOMATED VERIFICATION SUITE
=============================================================
--- Running Cryptographic Primitives Tests ---
✓ Poseidon hash determinism verified.
✓ Merkle Tree inclusion proof generation & verification verified.
✓ Member Identity generation & commitment derivation verified.
✓ Topic-Scoped Nullifier derivation & unlinkability verified.
✓ Nullifier Registry double-submission defense verified.

--- Running Zero-Knowledge Proof & RLN Tests ---
✓ Valid Zero-Knowledge Proof generated and verified.
✓ Report payload tampering correctly detected and rejected.
✓ Outdated/unauthorized Merkle root rejected.
✓ RLN Shamir Secret Sharing successfully extracted abusive member identity commitment.
✓ Content sanitization, PII masking, and tracking watermark removal verified.

--- Running Adversarial Security Evaluation Matrix ---
Simulations completed: 7 total tests.
Defenses passed: 7 / 7
✓ [TEST-1-FORGED-CREDENTIAL] Forged Credential & Outsider Rejection: DEFENSE VERIFIED
✓ [TEST-2-DUPLICATE-SUBMISSION] Privacy-Preserving Duplicate Control: DEFENSE VERIFIED
✓ [TEST-3-CROSS-TOPIC-CORRELATION] Cross-Topic Unlinkability Test: DEFENSE VERIFIED
✓ [TEST-4-ADMIN-DATABASE-AUDIT] Administrator Privacy & DB Dump Audit: DEFENSE VERIFIED
✓ [TEST-5-PAYLOAD-TAMPERING] Report Front-Running & Tampering Resistance: DEFENSE VERIFIED
✓ [TEST-6-REVOKED-CREDENTIAL] Credential Revocation Enforcement: DEFENSE VERIFIED
✓ [TEST-7-RLN-SLASHING] Rate-Limiting Nullifiers (RLN) Slashing: DEFENSE VERIFIED
✓ All 7 adversarial attack vectors successfully resisted.

=============================================================
  ALL TEST SUITES PASSED WITH 100% SUCCESSFUL DEFENSES!
=============================================================
```
