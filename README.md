# 🛡️ Incognito: Speak Without Being Seen

> **Privacy-Preserving Reporting System for Verified Members Using Zero-Knowledge Proofs & Topic-Scoped Nullifiers**

---

## 🌟 Backstory & Motivation

Honest feedback about managers, teachers, and institutions is frequently suppressed because people fear career retaliation, grade penalties, and social ostracization. Traditional reporting systems rely on administrators to protect identities—which fails if the administrator is corrupt, biased, or subpoenaed. Conversely, completely open anonymous platforms struggle with fabricated reports, coordinated smear campaigns, and spam abuse.

**Incognito** solves this fundamental dilemma: **it allows verified members to submit anonymous reports without revealing their identities—even to the system administrators—while mathematically preventing outsiders, duplicate submissions, and spam abuse.**

---

## 🔑 Key Features & Alignment with Problem Statement

| Problem Statement Requirement | Incognito Solution & Mechanism |
| :--- | :--- |
| **1. Anonymous Membership Proof** | **Sparse Merkle Tree & ZK Proofs**: Verifies member possesses an enrolled credential leaf in the organization Merkle tree over BN254 scalar field $\mathbb{F}_r$ using Poseidon hash without disclosing which leaf or identity. |
| **2. Ephemeral ID Proof Verification & Trashing** | **5-Step Onboarding with Zero Storage Retention**: Members register, select their institution/university from a searchable directory, and upload their ID badge. Once verified in transient RAM, the ID card is **immediately zero-overwritten and trashed** ($0$ bytes stored), enrolling only their anonymous ZK commitment. |
| **3. Unlinkable Submissions** | **Topic-Scoped Nullifiers**: $N = \text{Poseidon}(\text{nullifier}, \text{topicId})$. Submissions from the same member across different topics produce uncorrelated pseudo-random field elements ($r = 0.0002$, 50% Hamming distance flip). |
| **4. Privacy-Preserving Duplicate Control** | **Deterministic Nullifier Registry**: Enforces per-member submission quotas per topic. Re-submitting to the same topic produces the identical nullifier and is rejected without revealing who submitted it. |
| **5. Administrator Privacy** | **Zero Identity & IP Retention**: Server storage and logs contain **0 IP addresses, 0 user-agents, 0 ID card images, and 0 links between reports and members**. Reversing nullifiers requires $2^{254}$ operations (preimage resistant). |
| **6. Anonymous Abuse Prevention & Revocation** | **RLN (Rate-Limiting Nullifiers) & Dynamic Merkle Pruning**: Spam flooders double-signing a topic trigger 2-out-of-2 Shamir Secret Sharing polynomial slashing, mathematically extracting and revoking their commitment. Former members are pruned from the active Merkle root. |
| **7. Metadata Protection** | **Comprehensive Sanitization Pipeline**: Strips zero-width unicode tracking characters, redacts PII (emails, phones, staff IDs), quantizes timestamps to 1-hour epoch buckets, and adds 50-200ms network timing jitter. |
| **8. Adversarial Security Evaluation** | **Comprehensive 7-Vector Attack Suite & Playground**: Live simulations and automated test assertions for forged credentials, duplicate submissions, cross-topic correlation, rogue admin DB dumps, report tampering, revoked credentials, and collusion scenarios. |

---

## 🏗️ System Architecture

```
Member Browser (Client)               Incognito Server / Relay                Admin Review Console
────────────────────────               ────────────────────────                ────────────────────
1. Identity: (nullifier, trapdoor)
   commitment = Poseidon(secret)
          │
          ├──────── Enroll Commitment ──────────► Added to Merkle Tree
          │                                              │
2. Client ZK Pipeline:                                   ▼
   - Merkle Path Inclusion Proof                 Computes Root R
   - Topic Nullifier Derivation
   - Binding to Report Hash H_m
   - PII & Zero-Width Sanitizer
          │
          ├──── Anonymous Report + ZK Proof ────► 1. Verify Proof π against Root R
          │                                      2. Check Nullifier in Registry
          │                                      3. Strip all IP & User-Agent
          │                                      4. Store Report with ZERO linkage
          │                                              │
          │                                              ▼
                                                 Inbox: Verified Reports
                                                 Inspector: ZK Proof Artifacts
                                                 DB Dump: 0 Identifiers Leaked
```

---

## 🚀 Quickstart Guide

### 1. Installation
```bash
# Clone the repository
git clone https://github.com/your-org/incognito.git
cd bnb26

# Install dependencies
npm install
```

### 2. Run the Application
```bash
# Start server
npm start
```
Open **`http://localhost:3000`** in your browser to access:
- **Member Portal**: Enroll identity, test client-side ZK proof generation, author sanitized reports.
- **Admin Dashboard**: Inspect incoming verified reports, view cryptographic receipts, run the database privacy dump auditor, or revoke credentials.
- **Security Playground**: Run the full suite of live adversarial attack simulations and observe defense outcomes in real time.

### 3. Run Automated Tests
```bash
# Execute master test suite (Crypto, ZKP, and Security Evaluator)
npm test

# Run security evaluation suite directly
npm run test:security
```

---

## 📁 Repository Structure

```
bnb26/
├── README.md                           # Master Project Overview
├── package.json                        # Dependencies, scripts, and build targets
├── tsconfig.json                       # TypeScript compiler configuration
├── circuits/                           # Circom 2.0 ZK Circuit Definitions
│   ├── membership.circom              # Anonymous Membership Proof circuit
│   └── rln_rate_limit.circom          # Rate-Limiting Nullifier circuit
├── src/
│   ├── crypto/                        # Cryptographic primitives & ZK engine
│   │   ├── poseidon.ts                # Poseidon hash over BN254 scalar field
│   │   ├── merkleTree.ts              # Incremental / Sparse Merkle Tree
│   │   ├── identity.ts                # Member identity & commitment generation
│   │   ├── zkEngine.ts                # Zero-Knowledge proof generation & verification
│   │   ├── nullifier.ts               # Topic-scoped nullifiers & registry
│   │   ├── rln.ts                     # Rate-Limiting Nullifiers & Shamir slashing
│   │   └── sanitization.ts            # PII masking, metadata & zero-width cleaner
│   ├── server/                        # Backend API & Server
│   │   ├── app.ts                     # Express server & REST API
│   │   ├── storage.ts                 # Anonymous storage engine
│   │   ├── membershipService.ts       # Member enrollment & root tracking
│   │   ├── reportService.ts           # ZK verification & report ingestion
│   │   ├── moderationService.ts       # Automated content moderation
│   │   ├── metadataProtector.ts       # Zero IP middleware, header stripper, jitter
│   │   └── revocationService.ts       # Dynamic revocation & Merkle tree updates
│   ├── security/                      # Adversarial Security Evaluation
│   │   └── evaluator.ts               # 7-vector attack suite & collusion analysis
│   └── client/                        # Web Frontend
│       └── public/
│           ├── index.html             # Multi-portal single page application (Material 3 Expressive)
│           ├── styles.css             # Material 3 Expressive design system (sc.is-a.dev)
│           └── app.js                 # Client-side ZK proof generator & UI controller
├── tests/                             # Automated test suite
│   ├── crypto.test.ts                 # Cryptographic primitives & tree tests
│   ├── zkp.test.ts                    # Zero-Knowledge & RLN tests
│   ├── securityEvaluation.test.ts     # Attack simulations test assertions
│   └── runAllTests.ts                 # Master test runner
└── docs/                              # Comprehensive documentation
    ├── ARCHITECTURE.md                # System Architecture & Cryptographic Specification
    ├── SECURITY_EVALUATION.md         # Threat Model, Guarantees & Attack Surface
    └── USER_GUIDE.md                  # Step-by-Step Evaluator & User Guide
```

---

## 🛡️ Cryptographic Guarantees Achieved

1. **Zero-Knowledge Soundness**: Forged proofs without member credentials are computationally infeasible ($2^{-128}$ error probability).
2. **Computational Unlinkability**: Pre-image resistance and pseudo-randomness of Poseidon ensure zero correlation between reports across different topics.
3. **Double-Submission Prevention**: Topic-scoped nullifier collisions deterministically reject duplicate reports without revealing author identities.
4. **Information-Theoretic Whistleblower Privacy**: Single submissions leak 0 bits of information about the reporter's secret under Shamir's Secret Sharing.
5. **Abuse Deterrence via RLN**: Spammers attempting to flood a channel have their identity secrets mathematically extracted and automatically revoked.

---

## 📜 License
MIT License &copy; 2026 Incognito Team.
