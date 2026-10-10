# Incognito: System Architecture & Cryptographic Specification

## 1. Executive Overview

**Incognito** is a cryptographically guaranteed privacy-preserving reporting system designed to solve the retaliation dilemma in organizations, universities, and institutions. It allows verified members to submit anonymous whistleblower reports without revealing their identity to anyone—**including the system administrators**.

At its core, Incognito leverages **Zero-Knowledge Proofs (ZKPs)** over the BN254 scalar field, **Sparse Merkle Trees** for anonymous membership verification, **Topic-Scoped Cryptographic Nullifiers** for cross-topic unlinkability and double-submission prevention, and **Rate-Limiting Nullifiers (RLN)** using Shamir's Secret Sharing for mathematical spam and abuse slashing.

---

## 2. Cryptographic Primitives & Parameters

| Component | Primitive / Construction | Specification / Field |
| :--- | :--- | :--- |
| **Elliptic Curve / Field** | BN254 (alt_bn128) Scalar Field $\mathbb{F}_r$ | $r = 21888242871839275222246405745257275088548364400416034343698204186575808495617$ |
| **Algebraic Hash** | Poseidon Hash | SNARK-friendly, $t \in \{2, 3, 4\}$, $R_F=8$, $R_P=57$, S-box: $x^5 \pmod r$ |
| **Membership Accumulator** | Sparse Merkle Tree | Depth = 16 (Capacity: $2^{16} = 65,536$ members), Poseidon 2-to-1 compression |
| **ZK Proof Protocol** | Circom 2.0 / Groth16 / Fiat-Shamir ZK-PoK | Non-interactive zero-knowledge proof of knowledge |
| **Nullifier Mechanism** | Topic-Scoped Deterministic Nullifier | $N_{\text{topic}} = \text{Poseidon}(\text{identityNullifier}, \text{topicId}, \text{slotIndex})$ |
| **Anti-Spam / Rate-Limiting** | Rate-Limiting Nullifier (RLN) | Degree-1 polynomial over $\mathbb{F}_r$, 2-out-of-2 Shamir Secret Sharing |
| **Report Hash Binding** | Cryptographic SHA-256 mod $r$ | Binds proof $\pi$ to exact report content payload $M$ |

---

## 3. Detailed Architecture & Workflows

```
┌────────────────────────────────────────────────────────────────────────┐
│                        MEMBER CLIENT (BROWSER)                         │
│                                                                        │
│  [Identity Secrets]                                                    │
│  identityNullifier  ───┐                                               │
│  identityTrapdoor   ───┴─► secret = Poseidon(nullifier, trapdoor)      │
│                            commitment = Poseidon(secret)               │
│                                  │                                     │
│  [Enrollment]                    ▼ (Only public commitment sent)       │
└──────────────────────────────────┼─────────────────────────────────────┘
                                   │
                                   ▼
┌────────────────────────────────────────────────────────────────────────┐
│                  ORGANIZATION MEMBERSHIP REGISTRY                      │
│                                                                        │
│  Merkle Tree: Leaf[i] = commitment                                     │
│  Computes Root: R = MerkleRoot(Leaves...)                              │
└──────────────────────────────────┬─────────────────────────────────────┘
                                   │
                                   ▼ (Merkle Inclusion Proof Path)
┌────────────────────────────────────────────────────────────────────────┐
│                     ANONYMOUS REPORT SUBMISSION                        │
│                                                                        │
│  Client generates:                                                     │
│  1. Topic Nullifier: N_topic = Poseidon(identityNullifier, topicId)    │
│  2. Report Hash: H_m = SHA256(reportContent)                           │
│  3. ZK Proof π proving:                                                │
│     - Knowledge of (nullifier, trapdoor) matching leaf in tree         │
│     - Leaf inclusion under public root R                               │
│     - Correct derivation of N_topic                                    │
│     - Binding to H_m                                                   │
│  4. RLN Share: (x, y) on Shamir polynomial                             │
│  5. Sanitized Content: PII & zero-width watermarks stripped            │
└──────────────────────────────────┬─────────────────────────────────────┘
                                   │
                                   ▼ [Blind Network Relay with Jitter]
┌────────────────────────────────────────────────────────────────────────┐
│                     INCOGNITO VERIFIER & SERVER                        │
│                                                                        │
│  1. Check: Verify ZK Proof π against Root R and H_m                    │
│  2. Check: N_topic NOT in spentNullifiers[topicId] (Duplicate control) │
│  3. Check: If RLN double-sign detected ──► Extract secret & Slash      │
│  4. Store: Record report with ZERO IP, ZERO User-Agent, ZERO author    │
└────────────────────────────────────────────────────────────────────────┘
```

---

## 4. Key Mechanisms & Mathematical Guarantees

### 4.1 Anonymous Membership Proof
- **Problem**: How to verify a reporter is a valid organization member without knowing which member?
- **Solution**: Members hold secret pairs $(\text{nullifier}, \text{trapdoor})$. The organization Merkle tree contains leaves $C = \text{Poseidon}(\text{Poseidon}(\text{nullifier}, \text{trapdoor}))$.
- In the Zero-Knowledge circuit, the prover demonstrates knowledge of a valid path from an undisclosed leaf $C$ to the published Merkle Root $R$.
- **Privacy Guarantee**: Anonymity set is the entire set of enrolled members ($N$). The probability of an adversary guessing the reporter is $\frac{1}{N}$.

### 4.2 Cross-Topic Unlinkability
- **Problem**: How to prevent reports across different topics from being correlated to the same author?
- **Solution**: Nullifiers are strictly **topic-scoped**:
  $$N_{\text{topic}} = \text{Poseidon}(\text{identityNullifier}, \text{topicField})$$
- For Topic A and Topic B, the nullifiers are $N_A = \text{Poseidon}(\text{sk}, T_A)$ and $N_B = \text{Poseidon}(\text{sk}, T_B)$.
- Under the Random Oracle Model (ROM) and pre-image resistance of Poseidon, $N_A$ and $N_B$ are statistically independent. An adversary cannot link reports across topics.

### 4.3 Privacy-Preserving Duplicate Control
- **Problem**: How to enforce a 1-report quota per member per topic without knowing identities?
- **Solution**: The server maintains a spent nullifier registry for each topic: $\mathcal{S}_{T} = \{ N_1, N_2, \dots \}$.
- Because the nullifier $N_{\text{topic}}$ is deterministic, submitting twice to the same topic produces the exact same nullifier:
  $$N_1 = N_2 \implies N_1 \in \mathcal{S}_{T}$$
- The duplicate submission is rejected without learning who submitted it!

### 4.4 Rate-Limiting Nullifiers (RLN) & Shamir Slashing
- **Problem**: How to prevent malicious insiders from spamming or flooding the system anonymously?
- **Solution**: Rate-Limiting Nullifiers construct a degree-1 polynomial for each topic/epoch:
  $$f(x) = a_0 + a_1 \cdot x \pmod r$$
  where $a_0 = \text{identitySecret}$ and $a_1 = \text{Poseidon}(\text{identitySecret}, \text{topicField}, \text{epoch})$.
- **Normal Usage (1 report)**: The member reveals only one point $(x_1, y_1)$ and nullifier $N = \text{Poseidon}(a_1)$. By Shamir's Secret Sharing, 1 point on a degree-1 polynomial reveals **zero bits** about secret $a_0$.
- **Abuse (Double Submission)**: If the member submits a second message with the same nullifier $N$, two points $(x_1, y_1)$ and $(x_2, y_2)$ are revealed:
  $$a_1 = \frac{y_2 - y_1}{x_2 - x_1} \pmod r$$
  $$a_0 = y_1 - a_1 \cdot x_1 \pmod r$$
- The system recovers $a_0$, computes $C = \text{Poseidon}(a_0)$, identifies the abuser's leaf in the Merkle Tree, and automatically slashes/revokes their credential!

### 4.5 Administrator Privacy
- **Problem**: What if the administrator is corrupt, subpoenaed, or hacked?
- **Solution**:
  1. The administrator database stores **zero IP addresses, zero session tokens, zero timestamps with millisecond precision, and zero user-agent strings**.
  2. The database stores only the sanitized report, the ZK proof $\pi$, the topic nullifier $N$, and the quantized epoch timestamp.
  3. Reversing $N$ to find the member requires finding the pre-image of Poseidon, which requires $2^{254}$ operations (computationally impossible).

### 4.6 Metadata Protection & Traffic Sanitization
- **Zero-Width Watermark Removal**: Strips invisible unicode tracking characters (`​`, `‌`, `‍`, `﻿`) that compromised document editors insert to fingerprint leakers.
- **Automated PII Redaction**: Regex-based redaction of emails, telephone numbers, and employee ID numbers.
- **Timestamp Quantization**: All timestamps are quantized to 1-hour or 24-hour epoch buckets to eliminate physical access log correlation (e.g. CCTV badge swipes).
- **Network Timing Jitter**: Injects randomized 50ms–200ms latency jitter to disrupt packet timing analysis.
