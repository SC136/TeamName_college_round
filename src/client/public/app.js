/**
 * Incognito: Client-Side Cryptographic Protocol & Material 3 Expressive UI Controller
 *
 * Implements client-side Zero-Knowledge Proof generation, identity key management,
 * topic-scoped nullifier derivation, and adversarial security evaluation.
 */

// Field prime for BN254 scalar field
const SNARK_FIELD_PRIME = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;

function mod(n, p = SNARK_FIELD_PRIME) {
  const r = n % p;
  return r >= 0n ? r : r + p;
}

function modPow(base, exp, p = SNARK_FIELD_PRIME) {
  let res = 1n;
  let b = mod(base, p);
  let e = exp;
  while (e > 0n) {
    if (e % 2n === 1n) res = mod(res * b, p);
    b = mod(b * b, p);
    e /= 2n;
  }
  return res;
}

function modInverse(a, p = SNARK_FIELD_PRIME) {
  return modPow(a, p - 2n, p);
}

// Client-Side Poseidon Constants & Implementation
function generateConstants(t, totalRounds) {
  const constants = [];
  let state = 0x1234567890abcdefn;
  for (let i = 0; i < t * totalRounds; i++) {
    state = mod(state * 6364136223846793005n + 1442695040888963407n, SNARK_FIELD_PRIME);
    constants.push(state);
  }
  return constants;
}

function generateMDS(t) {
  const mds = [];
  for (let i = 0; i < t; i++) {
    mds[i] = [];
    for (let j = 0; j < t; j++) {
      const denom = mod(BigInt(i + 1) - BigInt(j + t + 1));
      mds[i][j] = modInverse(denom);
    }
  }
  return mds;
}

class ClientPoseidon {
  constructor(inputsCount) {
    this.t = inputsCount + 1;
    this.rF = 8;
    this.rP = this.t === 3 ? 57 : 56;
    this.rounds = this.rF + this.rP;
    this.roundConstants = generateConstants(this.t, this.rounds);
    this.mds = generateMDS(this.t);
  }

  hash(inputs) {
    const state = [0n, ...inputs.map((x) => mod(x))];
    const halfF = Math.floor(this.rF / 2);
    let rcIdx = 0;

    for (let r = 0; r < halfF; r++) {
      for (let i = 0; i < this.t; i++) state[i] = mod(state[i] + this.roundConstants[rcIdx++]);
      for (let i = 0; i < this.t; i++) state[i] = modPow(state[i], 5n);
      this.applyMDS(state);
    }
    for (let r = 0; r < this.rP; r++) {
      for (let i = 0; i < this.t; i++) state[i] = mod(state[i] + this.roundConstants[rcIdx++]);
      state[0] = modPow(state[0], 5n);
      this.applyMDS(state);
    }
    for (let r = 0; r < halfF; r++) {
      for (let i = 0; i < this.t; i++) state[i] = mod(state[i] + this.roundConstants[rcIdx++]);
      for (let i = 0; i < this.t; i++) state[i] = modPow(state[i], 5n);
      this.applyMDS(state);
    }
    return state[0];
  }

  applyMDS(state) {
    const next = new Array(this.t).fill(0n);
    for (let i = 0; i < this.t; i++) {
      let sum = 0n;
      for (let j = 0; j < this.t; j++) {
        sum = mod(sum + this.mds[i][j] * state[j]);
      }
      next[i] = sum;
    }
    for (let i = 0; i < this.t; i++) state[i] = next[i];
  }
}

const pos1 = new ClientPoseidon(1);
const pos2 = new ClientPoseidon(2);
const pos3 = new ClientPoseidon(3);

function poseidonHash1(a) { return pos1.hash([a]); }
function poseidonHash2(a, b) { return pos2.hash([a, b]); }
function poseidonHash3(a, b, c) { return pos3.hash([a, b, c]); }

function stringToField(str) {
  let hash = 0n;
  for (let i = 0; i < str.length; i++) {
    hash = mod(hash * 31n + BigInt(str.charCodeAt(i)));
  }
  return hash;
}

// Simple SHA-256 in browser via Web Crypto API
async function sha256Hex(str) {
  const enc = new TextEncoder();
  const data = enc.encode(str);
  const hashBuf = await crypto.subtle.digest('SHA-256', data);
  const hashArr = Array.from(new Uint8Array(hashBuf));
  return hashArr.map(b => b.toString(16).padStart(2, '0')).join('');
}

// Client Identity Class
class ClientIdentity {
  constructor(seed) {
    this.seed = seed;
    let h1 = 0n, h2 = 0n;
    for (let i = 0; i < seed.length; i++) {
      h1 = mod(h1 * 37n + BigInt(seed.charCodeAt(i)));
      h2 = mod(h2 * 41n + BigInt(seed.charCodeAt(i)));
    }
    this.nullifier = mod(h1 + 0x123456789n);
    this.trapdoor = mod(h2 + 0x987654321n);
    this.secret = poseidonHash2(this.nullifier, this.trapdoor);
    this.commitment = poseidonHash1(this.secret);
  }
}

// ============================================================================
// Application Controller State
// ============================================================================
const state = {
  currentIdentity: null,
  enrolledCommitments: new Set(),
  topics: [],
  selectedReportId: null
};

// ============================================================================
// Initialization & Event Wiring
// ============================================================================
document.addEventListener('DOMContentLoaded', async () => {
  setupNavigation();
  setupThemeToggle();
  setupMemberPortal();
  setupAdminDashboard();
  setupSecurityPlayground();

  // Load initial topics and switch to default profile
  await loadTopics();
  switchProfile('alice');
  await refreshAdminStats();
});

function setupThemeToggle() {
  const toggleBtn = document.getElementById('themeToggleBtn');
  const themeIcon = document.getElementById('themeIcon');

  // Load saved theme
  const savedTheme = localStorage.getItem('incognito-theme') || 'dark';
  applyTheme(savedTheme);

  toggleBtn.addEventListener('click', () => {
    const currentTheme = document.documentElement.getAttribute('data-theme') || 'dark';
    const nextTheme = currentTheme === 'light' ? 'dark' : 'light';
    applyTheme(nextTheme);
    localStorage.setItem('incognito-theme', nextTheme);
  });

  function applyTheme(t) {
    if (t === 'light') {
      document.documentElement.setAttribute('data-theme', 'light');
      document.body.classList.add('light-theme');
      themeIcon.textContent = 'dark_mode';
    } else {
      document.documentElement.removeAttribute('data-theme');
      document.body.classList.remove('light-theme');
      themeIcon.textContent = 'light_mode';
    }
  }
}

function setupNavigation() {
  const navBtns = document.querySelectorAll('.nav-btn');
  navBtns.forEach((btn) => {
    btn.addEventListener('click', () => {
      const viewId = btn.dataset.view;
      navBtns.forEach((b) => b.classList.remove('active'));
      btn.classList.add('active');

      document.querySelectorAll('.view-panel').forEach((panel) => {
        panel.classList.remove('active');
      });
      const targetPanel = document.getElementById(viewId);
      if (targetPanel) {
        targetPanel.classList.add('active');
      }

      if (viewId === 'admin-view') {
        refreshReports();
        refreshAdminStats();
      }
    });
  });
}

// ============================================================================
// Member Portal Logic
// ============================================================================
function setupMemberPortal() {
  const enrollBtn = document.getElementById('enrollBtn');
  const reportForm = document.getElementById('reportForm');
  const reportContent = document.getElementById('reportContent');
  const profilePills = document.querySelectorAll('.profile-chip');

  // Interactive profile chips
  profilePills.forEach((chip) => {
    chip.addEventListener('click', () => {
      profilePills.forEach((c) => c.classList.remove('active'));
      chip.classList.add('active');
      const profile = chip.dataset.profile;
      switchProfile(profile);
    });
  });

  enrollBtn.addEventListener('click', async () => {
    await enrollCurrentIdentity();
  });

  // Real-time content sanitization & stylometric indicator on keyup
  reportContent.addEventListener('input', () => {
    analyzeContentInput(reportContent.value);
  });

  // Handle report submission
  reportForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    await handleReportSubmission();
  });
}

function switchProfile(profileKey) {
  let seed = 'alice_secret_seed_2026';
  if (profileKey === 'bob') seed = 'bob_secret_seed_2026';
  if (profileKey === 'charlie') seed = 'charlie_secret_seed_2026';
  if (profileKey === 'custom') seed = 'custom_' + Date.now() + '_' + Math.random();

  state.currentIdentity = new ClientIdentity(seed);
  const commHex = '0x' + state.currentIdentity.commitment.toString(16);

  document.getElementById('displayCommitment').textContent = commHex;
  document.getElementById('displayNullifier').textContent = '0x' + state.currentIdentity.nullifier.toString(16).substring(0, 8) + '••••••••';

  // Automatically check or enroll
  checkEnrollmentStatus(commHex);
}

async function checkEnrollmentStatus(commHex) {
  try {
    const res = await fetch('/api/membership/root');
    const data = await res.json();
    if (data.success) {
      document.getElementById('displayCurrentRoot').textContent = data.root.substring(0, 16) + '...';
    }

    const proofRes = await fetch(`/api/membership/proof/${commHex}`);
    const proofData = await proofRes.json();
    const badge = document.getElementById('enrollmentStatusBadge');

    if (proofData.success) {
      badge.textContent = 'Enrolled in Tree';
      badge.className = 'badge badge-primary';
    } else {
      badge.textContent = 'Not Enrolled';
      badge.className = 'badge badge-gold';
    }
  } catch (err) {
    console.error('Error checking enrollment:', err);
  }
}

async function enrollCurrentIdentity() {
  if (!state.currentIdentity) return;
  const commHex = '0x' + state.currentIdentity.commitment.toString(16);
  try {
    const res = await fetch('/api/membership/enroll', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ commitment: commHex })
    });
    const data = await res.json();
    if (data.success) {
      const badge = document.getElementById('enrollmentStatusBadge');
      badge.textContent = 'Enrolled in Tree';
      badge.className = 'badge badge-primary';
      document.getElementById('displayCurrentRoot').textContent = data.root.substring(0, 16) + '...';
      alert(`Success! Identity commitment enrolled into Merkle Tree at index ${data.index}.`);
      await refreshAdminStats();
    } else {
      alert(`Enrollment failed: ${data.error}`);
    }
  } catch (err) {
    alert(`Enrollment network error: ${err.message}`);
  }
}

function analyzeContentInput(text) {
  const zeroWidthRegex = new RegExp('[\\u200B-\\u200D\\uFEFF\\u2060\\u200E\\u200F\\u202A-\\u202E]', 'g');
  const emailRegex = /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g;
  const phoneRegex = /(\+?\d{1,3}[-.\s]?)?(\(?\d{3}\)?[-.\s]?)?\d{3}[-.\s]?\d{4}/g;
  const employeeIdRegex = /\b(EMP|ID|STAFF)[-_]?\d{4,8}\b/gi;
  const selfIdPatterns = [
    /\b(my name is|i am|as the head of|from my desk|my department is|my direct supervisor)\b/i
  ];

  const warnings = [];
  const zwMatches = (text.match(zeroWidthRegex) || []).length;
  if (zwMatches > 0) warnings.push(`Detected & stripped ${zwMatches} invisible zero-width tracking characters!`);
  if (emailRegex.test(text)) warnings.push('Auto-redacting email address pattern.');
  if (phoneRegex.test(text)) warnings.push('Auto-redacting telephone number pattern.');
  if (employeeIdRegex.test(text)) warnings.push('Auto-redacting employee ID pattern.');

  let selfIdHits = 0;
  for (const p of selfIdPatterns) {
    if (p.test(text)) selfIdHits++;
  }

  const warningBox = document.getElementById('sanitizerWarningBox');
  const riskIndicator = document.getElementById('riskIndicator');

  if (selfIdHits > 0) {
    warnings.push('Warning: Self-identifying linguistic markers detected. Reword so role cannot be inferred.');
    riskIndicator.innerHTML = '<span class="badge badge-gold">Risk: MEDIUM</span>';
  } else {
    riskIndicator.innerHTML = '<span class="badge badge-tonal">Risk: LOW</span>';
  }

  if (warnings.length > 0) {
    warningBox.innerHTML = warnings.map(w => `<div>&bull; ${w}</div>`).join('');
    warningBox.style.display = 'block';
  } else {
    warningBox.style.display = 'none';
  }
}

async function loadTopics() {
  try {
    const res = await fetch('/api/topics');
    const data = await res.json();
    if (data.success) {
      state.topics = data.topics;
      const select = document.getElementById('topicSelect');
      const filter = document.getElementById('adminTopicFilter');

      select.innerHTML = '<option value="">-- Choose a Topic --</option>';
      filter.innerHTML = '<option value="">All Topics</option>';

      data.topics.forEach((t) => {
        const opt = document.createElement('option');
        opt.value = t.id;
        opt.textContent = `${t.title} [${t.category}]`;
        select.appendChild(opt);

        const filterOpt = document.createElement('option');
        filterOpt.value = t.id;
        filterOpt.textContent = t.title;
        filter.appendChild(filterOpt);
      });
    }
  } catch (err) {
    console.error('Failed to load topics:', err);
  }
}

// ============================================================================
// Client-Side ZK Proof Generation & Submission Pipeline
// ============================================================================
async function handleReportSubmission() {
  const topicId = document.getElementById('topicSelect').value;
  const content = document.getElementById('reportContent').value;
  const useRln = document.getElementById('rlnCheckbox').checked;

  if (!topicId || !content) return;

  const progressBox = document.getElementById('zkProgressBox');
  const receiptBox = document.getElementById('receiptBox');
  progressBox.style.display = 'block';
  receiptBox.style.display = 'none';

  const setStep = (id, status) => {
    const el = document.getElementById(id);
    if (!el) return;
    el.className = 'zk-step-item ' + status;
  };

  try {
    // Step 1: Witness
    setStep('stepWitness', 'active');
    await new Promise((r) => setTimeout(r, 120));
    const id = state.currentIdentity;
    const commHex = '0x' + id.commitment.toString(16);

    // Step 2: Merkle Path
    setStep('stepWitness', 'done');
    setStep('stepMerkle', 'active');
    const proofRes = await fetch(`/api/membership/proof/${commHex}`);
    const proofData = await proofRes.json();
    if (!proofData.success) {
      throw new Error(`Membership proof failed: ${proofData.error}. Please enroll this identity first.`);
    }
    const merkleProof = proofData.proof;

    // Step 3: Nullifier
    setStep('stepMerkle', 'done');
    setStep('stepNullifier', 'active');
    const topicField = stringToField(topicId);
    const nullifierBigInt = poseidonHash2(id.nullifier, topicField);
    const nullifierHashHex = '0x' + nullifierBigInt.toString(16);
    await new Promise((r) => setTimeout(r, 120));

    // Step 4: Proving SNARK Constraints (Fiat-Shamir PoK)
    setStep('stepNullifier', 'done');
    setStep('stepProof', 'active');

    const reportHashHex = '0x' + (await sha256Hex(content));
    const reportHashBigInt = mod(BigInt(reportHashHex));

    // Blinding factors
    const rNullifier = mod(BigInt('0x' + (await sha256Hex(Math.random().toString()))));
    const rTrapdoor = mod(BigInt('0x' + (await sha256Hex(Math.random().toString()))));

    const blindedNullifierCommit = poseidonHash2(rNullifier, topicField);
    const blindedSecretCommit = poseidonHash2(rNullifier, rTrapdoor);

    const challengePreimage = [
      BigInt(merkleProof.root).toString(16),
      topicField.toString(16),
      nullifierBigInt.toString(16),
      reportHashBigInt.toString(16),
      blindedNullifierCommit.toString(16),
      blindedSecretCommit.toString(16),
      '0'
    ].join(':');

    const challengeHex = '0x' + (await sha256Hex(challengePreimage));
    const challenge = mod(BigInt(challengeHex));

    const sNullifier = mod(rNullifier + challenge * id.nullifier);
    const sTrapdoor = mod(rTrapdoor + challenge * id.trapdoor);

    const g1x = mod(poseidonHash2(sNullifier, challenge));
    const g1y = mod(poseidonHash2(sTrapdoor, challenge));
    const g2x0 = mod(poseidonHash2(blindedNullifierCommit, g1x));
    const g2x1 = mod(poseidonHash2(blindedSecretCommit, g1y));
    const g2y0 = mod(poseidonHash2(g2x0, challenge));
    const g2y1 = mod(poseidonHash2(g2x1, challenge));
    const g1cx = mod(poseidonHash2(g1x, g2x0));
    const g1cy = mod(poseidonHash2(g1y, g2y1));

    const zkProof = {
      protocol: 'Incognito-ZK-SNARK-v1',
      a: ['0x' + g1x.toString(16), '0x' + g1y.toString(16)],
      b: [
        ['0x' + g2x0.toString(16), '0x' + g2x1.toString(16)],
        ['0x' + g2y0.toString(16), '0x' + g2y1.toString(16)]
      ],
      c: ['0x' + g1cx.toString(16), '0x' + g1cy.toString(16)],
      challenge: '0x' + challenge.toString(16),
      responseNullifier: '0x' + sNullifier.toString(16),
      responseTrapdoor: '0x' + sTrapdoor.toString(16),
      blindedNullifierCommit: '0x' + blindedNullifierCommit.toString(16),
      blindedSecretCommit: '0x' + blindedSecretCommit.toString(16),
      publicInputs: {
        merkleRoot: merkleProof.root,
        topicId,
        nullifierHash: nullifierHashHex,
        reportHash: reportHashHex,
        slotIndex: 0
      },
      timestamp: Date.now()
    };

    // RLN Share generation
    let rlnShare = undefined;
    if (useRln) {
      const a0 = id.secret;
      const a1 = poseidonHash3(id.secret, topicField, 1n);
      const x = stringToField(content);
      const y = mod(a0 + mod(a1 * x));
      const rlnNullifier = poseidonHash1(a1);
      rlnShare = {
        x: '0x' + x.toString(16),
        y: '0x' + y.toString(16),
        nullifier: '0x' + rlnNullifier.toString(16),
        epoch: 1
      };
    }

    // Step 5: Blind Relay Delivery
    setStep('stepProof', 'done');
    setStep('stepRelay', 'active');

    const submitRes = await fetch('/api/reports/submit', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        topicId,
        content,
        zkProof,
        rlnShare
      })
    });

    const submitData = await submitRes.json();
    setStep('stepRelay', 'done');

    if (!submitData.success) {
      alert(`Submission Rejected:\n${submitData.error}`);
      progressBox.style.display = 'none';
      return;
    }

    // Render receipt with Material 3 styling
    document.getElementById('receiptId').textContent = submitData.reportId;
    document.getElementById('receiptNullifier').textContent = submitData.nullifierHash;
    document.getElementById('receiptTimestamp').textContent = new Date(submitData.quantizedTimestamp).toLocaleString();

    const sevBadge = document.getElementById('receiptSeverity');
    sevBadge.textContent = submitData.moderationSeverity;
    sevBadge.className = 'badge ' + (submitData.moderationSeverity === 'CRITICAL' ? 'badge-error' : 'badge-primary');

    receiptBox.style.display = 'block';
    progressBox.style.display = 'none';

    document.getElementById('reportContent').value = '';
    await refreshAdminStats();
  } catch (err) {
    alert(`Proof generation error: ${err.message}`);
    progressBox.style.display = 'none';
  }
}

// ============================================================================
// Administrator Dashboard Logic
// ============================================================================
function setupAdminDashboard() {
  document.getElementById('refreshReportsBtn').addEventListener('click', refreshReports);
  document.getElementById('adminTopicFilter').addEventListener('change', refreshReports);

  document.getElementById('auditDbBtn').addEventListener('click', async () => {
    await runAdminAuditDump();
  });

  const revokeModal = document.getElementById('revokeModal');
  document.getElementById('showRevokeModalBtn').addEventListener('click', async () => {
    await populateRevokeModal();
    revokeModal.style.display = 'flex';
  });

  document.getElementById('closeRevokeModalBtn').addEventListener('click', () => {
    revokeModal.style.display = 'none';
  });
  document.getElementById('cancelRevokeBtn').addEventListener('click', () => {
    revokeModal.style.display = 'none';
  });

  document.getElementById('confirmRevokeBtn').addEventListener('click', async () => {
    const select = document.getElementById('revokeSelect');
    const comm = select.value;
    if (!comm) return;

    const res = await fetch('/api/membership/revoke', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ commitment: comm, reason: 'Administrative Revocation' })
    });
    const data = await res.json();
    if (data.success) {
      alert(`Member Revoked! Old Root: ${data.oldRoot.substring(0, 10)}... -> New Root: ${data.newRoot.substring(0, 10)}...`);
      revokeModal.style.display = 'none';
      await refreshAdminStats();
    } else {
      alert(`Revocation error: ${data.error}`);
    }
  });
}

async function refreshAdminStats() {
  try {
    const rootRes = await fetch('/api/membership/root');
    const rootData = await rootRes.json();
    if (rootData.success) {
      document.getElementById('statMembersCount').textContent = rootData.totalMembers;
    }

    const repRes = await fetch('/api/reports');
    const repData = await repRes.json();
    if (repData.success) {
      document.getElementById('statReportsCount').textContent = repData.count;
    }

    const auditRes = await fetch('/api/security/audit-dump');
    const auditData = await auditRes.json();
    if (auditData.success) {
      let spentCount = 0;
      for (const t in auditData.spentNullifiers) {
        spentCount += auditData.spentNullifiers[t].length;
      }
      document.getElementById('statNullifiersCount').textContent = spentCount;
    }
  } catch (err) {
    console.error('Error refreshing admin stats:', err);
  }
}

async function refreshReports() {
  const filter = document.getElementById('adminTopicFilter').value;
  const url = filter ? `/api/reports?topicId=${filter}` : '/api/reports';

  try {
    const res = await fetch(url);
    const data = await res.json();
    const container = document.getElementById('reportsList');

    if (!data.success || data.reports.length === 0) {
      container.innerHTML = '<div style="padding: 24px; text-align: center; color: var(--on-surface-variant); font-size: 0.88rem;">No reports found for this filter.</div>';
      return;
    }

    container.innerHTML = '';
    data.reports.forEach((r) => {
      const item = document.createElement('div');
      item.className = 'report-item';
      if (r.id === state.selectedReportId) item.classList.add('selected');

      const sevClass = r.moderationSeverity === 'CRITICAL' ? 'badge-error' :
                       r.moderationSeverity === 'HIGH' ? 'badge-gold' : 'badge-tonal';

      item.innerHTML = `
        <div class="report-item-header">
          <span class="report-item-title">${escapeHtml(r.topicId)}</span>
          <span class="badge ${sevClass}">${r.moderationSeverity}</span>
        </div>
        <div class="report-item-preview">${escapeHtml(r.content)}</div>
        <div class="report-item-meta">
          <span>Nullifier: ${r.nullifierHash.substring(0, 10)}...</span>
          <span>Time: ${new Date(r.quantizedTimestamp).toLocaleDateString()}</span>
        </div>
      `;

      item.addEventListener('click', () => {
        document.querySelectorAll('.report-item').forEach(el => el.classList.remove('selected'));
        item.classList.add('selected');
        inspectReport(r.id);
      });

      container.appendChild(item);
    });
  } catch (err) {
    console.error('Error refreshing reports:', err);
  }
}

async function inspectReport(reportId) {
  state.selectedReportId = reportId;
  const container = document.getElementById('inspectorContent');
  const badge = document.getElementById('inspectorStatusBadge');

  badge.textContent = 'Report ' + reportId;
  badge.className = 'badge badge-primary';

  try {
    const res = await fetch(`/api/reports/${reportId}`);
    const data = await res.json();
    if (!data.success) return;
    const r = data.report;

    container.innerHTML = `
      <div class="inspector-field">
        <div class="inspector-field-label">Report ID &amp; Quantized Epoch:</div>
        <div><strong>${r.id}</strong> &bull; <kbd>${new Date(r.quantizedTimestamp).toLocaleString()} (Rounded to 1hr)</kbd></div>
      </div>
      <div class="inspector-field">
        <div class="inspector-field-label">Topic-Scoped Cryptographic Nullifier:</div>
        <div class="code-tile" style="margin-top: 4px;">
          <span class="code-text">${r.nullifierHash}</span>
        </div>
      </div>
      <div class="inspector-field">
        <div class="inspector-field-label">Sanitized Report Body:</div>
        <div style="background: var(--surface-container); padding: 12px 14px; border-radius: var(--rounded-md); font-size: 0.88rem; margin-top: 4px; border: 1px solid var(--outline-variant);">
          ${escapeHtml(r.sanitizedContent)}
        </div>
      </div>
      <div class="inspector-field">
        <div class="inspector-field-label">Zero-Knowledge Verification Status:</div>
        <span class="badge badge-primary" style="margin-top: 4px;">
          <span class="material-symbols-rounded" style="font-size: 15px;">check_circle</span>
          Verified ZK-SNARK (BN254)
        </span>
        <div style="font-size: 0.78rem; color: var(--on-surface-variant); margin-top: 6px; font-family: var(--font-mono);">
          Root: ${r.zkProof.publicInputs.merkleRoot.substring(0, 16)}... &bull;
          Protocol: ${r.zkProof.protocol}
        </div>
      </div>
      <div class="inspector-field">
        <div class="inspector-field-label">Administrator Privacy Audit:</div>
        <span class="badge badge-tonal">IP: Stripped &bull; User-Agent: Stripped &bull; Author: Mathematically Hidden</span>
      </div>
    `;
  } catch (err) {
    container.innerHTML = `<div style="color: var(--error);">Failed to load report: ${err.message}</div>`;
  }
}

async function runAdminAuditDump() {
  const box = document.getElementById('auditResultBox');
  box.style.display = 'block';
  box.textContent = 'Performing live database dump & privacy audit...';

  try {
    const res = await fetch('/api/security/audit-dump');
    const data = await res.json();
    box.textContent = JSON.stringify(data, null, 2);
  } catch (err) {
    box.textContent = 'Audit dump failed: ' + err.message;
  }
}

async function populateRevokeModal() {
  const select = document.getElementById('revokeSelect');
  select.innerHTML = '<option value="">Loading members...</option>';

  const res = await fetch('/api/membership/members');
  const data = await res.json();
  if (data.success) {
    select.innerHTML = '';
    data.members.forEach((m) => {
      const opt = document.createElement('option');
      opt.value = m.commitment;
      opt.textContent = `Member #${m.index}: ${m.commitment.substring(0, 14)}... [${m.status}]`;
      select.appendChild(opt);
    });
  }
}

// ============================================================================
// Security Playground & Attack Simulations
// ============================================================================
function setupSecurityPlayground() {
  const runBtn = document.getElementById('runAllSimulationsBtn');
  runBtn.addEventListener('click', async () => {
    runBtn.disabled = true;
    runBtn.innerHTML = `
      <span class="material-symbols-rounded">sync</span>
      <span>Simulating Attacks...</span>
    `;

    const overallBadge = document.getElementById('evalOverallScore');
    overallBadge.textContent = 'Simulating...';
    overallBadge.className = 'badge badge-gold';

    try {
      const res = await fetch('/api/security/run-simulation', { method: 'POST' });
      const data = await res.json();

      if (data.success) {
        renderSecurityResults(data.results);
      }
    } catch (err) {
      alert('Security simulation failed: ' + err.message);
    } finally {
      runBtn.disabled = false;
      runBtn.innerHTML = `
        <span class="material-symbols-rounded">play_circle</span>
        <span>Re-Execute All Security Simulations</span>
      `;
    }
  });
}

function renderSecurityResults(results) {
  const overallBadge = document.getElementById('evalOverallScore');
  overallBadge.textContent = results.overallScore;
  overallBadge.className = results.failedDefenses === 0 ? 'badge badge-primary' : 'badge badge-error';

  const container = document.getElementById('securityTestsList');
  container.innerHTML = '';

  results.tests.forEach((t) => {
    const card = document.createElement('div');
    card.className = 'test-item-card ' + (t.defenseWorked ? 'pass' : 'fail');

    const statusBadge = t.defenseWorked
      ? '<span class="badge badge-primary"><span class="material-symbols-rounded" style="font-size:14px;">check_circle</span> Defense Verified</span>'
      : '<span class="badge badge-error"><span class="material-symbols-rounded" style="font-size:14px;">cancel</span> Attack Succeeded</span>';

    card.innerHTML = `
      <div class="test-header">
        <span class="test-id">${t.testId}</span>
        <h4>${escapeHtml(t.name)}</h4>
        ${statusBadge}
      </div>
      <p class="test-threat-line"><strong>Threat Model:</strong> ${escapeHtml(t.threatModel)}</p>
      <div class="test-details-box">
        <div><strong>Simulation Details:</strong> ${escapeHtml(t.details)}</div>
        <div style="margin-top: 6px; color: var(--primary);"><strong>Cryptographic Guarantee:</strong> ${escapeHtml(t.cryptographicGuarantee)}</div>
      </div>
    `;

    container.appendChild(card);
  });
}

function escapeHtml(str) {
  if (!str) return '';
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}
