-- ============================================================================
-- Incognito Privacy-Preserving Reporting System: Database Schema
--
-- Supabase / PostgreSQL Schema definition following postgres-best-practices:
-- 1. All lowercase snake_case identifiers
-- 2. Explicit primary keys (UUID / natural keys) on all tables
-- 3. Proper data types (timestamptz, jsonb, text with constraints)
-- 4. Foreign key indexes to avoid full table scans
-- 5. Row Level Security (RLS) enabled on all tables
-- ============================================================================

-- 1. Topics Table
create table if not exists topics (
  id text primary key,
  title text not null,
  category text not null check (category in ('MANAGEMENT', 'HARASSMENT', 'SAFETY', 'ACADEMIC', 'GENERAL')),
  description text not null,
  allowed_quota_per_member integer not null default 1 check (allowed_quota_per_member > 0),
  active boolean not null default true,
  created_at timestamptz not null default now()
);

-- 2. Enrolled Members Table
-- Stores member public commitments in the Sparse Merkle Tree
-- Note: Zero secrets or identities stored. Commitments are Poseidon hashes.
create table if not exists members (
  commitment text primary key,
  member_index bigint not null unique check (member_index >= 0),
  status text not null default 'ACTIVE' check (status in ('ACTIVE', 'REVOKED')),
  enrolled_at timestamptz not null default now(),
  revoked_at timestamptz
);

create index if not exists idx_members_member_index on members(member_index);
create index if not exists idx_members_status on members(status);

-- 3. Sparse Merkle Tree Leaves Table
-- Persists Merkle Tree leaf insertion order so roots and paths are reconstructed across restarts
create table if not exists merkle_leaves (
  leaf_index bigint primary key,
  leaf_hash text not null,
  created_at timestamptz not null default now()
);

-- 4. Topic-Scoped Spent Nullifiers Table
-- Prevents double-submission and ballot stuffing per topic
create table if not exists spent_nullifiers (
  id uuid primary key default gen_random_uuid(),
  topic_id text not null references topics(id) on delete cascade,
  nullifier_hash text not null,
  created_at timestamptz not null default now(),
  constraint uq_spent_nullifiers_topic_hash unique (topic_id, nullifier_hash)
);

create index if not exists idx_spent_nullifiers_topic_hash on spent_nullifiers(topic_id, nullifier_hash);

-- 5. Anonymous Reports Table
-- Persists sanitized reports accompanied only by ZK proof public signals and nullifiers
create table if not exists reports (
  id text primary key,
  topic_id text not null references topics(id) on delete restrict,
  sanitized_content text not null,
  nullifier_hash text not null,
  quantized_timestamp bigint not null,
  moderation_category text not null default 'GENERAL',
  moderation_severity text not null default 'MEDIUM' check (moderation_severity in ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW')),
  pii_redacted boolean not null default false,
  status text not null default 'PENDING' check (status in ('PENDING', 'INVESTIGATING', 'RESOLVED', 'DISMISSED')),
  zk_proof jsonb not null,
  attachments jsonb,
  created_at timestamptz not null default now()
);

create index if not exists idx_reports_topic_id on reports(topic_id);
create index if not exists idx_reports_nullifier_hash on reports(nullifier_hash);
create index if not exists idx_reports_status on reports(status);
create index if not exists idx_reports_created_at on reports(created_at desc);

-- 6. RLN Shares Table (Rate Limiting Shamir polynomial points)
create table if not exists rln_shares (
  id uuid primary key default gen_random_uuid(),
  nullifier text not null,
  x text not null,
  y text not null,
  epoch bigint not null,
  created_at timestamptz not null default now()
);

create index if not exists idx_rln_shares_nullifier on rln_shares(nullifier);

-- ============================================================================
-- Row Level Security (RLS) Configuration
-- ============================================================================

alter table topics enable row level security;
alter table members enable row level security;
alter table merkle_leaves enable row level security;
alter table spent_nullifiers enable row level security;
alter table reports enable row level security;
alter table rln_shares enable row level security;

-- Topics: Public read access
create policy "Allow all read access to topics"
  on topics for select
  using (true);

-- Members: Public read access for membership root and proofs verification
create policy "Allow all read access to members"
  on members for select
  using (true);

-- Members: Insert permitted for new member commitment enrollments
create policy "Allow insert member commitments"
  on members for insert
  with check (true);

-- Members: Update permitted for revocations/slashing
create policy "Allow update member status"
  on members for update
  using (true);

-- Merkle leaves: Full read and append access
create policy "Allow read merkle leaves"
  on merkle_leaves for select
  using (true);

create policy "Allow insert merkle leaves"
  on merkle_leaves for insert
  with check (true);

-- Spent Nullifiers: Read and Insert access to prevent replay attacks
create policy "Allow read spent nullifiers"
  on spent_nullifiers for select
  using (true);

create policy "Allow insert spent nullifiers"
  on spent_nullifiers for insert
  with check (true);

-- Reports: Read access for reviewers & investigators
create policy "Allow read reports"
  on reports for select
  using (true);

-- Reports: Anonymous insert access for valid submissions
create policy "Allow submit anonymous reports"
  on reports for insert
  with check (true);

-- Reports: Update status for investigation workflows
create policy "Allow update report status"
  on reports for update
  using (true);

-- RLN Shares: Read and write access
create policy "Allow read rln shares"
  on rln_shares for select
  using (true);

create policy "Allow insert rln shares"
  on rln_shares for insert
  with check (true);

-- ============================================================================
-- Default Initial Topics Seed
-- ============================================================================
insert into topics (id, title, category, description, allowed_quota_per_member, active)
values
  ('mgmt-eval-q4', 'Executive & Management Leadership Feedback', 'MANAGEMENT', 'Anonymous evaluation of executive leadership, managerial conduct, and institutional decisions.', 1, true),
  ('workplace-harassment', 'Workplace & Academic Harassment Reporting', 'HARASSMENT', 'Confidential channel for reporting discrimination, harassment, bullying, or hostile environment.', 2, true),
  ('safety-compliance', 'Workplace Safety & Lab Compliance Violations', 'SAFETY', 'Report OSHA, physical safety, biological hazard, or security protocol violations.', 3, true),
  ('academic-grading-integrity', 'Grading Malpractice & Academic Integrity', 'ACADEMIC', 'Report instructor bias, unfair grading practices, or academic integrity violations.', 1, true)
on conflict (id) do nothing;
