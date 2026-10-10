/**
 * Incognito Supabase Integration Service
 *
 * Implements persistent data access layer backed by Supabase PostgreSQL:
 * - Persists topics, enrolled members, and Sparse Merkle Tree leaf history
 * - Persists topic-scoped spent nullifiers to prevent replay attacks across server restarts
 * - Persists submitted sanitized reports and investigation statuses
 * - Persists RLN Shamir polynomial shares for rate-limiting enforcement
 *
 * Conforms to Supabase Postgres best practices:
 * - Proper error handling
 * - Lowercase snake_case column mapping
 * - Safe fallback to local cache/memory when Supabase env variables are not provided
 */

import { createClient, SupabaseClient } from '@supabase/supabase-js';

export interface DbTopic {
  id: string;
  title: string;
  category: 'MANAGEMENT' | 'HARASSMENT' | 'SAFETY' | 'ACADEMIC' | 'GENERAL';
  description: string;
  allowed_quota_per_member: number;
  active: boolean;
  created_at?: string;
}

export interface DbMember {
  commitment: string;
  member_index: number;
  status: 'ACTIVE' | 'REVOKED';
  enrolled_at?: string;
  revoked_at?: string;
}

export interface DbReport {
  id: string;
  topic_id: string;
  sanitized_content: string;
  nullifier_hash: string;
  quantized_timestamp: number;
  moderation_category: string;
  moderation_severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  pii_redacted: boolean;
  status: 'PENDING' | 'INVESTIGATING' | 'RESOLVED' | 'DISMISSED';
  zk_proof: any;
  attachments?: any;
  created_at?: string;
}

export interface DbRlnShare {
  id?: string;
  nullifier: string;
  x: string;
  y: string;
  epoch: number;
  created_at?: string;
}

export class SupabaseService {
  private client: SupabaseClient | null = null;
  private isConnected: boolean = false;

  constructor() {
    const supabaseUrl = process.env.SUPABASE_URL;
    const supabaseKey =
      process.env.SUPABASE_SERVICE_ROLE_KEY ||
      process.env.SUPABASE_KEY ||
      process.env.SUPABASE_ANON_KEY;

    if (supabaseUrl && supabaseKey) {
      try {
        this.client = createClient(supabaseUrl, supabaseKey, {
          auth: {
            persistSession: false,
            autoRefreshToken: false
          }
        });
        this.isConnected = true;
        console.log('[SupabaseService] Connected to Supabase PostgreSQL at:', supabaseUrl);
      } catch (err: any) {
        console.warn('[SupabaseService] Failed to initialize Supabase client:', err.message);
        this.client = null;
        this.isConnected = false;
      }
    } else {
      console.log('[SupabaseService] No SUPABASE_URL / SUPABASE_KEY provided. Operating with in-memory persistence layer.');
    }
  }

  public isAvailable(): boolean {
    return this.isConnected && this.client !== null;
  }

  // --- Topics ---
  public async getTopics(): Promise<DbTopic[] | null> {
    if (!this.client) return null;
    try {
      const { data, error } = await this.client
        .from('topics')
        .select('*')
        .order('created_at', { ascending: true });

      if (error) {
        console.error('[SupabaseService] getTopics error:', error.message);
        return null;
      }
      return data as DbTopic[];
    } catch (err: any) {
      console.error('[SupabaseService] getTopics exception:', err.message);
      return null;
    }
  }

  public async upsertTopic(topic: DbTopic): Promise<boolean> {
    if (!this.client) return false;
    try {
      const { error } = await this.client.from('topics').upsert({
        id: topic.id,
        title: topic.title,
        category: topic.category,
        description: topic.description,
        allowed_quota_per_member: topic.allowed_quota_per_member,
        active: topic.active
      });

      if (error) {
        console.error('[SupabaseService] upsertTopic error:', error.message);
        return false;
      }
      return true;
    } catch (err: any) {
      console.error('[SupabaseService] upsertTopic exception:', err.message);
      return false;
    }
  }

  // --- Members ---
  public async getMembers(): Promise<DbMember[] | null> {
    if (!this.client) return null;
    try {
      const { data, error } = await this.client
        .from('members')
        .select('*')
        .order('member_index', { ascending: true });

      if (error) {
        console.error('[SupabaseService] getMembers error:', error.message);
        return null;
      }
      return data as DbMember[];
    } catch (err: any) {
      console.error('[SupabaseService] getMembers exception:', err.message);
      return null;
    }
  }

  public async getMemberByCommitment(commitment: string): Promise<DbMember | null> {
    if (!this.client) return null;
    try {
      const { data, error } = await this.client
        .from('members')
        .select('*')
        .eq('commitment', commitment.toLowerCase())
        .maybeSingle();

      if (error || !data) return null;
      return data as DbMember;
    } catch {
      return null;
    }
  }

  public async enrollMember(commitment: string, memberIndex: number): Promise<boolean> {
    if (!this.client) return false;
    try {
      const { error } = await this.client.from('members').upsert({
        commitment: commitment.toLowerCase(),
        member_index: memberIndex,
        status: 'ACTIVE',
        enrolled_at: new Date().toISOString()
      });

      if (error) {
        console.error('[SupabaseService] enrollMember error:', error.message);
        return false;
      }
      return true;
    } catch (err: any) {
      console.error('[SupabaseService] enrollMember exception:', err.message);
      return false;
    }
  }

  public async updateMemberStatus(commitment: string, status: 'ACTIVE' | 'REVOKED'): Promise<boolean> {
    if (!this.client) return false;
    try {
      const updateData: any = { status };
      if (status === 'REVOKED') {
        updateData.revoked_at = new Date().toISOString();
      }

      const { error } = await this.client
        .from('members')
        .update(updateData)
        .eq('commitment', commitment.toLowerCase());

      return !error;
    } catch {
      return false;
    }
  }

  // --- Merkle Leaves ---
  public async getMerkleLeaves(): Promise<{ leaf_index: number; leaf_hash: string }[] | null> {
    if (!this.client) return null;
    try {
      const { data, error } = await this.client
        .from('merkle_leaves')
        .select('leaf_index, leaf_hash')
        .order('leaf_index', { ascending: true });

      if (error) return null;
      return data;
    } catch {
      return null;
    }
  }

  public async recordMerkleLeaf(index: number, leafHash: string): Promise<boolean> {
    if (!this.client) return false;
    try {
      const { error } = await this.client.from('merkle_leaves').upsert({
        leaf_index: index,
        leaf_hash: leafHash
      });
      return !error;
    } catch {
      return false;
    }
  }

  // --- Spent Nullifiers ---
  public async isNullifierSpent(topicId: string, nullifierHash: string): Promise<boolean> {
    if (!this.client) return false;
    try {
      const { data, error } = await this.client
        .from('spent_nullifiers')
        .select('id')
        .eq('topic_id', topicId)
        .eq('nullifier_hash', nullifierHash.toLowerCase())
        .maybeSingle();

      return !error && data !== null;
    } catch {
      return false;
    }
  }

  public async recordSpentNullifier(topicId: string, nullifierHash: string): Promise<boolean> {
    if (!this.client) return false;
    try {
      const { error } = await this.client.from('spent_nullifiers').insert({
        topic_id: topicId,
        nullifier_hash: nullifierHash.toLowerCase()
      });
      return !error;
    } catch {
      return false;
    }
  }

  public async getAllSpentNullifiers(): Promise<Record<string, string[]>> {
    if (!this.client) return {};
    try {
      const { data, error } = await this.client.from('spent_nullifiers').select('topic_id, nullifier_hash');
      if (error || !data) return {};

      const map: Record<string, string[]> = {};
      for (const row of data) {
        if (!map[row.topic_id]) map[row.topic_id] = [];
        map[row.topic_id].push(row.nullifier_hash);
      }
      return map;
    } catch {
      return {};
    }
  }

  // --- Reports ---
  public async getReports(topicId?: string): Promise<DbReport[] | null> {
    if (!this.client) return null;
    try {
      let query = this.client.from('reports').select('*').order('created_at', { ascending: false });
      if (topicId) {
        query = query.eq('topic_id', topicId);
      }
      const { data, error } = await query;
      if (error) return null;
      return data as DbReport[];
    } catch {
      return null;
    }
  }

  public async getReportById(id: string): Promise<DbReport | null> {
    if (!this.client) return null;
    try {
      const { data, error } = await this.client
        .from('reports')
        .select('*')
        .eq('id', id)
        .maybeSingle();

      if (error || !data) return null;
      return data as DbReport;
    } catch {
      return null;
    }
  }

  public async insertReport(report: DbReport): Promise<boolean> {
    if (!this.client) return false;
    try {
      const { error } = await this.client.from('reports').insert({
        id: report.id,
        topic_id: report.topic_id,
        sanitized_content: report.sanitized_content,
        nullifier_hash: report.nullifier_hash.toLowerCase(),
        quantized_timestamp: report.quantized_timestamp,
        moderation_category: report.moderation_category,
        moderation_severity: report.moderation_severity,
        pii_redacted: report.pii_redacted,
        status: report.status || 'PENDING',
        zk_proof: report.zk_proof,
        attachments: report.attachments || []
      });

      if (error) {
        console.error('[SupabaseService] insertReport error:', error.message);
        return false;
      }
      return true;
    } catch (err: any) {
      console.error('[SupabaseService] insertReport exception:', err.message);
      return false;
    }
  }

  public async updateReportStatus(id: string, status: DbReport['status']): Promise<boolean> {
    if (!this.client) return false;
    try {
      const { error } = await this.client.from('reports').update({ status }).eq('id', id);
      return !error;
    } catch {
      return false;
    }
  }

  // --- RLN Shares ---
  public async getRlnShares(nullifier: string): Promise<DbRlnShare[]> {
    if (!this.client) return [];
    try {
      const { data, error } = await this.client
        .from('rln_shares')
        .select('*')
        .eq('nullifier', nullifier.toLowerCase());

      if (error || !data) return [];
      return data as DbRlnShare[];
    } catch {
      return [];
    }
  }

  public async insertRlnShare(share: { nullifier: string; x: string; y: string; epoch: number }): Promise<boolean> {
    if (!this.client) return false;
    try {
      const { error } = await this.client.from('rln_shares').insert({
        nullifier: share.nullifier.toLowerCase(),
        x: share.x,
        y: share.y,
        epoch: share.epoch
      });
      return !error;
    } catch {
      return false;
    }
  }
}
