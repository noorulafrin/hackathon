import fs from 'fs';
import path from 'path';
import initSqlJs, { Database, SqlJsStatic } from 'sql.js';
import { SecurityAlert, TelemetryRecord, AuditLogEntry, SecurityPolicy } from '../src/types/cyber.ts';

const DATA_DIR = path.resolve(process.cwd(), 'data');
const DB_FILE = path.join(DATA_DIR, 'cybersentinel.sqlite');

let SQL: SqlJsStatic | null = null;
let db: Database | null = null;
let saveTimeout: NodeJS.Timeout | null = null;

export async function getDatabase(): Promise<Database> {
  if (db) return db;

  if (!fs.existsSync(DATA_DIR)) {
    fs.mkdirSync(DATA_DIR, { recursive: true });
  }

  SQL = await initSqlJs();

  if (fs.existsSync(DB_FILE)) {
    try {
      const fileBuffer = fs.readFileSync(DB_FILE);
      db = new SQL.Database(fileBuffer);
    } catch (err) {
      console.error('Failed to load existing SQLite database file, creating fresh:', err);
      db = new SQL.Database();
    }
  } else {
    db = new SQL.Database();
  }

  // Schema creation
  db.run(`
    CREATE TABLE IF NOT EXISTS telemetry (
      id TEXT PRIMARY KEY,
      timestamp TEXT NOT NULL,
      source_ip TEXT NOT NULL,
      dest_ip TEXT NOT NULL,
      src_port INTEGER,
      dest_port INTEGER,
      protocol TEXT,
      bytes INTEGER,
      packets INTEGER,
      auth_status TEXT,
      event_type TEXT,
      is_demo INTEGER DEFAULT 0
    );

    CREATE TABLE IF NOT EXISTS alerts (
      id TEXT PRIMARY KEY,
      timestamp TEXT NOT NULL,
      source_ip TEXT NOT NULL,
      dest_ip TEXT NOT NULL,
      src_port INTEGER,
      dest_port INTEGER,
      protocol TEXT,
      threat_category TEXT NOT NULL,
      risk_score REAL NOT NULL,
      severity TEXT NOT NULL,
      anomaly_score REAL NOT NULL,
      confidence_pct REAL NOT NULL,
      evidence_features TEXT,
      recommended_action TEXT,
      status TEXT NOT NULL,
      policy_breach INTEGER DEFAULT 0,
      model_version TEXT,
      probabilities TEXT,
      behavioral_features TEXT,
      raw_telemetry TEXT,
      is_demo INTEGER DEFAULT 0
    );

    CREATE TABLE IF NOT EXISTS audit_logs (
      id TEXT PRIMARY KEY,
      alert_id TEXT,
      timestamp TEXT NOT NULL,
      source_ip TEXT,
      dest_ip TEXT,
      classification TEXT,
      risk_score REAL,
      evidence_summary TEXT,
      status TEXT,
      action_taken TEXT,
      operator TEXT,
      model_version TEXT,
      feature_values TEXT
    );

    CREATE TABLE IF NOT EXISTS policy (
      id INTEGER PRIMARY KEY CHECK (id = 1),
      max_risk_threshold REAL DEFAULT 70,
      auto_prioritize_high_risk INTEGER DEFAULT 1,
      enable_noise_filtering INTEGER DEFAULT 1,
      enable_background_filtering INTEGER DEFAULT 1,
      sliding_window_seconds INTEGER DEFAULT 60,
      auto_isolate_endpoints INTEGER DEFAULT 0
    );

    CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON alerts (timestamp);
    CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts (severity);
    CREATE INDEX IF NOT EXISTS idx_alerts_threat ON alerts (threat_category);
    CREATE INDEX IF NOT EXISTS idx_telemetry_source_ip ON telemetry (source_ip);
  `);

  // Ensure default policy exists
  const policyCheck = db.exec('SELECT id FROM policy WHERE id = 1');
  if (policyCheck.length === 0 || policyCheck[0].values.length === 0) {
    db.run(`
      INSERT INTO policy (id, max_risk_threshold, auto_prioritize_high_risk, enable_noise_filtering, enable_background_filtering, sliding_window_seconds, auto_isolate_endpoints)
      VALUES (1, 70, 1, 1, 1, 60, 0);
    `);
    persistDatabase();
  }

  return db;
}

export function persistDatabase(): void {
  if (!db) return;
  if (saveTimeout) clearTimeout(saveTimeout);
  saveTimeout = setTimeout(() => {
    try {
      if (!fs.existsSync(DATA_DIR)) {
        fs.mkdirSync(DATA_DIR, { recursive: true });
      }
      const data = db!.export();
      const buffer = Buffer.from(data);
      fs.writeFileSync(DB_FILE, buffer);
    } catch (e) {
      console.error('Error saving SQLite database file:', e);
    }
  }, 100);
}

// Data Access Helpers
export async function insertTelemetryRecord(record: TelemetryRecord, isDemo: boolean = false): Promise<void> {
  const database = await getDatabase();
  const id = record.id || `tel_${Date.now()}_${Math.random().toString(36).substring(2, 7)}`;
  database.run(
    `INSERT INTO telemetry (id, timestamp, source_ip, dest_ip, src_port, dest_port, protocol, bytes, packets, auth_status, event_type, is_demo)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    [
      id,
      record.timestamp,
      record.source_ip,
      record.dest_ip,
      record.src_port,
      record.dest_port,
      record.protocol,
      record.bytes,
      record.packets,
      record.auth_status,
      record.event_type,
      isDemo ? 1 : 0,
    ]
  );
  persistDatabase();
}

export async function insertAlert(alert: SecurityAlert): Promise<void> {
  const database = await getDatabase();
  database.run(
    `INSERT OR REPLACE INTO alerts 
     (id, timestamp, source_ip, dest_ip, src_port, dest_port, protocol, threat_category, risk_score, severity, anomaly_score, confidence_pct, evidence_features, recommended_action, status, policy_breach, model_version, probabilities, behavioral_features, raw_telemetry, is_demo)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    [
      alert.id,
      alert.timestamp,
      alert.source_ip,
      alert.dest_ip,
      alert.src_port,
      alert.dest_port,
      alert.protocol,
      alert.threat_category,
      alert.risk_score,
      alert.severity,
      alert.anomaly_score,
      alert.confidence_pct,
      JSON.stringify(alert.evidence_features),
      alert.recommended_action,
      alert.status,
      alert.policy_breach ? 1 : 0,
      alert.model_version,
      JSON.stringify(alert.probabilities),
      JSON.stringify(alert.behavioral_features),
      JSON.stringify(alert.raw_telemetry),
      alert.is_demo ? 1 : 0,
    ]
  );

  // Automatically insert audit log entry for alert generation
  const auditId = `aud_${Date.now()}_${Math.random().toString(36).substring(2, 6)}`;
  database.run(
    `INSERT INTO audit_logs 
     (id, alert_id, timestamp, source_ip, dest_ip, classification, risk_score, evidence_summary, status, action_taken, operator, model_version, feature_values)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    [
      auditId,
      alert.id,
      alert.timestamp,
      alert.source_ip,
      alert.dest_ip,
      alert.threat_category,
      alert.risk_score,
      alert.evidence_features.join('; '),
      alert.status,
      alert.policy_breach ? 'FLAGGED_POLICY_BREACH' : 'INGEST_AND_SCORE',
      'CyberSentinel Engine',
      alert.model_version,
      JSON.stringify({
        events_per_src: alert.behavioral_features.events_per_source,
        unique_ports: alert.behavioral_features.unique_dest_port_count,
        failed_logins: alert.behavioral_features.failed_login_count,
        bytes_sent: alert.behavioral_features.bytes_sent,
        anomaly_score: alert.anomaly_score,
      }),
    ]
  );

  persistDatabase();
}

export async function getAlerts(filters?: {
  severity?: string;
  threat?: string;
  status?: string;
  search?: string;
  limit?: number;
}): Promise<SecurityAlert[]> {
  const database = await getDatabase();
  let sql = 'SELECT * FROM alerts WHERE 1=1';
  const params: any[] = [];

  if (filters?.severity && filters.severity !== 'All') {
    sql += ' AND severity = ?';
    params.push(filters.severity);
  }
  if (filters?.threat && filters.threat !== 'All') {
    sql += ' AND threat_category = ?';
    params.push(filters.threat);
  }
  if (filters?.status && filters.status !== 'All') {
    sql += ' AND status = ?';
    params.push(filters.status);
  }
  if (filters?.search) {
    sql += ' AND (source_ip LIKE ? OR dest_ip LIKE ? OR id LIKE ?)';
    const s = `%${filters.search}%`;
    params.push(s, s, s);
  }

  sql += ' ORDER BY timestamp DESC';
  if (filters?.limit) {
    sql += ` LIMIT ${filters.limit}`;
  } else {
    sql += ' LIMIT 300';
  }

  const res = database.exec(sql, params);
  if (res.length === 0 || !res[0].values) return [];

  const columns = res[0].columns;
  return res[0].values.map((row) => {
    const obj: any = {};
    columns.forEach((col, idx) => {
      obj[col] = row[idx];
    });
    return {
      id: obj.id,
      timestamp: obj.timestamp,
      source_ip: obj.source_ip,
      dest_ip: obj.dest_ip,
      src_port: Number(obj.src_port),
      dest_port: Number(obj.dest_port),
      protocol: obj.protocol,
      threat_category: obj.threat_category,
      risk_score: Number(obj.risk_score),
      severity: obj.severity,
      anomaly_score: Number(obj.anomaly_score),
      confidence_pct: Number(obj.confidence_pct),
      evidence_features: obj.evidence_features ? JSON.parse(obj.evidence_features) : [],
      recommended_action: obj.recommended_action,
      status: obj.status,
      policy_breach: Boolean(obj.policy_breach),
      model_version: obj.model_version,
      probabilities: obj.probabilities ? JSON.parse(obj.probabilities) : {},
      behavioral_features: obj.behavioral_features ? JSON.parse(obj.behavioral_features) : {},
      raw_telemetry: obj.raw_telemetry ? JSON.parse(obj.raw_telemetry) : {},
      is_demo: Boolean(obj.is_demo),
    } as SecurityAlert;
  });
}

export async function getAlertById(id: string): Promise<SecurityAlert | null> {
  const database = await getDatabase();
  const res = database.exec('SELECT * FROM alerts WHERE id = ? LIMIT 1', [id]);
  if (res.length === 0 || res[0].values.length === 0) return null;

  const columns = res[0].columns;
  const row = res[0].values[0];
  const obj: any = {};
  columns.forEach((col, idx) => {
    obj[col] = row[idx];
  });

  return {
    id: obj.id,
    timestamp: obj.timestamp,
    source_ip: obj.source_ip,
    dest_ip: obj.dest_ip,
    src_port: Number(obj.src_port),
    dest_port: Number(obj.dest_port),
    protocol: obj.protocol,
    threat_category: obj.threat_category,
    risk_score: Number(obj.risk_score),
    severity: obj.severity,
    anomaly_score: Number(obj.anomaly_score),
    confidence_pct: Number(obj.confidence_pct),
    evidence_features: obj.evidence_features ? JSON.parse(obj.evidence_features) : [],
    recommended_action: obj.recommended_action,
    status: obj.status,
    policy_breach: Boolean(obj.policy_breach),
    model_version: obj.model_version,
    probabilities: obj.probabilities ? JSON.parse(obj.probabilities) : {},
    behavioral_features: obj.behavioral_features ? JSON.parse(obj.behavioral_features) : {},
    raw_telemetry: obj.raw_telemetry ? JSON.parse(obj.raw_telemetry) : {},
    is_demo: Boolean(obj.is_demo),
  };
}

export async function updateAlertStatus(
  id: string,
  newStatus: 'New' | 'Reviewed' | 'Resolved',
  operator: string = 'SOC Analyst'
): Promise<SecurityAlert | null> {
  const database = await getDatabase();
  database.run('UPDATE alerts SET status = ? WHERE id = ?', [newStatus, id]);

  const alert = await getAlertById(id);
  if (alert) {
    const auditId = `aud_${Date.now()}_${Math.random().toString(36).substring(2, 6)}`;
    database.run(
      `INSERT INTO audit_logs 
       (id, alert_id, timestamp, source_ip, dest_ip, classification, risk_score, evidence_summary, status, action_taken, operator, model_version, feature_values)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        auditId,
        alert.id,
        new Date().toISOString(),
        alert.source_ip,
        alert.dest_ip,
        alert.threat_category,
        alert.risk_score,
        `Status transitioned to ${newStatus}`,
        newStatus,
        `STATUS_UPDATE_${newStatus.toUpperCase()}`,
        operator,
        alert.model_version,
        JSON.stringify({ updated_to: newStatus, previous_evidence_count: alert.evidence_features.length }),
      ]
    );
  }

  persistDatabase();
  return alert;
}

export async function getAuditLogs(limit: number = 200): Promise<AuditLogEntry[]> {
  const database = await getDatabase();
  const res = database.exec(`SELECT * FROM audit_logs ORDER BY timestamp DESC LIMIT ${limit}`);
  if (res.length === 0 || !res[0].values) return [];

  const columns = res[0].columns;
  return res[0].values.map((row) => {
    const obj: any = {};
    columns.forEach((col, idx) => {
      obj[col] = row[idx];
    });
    return {
      id: obj.id,
      alert_id: obj.alert_id,
      timestamp: obj.timestamp,
      source_ip: obj.source_ip,
      dest_ip: obj.dest_ip,
      classification: obj.classification,
      risk_score: Number(obj.risk_score),
      evidence_summary: obj.evidence_summary,
      status: obj.status,
      action_taken: obj.action_taken,
      operator: obj.operator,
      model_version: obj.model_version,
      feature_values: obj.feature_values,
    };
  });
}

export async function getPolicy(): Promise<SecurityPolicy> {
  const database = await getDatabase();
  const res = database.exec('SELECT * FROM policy WHERE id = 1 LIMIT 1');
  if (res.length === 0 || res[0].values.length === 0) {
    return {
      max_risk_threshold: 70,
      auto_prioritize_high_risk: true,
      enable_noise_filtering: true,
      enable_background_filtering: true,
      sliding_window_seconds: 60,
      auto_isolate_endpoints: false,
    };
  }

  const row = res[0].values[0];
  const cols = res[0].columns;
  const obj: any = {};
  cols.forEach((c, idx) => {
    obj[c] = row[idx];
  });

  return {
    max_risk_threshold: Number(obj.max_risk_threshold ?? 70),
    auto_prioritize_high_risk: Boolean(obj.auto_prioritize_high_risk ?? 1),
    enable_noise_filtering: Boolean(obj.enable_noise_filtering ?? 1),
    enable_background_filtering: Boolean(obj.enable_background_filtering ?? 1),
    sliding_window_seconds: Number(obj.sliding_window_seconds ?? 60),
    auto_isolate_endpoints: Boolean(obj.auto_isolate_endpoints ?? 0),
  };
}

export async function updatePolicy(policy: Partial<SecurityPolicy>): Promise<SecurityPolicy> {
  const database = await getDatabase();
  const current = await getPolicy();
  const updated: SecurityPolicy = {
    ...current,
    ...policy,
  };

  database.run(
    `UPDATE policy SET 
     max_risk_threshold = ?,
     auto_prioritize_high_risk = ?,
     enable_noise_filtering = ?,
     enable_background_filtering = ?,
     sliding_window_seconds = ?,
     auto_isolate_endpoints = ?
     WHERE id = 1`,
    [
      updated.max_risk_threshold,
      updated.auto_prioritize_high_risk ? 1 : 0,
      updated.enable_noise_filtering ? 1 : 0,
      updated.enable_background_filtering ? 1 : 0,
      updated.sliding_window_seconds,
      updated.auto_isolate_endpoints ? 1 : 0,
    ]
  );

  // Add audit log for policy modification
  const auditId = `aud_${Date.now()}_policy`;
  database.run(
    `INSERT INTO audit_logs 
     (id, alert_id, timestamp, source_ip, dest_ip, classification, risk_score, evidence_summary, status, action_taken, operator, model_version, feature_values)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    [
      auditId,
      'POLICY_SYS',
      new Date().toISOString(),
      '127.0.0.1',
      'CONFIG',
      'POLICY_UPDATE',
      0,
      `Threshold updated to ${updated.max_risk_threshold}, noise filtering: ${updated.enable_noise_filtering}`,
      'Active',
      'UPDATE_SECURITY_POLICY',
      'SOC Lead Administrator',
      'v2.4.1 SentinelCore',
      JSON.stringify(updated),
    ]
  );

  persistDatabase();
  return updated;
}

export async function clearAllData(): Promise<void> {
  const database = await getDatabase();
  database.run('DELETE FROM alerts;');
  database.run('DELETE FROM telemetry;');
  database.run('DELETE FROM audit_logs;');
  persistDatabase();
}
