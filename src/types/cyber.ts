export interface TelemetryRecord {
  id?: string;
  timestamp: string;
  source_ip: string;
  dest_ip: string;
  src_port: number;
  dest_port: number;
  protocol: string;
  bytes: number;
  packets: number;
  auth_status: 'success' | 'failure' | 'none' | 'mfa_required' | string;
  event_type: 'connection' | 'auth' | 'flow' | 'dns' | 'file_transfer' | string;
}

export interface ValidationErrorItem {
  record_index: number;
  field: string;
  issue: string;
  raw_value?: any;
}

export interface ValidationSummary {
  total_records: number;
  valid_records: number;
  skipped_records: number;
  errors: ValidationErrorItem[];
}

export interface BehavioralFeatures {
  source_ip: string;
  dest_ip: string;
  window_seconds: number;
  events_per_source: number;
  unique_dest_count: number;
  unique_dest_port_count: number;
  failed_login_count: number;
  successful_login_count: number;
  auth_fail_ratio: number;
  bytes_sent: number;
  bytes_received: number;
  packets_sent: number;
  avg_packet_size: number;
  connection_rate_per_sec: number;
  is_internal_src: boolean;
  is_internal_dest: boolean;
  is_lateral_internal: boolean;
  is_external_egress: boolean;
  is_noise_traffic: boolean;
  protocol_distribution: Record<string, number>;
  rate_of_change: number;
}

export interface ContributingFeature {
  feature: string;
  value: string | number;
  baseline: string | number;
  deviation: string;
  weight: number;
}

export interface AnomalyResult {
  anomaly_score: number; // 0 to 100
  is_anomalous: boolean;
  contributing_features: ContributingFeature[];
}

export type ThreatClass =
  | 'Normal'
  | 'Port Scan'
  | 'Brute Force'
  | 'Lateral Movement'
  | 'Data Exfiltration'
  | 'Suspicious / Unknown Anomaly';

export interface ThreatClassification {
  predicted_threat: ThreatClass;
  confidence_pct: number;
  probabilities: Record<ThreatClass, number>;
}

export type SeverityLevel = 'Normal' | 'Suspicious' | 'Malicious';

export interface RiskScoreResult {
  risk_score: number; // 0 to 100
  severity: SeverityLevel;
  breakdown: {
    anomaly_contribution: number;
    confidence_contribution: number;
    behavioral_severity: number;
    noise_discount: number;
  };
}

export interface EvidenceExplanation {
  evidence_statements: string[];
  narrative: string;
  recommended_action: string;
  policy_breach: boolean;
  policy_threshold: number;
}

export type AlertStatus = 'New' | 'Reviewed' | 'Resolved';

export interface SecurityAlert {
  id: string;
  timestamp: string;
  source_ip: string;
  dest_ip: string;
  src_port: number;
  dest_port: number;
  protocol: string;
  threat_category: ThreatClass;
  risk_score: number;
  severity: SeverityLevel;
  anomaly_score: number;
  confidence_pct: number;
  evidence_features: string[];
  recommended_action: string;
  status: AlertStatus;
  policy_breach: boolean;
  model_version: string;
  probabilities: Record<ThreatClass, number>;
  behavioral_features: BehavioralFeatures;
  raw_telemetry: TelemetryRecord;
  is_demo?: boolean;
}

export interface SecurityPolicy {
  max_risk_threshold: number;
  auto_prioritize_high_risk: boolean;
  enable_noise_filtering: boolean;
  enable_background_filtering: boolean;
  sliding_window_seconds: number;
  auto_isolate_endpoints: boolean;
}

export interface AuditLogEntry {
  id: string;
  alert_id: string;
  timestamp: string;
  source_ip: string;
  dest_ip: string;
  classification: string;
  risk_score: number;
  evidence_summary: string;
  status: string;
  action_taken: string;
  operator: string;
  model_version: string;
  feature_values: string;
}

export interface SystemHealth {
  telemetry_pipeline: 'ONLINE' | 'DEGRADED' | 'OFFLINE';
  feature_engine: 'ONLINE' | 'DEGRADED' | 'OFFLINE';
  anomaly_detector: 'ONLINE' | 'DEGRADED' | 'OFFLINE';
  classifier: 'ONLINE' | 'DEGRADED' | 'OFFLINE';
  database: 'ONLINE' | 'DEGRADED' | 'OFFLINE';
  policy_engine: 'ONLINE' | 'DEGRADED' | 'OFFLINE';
  events_processed: number;
  alerts_generated: number;
  active_policy_breaches: number;
  last_processed_timestamp: string;
  model_version: string;
  uptime_seconds: number;
  processing_latency_ms: number;
}

export interface SOCAnalytics {
  total_events: number;
  total_alerts: number;
  critical_alerts: number; // risk 71-100
  suspicious_alerts: number; // risk 31-70
  normal_events: number; // risk 0-30
  average_risk_score: number;
  policy_breaches_count: number;
  threat_distribution: Array<{ category: string; count: number; percentage: number }>;
  risk_distribution: Array<{ band: string; count: number; color: string }>;
  timeline: Array<{ time: string; normal: number; suspicious: number; malicious: number; total: number }>;
  top_sources: Array<{ ip: string; event_count: number; max_risk: number; dominant_threat: string }>;
  top_destinations: Array<{ ip: string; event_count: number }>;
}
