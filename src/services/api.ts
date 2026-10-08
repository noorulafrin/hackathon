import {
  SecurityAlert,
  SOCAnalytics,
  SystemHealth,
  SecurityPolicy,
  AuditLogEntry,
  ValidationSummary,
} from '../types/cyber.ts';

export async function fetchAnalytics(): Promise<SOCAnalytics> {
  const res = await fetch('/api/analytics');
  if (!res.ok) throw new Error('Failed to fetch analytics');
  return res.json();
}

export async function fetchAlerts(params?: {
  severity?: string;
  threat?: string;
  status?: string;
  search?: string;
  limit?: number;
}): Promise<SecurityAlert[]> {
  const query = new URLSearchParams();
  if (params?.severity) query.set('severity', params.severity);
  if (params?.threat) query.set('threat', params.threat);
  if (params?.status) query.set('status', params.status);
  if (params?.search) query.set('search', params.search);
  if (params?.limit) query.set('limit', params.limit.toString());

  const res = await fetch(`/api/alerts?${query.toString()}`);
  if (!res.ok) throw new Error('Failed to fetch alerts');
  const data = await res.json();
  return data.alerts || [];
}

export async function fetchAlertById(id: string): Promise<SecurityAlert> {
  const res = await fetch(`/api/alerts/${encodeURIComponent(id)}`);
  if (!res.ok) throw new Error('Failed to fetch alert details');
  return res.json();
}

export async function updateAlertStatus(
  id: string,
  status: 'New' | 'Reviewed' | 'Resolved',
  operator: string = 'SOC Analyst'
): Promise<SecurityAlert> {
  const res = await fetch(`/api/alerts/${encodeURIComponent(id)}/status`, {
    method: 'PATCH',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ status, operator }),
  });
  if (!res.ok) throw new Error('Failed to update alert status');
  const data = await res.json();
  return data.alert;
}

export async function fetchAuditLogs(limit: number = 200): Promise<AuditLogEntry[]> {
  const res = await fetch(`/api/audit?limit=${limit}`);
  if (!res.ok) throw new Error('Failed to fetch audit logs');
  const data = await res.json();
  return data.logs || [];
}

export async function fetchSystemHealth(): Promise<SystemHealth> {
  const res = await fetch('/api/system-health');
  if (!res.ok) throw new Error('Failed to fetch system health');
  return res.json();
}

export async function fetchPolicy(): Promise<SecurityPolicy> {
  const res = await fetch('/api/policy');
  if (!res.ok) throw new Error('Failed to fetch policy');
  return res.json();
}

export async function updatePolicy(policy: Partial<SecurityPolicy>): Promise<SecurityPolicy> {
  const res = await fetch('/api/policy', {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(policy),
  });
  if (!res.ok) throw new Error('Failed to update policy');
  const data = await res.json();
  return data.policy;
}

export async function ingestTelemetry(records: any[]): Promise<{
  events_processed: number;
  alerts_generated: number;
  validation: ValidationSummary;
  alerts: SecurityAlert[];
}> {
  const res = await fetch('/api/telemetry', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(records),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.error || 'Failed to ingest telemetry');
  }
  return res.json();
}

export async function uploadTelemetryFile(content: string): Promise<{
  events_processed: number;
  alerts_generated: number;
  validation: ValidationSummary;
  alerts: SecurityAlert[];
}> {
  const res = await fetch('/api/telemetry/upload', {
    method: 'POST',
    headers: { 'Content-Type': 'text/plain' },
    body: content,
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.error || 'Failed to upload telemetry');
  }
  return res.json();
}

export async function runDemoSimulation(): Promise<{
  scenario: string;
  events_processed: number;
  alerts_generated: number;
  validation: ValidationSummary;
  alerts: SecurityAlert[];
}> {
  const res = await fetch('/api/demo/run', { method: 'POST' });
  if (!res.ok) throw new Error('Failed to run demo simulation');
  return res.json();
}

export async function resetDemoData(): Promise<void> {
  const res = await fetch('/api/demo/reset', { method: 'POST' });
  if (!res.ok) throw new Error('Failed to reset demo data');
}

export async function fetchSampleData(): Promise<{ json: string; csv: string }> {
  const res = await fetch('/api/sample-data');
  if (!res.ok) throw new Error('Failed to fetch sample telemetry');
  return res.json();
}
