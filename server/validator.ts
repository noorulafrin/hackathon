import { TelemetryRecord, ValidationErrorItem, ValidationSummary } from '../src/types/cyber.ts';

const VALID_PROTOCOLS = new Set(['TCP', 'UDP', 'ICMP', 'DNS', 'HTTP', 'HTTPS', 'SSH', 'RDP', 'SMB', 'TLS']);
const VALID_EVENT_TYPES = new Set(['connection', 'auth', 'flow', 'dns', 'file_transfer', 'session', 'endpoint']);

function isValidIPv4(ip: string): boolean {
  if (typeof ip !== 'string') return false;
  const parts = ip.trim().split('.');
  if (parts.length !== 4) return false;
  return parts.every((p) => {
    if (!/^\d+$/.test(p)) return false;
    const n = parseInt(p, 10);
    return n >= 0 && n <= 255;
  });
}

function isValidIPv6(ip: string): boolean {
  if (typeof ip !== 'string') return false;
  const regex = /^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$/;
  return regex.test(ip.trim());
}

function isValidIP(ip: string): boolean {
  return isValidIPv4(ip) || isValidIPv6(ip);
}

function parseAndValidateTimestamp(ts: any): string | null {
  if (!ts) return null;
  const d = new Date(ts);
  if (isNaN(d.getTime())) return null;
  return d.toISOString();
}

export function validateTelemetryRecord(record: any, index: number): { valid: boolean; record?: TelemetryRecord; errors: ValidationErrorItem[] } {
  const errors: ValidationErrorItem[] = [];

  if (!record || typeof record !== 'object') {
    return {
      valid: false,
      errors: [{ record_index: index, field: 'root', issue: 'Record is null, undefined, or not an object', raw_value: record }],
    };
  }

  // 1. Source IP
  if (!record.source_ip || typeof record.source_ip !== 'string' || !isValidIP(record.source_ip)) {
    errors.push({
      record_index: index,
      field: 'source_ip',
      issue: 'Invalid or missing source IPv4/IPv6 address',
      raw_value: record.source_ip,
    });
  }

  // 2. Dest IP
  if (!record.dest_ip || typeof record.dest_ip !== 'string' || !isValidIP(record.dest_ip)) {
    errors.push({
      record_index: index,
      field: 'dest_ip',
      issue: 'Invalid or missing destination IPv4/IPv6 address',
      raw_value: record.dest_ip,
    });
  }

  // 3. Timestamp
  const normalizedTs = parseAndValidateTimestamp(record.timestamp);
  if (!normalizedTs) {
    errors.push({
      record_index: index,
      field: 'timestamp',
      issue: 'Invalid or unparseable timestamp date string',
      raw_value: record.timestamp,
    });
  }

  // 4. Ports
  const srcPort = Number(record.src_port);
  if (isNaN(srcPort) || srcPort < 0 || srcPort > 65535) {
    errors.push({
      record_index: index,
      field: 'src_port',
      issue: 'Source port must be an integer between 0 and 65535',
      raw_value: record.src_port,
    });
  }

  const destPort = Number(record.dest_port);
  if (isNaN(destPort) || destPort < 0 || destPort > 65535) {
    errors.push({
      record_index: index,
      field: 'dest_port',
      issue: 'Destination port must be an integer between 0 and 65535',
      raw_value: record.dest_port,
    });
  }

  // 5. Bytes & Packets
  const bytes = Number(record.bytes);
  if (isNaN(bytes) || bytes < 0) {
    errors.push({
      record_index: index,
      field: 'bytes',
      issue: 'Bytes count must be a non-negative number',
      raw_value: record.bytes,
    });
  }

  const packets = Number(record.packets);
  if (isNaN(packets) || packets < 0) {
    errors.push({
      record_index: index,
      field: 'packets',
      issue: 'Packets count must be a non-negative number',
      raw_value: record.packets,
    });
  }

  // 6. Protocol
  const protocolStr = String(record.protocol || 'TCP').toUpperCase().trim();
  if (!VALID_PROTOCOLS.has(protocolStr) && protocolStr.length > 10) {
    errors.push({
      record_index: index,
      field: 'protocol',
      issue: `Unknown or malformed network protocol '${record.protocol}'`,
      raw_value: record.protocol,
    });
  }

  // 7. Event Type
  const eventType = String(record.event_type || 'connection').toLowerCase().trim();
  if (!VALID_EVENT_TYPES.has(eventType)) {
    // Gracefully handle or log warning
    errors.push({
      record_index: index,
      field: 'event_type',
      issue: `Unrecognized event type '${record.event_type}'. Expected: ${Array.from(VALID_EVENT_TYPES).join(', ')}`,
      raw_value: record.event_type,
    });
  }

  if (errors.length > 0) {
    return { valid: false, errors };
  }

  const validRecord: TelemetryRecord = {
    id: record.id || `tel_${Date.now()}_${Math.random().toString(36).substring(2, 7)}`,
    timestamp: normalizedTs!,
    source_ip: record.source_ip.trim(),
    dest_ip: record.dest_ip.trim(),
    src_port: srcPort,
    dest_port: destPort,
    protocol: protocolStr,
    bytes: bytes,
    packets: packets,
    auth_status: String(record.auth_status || 'none').toLowerCase().trim(),
    event_type: eventType,
  };

  return { valid: true, record: validRecord, errors: [] };
}

export function validateTelemetryBatch(records: any[]): {
  valid_records: TelemetryRecord[];
  skipped_records: any[];
  summary: ValidationSummary;
} {
  const valid_records: TelemetryRecord[] = [];
  const skipped_records: any[] = [];
  const allErrors: ValidationErrorItem[] = [];

  records.forEach((raw, idx) => {
    const result = validateTelemetryRecord(raw, idx + 1);
    if (result.valid && result.record) {
      valid_records.push(result.record);
    } else {
      skipped_records.push(raw);
      allErrors.push(...result.errors);
    }
  });

  return {
    valid_records,
    skipped_records,
    summary: {
      total_records: records.length,
      valid_records: valid_records.length,
      skipped_records: skipped_records.length,
      errors: allErrors,
    },
  };
}

export function parseCsvTelemetry(csvText: string): any[] {
  const lines = csvText.trim().split(/\r?\n/).filter((l) => l.trim().length > 0);
  if (lines.length < 2) return [];

  const headers = lines[0].split(',').map((h) => h.trim().replace(/^["']|["']$/g, ''));
  const parsedRows: any[] = [];

  for (let i = 1; i < lines.length; i++) {
    const values = lines[i].split(',').map((v) => v.trim().replace(/^["']|["']$/g, ''));
    const obj: any = {};
    headers.forEach((h, colIdx) => {
      obj[h] = values[colIdx] ?? '';
    });
    parsedRows.push(obj);
  }

  return parsedRows;
}
