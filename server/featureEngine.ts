import { TelemetryRecord, BehavioralFeatures } from '../src/types/cyber.ts';

// In-memory sliding window history buffer grouped by source IP
interface TelemetryHistoryEntry {
  record: TelemetryRecord;
  epochMs: number;
}

const sourceHistory = new Map<string, TelemetryHistoryEntry[]>();
const MAX_HISTORY_PER_SOURCE = 500;

export function isPrivateIP(ip: string): boolean {
  if (ip.startsWith('10.') || ip.startsWith('192.168.')) return true;
  if (ip.startsWith('172.')) {
    const secondOctet = parseInt(ip.split('.')[1], 10);
    if (secondOctet >= 16 && secondOctet <= 31) return true;
  }
  if (ip === '127.0.0.1' || ip === 'localhost') return true;
  return false;
}

export function isBroadcastOrMulticast(ip: string): boolean {
  if (ip === '255.255.255.255') return true;
  if (ip.startsWith('224.') || ip.startsWith('239.') || ip.startsWith('233.')) return true;
  return false;
}

export function isKnownBenignService(record: TelemetryRecord): boolean {
  // DHCP
  if (
    (record.src_port === 67 && record.dest_port === 68) ||
    (record.src_port === 68 && record.dest_port === 67)
  ) return true;

  // Multicast / SSDP
  if (record.dest_port === 1900 || record.dest_port === 5353) return true;

  // NTP routine clock sync (low bytes)
  if (record.dest_port === 123 && record.bytes < 500) return true;

  // Broadcast traffic
  if (isBroadcastOrMulticast(record.dest_ip)) return true;

  return false;
}

export function addRecordToHistory(record: TelemetryRecord): void {
  const epoch = new Date(record.timestamp).getTime();
  const list = sourceHistory.get(record.source_ip) || [];
  list.push({ record, epochMs: epoch });
  if (list.length > MAX_HISTORY_PER_SOURCE) {
    list.shift();
  }
  sourceHistory.set(record.source_ip, list);
}

export function clearTelemetryHistory(): void {
  sourceHistory.clear();
}

export function extractBehavioralFeatures(
  currentRecord: TelemetryRecord,
  windowSeconds: number = 60
): BehavioralFeatures {
  const currentEpoch = new Date(currentRecord.timestamp).getTime();
  const windowMs = windowSeconds * 1000;
  const cutoff = currentEpoch - windowMs;

  const history = sourceHistory.get(currentRecord.source_ip) || [];
  const inWindow = history.filter((h) => h.epochMs >= cutoff && h.epochMs <= currentEpoch);

  // If inWindow is empty (e.g. first record), include currentRecord
  const windowRecords = inWindow.length > 0 ? inWindow.map((h) => h.record) : [currentRecord];

  // Also include the current record if not in windowRecords
  if (!windowRecords.some((r) => r.id === currentRecord.id)) {
    windowRecords.push(currentRecord);
  }

  const eventsCount = windowRecords.length;
  const uniqueDestIps = new Set<string>();
  const uniqueDestPorts = new Set<number>();
  let failedLogins = 0;
  let successfulLogins = 0;
  let totalBytesSent = 0;
  let totalPacketsSent = 0;
  const protoMap: Record<string, number> = {};

  for (const r of windowRecords) {
    uniqueDestIps.add(r.dest_ip);
    uniqueDestPorts.add(r.dest_port);

    if (r.auth_status === 'failure') failedLogins++;
    if (r.auth_status === 'success') successfulLogins++;

    totalBytesSent += r.bytes || 0;
    totalPacketsSent += r.packets || 0;

    const p = (r.protocol || 'TCP').toUpperCase();
    protoMap[p] = (protoMap[p] || 0) + 1;
  }

  const totalLogins = failedLogins + successfulLogins;
  const authFailRatio = totalLogins > 0 ? failedLogins / totalLogins : 0;

  const durationSec = Math.max(1, windowSeconds);
  const connectionRate = eventsCount / durationSec;
  const avgPacketSize = totalPacketsSent > 0 ? Math.round(totalBytesSent / totalPacketsSent) : 0;

  const isInternalSrc = isPrivateIP(currentRecord.source_ip);
  const isInternalDest = isPrivateIP(currentRecord.dest_ip);
  const isLateral = isInternalSrc && isInternalDest && currentRecord.source_ip !== currentRecord.dest_ip;
  const isEgress = isInternalSrc && !isInternalDest;
  const isNoise = isKnownBenignService(currentRecord);

  // Baseline rate comparison (prior window)
  const priorCutoff = cutoff - windowMs;
  const priorWindow = history.filter((h) => h.epochMs >= priorCutoff && h.epochMs < cutoff);
  const priorCount = priorWindow.length;
  const rateOfChange = priorCount > 0 ? (eventsCount - priorCount) / priorCount : 1.0;

  return {
    source_ip: currentRecord.source_ip,
    dest_ip: currentRecord.dest_ip,
    window_seconds: windowSeconds,
    events_per_source: eventsCount,
    unique_dest_count: uniqueDestIps.size,
    unique_dest_port_count: uniqueDestPorts.size,
    failed_login_count: failedLogins,
    successful_login_count: successfulLogins,
    auth_fail_ratio: Number(authFailRatio.toFixed(3)),
    bytes_sent: totalBytesSent,
    bytes_received: Math.round(totalBytesSent * 0.15), // estimated response traffic
    packets_sent: totalPacketsSent,
    avg_packet_size: avgPacketSize,
    connection_rate_per_sec: Number(connectionRate.toFixed(2)),
    is_internal_src: isInternalSrc,
    is_internal_dest: isInternalDest,
    is_lateral_internal: isLateral,
    is_external_egress: isEgress,
    is_noise_traffic: isNoise,
    protocol_distribution: protoMap,
    rate_of_change: Number(rateOfChange.toFixed(2)),
  };
}
