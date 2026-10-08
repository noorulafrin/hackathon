import { TelemetryRecord } from '../src/types/cyber.ts';

export function generateDemoTelemetryScenario(): {
  name: string;
  records: TelemetryRecord[];
} {
  const now = Date.now();
  const allRecords: TelemetryRecord[] = [];

  // Helper to format ISO timestamp relative to now
  const ts = (offsetSeconds: number) => new Date(now - (300 - offsetSeconds) * 1000).toISOString();

  // 1. Normal Traffic Baseline (DNS queries, regular HTTPS web traffic, database queries)
  const normalHosts = ['10.0.0.5', '10.0.0.8', '10.0.0.12', '192.168.1.105'];
  const webServers = ['142.250.190.46', '104.18.26.120', '151.101.65.140'];

  for (let i = 0; i < 20; i++) {
    const src = normalHosts[i % normalHosts.length];
    const dst = webServers[i % webServers.length];
    allRecords.push({
      id: `dem_norm_${i + 1}`,
      timestamp: ts(i * 12),
      source_ip: src,
      dest_ip: dst,
      src_port: 49152 + i * 3,
      dest_port: 443,
      protocol: 'TCP',
      bytes: Math.floor(4000 + Math.random() * 25000),
      packets: Math.floor(8 + Math.random() * 30),
      auth_status: 'none',
      event_type: 'connection',
    });
  }

  // Routine DNS queries (Benign noise handling check)
  allRecords.push({
    id: 'dem_dns_1',
    timestamp: ts(150),
    source_ip: '10.0.0.5',
    dest_ip: '1.1.1.1',
    src_port: 53120,
    dest_port: 53,
    protocol: 'UDP',
    bytes: 140,
    packets: 2,
    auth_status: 'none',
    event_type: 'dns',
  });

  // 2. Port Scan Attack: 192.168.1.20 probing 42 distinct destination ports within 30s
  const scanPorts = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1433,
    1521, 2049, 3306, 3389, 5432, 5900, 5985, 6379, 8000, 8080, 8443, 8888,
    9000, 9200, 11211, 27017, 27018, 5000, 8008, 8088, 8880, 9090, 9443, 10000,
    161, 389
  ];

  scanPorts.forEach((port, idx) => {
    allRecords.push({
      id: `dem_scan_${idx + 1}`,
      timestamp: ts(200 + Math.floor(idx * 0.6)), // 42 ports in ~25 seconds
      source_ip: '192.168.1.20',
      dest_ip: '192.168.1.100',
      src_port: 55000 + idx,
      dest_port: port,
      protocol: 'TCP',
      bytes: 64,
      packets: 1,
      auth_status: 'none',
      event_type: 'connection',
    });
  });

  // 3. Brute Force Credential Attack: 10.0.0.15 launching 37 failed logins against SSH/Auth within 60s
  for (let i = 1; i <= 37; i++) {
    allRecords.push({
      id: `dem_bf_${i}`,
      timestamp: ts(220 + Math.floor(i * 1.4)), // 37 attempts across ~50 seconds
      source_ip: '10.0.0.15',
      dest_ip: '10.0.0.2',
      src_port: 48000 + i,
      dest_port: 22,
      protocol: 'SSH',
      bytes: 1420,
      packets: 8,
      auth_status: 'failure',
      event_type: 'auth',
    });
  }

  // 4. Lateral Movement: 10.0.1.50 hopping across 14 internal endpoints on SMB/RDP ports 445 & 3389
  const internalDestHosts = [
    '10.0.2.10', '10.0.2.11', '10.0.2.12', '10.0.2.15', '10.0.2.22', '10.0.2.30',
    '10.0.2.45', '10.0.2.50', '10.0.2.66', '10.0.2.80', '10.0.2.91', '10.0.2.105',
    '10.0.2.118', '10.0.2.140'
  ];

  internalDestHosts.forEach((targetHost, idx) => {
    allRecords.push({
      id: `dem_lat_${idx + 1}`,
      timestamp: ts(240 + idx * 2),
      source_ip: '10.0.1.50',
      dest_ip: targetHost,
      src_port: 51200 + idx,
      dest_port: idx % 2 === 0 ? 445 : 3389,
      protocol: 'SMB',
      bytes: 38400,
      packets: 42,
      auth_status: 'success',
      event_type: 'connection',
    });
  });

  // 5. Data Exfiltration: 10.0.0.25 transmitting 850 MB outbound to unusual external host 198.51.100.89
  allRecords.push({
    id: 'dem_exfil_1',
    timestamp: ts(285),
    source_ip: '10.0.0.25',
    dest_ip: '198.51.100.89',
    src_port: 59340,
    dest_port: 443,
    protocol: 'HTTPS',
    bytes: 850 * 1024 * 1024, // 850 MB
    packets: 580000,
    auth_status: 'none',
    event_type: 'file_transfer',
  });

  // Sort chronologically by timestamp
  allRecords.sort((a, b) => new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime());

  return {
    name: 'Comprehensive SOC Attack & Baseline Telemetry Replay',
    records: allRecords,
  };
}

export const SAMPLE_JSON_SNIPPET = JSON.stringify(
  [
    {
      timestamp: new Date().toISOString(),
      source_ip: "192.168.1.20",
      dest_ip: "192.168.1.100",
      src_port: 54122,
      dest_port: 445,
      protocol: "TCP",
      bytes: 64,
      packets: 1,
      auth_status: "none",
      event_type: "connection"
    },
    {
      timestamp: new Date(Date.now() - 5000).toISOString(),
      source_ip: "10.0.0.15",
      dest_ip: "10.0.0.2",
      src_port: 48110,
      dest_port: 22,
      protocol: "SSH",
      bytes: 1420,
      packets: 8,
      auth_status: "failure",
      event_type: "auth"
    },
    {
      timestamp: new Date(Date.now() - 10000).toISOString(),
      source_ip: "10.0.0.25",
      dest_ip: "198.51.100.89",
      src_port: 59340,
      dest_port: 443,
      protocol: "HTTPS",
      bytes: 891289600,
      packets: 582100,
      auth_status: "none",
      event_type: "file_transfer"
    }
  ],
  null,
  2
);

export const SAMPLE_CSV_SNIPPET = `timestamp,source_ip,dest_ip,src_port,dest_port,protocol,bytes,packets,auth_status,event_type
${new Date().toISOString()},192.168.1.20,192.168.1.100,54122,80,TCP,64,1,none,connection
${new Date(Date.now() - 1000).toISOString()},192.168.1.20,192.168.1.100,54123,443,TCP,64,1,none,connection
${new Date(Date.now() - 2000).toISOString()},192.168.1.20,192.168.1.100,54124,22,TCP,64,1,none,connection
${new Date(Date.now() - 3000).toISOString()},192.168.1.20,192.168.1.100,54125,445,TCP,64,1,none,connection
${new Date(Date.now() - 4000).toISOString()},10.0.0.15,10.0.0.2,49200,22,SSH,1200,6,failure,auth
${new Date(Date.now() - 5000).toISOString()},10.0.0.15,10.0.0.2,49201,22,SSH,1200,6,failure,auth
${new Date(Date.now() - 6000).toISOString()},10.0.0.25,198.51.100.89,59340,443,HTTPS,891289600,582100,none,file_transfer`;
