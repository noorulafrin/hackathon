import { BehavioralFeatures, ThreatClassification, AnomalyResult, SecurityPolicy } from '../src/types/cyber.ts';

export interface ExplanationResult {
  evidence_statements: string[];
  recommended_action: string;
  policy_breach: boolean;
}

export function generateEvidenceExplanation(
  features: BehavioralFeatures,
  classification: ThreatClassification,
  anomaly: AnomalyResult,
  riskScore: number,
  policy: SecurityPolicy
): ExplanationResult {
  const statements: string[] = [];

  // 1. Concrete quantitative evidence statements
  if (features.unique_dest_port_count >= 5) {
    statements.push(
      `${features.unique_dest_port_count} unique destination ports probed across host within ${features.window_seconds}s window.`
    );
  }

  if (features.failed_login_count >= 2) {
    const failRateStr = (features.auth_fail_ratio * 100).toFixed(0);
    statements.push(
      `${features.failed_login_count} failed authentication attempts recorded (${failRateStr}% failure rate) within ${features.window_seconds}s.`
    );
  }

  const egressMb = (features.bytes_sent / (1024 * 1024)).toFixed(1);
  if (features.bytes_sent >= 10 * 1024 * 1024) {
    statements.push(
      `${egressMb} MB outbound egress traffic transferred to ${features.is_external_egress ? 'external remote endpoint' : 'internal host'}.`
    );
  }

  if (features.is_lateral_internal && features.unique_dest_count >= 3) {
    statements.push(
      `Internal peer-to-peer lateral connection fan-out: ${features.unique_dest_count} distinct internal endpoints contacted.`
    );
  }

  if (features.connection_rate_per_sec >= 1.0) {
    statements.push(
      `High burst connection frequency: ${features.connection_rate_per_sec} flows/sec (${features.events_per_source} total events in window).`
    );
  }

  if (anomaly.is_anomalous) {
    statements.push(
      `Isolation Forest flagged behavioral outlier: anomaly score ${anomaly.anomaly_score}/100 with deviation in ${anomaly.contributing_features.map((c) => c.feature).slice(0, 2).join(' & ')}.`
    );
  }

  if (features.is_noise_traffic) {
    statements.push(
      `Traffic matches known benign network protocol or broadcast pattern (noise reduction discount applied).`
    );
  }

  if (statements.length === 0) {
    statements.push('Nominal communication pattern consistent with established baseline profile.');
  }

  // 2. Concrete recommended SOC actions based on attack vector
  let recommendedAction = 'Continue routine telemetry surveillance. No containment required.';

  switch (classification.predicted_threat) {
    case 'Port Scan':
      recommendedAction =
        'Enforce dynamic rate-limiting on source IP, drop SYN packets at edge perimeter, and inspect host for automated scanner utility (e.g. Nmap/ZMap).';
      break;
    case 'Brute Force':
      recommendedAction =
        'Temporarily lock targeted service accounts, terminate active authentication sessions, enforce MFA requirement, and block attacker IP at firewall.';
      break;
    case 'Lateral Movement':
      recommendedAction =
        'Isolate compromised source endpoint on VLAN, revoke Kerberos/NTLM tickets, inspect SMB/RDP administrative shares, and review endpoint EDR process tree.';
      break;
    case 'Data Exfiltration':
      recommendedAction =
        'Sever egress socket immediately, block destination IP on perimeter firewall/proxy, initiate packet capture, and trigger DLP incident response triage.';
      break;
    case 'Suspicious / Unknown Anomaly':
      recommendedAction =
        'Triage anomalous network flow, capture full PCAP payload for forensic inspection, and verify integrity of source process with endpoint EDR.';
      break;
    case 'Normal':
      recommendedAction = 'Traffic within baseline tolerances. Maintain standard SOC logging.';
      break;
  }

  // 3. Policy evaluation
  const policyBreach = riskScore >= policy.max_risk_threshold;

  return {
    evidence_statements: statements,
    recommended_action: recommendedAction,
    policy_breach: policyBreach,
  };
}
