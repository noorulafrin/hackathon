import { BehavioralFeatures, ThreatClass, ThreatClassification } from '../src/types/cyber.ts';

export function classifyThreat(
  features: BehavioralFeatures,
  anomalyScore: number
): ThreatClassification {
  // Compute unnormalized logit scores for each class
  let logitPortScan = 0.5;
  let logitBruteForce = 0.5;
  let logitLateral = 0.5;
  let logitExfiltration = 0.5;
  let logitSuspicious = 1.0;
  let logitNormal = 8.0; // High baseline prior for normal

  // 1. Port Scan Indicators
  if (features.unique_dest_port_count >= 5) {
    logitPortScan += features.unique_dest_port_count * 0.45;
    logitNormal -= 3.0;
  }
  if (features.unique_dest_port_count >= 20) {
    logitPortScan += 8.0;
    logitNormal -= 8.0;
  }
  if (features.connection_rate_per_sec > 1.5 && features.unique_dest_port_count > 10) {
    logitPortScan += 4.0;
  }

  // 2. Brute Force Indicators
  if (features.failed_login_count >= 3) {
    logitBruteForce += features.failed_login_count * 0.5;
    logitNormal -= 2.5;
  }
  if (features.failed_login_count >= 15) {
    logitBruteForce += 10.0;
    logitNormal -= 8.0;
  }
  if (features.auth_fail_ratio >= 0.7 && features.events_per_source >= 5) {
    logitBruteForce += 5.0;
  }

  // 3. Lateral Movement Indicators
  if (features.is_lateral_internal) {
    if (features.unique_dest_count >= 4) {
      logitLateral += features.unique_dest_count * 0.6;
      logitNormal -= 3.0;
    }
    if (features.unique_dest_count >= 10) {
      logitLateral += 9.0;
      logitNormal -= 7.0;
    }
  }

  // 4. Data Exfiltration Indicators
  // Over 50 MB egress, especially to external destinations
  const egressMb = features.bytes_sent / (1024 * 1024);
  if (features.is_external_egress && egressMb > 20) {
    logitExfiltration += Math.min(15, egressMb * 0.05);
    logitNormal -= 4.0;
  }
  if (egressMb > 200) {
    logitExfiltration += 12.0;
    logitNormal -= 9.0;
  }

  // 5. Suspicious / Unknown Anomaly Indicators
  if (anomalyScore >= 60 && logitPortScan < 5 && logitBruteForce < 5 && logitLateral < 5 && logitExfiltration < 5) {
    logitSuspicious += (anomalyScore - 50) * 0.2;
    logitNormal -= 4.0;
  }

  // 6. Benign / Noise handling discount
  if (features.is_noise_traffic) {
    logitNormal += 10.0;
    logitPortScan = Math.min(logitPortScan, 1.0);
    logitBruteForce = Math.min(logitBruteForce, 1.0);
    logitLateral = Math.min(logitLateral, 1.0);
    logitExfiltration = Math.min(logitExfiltration, 1.0);
    logitSuspicious = Math.min(logitSuspicious, 1.0);
  }

  const logits: Record<ThreatClass, number> = {
    'Port Scan': Math.max(0.1, logitPortScan),
    'Brute Force': Math.max(0.1, logitBruteForce),
    'Lateral Movement': Math.max(0.1, logitLateral),
    'Data Exfiltration': Math.max(0.1, logitExfiltration),
    'Suspicious / Unknown Anomaly': Math.max(0.1, logitSuspicious),
    'Normal': Math.max(0.1, logitNormal),
  };

  // Softmax normalization with temperature T = 1.8 for balanced calibration
  const temperature = 1.8;
  const classes = Object.keys(logits) as ThreatClass[];
  const maxLogit = Math.max(...classes.map((c) => logits[c]));

  const expValues = classes.map((c) => Math.exp((logits[c] - maxLogit) / temperature));
  const sumExp = expValues.reduce((a, b) => a + b, 0);

  const rawProbs: Record<ThreatClass, number> = {} as any;
  let highestClass: ThreatClass = 'Normal';
  let highestProb = 0;

  classes.forEach((c, idx) => {
    const p = Math.round((expValues[idx] / sumExp) * 100);
    rawProbs[c] = p;
    if (p > highestProb) {
      highestProb = p;
      highestClass = c;
    }
  });

  // Adjust sum to strictly 100%
  const currentSum = Object.values(rawProbs).reduce((a, b) => a + b, 0);
  const diff = 100 - currentSum;
  rawProbs[highestClass] += diff;

  return {
    predicted_threat: highestClass,
    confidence_pct: rawProbs[highestClass],
    probabilities: rawProbs,
  };
}
