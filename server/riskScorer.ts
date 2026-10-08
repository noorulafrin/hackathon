import { BehavioralFeatures, RiskScoreResult, SeverityLevel, ThreatClassification } from '../src/types/cyber.ts';

export function calculateDeterministicRiskScore(
  features: BehavioralFeatures,
  anomalyScore: number,
  classification: ThreatClassification
): RiskScoreResult {
  let behavioralSeverity = 5;

  // Specific evidence additive points
  if (features.unique_dest_port_count >= 30) {
    behavioralSeverity += 50;
  } else if (features.unique_dest_port_count >= 15) {
    behavioralSeverity += 35;
  } else if (features.unique_dest_port_count >= 5) {
    behavioralSeverity += 15;
  }

  if (features.failed_login_count >= 30) {
    behavioralSeverity += 55;
  } else if (features.failed_login_count >= 10) {
    behavioralSeverity += 35;
  } else if (features.failed_login_count >= 3) {
    behavioralSeverity += 15;
  }

  const egressMb = features.bytes_sent / (1024 * 1024);
  if (egressMb >= 500) {
    behavioralSeverity += 60;
  } else if (egressMb >= 100) {
    behavioralSeverity += 40;
  } else if (egressMb >= 20) {
    behavioralSeverity += 20;
  }

  if (features.is_lateral_internal && features.unique_dest_count >= 8) {
    behavioralSeverity += 45;
  } else if (features.is_lateral_internal && features.unique_dest_count >= 3) {
    behavioralSeverity += 20;
  }

  // Weightings
  const anomalyContribution = Math.round(anomalyScore * 0.35);
  const confidenceContribution = Math.round((classification.confidence_pct / 100) * 25);
  const behavioralContribution = Math.min(45, Math.round(behavioralSeverity * 0.4));

  let noiseDiscount = 0;
  if (features.is_noise_traffic) {
    noiseDiscount = 40;
  }

  if (classification.predicted_threat === 'Normal') {
    noiseDiscount += 25;
  }

  // Total raw score
  let rawScore = anomalyContribution + confidenceContribution + behavioralContribution - noiseDiscount;

  // Specific high-confidence threat floors:
  if (classification.predicted_threat === 'Port Scan' && features.unique_dest_port_count >= 25) {
    rawScore = Math.max(rawScore, 82);
  }
  if (classification.predicted_threat === 'Brute Force' && features.failed_login_count >= 25) {
    rawScore = Math.max(rawScore, 78);
  }
  if (classification.predicted_threat === 'Data Exfiltration' && egressMb >= 400) {
    rawScore = Math.max(rawScore, 90);
  }
  if (classification.predicted_threat === 'Lateral Movement' && features.unique_dest_count >= 10) {
    rawScore = Math.max(rawScore, 76);
  }

  // Ensure deterministic clamping between 0 and 100
  const finalScore = Math.max(0, Math.min(100, Math.round(rawScore)));

  // Categorize into standard cybersecurity risk bands
  let severity: SeverityLevel = 'Normal';
  if (finalScore >= 71) {
    severity = 'Malicious';
  } else if (finalScore >= 31) {
    severity = 'Suspicious';
  } else {
    severity = 'Normal';
  }

  return {
    risk_score: finalScore,
    severity,
    breakdown: {
      anomaly_contribution: anomalyContribution,
      confidence_contribution: confidenceContribution,
      behavioral_severity: behavioralContribution,
      noise_discount: noiseDiscount,
    },
  };
}
